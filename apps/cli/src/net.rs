//! Transport/client construction shared by every network subcommand.
//!
//! Every network subcommand (`context`, `object`, `receipt`, `next-nonce`,
//! `transfer`; not `address`, which never dials out) accepts the same paired
//! optional `--tls-server-name`/`--tls-ca-cert-der-file` flags and parses
//! them centrally, here, into exactly one [`CliTransport`]. With neither
//! flag, `--endpoint` must be loopback and this binary talks the legacy
//! plaintext [`LoopbackHttpTransport`] (unchanged local-development
//! behavior). With both flags, `--endpoint` is treated as an already-
//! resolved remote [`SocketAddr`] (this binary performs no DNS resolution of
//! its own) and this binary instead dials [`RemoteTlsHttpTransport`] using
//! only the caller-supplied DNS name and bounded CA trust anchor — never a
//! system trust store, never IP-address hostname fallback, never
//! mTLS/redirects/retries/a proxy/background work (see `ARCHITECTURE.md`
//! DR-0085). Supplying exactly one of the two flags is a local configuration
//! error and fails closed before any network dispatch.
//!
//! Timeouts and body/header bounds are fixed, documented constants — not a
//! silently discovered default — because every subcommand needs exactly the
//! same bounded transport.

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use sunrise_edge_client::{
    Client, LoopbackHttpTransport, MAX_CA_CERTIFICATE_DER_BYTES, RemoteTlsHttpTransport, Transport,
    TransportError, WireRequest, WireResponse,
};

use crate::args::{FlagSpec, ParsedArgs, scalar};
use crate::error::CliError;

/// Bounded connect timeout for every request this binary makes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded read timeout for every request this binary makes.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded write timeout for every request this binary makes.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded TLS handshake read timeout, used only by the remote TLS transport.
pub const TLS_HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded TLS handshake write timeout, used only by the remote TLS transport.
pub const TLS_HANDSHAKE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum accepted response header bytes.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// Maximum accepted response body bytes.
pub const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// `--tls-server-name` flag name.
pub const TLS_SERVER_NAME: &str = "--tls-server-name";
/// `--tls-ca-cert-der-file` flag name.
pub const TLS_CA_CERT_DER_FILE: &str = "--tls-ca-cert-der-file";

/// The two optional TLS flag specs every network subcommand accepts, in
/// addition to its own flags.
#[must_use]
pub const fn tls_flag_specs() -> [FlagSpec; 2] {
    [scalar(TLS_SERVER_NAME), scalar(TLS_CA_CERT_DER_FILE)]
}

/// This binary's one production transport, exactly one of which any given
/// invocation constructs: the legacy loopback-only plaintext transport, or
/// the remote TLS transport. `Client<CliTransport>` is therefore always
/// exactly one concrete type, regardless of which mode a caller selected.
pub enum CliTransport {
    /// Legacy plaintext loopback transport (no TLS flags supplied).
    Loopback(LoopbackHttpTransport),
    /// Remote TLS transport (both TLS flags supplied).
    RemoteTls(RemoteTlsHttpTransport),
}

impl Transport for CliTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        match self {
            Self::Loopback(transport) => transport.send(request),
            Self::RemoteTls(transport) => transport.send(request),
        }
    }
}

/// Parses `value` as a socket address and rejects anything but loopback.
pub fn parse_loopback_endpoint(value: &str) -> Result<SocketAddr, CliError> {
    let addr = parse_endpoint(value)?;
    if !addr.ip().is_loopback() {
        return Err(CliError::NonLoopbackEndpoint(addr));
    }
    Ok(addr)
}

fn parse_endpoint(value: &str) -> Result<SocketAddr, CliError> {
    value.parse().map_err(|source| CliError::InvalidEndpoint {
        value: value.to_string(),
        source,
    })
}

/// Builds a bounded client targeting `endpoint`, using `tls` to select and
/// configure this binary's one production transport (see the module docs).
pub fn connect(endpoint: &str, tls: &ParsedArgs) -> Result<Client<CliTransport>, CliError> {
    let transport = build_transport(
        endpoint,
        tls.get(TLS_SERVER_NAME),
        tls.get(TLS_CA_CERT_DER_FILE),
    )?;
    Ok(Client::new(transport))
}

fn build_transport(
    endpoint: &str,
    server_name: Option<&str>,
    ca_cert_der_file: Option<&str>,
) -> Result<CliTransport, CliError> {
    match (server_name, ca_cert_der_file) {
        (None, None) => Ok(CliTransport::Loopback(connect_loopback(endpoint)?)),
        (Some(server_name), Some(ca_cert_der_file)) => Ok(CliTransport::RemoteTls(
            connect_remote_tls(endpoint, server_name, ca_cert_der_file)?,
        )),
        (Some(_), None) => Err(CliError::PartialTlsConfiguration {
            missing: TLS_CA_CERT_DER_FILE,
        }),
        (None, Some(_)) => Err(CliError::PartialTlsConfiguration {
            missing: TLS_SERVER_NAME,
        }),
    }
}

fn connect_loopback(endpoint: &str) -> Result<LoopbackHttpTransport, CliError> {
    let addr = parse_loopback_endpoint(endpoint)?;
    LoopbackHttpTransport::new(
        addr,
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        WRITE_TIMEOUT,
        NonZeroUsize::new(MAX_RESPONSE_HEADER_BYTES).unwrap_or(NonZeroUsize::MIN),
        NonZeroUsize::new(MAX_RESPONSE_BODY_BYTES).unwrap_or(NonZeroUsize::MIN),
    )
    .map_err(CliError::Transport)
}

fn connect_remote_tls(
    endpoint: &str,
    server_name: &str,
    ca_cert_der_file: &str,
) -> Result<RemoteTlsHttpTransport, CliError> {
    // No DNS resolution happens here or anywhere else in this binary:
    // `--endpoint` must already be a literal `SocketAddr`, and `server_name`
    // is used only for TLS SNI/hostname validation, never resolved.
    let addr = parse_endpoint(endpoint)?;
    let ca_der = read_bounded_ca_cert_der(ca_cert_der_file)?;
    RemoteTlsHttpTransport::new(
        addr,
        server_name,
        &ca_der,
        CONNECT_TIMEOUT,
        TLS_HANDSHAKE_READ_TIMEOUT,
        TLS_HANDSHAKE_WRITE_TIMEOUT,
        READ_TIMEOUT,
        WRITE_TIMEOUT,
        NonZeroUsize::new(MAX_RESPONSE_HEADER_BYTES).unwrap_or(NonZeroUsize::MIN),
        NonZeroUsize::new(MAX_RESPONSE_BODY_BYTES).unwrap_or(NonZeroUsize::MIN),
    )
    .map_err(CliError::Transport)
}

/// Reads `path` as a bounded CA trust-anchor DER file, using only `std`.
///
/// The read is capped at one byte more than
/// [`MAX_CA_CERTIFICATE_DER_BYTES`] before allocation or the read completes
/// (via a bounded [`Read::take`] adaptor), so a caller can never be made to
/// buffer an unbounded amount of attacker- or mistake-supplied file content
/// just to detect that it is oversized. An empty file, an oversized file, and
/// any I/O failure are each reported as a distinct, actionable [`CliError`]
/// variant that names the path but never the file's contents.
fn read_bounded_ca_cert_der(path: &str) -> Result<Vec<u8>, CliError> {
    let mut file = File::open(path).map_err(|source| CliError::CaCertificateFileRead {
        path: path.to_string(),
        source,
    })?;
    let cap = u64::try_from(MAX_CA_CERTIFICATE_DER_BYTES).unwrap_or(u64::MAX);
    let mut buffer = Vec::new();
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|source| CliError::CaCertificateFileRead {
            path: path.to_string(),
            source,
        })?;
    if buffer.len() > MAX_CA_CERTIFICATE_DER_BYTES {
        return Err(CliError::CaCertificateFileTooLarge {
            path: path.to_string(),
            maximum: MAX_CA_CERTIFICATE_DER_BYTES,
        });
    }
    if buffer.is_empty() {
        return Err(CliError::CaCertificateFileEmpty {
            path: path.to_string(),
        });
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(contents: &[u8]) -> Self {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-cli-net-test-{}-{sequence}",
                std::process::id()
            ));
            let mut file = File::create(&path).unwrap();
            file.write_all(contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_file(&self.0);
        }
    }

    fn parsed(pairs: &[(&'static str, &str)]) -> ParsedArgs {
        let specs: Vec<FlagSpec> = pairs.iter().map(|(name, _)| scalar(name)).collect();
        let args: Vec<std::ffi::OsString> = pairs
            .iter()
            .flat_map(|(name, value)| {
                [
                    std::ffi::OsString::from(*name),
                    std::ffi::OsString::from(*value),
                ]
            })
            .collect();
        crate::args::parse_flags(args, &specs).unwrap()
    }

    #[test]
    fn accepts_loopback_endpoints() {
        assert!(parse_loopback_endpoint("127.0.0.1:7400").is_ok());
        assert!(parse_loopback_endpoint("[::1]:7400").is_ok());
    }

    #[test]
    fn rejects_non_loopback_endpoints() {
        assert!(matches!(
            parse_loopback_endpoint("93.184.216.34:80"),
            Err(CliError::NonLoopbackEndpoint(_))
        ));
    }

    #[test]
    fn rejects_malformed_endpoints() {
        assert!(matches!(
            parse_loopback_endpoint("not-an-address"),
            Err(CliError::InvalidEndpoint { .. })
        ));
    }

    #[test]
    fn no_tls_flags_selects_loopback_and_still_rejects_non_loopback() {
        let tls = parsed(&[]);
        assert!(matches!(
            build_transport(
                "127.0.0.1:7400",
                tls.get(TLS_SERVER_NAME),
                tls.get(TLS_CA_CERT_DER_FILE)
            ),
            Ok(CliTransport::Loopback(_))
        ));
        assert!(matches!(
            build_transport(
                "93.184.216.34:80",
                tls.get(TLS_SERVER_NAME),
                tls.get(TLS_CA_CERT_DER_FILE)
            ),
            Err(CliError::NonLoopbackEndpoint(_))
        ));
    }

    #[test]
    fn only_server_name_fails_closed_before_any_network_dispatch() {
        let tls = parsed(&[(TLS_SERVER_NAME, "example.invalid")]);
        let result = build_transport(
            "93.184.216.34:443",
            tls.get(TLS_SERVER_NAME),
            tls.get(TLS_CA_CERT_DER_FILE),
        );
        assert!(matches!(
            result,
            Err(CliError::PartialTlsConfiguration {
                missing: TLS_CA_CERT_DER_FILE
            })
        ));
    }

    #[test]
    fn only_ca_cert_file_fails_closed_before_any_network_dispatch() {
        let ca_file = TempFile::new(&[0xAA; 8]);
        let tls = parsed(&[(TLS_CA_CERT_DER_FILE, ca_file.0.to_str().unwrap())]);
        let result = build_transport(
            "93.184.216.34:443",
            tls.get(TLS_SERVER_NAME),
            tls.get(TLS_CA_CERT_DER_FILE),
        );
        assert!(matches!(
            result,
            Err(CliError::PartialTlsConfiguration {
                missing: TLS_SERVER_NAME
            })
        ));
    }

    #[test]
    fn both_tls_flags_select_remote_tls_for_a_non_loopback_endpoint() {
        let ca_file = TempFile::new(&[0xAA; 8]);
        let tls = parsed(&[
            (TLS_SERVER_NAME, "example.invalid"),
            (TLS_CA_CERT_DER_FILE, ca_file.0.to_str().unwrap()),
        ]);
        // The DER bytes above are not a valid certificate, so construction
        // still fails, but as a `TransportError::InvalidCaCertificate`
        // surfaced only *after* the CA file was read successfully — proving
        // this reached the remote-TLS branch, not the loopback one, and
        // never rejected the address for being non-loopback.
        let result = build_transport(
            "93.184.216.34:443",
            tls.get(TLS_SERVER_NAME),
            tls.get(TLS_CA_CERT_DER_FILE),
        );
        assert!(matches!(
            result,
            Err(CliError::Transport(TransportError::InvalidCaCertificate(_)))
        ));
    }

    #[test]
    fn both_tls_flags_reject_a_malformed_dns_server_name() {
        let ca_file = TempFile::new(&[0xAA; 8]);
        let tls = parsed(&[
            (TLS_SERVER_NAME, "127.0.0.1"),
            (TLS_CA_CERT_DER_FILE, ca_file.0.to_str().unwrap()),
        ]);
        let result = build_transport(
            "93.184.216.34:443",
            tls.get(TLS_SERVER_NAME),
            tls.get(TLS_CA_CERT_DER_FILE),
        );
        assert!(matches!(
            result,
            Err(CliError::Transport(TransportError::InvalidServerName))
        ));
    }

    #[test]
    fn rejects_an_empty_ca_cert_der_file() {
        let ca_file = TempFile::new(&[]);
        let result = read_bounded_ca_cert_der(ca_file.0.to_str().unwrap());
        assert!(matches!(
            result,
            Err(CliError::CaCertificateFileEmpty { .. })
        ));
    }

    #[test]
    fn rejects_an_oversized_ca_cert_der_file() {
        let ca_file = TempFile::new(&vec![0xAA; MAX_CA_CERTIFICATE_DER_BYTES + 1]);
        let result = read_bounded_ca_cert_der(ca_file.0.to_str().unwrap());
        assert!(matches!(
            result,
            Err(CliError::CaCertificateFileTooLarge { maximum, .. })
                if maximum == MAX_CA_CERTIFICATE_DER_BYTES
        ));
    }

    #[test]
    fn accepts_a_ca_cert_der_file_at_exactly_the_maximum_size() {
        let ca_file = TempFile::new(&vec![0xAA; MAX_CA_CERTIFICATE_DER_BYTES]);
        let result = read_bounded_ca_cert_der(ca_file.0.to_str().unwrap());
        assert_eq!(result.unwrap().len(), MAX_CA_CERTIFICATE_DER_BYTES);
    }

    #[test]
    fn reports_a_read_failure_for_a_missing_ca_cert_der_file() {
        let path = std::env::temp_dir().join("sunrise-edge-cli-net-test-missing-file");
        let result = read_bounded_ca_cert_der(path.to_str().unwrap());
        assert!(matches!(
            result,
            Err(CliError::CaCertificateFileRead { .. })
        ));
    }
}
