//! Loopback-only transport/client construction shared by every network
//! subcommand.
//!
//! Timeouts and body/header bounds are fixed, documented constants — not a
//! silently discovered default — because every subcommand needs exactly the
//! same bounded local-development transport.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use sunrise_edge_client::{Client, LoopbackHttpTransport};

use crate::error::CliError;

/// Bounded connect timeout for every request this binary makes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded read timeout for every request this binary makes.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded write timeout for every request this binary makes.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum accepted response header bytes.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// Maximum accepted response body bytes.
pub const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Parses `value` as a socket address and rejects anything but loopback.
pub fn parse_loopback_endpoint(value: &str) -> Result<SocketAddr, CliError> {
    let addr: SocketAddr = value.parse().map_err(|source| CliError::InvalidEndpoint {
        value: value.to_string(),
        source,
    })?;
    if !addr.ip().is_loopback() {
        return Err(CliError::NonLoopbackEndpoint(addr));
    }
    Ok(addr)
}

/// Builds a bounded loopback-only client targeting `endpoint`.
pub fn connect(endpoint: &str) -> Result<Client<LoopbackHttpTransport>, CliError> {
    let addr = parse_loopback_endpoint(endpoint)?;
    let transport = LoopbackHttpTransport::new(
        addr,
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        WRITE_TIMEOUT,
        NonZeroUsize::new(MAX_RESPONSE_HEADER_BYTES).unwrap_or(NonZeroUsize::MIN),
        NonZeroUsize::new(MAX_RESPONSE_BODY_BYTES).unwrap_or(NonZeroUsize::MIN),
    )
    .map_err(CliError::Transport)?;
    Ok(Client::new(transport))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
