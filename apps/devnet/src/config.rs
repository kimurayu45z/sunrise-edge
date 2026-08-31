//! Strict command-line configuration for the local devnet.

use node_core::MAX_CHAIN_ID_BYTES;
use protocol_types::{ChainId, Epoch};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    net::{AddrParseError, SocketAddr},
    num::ParseIntError,
    path::{Path, PathBuf},
};

/// Hard admission ceiling for the local-only devnet.
pub const MAX_DEVNET_CONCURRENCY: usize = 1_024;
/// Maximum development owners seeded by one local process boot.
pub const MAX_DEVNET_OWNERS: usize = 64;

/// One browser/client-controlled development owner address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevOwner([u8; 32]);

impl DevOwner {
    /// Creates a development owner from its exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact owner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for DevOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Validated process configuration for one local devnet boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevnetConfig {
    data_dir: PathBuf,
    listen: SocketAddr,
    chain_id: ChainId,
    epoch: Epoch,
    dev_owners: Vec<DevOwner>,
    max_concurrent: usize,
}

impl DevnetConfig {
    /// Parses command-line arguments after the executable name.
    ///
    /// Every scalar flag is required exactly once. `--dev-owner` is required
    /// at least once and may be repeated with distinct, exact 32-byte lowercase
    /// or uppercase hexadecimal values. Binding is restricted to loopback.
    pub fn parse_from<I, S>(args: I) -> Result<Self, DevnetConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut data_dir: Option<PathBuf> = None;
        let mut listen: Option<SocketAddr> = None;
        let mut chain_id: Option<ChainId> = None;
        let mut epoch: Option<Epoch> = None;
        let mut dev_owners: Vec<DevOwner> = Vec::new();
        let mut max_concurrent: Option<usize> = None;
        let mut iterator = args.into_iter().map(Into::into);

        while let Some(flag_os) = iterator.next() {
            let flag: &str = flag_os.to_str().ok_or(DevnetConfigError::NonUtf8Flag)?;
            match flag {
                "--data-dir" => {
                    ensure_absent("--data-dir", &data_dir)?;
                    let value: OsString = required_value(&mut iterator, "--data-dir")?;
                    if value.is_empty() {
                        return Err(DevnetConfigError::EmptyDataDirectory);
                    }
                    data_dir = Some(PathBuf::from(value));
                }
                "--listen" => {
                    ensure_absent("--listen", &listen)?;
                    let value: String = required_utf8_value(&mut iterator, "--listen")?;
                    let parsed: SocketAddr = value.parse().map_err(|source: AddrParseError| {
                        DevnetConfigError::InvalidListen { value, source }
                    })?;
                    if !parsed.ip().is_loopback() {
                        return Err(DevnetConfigError::NonLoopbackListen(parsed));
                    }
                    listen = Some(parsed);
                }
                "--chain-id" => {
                    ensure_absent("--chain-id", &chain_id)?;
                    let value: String = required_utf8_value(&mut iterator, "--chain-id")?;
                    if value.trim() != value {
                        return Err(DevnetConfigError::InvalidChainId(value));
                    }
                    let length: usize = value.len();
                    if length > MAX_CHAIN_ID_BYTES {
                        return Err(DevnetConfigError::ChainIdTooLong {
                            length,
                            maximum: MAX_CHAIN_ID_BYTES,
                        });
                    }
                    let parsed: ChainId = ChainId::new(value.clone())
                        .map_err(|_| DevnetConfigError::InvalidChainId(value))?;
                    chain_id = Some(parsed);
                }
                "--epoch" => {
                    ensure_absent("--epoch", &epoch)?;
                    let value: String = required_utf8_value(&mut iterator, "--epoch")?;
                    let parsed: u64 = value.parse().map_err(|source: ParseIntError| {
                        DevnetConfigError::InvalidInteger {
                            flag: "--epoch",
                            value,
                            source,
                        }
                    })?;
                    epoch = Some(Epoch::new(parsed));
                }
                "--dev-owner" => {
                    if dev_owners.len() >= MAX_DEVNET_OWNERS {
                        return Err(DevnetConfigError::TooManyDevOwners {
                            maximum: MAX_DEVNET_OWNERS,
                        });
                    }
                    let value: String = required_utf8_value(&mut iterator, "--dev-owner")?;
                    let owner: DevOwner = parse_dev_owner(&value)?;
                    if dev_owners.contains(&owner) {
                        return Err(DevnetConfigError::DuplicateDevOwner(owner));
                    }
                    dev_owners.push(owner);
                }
                "--max-concurrent" => {
                    ensure_absent("--max-concurrent", &max_concurrent)?;
                    let value: String = required_utf8_value(&mut iterator, "--max-concurrent")?;
                    let parsed: usize = value.parse().map_err(|source: ParseIntError| {
                        DevnetConfigError::InvalidInteger {
                            flag: "--max-concurrent",
                            value,
                            source,
                        }
                    })?;
                    if parsed == 0 || parsed > MAX_DEVNET_CONCURRENCY {
                        return Err(DevnetConfigError::MaxConcurrentOutOfRange(parsed));
                    }
                    max_concurrent = Some(parsed);
                }
                _ => return Err(DevnetConfigError::UnknownFlag(flag_os)),
            }
        }

        if dev_owners.is_empty() {
            return Err(DevnetConfigError::MissingDevOwner);
        }
        Ok(Self {
            data_dir: data_dir.ok_or(DevnetConfigError::MissingFlag("--data-dir"))?,
            listen: listen.ok_or(DevnetConfigError::MissingFlag("--listen"))?,
            chain_id: chain_id.ok_or(DevnetConfigError::MissingFlag("--chain-id"))?,
            epoch: epoch.ok_or(DevnetConfigError::MissingFlag("--epoch"))?,
            dev_owners,
            max_concurrent: max_concurrent
                .ok_or(DevnetConfigError::MissingFlag("--max-concurrent"))?,
        })
    }

    /// Returns the directory containing local devnet state.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the validated loopback listen address.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns the configured chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured starting epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the development owners in declared order.
    #[must_use]
    pub fn dev_owners(&self) -> &[DevOwner] {
        &self.dev_owners
    }

    /// Returns the bounded synchronous admission limit.
    #[must_use]
    pub const fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

fn ensure_absent<T>(flag: &'static str, value: &Option<T>) -> Result<(), DevnetConfigError> {
    if value.is_some() {
        Err(DevnetConfigError::DuplicateFlag(flag))
    } else {
        Ok(())
    }
}

fn required_value<I>(iterator: &mut I, flag: &'static str) -> Result<OsString, DevnetConfigError>
where
    I: Iterator<Item = OsString>,
{
    iterator.next().ok_or(DevnetConfigError::MissingValue(flag))
}

fn required_utf8_value<I>(iterator: &mut I, flag: &'static str) -> Result<String, DevnetConfigError>
where
    I: Iterator<Item = OsString>,
{
    let value: OsString = required_value(iterator, flag)?;
    value
        .into_string()
        .map_err(|_| DevnetConfigError::NonUtf8Value(flag))
}

fn parse_dev_owner(value: &str) -> Result<DevOwner, DevnetConfigError> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(DevnetConfigError::InvalidDevOwner(value.to_owned()));
    }
    let mut bytes: [u8; 32] = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high: u8 = decode_hex_nibble(pair[0]);
        let low: u8 = decode_hex_nibble(pair[1]);
        bytes[index] = (high << 4) | low;
    }
    Ok(DevOwner::new(bytes))
}

const fn decode_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

/// Fail-closed command-line configuration errors.
#[derive(Debug)]
pub enum DevnetConfigError {
    /// A command-line flag was not UTF-8.
    NonUtf8Flag,
    /// An unsupported flag was supplied.
    UnknownFlag(OsString),
    /// A required scalar flag was omitted.
    MissingFlag(&'static str),
    /// A scalar flag was repeated.
    DuplicateFlag(&'static str),
    /// A flag had no following value.
    MissingValue(&'static str),
    /// A flag requiring textual input received non-UTF-8 bytes.
    NonUtf8Value(&'static str),
    /// The data-directory argument was empty.
    EmptyDataDirectory,
    /// The listen address was not a socket address.
    InvalidListen {
        /// Rejected input.
        value: String,
        /// Parser failure.
        source: AddrParseError,
    },
    /// The devnet was asked to bind beyond loopback.
    NonLoopbackListen(SocketAddr),
    /// The chain identity was empty or padded with whitespace.
    InvalidChainId(String),
    /// The chain identity exceeded the ingress resource bound.
    ChainIdTooLong {
        /// Supplied UTF-8 byte length.
        length: usize,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// A decimal integer was invalid.
    InvalidInteger {
        /// Flag being parsed.
        flag: &'static str,
        /// Rejected input.
        value: String,
        /// Parser failure.
        source: ParseIntError,
    },
    /// The admission limit was zero or exceeded the local hard ceiling.
    MaxConcurrentOutOfRange(usize),
    /// No development owner was supplied.
    MissingDevOwner,
    /// More development owners were supplied than one boot may seed.
    TooManyDevOwners {
        /// Maximum owner count accepted by one process.
        maximum: usize,
    },
    /// A development owner was not exactly 32 bytes of hexadecimal.
    InvalidDevOwner(String),
    /// A development owner appeared more than once.
    DuplicateDevOwner(DevOwner),
}

impl fmt::Display for DevnetConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Flag => f.write_str("command-line flag is not valid UTF-8"),
            Self::UnknownFlag(flag) => write!(f, "unknown devnet flag: {}", flag.to_string_lossy()),
            Self::MissingFlag(flag) => write!(f, "required devnet flag is missing: {flag}"),
            Self::DuplicateFlag(flag) => write!(f, "devnet flag may appear only once: {flag}"),
            Self::MissingValue(flag) => write!(f, "devnet flag requires a value: {flag}"),
            Self::NonUtf8Value(flag) => write!(f, "devnet flag value is not valid UTF-8: {flag}"),
            Self::EmptyDataDirectory => f.write_str("--data-dir must not be empty"),
            Self::InvalidListen { value, .. } => write!(f, "invalid --listen address: {value}"),
            Self::NonLoopbackListen(address) => {
                write!(f, "--listen must be loopback-only, got {address}")
            }
            Self::InvalidChainId(value) => write!(f, "invalid --chain-id: {value:?}"),
            Self::ChainIdTooLong { length, maximum } => write!(
                f,
                "--chain-id is {length} bytes, maximum accepted length is {maximum}"
            ),
            Self::InvalidInteger { flag, value, .. } => {
                write!(f, "invalid decimal integer for {flag}: {value}")
            }
            Self::MaxConcurrentOutOfRange(value) => write!(
                f,
                "--max-concurrent must be in 1..={MAX_DEVNET_CONCURRENCY}, got {value}"
            ),
            Self::MissingDevOwner => f.write_str("at least one --dev-owner is required"),
            Self::TooManyDevOwners { maximum } => {
                write!(f, "at most {maximum} --dev-owner values are accepted")
            }
            Self::InvalidDevOwner(value) => write!(
                f,
                "--dev-owner must be exactly 64 hexadecimal characters, got {value:?}"
            ),
            Self::DuplicateDevOwner(owner) => {
                write!(f, "--dev-owner must be unique, duplicate {owner}")
            }
        }
    }
}

impl Error for DevnetConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidListen { source, .. } => Some(source),
            Self::InvalidInteger { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> Vec<OsString> {
        vec![
            "--data-dir".into(),
            "/tmp/sunrise-edge-devnet".into(),
            "--listen".into(),
            "127.0.0.1:7400".into(),
            "--chain-id".into(),
            "sunrise-dev".into(),
            "--epoch".into(),
            "7".into(),
            "--dev-owner".into(),
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "--max-concurrent".into(),
            "16".into(),
        ]
    }

    #[test]
    fn parses_exact_local_configuration() {
        let config = DevnetConfig::parse_from(valid_args()).unwrap();
        assert_eq!(config.listen(), "127.0.0.1:7400".parse().unwrap());
        assert_eq!(config.chain_id().as_str(), "sunrise-dev");
        assert_eq!(config.epoch(), Epoch::new(7));
        assert_eq!(config.dev_owners(), &[DevOwner::new([0x11; 32])]);
        assert_eq!(config.max_concurrent(), 16);
    }

    #[test]
    fn rejects_non_loopback_binding() {
        let mut args = valid_args();
        args[3] = "0.0.0.0:7400".into();
        assert!(matches!(
            DevnetConfig::parse_from(args),
            Err(DevnetConfigError::NonLoopbackListen(_))
        ));
    }

    #[test]
    fn requires_owner_and_bounded_nonzero_admission() {
        let mut without_owner = valid_args();
        without_owner.drain(8..10);
        assert!(matches!(
            DevnetConfig::parse_from(without_owner),
            Err(DevnetConfigError::MissingDevOwner)
        ));

        for value in ["0", "1025"] {
            let mut args = valid_args();
            args[11] = value.into();
            assert!(matches!(
                DevnetConfig::parse_from(args),
                Err(DevnetConfigError::MaxConcurrentOutOfRange(_))
            ));
        }
    }

    #[test]
    fn rejects_malformed_or_duplicate_owner() {
        let mut malformed = valid_args();
        malformed[9] = "11".into();
        assert!(matches!(
            DevnetConfig::parse_from(malformed),
            Err(DevnetConfigError::InvalidDevOwner(_))
        ));

        let mut duplicate = valid_args();
        duplicate.splice(
            10..10,
            [
                OsString::from("--dev-owner"),
                OsString::from("1111111111111111111111111111111111111111111111111111111111111111"),
            ],
        );
        assert!(matches!(
            DevnetConfig::parse_from(duplicate),
            Err(DevnetConfigError::DuplicateDevOwner(_))
        ));
    }

    #[test]
    fn rejects_more_than_the_bounded_owner_count() {
        let mut args: Vec<OsString> = valid_args();
        args.drain(8..10);
        let max_concurrent: Vec<OsString> = args.split_off(8);
        for value in 1..=(MAX_DEVNET_OWNERS + 1) {
            args.push(OsString::from("--dev-owner"));
            args.push(OsString::from(format!("{value:064x}")));
        }
        args.extend(max_concurrent);

        assert!(matches!(
            DevnetConfig::parse_from(args),
            Err(DevnetConfigError::TooManyDevOwners {
                maximum: MAX_DEVNET_OWNERS
            })
        ));
    }

    #[test]
    fn rejects_unknown_duplicate_missing_value_and_long_chain_flags() {
        let mut unknown = valid_args();
        unknown.push("positional".into());
        assert!(matches!(
            DevnetConfig::parse_from(unknown),
            Err(DevnetConfigError::UnknownFlag(_))
        ));

        let mut duplicate = valid_args();
        duplicate.extend(["--epoch".into(), "8".into()]);
        assert!(matches!(
            DevnetConfig::parse_from(duplicate),
            Err(DevnetConfigError::DuplicateFlag("--epoch"))
        ));

        assert!(matches!(
            DevnetConfig::parse_from([OsString::from("--data-dir")]),
            Err(DevnetConfigError::MissingValue("--data-dir"))
        ));

        let mut long_chain = valid_args();
        long_chain[5] = "x".repeat(MAX_CHAIN_ID_BYTES + 1).into();
        assert!(matches!(
            DevnetConfig::parse_from(long_chain),
            Err(DevnetConfigError::ChainIdTooLong { .. })
        ));
    }
}
