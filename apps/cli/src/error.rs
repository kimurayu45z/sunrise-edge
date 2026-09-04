//! Aggregated, typed, actionable CLI errors.

use std::fmt;
use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;

use sunrise_edge_client::{
    CanonicalEncodingError, ClientError, ExpectedProtocolContextError, NodeCoreError, ObjectError,
    TransportError, TypeError,
};

use crate::args::ArgsError;
use crate::hex::HexError;
use crate::seed::SeedFileError;

/// Every error this binary can return. `main` prints this and exits
/// non-zero for every variant.
#[derive(Debug)]
pub enum CliError {
    /// No subcommand was supplied.
    MissingCommand,
    /// The supplied subcommand name is not implemented.
    UnknownCommand(String),
    /// Argument parsing failed.
    Args(ArgsError),
    /// A hexadecimal argument was malformed.
    Hex(HexError),
    /// Development seed file loading failed.
    Seed(SeedFileError),
    /// `--endpoint` was not a valid socket address.
    InvalidEndpoint {
        /// The rejected value.
        value: String,
        /// The parser failure.
        source: AddrParseError,
    },
    /// `--endpoint` was not a loopback address.
    NonLoopbackEndpoint(SocketAddr),
    /// Exactly one of the paired `--tls-server-name`/`--tls-ca-cert-der-file`
    /// flags was supplied; both or neither are required, and this is
    /// reported before any network dispatch.
    PartialTlsConfiguration {
        /// The flag that must also be supplied to complete the pair.
        missing: &'static str,
    },
    /// The `--tls-ca-cert-der-file` path could not be opened or read.
    CaCertificateFileRead {
        /// The rejected path.
        path: String,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The `--tls-ca-cert-der-file` contents were empty.
    CaCertificateFileEmpty {
        /// The rejected path.
        path: String,
    },
    /// The `--tls-ca-cert-der-file` contents exceeded the client's maximum
    /// accepted CA trust-anchor DER length.
    CaCertificateFileTooLarge {
        /// The rejected path.
        path: String,
        /// The configured maximum, in bytes.
        maximum: usize,
    },
    /// A decimal integer argument was invalid.
    InvalidInteger {
        /// Flag name.
        flag: &'static str,
        /// Rejected value.
        value: String,
        /// Parser failure.
        source: ParseIntError,
    },
    /// A hash-algorithm identifier was not one this workspace implements.
    InvalidHashAlgorithm(u16),
    /// `--amount` was zero.
    ZeroAmount,
    /// `--gas-limit` was zero.
    ZeroGasLimit,
    /// `--source-object` and `--destination-object` named the same object.
    SameSourceAndDestination,
    /// Exactly one of the paired `--fee-asset-id`/`--max-fee`/
    /// `--fee-treasury-object` flags was supplied; all three or none are
    /// required, and this is reported before any network dispatch.
    PartialFeeConfiguration {
        /// A flag that must also be supplied to complete the trio.
        missing: &'static str,
    },
    /// `--max-fee` was zero.
    ZeroMaxFee,
    /// `--fee-treasury-object` named the same object as `--source-object` or
    /// `--destination-object`.
    FeeTreasuryConflictsWithTransfer,
    /// A `--wait-*` bound flag was supplied without `--wait`.
    WaitBoundWithoutWait(&'static str),
    /// `--wait` was supplied without one of its required bound flags.
    WaitBoundRequired(&'static str),
    /// An `--expected-chain-id` or `--expected-domain` flag failed to
    /// construct a valid protocol type (an empty chain id, or an all-zero
    /// domain).
    InvalidExpectedProtocolType(TypeError),
    /// The locally constructed S1 expected protocol context (see
    /// `ARCHITECTURE.md` DR-0085) had a missing/zero/malformed field.
    InvalidExpectedContext(ExpectedProtocolContextError),
    /// The next-nonce query result's epoch disagreed with the context
    /// query's epoch.
    EpochMismatch {
        /// Epoch reported by `/v1/context`.
        context_epoch: u64,
        /// Epoch reported by the next-nonce query.
        nonce_epoch: u64,
    },
    /// A referenced object is not currently a live, `Write`-usable inline
    /// object.
    ObjectNotCurrentlyInline {
        /// Flag naming the object.
        flag: &'static str,
        /// The object identifier, as hex.
        object_id: String,
        /// A stable status label (`absent`, `tombstoned`, or
        /// `current_blob_reference`).
        status: &'static str,
    },
    /// A `CurrentInline` object's canonical body failed to decode.
    ObjectBodyDecodeFailed {
        /// Flag naming the object.
        flag: &'static str,
        /// The object identifier, as hex.
        object_id: String,
        /// The decode failure.
        source: ObjectError,
    },
    /// A referenced object exists and is `CurrentInline`, but its owner does
    /// not equal the locally required address for that access.
    ObjectOwnerMismatch {
        /// Flag naming the object.
        flag: &'static str,
        /// The object identifier, as hex.
        object_id: String,
        /// The exact locally required Address owner, as hex.
        expected_owner: String,
        /// A stable label describing the actual owner
        /// (`address:<hex>`, `shared`, `immutable`, or `system`).
        owner: String,
    },
    /// `submit_transaction` returned zero responses for the submitted
    /// request.
    EmptySubmitResponse,
    /// A submitted transaction's response declared
    /// `NodeResponseStatus::Rejected`.
    TransactionRejected {
        /// Index into the submit result's `responses()` for the rejected
        /// response.
        index: usize,
    },
    /// A submitted transaction's response was `Accepted` at the node-core
    /// level, but its decoded execution effects declared
    /// `ExecutionStatus::Failure`.
    TransactionExecutionFailed {
        /// Index into the submit result's `responses()` for the failed
        /// response.
        index: usize,
        /// The sanitized execution failure reason.
        reason: String,
    },
    /// Canonical argument-frame encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// A node-core canonical type failed to construct or validate.
    NodeCore(NodeCoreError),
    /// The bounded transport layer failed before a transaction could be
    /// submitted.
    Transport(TransportError),
    /// The `sunrise-edge-client` library rejected a call. Boxed because
    /// `ClientError` is large relative to this enum's other variants.
    Client(Box<ClientError>),
    /// No signer was selected: neither `--seed-file` nor all three of
    /// `--ledger-hid-path`/`--ledger-account`/
    /// `--ledger-expected-firmware-version` were supplied.
    MissingSignerSelection,
    /// `--seed-file` was combined with any of `--ledger-hid-path`,
    /// `--ledger-account`, or `--ledger-expected-firmware-version`; exactly
    /// one signer must be selected.
    ConflictingSignerSelection,
    /// Exactly one of the paired `--ledger-hid-path`/`--ledger-account`/
    /// `--ledger-expected-firmware-version` flags was supplied; all three
    /// are required together.
    PartialLedgerSignerConfiguration {
        /// The flag that must also be supplied to complete the trio.
        missing: &'static str,
    },
    /// `--ledger-expected-firmware-version` was empty, non-ASCII, or too
    /// long. Reported before any device connection is ever attempted.
    LedgerExpectedFirmwareVersion(sunrise_edge_ledger::ExpectedFirmwareVersionError),
    /// Connecting to a Ledger device or verifying its reported
    /// configuration/public key failed before any transaction was ever
    /// prepared or signed.
    LedgerConnect(Box<dyn std::error::Error + Send + Sync>),
    /// Verifying the device's dashboard/firmware identity, opening the
    /// Sunrise application, or verifying the reconnected active
    /// application's identity failed (see
    /// `sunrise_edge_ledger::verify_dashboard_and_open`/
    /// `verify_active_app`).
    LedgerIdentity(Box<dyn std::error::Error + Send + Sync>),
    /// The bounded, same-HID-path reconnect this host attempts after
    /// `open app` never observed the device reappear before its monotonic
    /// deadline elapsed.
    LedgerReconnectTimedOut {
        /// The HID path this host retried.
        path: String,
        /// The bounded deadline, in milliseconds.
        deadline_ms: u64,
        /// The most recent reconnect attempt's failure.
        last_error: String,
    },
    /// A Ledger signer was selected, but this binary was built without the
    /// `usb-hid` Cargo feature, so no real USB/HID transport is available.
    LedgerTransportFeatureDisabled,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => f.write_str(
                "no subcommand supplied; expected one of: address, context, object, receipt, next-nonce, transfer",
            ),
            Self::UnknownCommand(command) => write!(f, "unknown subcommand: {command:?}"),
            Self::Args(error) => write!(f, "{error}"),
            Self::Hex(error) => write!(f, "{error}"),
            Self::Seed(error) => write!(f, "{error}"),
            Self::InvalidEndpoint { value, source } => {
                write!(f, "invalid --endpoint {value:?}: {source}")
            }
            Self::NonLoopbackEndpoint(addr) => {
                write!(f, "--endpoint must be a loopback address, got {addr}")
            }
            Self::PartialTlsConfiguration { missing } => write!(
                f,
                "--tls-server-name and --tls-ca-cert-der-file must both be supplied together; missing {missing}"
            ),
            Self::CaCertificateFileRead { path, source } => {
                write!(f, "failed to read --tls-ca-cert-der-file {path:?}: {source}")
            }
            Self::CaCertificateFileEmpty { path } => {
                write!(f, "--tls-ca-cert-der-file {path:?} was empty")
            }
            Self::CaCertificateFileTooLarge { path, maximum } => write!(
                f,
                "--tls-ca-cert-der-file {path:?} exceeded the maximum accepted {maximum} bytes"
            ),
            Self::InvalidInteger { flag, value, source } => {
                write!(f, "invalid decimal integer for {flag}: {value:?}: {source}")
            }
            Self::InvalidHashAlgorithm(id) => {
                write!(f, "hash-algorithm id {id} is not implemented")
            }
            Self::ZeroAmount => f.write_str("--amount must be non-zero"),
            Self::ZeroGasLimit => f.write_str("--gas-limit must be non-zero"),
            Self::SameSourceAndDestination => {
                f.write_str("--source-object and --destination-object must name distinct objects")
            }
            Self::PartialFeeConfiguration { missing } => write!(
                f,
                "--fee-asset-id, --max-fee, and --fee-treasury-object must all be supplied together; missing {missing}"
            ),
            Self::ZeroMaxFee => f.write_str("--max-fee must be non-zero"),
            Self::FeeTreasuryConflictsWithTransfer => f.write_str(
                "--fee-treasury-object must be distinct from --source-object and --destination-object",
            ),
            Self::WaitBoundWithoutWait(flag) => {
                write!(f, "{flag} requires --wait to also be supplied")
            }
            Self::WaitBoundRequired(flag) => {
                write!(f, "--wait requires {flag} to also be supplied")
            }
            Self::InvalidExpectedProtocolType(error) => {
                write!(f, "invalid --expected-* value: {error}")
            }
            Self::InvalidExpectedContext(error) => {
                write!(f, "invalid --expected-* protocol context: {error}")
            }
            Self::EpochMismatch {
                context_epoch,
                nonce_epoch,
            } => write!(
                f,
                "context epoch {context_epoch} disagrees with next-nonce epoch {nonce_epoch}; retry"
            ),
            Self::ObjectNotCurrentlyInline {
                flag,
                object_id,
                status,
            } => write!(
                f,
                "{flag} {object_id} is not currently a live inline object (status={status})"
            ),
            Self::ObjectBodyDecodeFailed {
                flag,
                object_id,
                source,
            } => write!(
                f,
                "{flag} {object_id}'s canonical object body failed to decode: {source}"
            ),
            Self::ObjectOwnerMismatch {
                flag,
                object_id,
                expected_owner,
                owner,
            } => write!(
                f,
                "{flag} {object_id} owner mismatch (expected=address:{expected_owner}, owner={owner})"
            ),
            Self::EmptySubmitResponse => {
                f.write_str("submit_transaction returned no responses for the submitted request")
            }
            Self::TransactionRejected { index } => {
                write!(f, "response[{index}] was rejected by the node")
            }
            Self::TransactionExecutionFailed { index, reason } => {
                write!(f, "response[{index}] execution failed: {reason}")
            }
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::NodeCore(error) => write!(f, "{error}"),
            Self::Transport(error) => write!(f, "{error}"),
            Self::Client(error) => write!(f, "{error}"),
            Self::MissingSignerSelection => f.write_str(
                "no signer selected; supply --seed-file, or all of --ledger-hid-path, --ledger-account, and --ledger-expected-firmware-version",
            ),
            Self::ConflictingSignerSelection => f.write_str(
                "--seed-file cannot be combined with --ledger-hid-path, --ledger-account, or --ledger-expected-firmware-version; select exactly one signer",
            ),
            Self::PartialLedgerSignerConfiguration { missing } => write!(
                f,
                "--ledger-hid-path, --ledger-account, and --ledger-expected-firmware-version must all be supplied together; missing {missing}"
            ),
            Self::LedgerExpectedFirmwareVersion(error) => {
                write!(f, "invalid --ledger-expected-firmware-version: {error}")
            }
            Self::LedgerConnect(error) => write!(f, "ledger device connection failed: {error}"),
            Self::LedgerIdentity(error) => {
                write!(f, "ledger device identity verification failed: {error}")
            }
            Self::LedgerReconnectTimedOut {
                path,
                deadline_ms,
                last_error,
            } => write!(
                f,
                "timed out after {deadline_ms}ms reconnecting to ledger device at {path:?}: {last_error}"
            ),
            Self::LedgerTransportFeatureDisabled => f.write_str(
                "a Ledger signer was selected, but this binary was built without the usb-hid feature",
            ),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Args(error) => Some(error),
            Self::Hex(error) => Some(error),
            Self::Seed(error) => Some(error),
            Self::InvalidEndpoint { source, .. } => Some(source),
            Self::CaCertificateFileRead { source, .. } => Some(source),
            Self::InvalidInteger { source, .. } => Some(source),
            Self::ObjectBodyDecodeFailed { source, .. } => Some(source),
            Self::CanonicalEncoding(error) => Some(error),
            Self::NodeCore(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::InvalidExpectedProtocolType(error) => Some(error),
            Self::InvalidExpectedContext(error) => Some(error),
            Self::LedgerExpectedFirmwareVersion(error) => Some(error),
            Self::LedgerConnect(error) => Some(error.as_ref()),
            Self::LedgerIdentity(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ArgsError> for CliError {
    fn from(value: ArgsError) -> Self {
        Self::Args(value)
    }
}

impl From<HexError> for CliError {
    fn from(value: HexError) -> Self {
        Self::Hex(value)
    }
}

impl From<SeedFileError> for CliError {
    fn from(value: SeedFileError) -> Self {
        Self::Seed(value)
    }
}

impl From<ClientError> for CliError {
    fn from(value: ClientError) -> Self {
        Self::Client(Box::new(value))
    }
}

impl From<TransportError> for CliError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<NodeCoreError> for CliError {
    fn from(value: NodeCoreError) -> Self {
        Self::NodeCore(value)
    }
}

impl From<TypeError> for CliError {
    fn from(value: TypeError) -> Self {
        Self::InvalidExpectedProtocolType(value)
    }
}

impl From<ExpectedProtocolContextError> for CliError {
    fn from(value: ExpectedProtocolContextError) -> Self {
        Self::InvalidExpectedContext(value)
    }
}

impl From<CanonicalEncodingError> for CliError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}
