//! Typed, actionable errors for the Sunrise Edge Rust client.

use core::fmt;
use std::error::Error;
use std::time::Duration;

use node_core::RequestId;
use objects::{Address, ObjectId};
use protocol_types::SignatureSchemeId;

use crate::context::ProtocolContextMismatch;
use crate::transport::TransportError;

/// Errors returned by the Sunrise Edge Rust client.
///
/// Every variant is actionable: it names the boundary that rejected the
/// call (transport, wire codec, node-core validation, cryptography) rather
/// than collapsing everything into one opaque failure.
#[derive(Debug)]
pub enum ClientError {
    /// The bounded transport layer failed before returning a well-formed
    /// HTTP response.
    Transport(TransportError),
    /// The server returned a status code outside the call's expected
    /// success set.
    UnexpectedStatus {
        /// HTTP status code returned by the server.
        status: u16,
        /// Response body, decoded lossily as UTF-8 for diagnostics.
        body: String,
    },
    /// A successful response declared a content type other than the exact
    /// media type this call required.
    UnexpectedContentType {
        /// The media type this call required.
        expected: &'static str,
        /// The media type the server actually declared, if any.
        actual: Option<String>,
    },
    /// Canonical query-result encoding or decoding failed.
    Wire(node_wire::QueryResultError),
    /// A remote `/v1/context` result did not match the caller's locally
    /// configured [`crate::context::ExpectedProtocolContext`] (see
    /// `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0085 / `TODO.md` CLI-First Node Production Gate
    /// S1). This is the mandatory pre-signing trusted-context check: a
    /// successful transport connection alone never establishes this.
    ProtocolContextMismatch(ProtocolContextMismatch),
    /// Canonical event/result envelope encoding or decoding failed.
    Contract(node_wire::HttpContractError),
    /// A node-core canonical type failed to encode, decode, or validate.
    NodeCore(node_core::NodeCoreError),
    /// A canonical transaction type failed to encode, decode, or validate.
    Execution(execution::ExecutionError),
    /// Signing or signature-domain framing failed.
    Crypto(crypto::CryptoError),
    /// The exact signed frame could not be converted into an approved,
    /// bounded clear-signing view.
    SigningView(signing_view::SigningViewError),
    /// An external signer reported a different signature scheme than the
    /// prepared transaction.
    ExternalSignerSchemeMismatch {
        /// Scheme fixed by the prepared transaction.
        expected: SignatureSchemeId,
        /// Scheme reported by the external signer.
        actual: SignatureSchemeId,
    },
    /// An external signer reported a different address than the prepared
    /// transaction sender.
    ExternalSignerAddressMismatch {
        /// Sender fixed by the prepared transaction.
        expected: Address,
        /// Address reported by the external signer.
        actual: Address,
    },
    /// The external signer failed before returning signature bytes.
    ExternalSigner(Box<dyn Error + Send + Sync>),
    /// The decoded submit result was bound to a request id other than the
    /// one the caller supplied, so it was rejected before being returned.
    SubmitResponseRequestIdMismatch {
        /// Request id the caller submitted.
        expected: RequestId,
        /// Request id carried by the decoded result.
        actual: RequestId,
    },
    /// An object query returned a canonically valid result for another
    /// selector, so the untrusted response was rejected.
    ObjectQuerySelectorMismatch {
        /// Object identifier requested by the caller.
        expected: ObjectId,
        /// Object identifier carried by the decoded result.
        actual: ObjectId,
    },
    /// A receipt query returned a canonically valid result for another
    /// selector, so the untrusted response was rejected.
    ReceiptQuerySelectorMismatch {
        /// Request identifier requested by the caller.
        expected: RequestId,
        /// Request identifier carried by the decoded result.
        actual: RequestId,
    },
    /// A next-nonce query returned a canonically valid result for another
    /// sender, so the untrusted response was rejected.
    NextNonceQuerySelectorMismatch {
        /// Sender requested by the caller.
        expected: Address,
        /// Sender carried by the decoded result.
        actual: Address,
    },
    /// Bounded receipt polling exhausted its caller-supplied attempt or
    /// elapsed-time bound without observing a present receipt.
    ReceiptPollExhausted {
        /// Number of attempts made.
        attempts: u32,
        /// Total elapsed wall-clock time across all attempts.
        elapsed: Duration,
    },
    /// The caller supplied an elapsed-time bound that could not be added to
    /// the current monotonic clock instant.
    ReceiptPollDeadlineOverflow,
    /// [`crate::transaction::PreparedTransaction::prepare`] or
    /// [`crate::transaction::PreparedTransaction::finalize`] was asked to
    /// use a signature scheme this client does not implement. Only
    /// `Ed25519` is implemented anywhere in this workspace today (see
    /// `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0084).
    UnsupportedSignatureScheme(SignatureSchemeId),
    /// A signature presented to
    /// [`crate::transaction::PreparedTransaction::finalize`] had the exact
    /// expected length but did not cryptographically verify against the
    /// transaction's sender treated as an `AddressIsPublicKey` Ed25519
    /// verification key.
    ExternalSignatureInvalid {
        /// The transaction's sender address.
        sender: Address,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::UnexpectedStatus { status, body } => {
                write!(f, "unexpected HTTP status {status}: {body}")
            }
            Self::UnexpectedContentType { expected, actual } => write!(
                f,
                "unexpected content type: expected {expected}, got {actual:?}"
            ),
            Self::Wire(error) => write!(f, "query result codec error: {error}"),
            Self::ProtocolContextMismatch(error) => write!(f, "{error}"),
            Self::Contract(error) => write!(f, "event result codec error: {error}"),
            Self::NodeCore(error) => write!(f, "node-core validation error: {error}"),
            Self::Execution(error) => write!(f, "transaction codec error: {error}"),
            Self::Crypto(error) => write!(f, "cryptography error: {error}"),
            Self::SigningView(error) => write!(f, "clear-signing error: {error}"),
            Self::ExternalSignerSchemeMismatch { expected, actual } => write!(
                f,
                "external signer scheme {} disagrees with prepared scheme {}",
                actual.as_u16(),
                expected.as_u16()
            ),
            Self::ExternalSignerAddressMismatch { expected, actual } => write!(
                f,
                "external signer address {actual} disagrees with prepared sender {expected}"
            ),
            Self::ExternalSigner(error) => write!(f, "external signer failed: {error}"),
            Self::SubmitResponseRequestIdMismatch { expected, actual } => write!(
                f,
                "submit result request id {actual} disagrees with submitted request id {expected}"
            ),
            Self::ObjectQuerySelectorMismatch { expected, actual } => write!(
                f,
                "object query result selector {actual} disagrees with requested object {expected}"
            ),
            Self::ReceiptQuerySelectorMismatch { expected, actual } => write!(
                f,
                "receipt query result selector {actual} disagrees with requested id {expected}"
            ),
            Self::NextNonceQuerySelectorMismatch { expected, actual } => write!(
                f,
                "next-nonce query result selector {actual} disagrees with requested sender {expected}"
            ),
            Self::ReceiptPollExhausted { attempts, elapsed } => write!(
                f,
                "receipt poll exhausted after {attempts} attempts and {elapsed:?}"
            ),
            Self::ReceiptPollDeadlineOverflow => {
                f.write_str("receipt poll elapsed-time bound overflows the monotonic clock")
            }
            Self::UnsupportedSignatureScheme(scheme) => {
                write!(f, "signature scheme {} is not implemented", scheme.as_u16())
            }
            Self::ExternalSignatureInvalid { sender } => write!(
                f,
                "signature does not verify against sender {sender} under the declared scheme"
            ),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::ProtocolContextMismatch(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::NodeCore(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::SigningView(error) => Some(error),
            Self::ExternalSigner(error) => Some(error.as_ref()),
            Self::UnexpectedStatus { .. }
            | Self::UnexpectedContentType { .. }
            | Self::SubmitResponseRequestIdMismatch { .. }
            | Self::ObjectQuerySelectorMismatch { .. }
            | Self::ReceiptQuerySelectorMismatch { .. }
            | Self::NextNonceQuerySelectorMismatch { .. }
            | Self::ReceiptPollExhausted { .. }
            | Self::ReceiptPollDeadlineOverflow
            | Self::UnsupportedSignatureScheme(_)
            | Self::ExternalSignerSchemeMismatch { .. }
            | Self::ExternalSignerAddressMismatch { .. }
            | Self::ExternalSignatureInvalid { .. } => None,
        }
    }
}

impl From<TransportError> for ClientError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<node_wire::QueryResultError> for ClientError {
    fn from(value: node_wire::QueryResultError) -> Self {
        Self::Wire(value)
    }
}

impl From<ProtocolContextMismatch> for ClientError {
    fn from(value: ProtocolContextMismatch) -> Self {
        Self::ProtocolContextMismatch(value)
    }
}

impl From<node_wire::HttpContractError> for ClientError {
    fn from(value: node_wire::HttpContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<node_core::NodeCoreError> for ClientError {
    fn from(value: node_core::NodeCoreError) -> Self {
        Self::NodeCore(value)
    }
}

impl From<execution::ExecutionError> for ClientError {
    fn from(value: execution::ExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<crypto::CryptoError> for ClientError {
    fn from(value: crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<signing_view::SigningViewError> for ClientError {
    fn from(value: signing_view::SigningViewError) -> Self {
        Self::SigningView(value)
    }
}
