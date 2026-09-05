#![forbid(unsafe_code)]

//! Shared canonical HTTP wire contract for the Developer MVP (DR-0083).
//!
//! This crate owns the exact canonical event/query-result codecs and the
//! route/media-type constants shared between the `native-http` server
//! adapter and `clients/rust`. It depends only on `node-core` and the
//! foundational protocol crates it re-uses (`canonical-encoding`, `objects`,
//! `protocol-types`, `runtime`) — never on Axum, Tokio, or any transport
//! implementation. Routing, admission, clocks, storage authority, and HTTP
//! status classification remain server concerns in `native-http`.
//!
//! `native-http` re-exports every name in this crate's public API so
//! existing server callers keep their original import paths; the bytes
//! produced and accepted here are unchanged from their prior `native-http`
//! definitions.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use node_core::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_CHAIN_ID_BYTES, MAX_NODE_OUTPUT_ITEMS, NodeCoreError,
    NodeDedupRecord, NodeResponse, ObjectQueryResult as NodeObjectQueryResult,
    ReceiptQueryResult as NodeReceiptQueryResult, RequestId,
};
use objects::{Address, ObjectId, decode_object};
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, HashSuiteId, ProtocolVersion};
use runtime::{
    AtomicityDomainId, DurableObjectVersion, MAX_DURABLE_RECEIPT_BYTES, ObjectHeadRevision,
};
use std::error::Error;

const HTTP_RESULT_TYPE_ID: u16 = 0xE101;
const HTTP_RESULT_ENCODING_VERSION: u16 = 1;
const QUERY_RESULT_ENCODING_VERSION: u16 = 1;
const OBJECT_QUERY_RESULT_ENCODING_VERSION_V1: u16 = 1;
const OBJECT_QUERY_RESULT_ENCODING_VERSION_V2: u16 = 2;

/// Canonical type identifier for [`HttpContextQueryResult`] (DR-0082).
pub const CONTEXT_QUERY_RESULT_TYPE_ID: u16 = 0xE102;
/// Canonical type identifier for [`HttpObjectQueryResult`] (DR-0082).
pub const OBJECT_QUERY_RESULT_TYPE_ID: u16 = 0xE103;
/// Canonical type identifier for [`HttpReceiptQueryResult`] (DR-0082).
pub const RECEIPT_QUERY_RESULT_TYPE_ID: u16 = 0xE104;
/// Canonical type identifier for [`HttpNextNonceQueryResult`] (DR-0082).
pub const NEXT_NONCE_QUERY_RESULT_TYPE_ID: u16 = 0xE105;

/// Versioned media type returned by every bounded query route (DR-0082).
pub const QUERY_RESULT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.query-result";
/// Bounded query route returning trusted chain/protocol/domain context.
pub const QUERY_CONTEXT_PATH: &str = "/v1/context";
/// Bounded query route returning one durable object by identifier.
pub const QUERY_OBJECT_PATH: &str = "/v1/objects/{object_id}";
/// Bounded query route returning one durable receipt by request identifier.
pub const QUERY_RECEIPT_PATH: &str = "/v1/receipts/{request_id}";
/// Bounded query route returning one sender's current-epoch next nonce.
pub const QUERY_NEXT_NONCE_PATH: &str = "/v1/senders/{sender}/next-nonce";

/// Versioned media type accepted by the event endpoint.
pub const NODE_EVENT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.node-event";
/// Versioned media type returned for a successful invocation.
pub const NODE_RESULT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.node-result";
/// Native route that accepts one canonical node event.
pub const NODE_EVENT_PATH: &str = "/v1/events";
/// Liveness route. It intentionally performs no storage or protocol checks.
pub const LIVENESS_PATH: &str = "/health/live";

/// Errors from encoding or decoding the bounded HTTP invocation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpContractError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A nested node response failed validation.
    NodeCore(NodeCoreError),
    /// A result carried more responses than one invocation allows.
    TooManyResponses(usize),
    /// A response belonged to another request.
    RequestMismatch {
        /// Result request identifier.
        expected: RequestId,
        /// Nested response request identifier.
        actual: RequestId,
    },
    /// A request identifier had the wrong length.
    InvalidRequestIdLength(usize),
    /// The response-list bytes ended early.
    TruncatedResponseList,
    /// The response list contained trailing bytes.
    TrailingResponseListBytes(usize),
    /// A nested response length could not be represented safely.
    ResponseLengthOverflow(usize),
}

impl fmt::Display for HttpContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::NodeCore(error) => write!(f, "node response validation failed: {error}"),
            Self::TooManyResponses(count) => write!(
                f,
                "HTTP result has {count} responses, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::RequestMismatch { expected, actual } => write!(
                f,
                "HTTP result response mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "HTTP result request id is {length} bytes, expected 32")
            }
            Self::TruncatedResponseList => f.write_str("HTTP result response list is truncated"),
            Self::TrailingResponseListBytes(length) => {
                write!(f, "HTTP result response list has {length} trailing bytes")
            }
            Self::ResponseLengthOverflow(length) => {
                write!(
                    f,
                    "HTTP result response is too large to frame: {length} bytes"
                )
            }
        }
    }
}

impl Error for HttpContractError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::NodeCore(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalEncodingError> for HttpContractError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for HttpContractError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<NodeCoreError> for HttpContractError {
    fn from(value: NodeCoreError) -> Self {
        Self::NodeCore(value)
    }
}

/// Canonical success body shared by native and future edge HTTP adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpNodeResult {
    request_id: RequestId,
    responses: Vec<NodeResponse>,
}

impl HttpNodeResult {
    /// Creates a bounded result whose responses all match the request.
    pub fn new(
        request_id: RequestId,
        responses: Vec<NodeResponse>,
    ) -> Result<Self, HttpContractError> {
        if responses.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(HttpContractError::TooManyResponses(responses.len()));
        }
        for response in &responses {
            if response.request_id() != request_id {
                return Err(HttpContractError::RequestMismatch {
                    expected: request_id,
                    actual: response.request_id(),
                });
            }
        }
        Ok(Self {
            request_id,
            responses,
        })
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns responses in deterministic transition order.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Encodes the complete HTTP success body.
    pub fn encode(&self) -> Result<Vec<u8>, HttpContractError> {
        let mut response_list = Vec::new();
        for response in &self.responses {
            let encoded = response.encode()?;
            let length = u32::try_from(encoded.len())
                .map_err(|_| HttpContractError::ResponseLengthOverflow(encoded.len()))?;
            response_list.extend_from_slice(&length.to_le_bytes());
            response_list.extend_from_slice(&encoded);
        }

        let count = u32::try_from(self.responses.len())
            .map_err(|_| HttpContractError::TooManyResponses(self.responses.len()))?;
        let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u32(2, count)?;
        frame.field_bytes(3, response_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes a complete HTTP success body and all nested responses.
    pub fn decode(bytes: &[u8]) -> Result<Self, HttpContractError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(HTTP_RESULT_TYPE_ID)?;
        frame.require_version(HTTP_RESULT_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| HttpContractError::InvalidRequestIdLength(request_bytes.len()))?;
        let request_id = RequestId::new(request_array)?;
        let count = usize::try_from(frame.required_u32(2)?)
            .map_err(|_| HttpContractError::TooManyResponses(usize::MAX))?;
        if count > MAX_NODE_OUTPUT_ITEMS {
            return Err(HttpContractError::TooManyResponses(count));
        }

        let list = frame.required_field(3)?;
        let mut offset = 0_usize;
        let mut responses = Vec::with_capacity(count);
        for _ in 0..count {
            let length_bytes = take_list_bytes(list, &mut offset, 4)?;
            let length = usize::try_from(u32::from_le_bytes([
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                length_bytes[3],
            ]))
            .map_err(|_| HttpContractError::ResponseLengthOverflow(usize::MAX))?;
            let encoded = take_list_bytes(list, &mut offset, length)?;
            responses.push(NodeResponse::decode(encoded)?);
        }
        if offset != list.len() {
            return Err(HttpContractError::TrailingResponseListBytes(
                list.len() - offset,
            ));
        }
        Self::new(request_id, responses)
    }
}

/// Errors from encoding or decoding a bounded query-result frame (DR-0082).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResultError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A decoded chain identifier was invalid.
    InvalidChainId(protocol_types::TypeError),
    /// A chain identifier exceeded node-core's ingress resource bound.
    ChainIdTooLong(usize),
    /// A decoded atomicity-domain identifier was invalid.
    InvalidDomain(protocol_types::TypeError),
    /// A decoded atomicity-domain field had the wrong byte length.
    InvalidDomainLength(usize),
    /// A decoded object identifier field had the wrong byte length.
    InvalidObjectIdLength(usize),
    /// A decoded request identifier field had the wrong byte length.
    InvalidRequestIdLength(usize),
    /// A decoded sender address field had the wrong byte length.
    InvalidSenderLength(usize),
    /// A decoded digest named an unknown hash algorithm.
    InvalidDigestAlgorithm(protocol_types::TypeError),
    /// A decoded digest field had the wrong byte length.
    InvalidDigestLength(usize),
    /// A decoded object-head revision was zero.
    InvalidHeadRevision(u64),
    /// A decoded immutable object version was zero.
    InvalidObjectVersion(u64),
    /// An object query-result status identifier is unknown.
    UnknownObjectStatus(u16),
    /// A receipt query-result status identifier is unknown.
    UnknownReceiptStatus(u16),
    /// The context's protocol version was zero.
    ZeroProtocolVersion,
    /// The context's active hash-suite identifier was zero.
    ZeroHashSuiteId,
    /// The context's transaction-authentication profile identifier was zero.
    ZeroTransactionAuthProfileId,
    /// The context's signature-scheme identifier was zero.
    ZeroSignatureSchemeId,
    /// The context's address-binding identifier was zero.
    ZeroAddressBindingId,
    /// The context's canonical `ProtocolConfig` bytes were empty.
    EmptyProtocolConfigBytes,
    /// An inline object body exceeded the pre-activation verification bound.
    ObjectBodyTooLarge {
        /// Actual inline body length in bytes.
        actual: usize,
        /// Maximum accepted inline body length in bytes.
        maximum: usize,
    },
    /// The nested canonical `objects::Object` failed to decode.
    InvalidCanonicalObject(objects::ObjectError),
    /// The nested canonical object's identifier disagreed with the outer selector.
    ObjectIdentityMismatch {
        /// Object identifier carried by the outer result.
        expected: ObjectId,
        /// Object identifier decoded from the nested canonical body.
        actual: ObjectId,
    },
    /// The nested canonical object's version disagreed with the outer field.
    ObjectVersionMismatch {
        /// Version carried by the outer result.
        expected: u64,
        /// Version decoded from the nested canonical body.
        actual: u64,
    },
    /// A durable receipt body exceeded the durable receipt resource bound.
    ReceiptTooLarge {
        /// Actual receipt length in bytes.
        actual: usize,
        /// Maximum accepted receipt length in bytes.
        maximum: usize,
    },
    /// The nested canonical `NodeDedupRecord` failed to decode or re-encode.
    InvalidDedupRecord(NodeCoreError),
    /// The nested dedup record's request id disagreed with the outer selector.
    RequestIdentityMismatch {
        /// Request identifier carried by the outer result.
        expected: RequestId,
        /// Request identifier decoded from the nested dedup record.
        actual: RequestId,
    },
    /// The nested dedup record's event digest disagreed with the outer field.
    EventDigestMismatch,
    /// The nested dedup record did not re-encode to exactly its persisted bytes.
    NonCanonicalReEncoding,
}

impl fmt::Display for QueryResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::InvalidChainId(error) => write!(f, "invalid chain id: {error}"),
            Self::ChainIdTooLong(length) => {
                write!(
                    f,
                    "chain id is {length} bytes, maximum is {MAX_CHAIN_ID_BYTES}"
                )
            }
            Self::InvalidDomain(error) => write!(f, "invalid atomicity domain id: {error}"),
            Self::InvalidDomainLength(length) => {
                write!(f, "atomicity domain field is {length} bytes, expected 32")
            }
            Self::InvalidObjectIdLength(length) => {
                write!(f, "object id field is {length} bytes, expected 32")
            }
            Self::InvalidRequestIdLength(length) => {
                write!(f, "request id field is {length} bytes, expected 32")
            }
            Self::InvalidSenderLength(length) => {
                write!(f, "sender field is {length} bytes, expected 32")
            }
            Self::InvalidDigestAlgorithm(error) => write!(f, "invalid digest algorithm: {error}"),
            Self::InvalidDigestLength(length) => {
                write!(f, "digest field is {length} bytes, expected 32")
            }
            Self::InvalidHeadRevision(value) => {
                write!(f, "object head revision must not be zero, got {value}")
            }
            Self::InvalidObjectVersion(value) => {
                write!(f, "object version must not be zero, got {value}")
            }
            Self::UnknownObjectStatus(id) => write!(f, "unknown object query status id: {id}"),
            Self::UnknownReceiptStatus(id) => write!(f, "unknown receipt query status id: {id}"),
            Self::ZeroProtocolVersion => f.write_str("context protocol version must not be zero"),
            Self::ZeroHashSuiteId => f.write_str("context hash suite id must not be zero"),
            Self::ZeroTransactionAuthProfileId => {
                f.write_str("context transaction auth profile id must not be zero")
            }
            Self::ZeroSignatureSchemeId => {
                f.write_str("context signature scheme id must not be zero")
            }
            Self::ZeroAddressBindingId => {
                f.write_str("context address binding id must not be zero")
            }
            Self::EmptyProtocolConfigBytes => {
                f.write_str("context canonical protocol config bytes must not be empty")
            }
            Self::ObjectBodyTooLarge { actual, maximum } => write!(
                f,
                "inline object body is {actual} bytes, maximum is {maximum}"
            ),
            Self::InvalidCanonicalObject(error) => {
                write!(f, "nested canonical object is invalid: {error}")
            }
            Self::ObjectIdentityMismatch { expected, actual } => write!(
                f,
                "nested canonical object id {actual} disagrees with outer selector {expected}"
            ),
            Self::ObjectVersionMismatch { expected, actual } => write!(
                f,
                "nested canonical object version {actual} disagrees with outer field {expected}"
            ),
            Self::ReceiptTooLarge { actual, maximum } => {
                write!(f, "receipt body is {actual} bytes, maximum is {maximum}")
            }
            Self::InvalidDedupRecord(error) => {
                write!(f, "nested dedup record is invalid: {error}")
            }
            Self::RequestIdentityMismatch { expected, actual } => write!(
                f,
                "nested dedup record request id {actual} disagrees with outer selector {expected}"
            ),
            Self::EventDigestMismatch => {
                f.write_str("nested dedup record event digest disagrees with outer field")
            }
            Self::NonCanonicalReEncoding => {
                f.write_str("nested dedup record does not re-encode to its persisted bytes")
            }
        }
    }
}

impl Error for QueryResultError {}

impl From<CanonicalEncodingError> for QueryResultError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for QueryResultError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

fn encode_digest_fields(
    frame: &mut CanonicalStruct,
    algorithm_field_id: u16,
    bytes_field_id: u16,
    digest: Digest32,
) -> Result<(), QueryResultError> {
    frame.field_u16(algorithm_field_id, digest.algorithm().as_u16())?;
    frame.field_bytes(bytes_field_id, digest.bytes().to_vec())?;
    Ok(())
}

fn decode_digest_fields(
    frame: &CanonicalFrame<'_>,
    algorithm_field_id: u16,
    bytes_field_id: u16,
) -> Result<Digest32, QueryResultError> {
    let algorithm = HashAlgorithmId::try_from(frame.required_u16(algorithm_field_id)?)
        .map_err(QueryResultError::InvalidDigestAlgorithm)?;
    let bytes = frame.required_field(bytes_field_id)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QueryResultError::InvalidDigestLength(bytes.len()))?;
    Ok(Digest32::new(algorithm, bytes))
}

fn decode_object_id_field(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<ObjectId, QueryResultError> {
    let bytes = frame.required_field(field_id)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QueryResultError::InvalidObjectIdLength(bytes.len()))?;
    Ok(ObjectId::new(array))
}

fn decode_request_id_field(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<RequestId, QueryResultError> {
    let bytes = frame.required_field(field_id)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QueryResultError::InvalidRequestIdLength(bytes.len()))?;
    RequestId::new(array).map_err(|_| QueryResultError::InvalidRequestIdLength(32))
}

fn decode_sender_field(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<Address, QueryResultError> {
    let bytes = frame.required_field(field_id)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QueryResultError::InvalidSenderLength(bytes.len()))?;
    Ok(Address::new(array))
}

/// Stable status identifiers for [`HttpObjectQueryResult`] (DR-0082).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectQueryStatus {
    /// No head row has ever existed for the queried object identifier.
    Absent = 1,
    /// A delete retained the last immutable version and head revision.
    Tombstoned = 2,
    /// A current inline object carrying the context a client needs for
    /// independent digest verification.
    CurrentInline = 3,
    /// A current version whose body is stored externally as a blob.
    CurrentBlobReference = 4,
}

impl ObjectQueryStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for ObjectQueryStatus {
    type Error = QueryResultError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Absent),
            2 => Ok(Self::Tombstoned),
            3 => Ok(Self::CurrentInline),
            4 => Ok(Self::CurrentBlobReference),
            other => Err(QueryResultError::UnknownObjectStatus(other)),
        }
    }
}

/// Stable status identifiers for [`HttpReceiptQueryResult`] (DR-0082).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptQueryStatus {
    /// No durable receipt exists for the queried request identifier.
    Absent = 1,
    /// A durable receipt exists and was independently re-verified.
    Present = 2,
}

impl ReceiptQueryStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for ReceiptQueryStatus {
    type Error = QueryResultError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Absent),
            2 => Ok(Self::Present),
            other => Err(QueryResultError::UnknownReceiptStatus(other)),
        }
    }
}

/// Canonical `GET /v1/context` result (DR-0082, type `0xE102`).
///
/// This is a directly useful, self-contained client snapshot of trusted
/// composition: the chain/protocol/epoch replay boundary, the active
/// cryptographic and transaction-authentication configuration, the single
/// committed logical atomicity domain, and the exact canonical
/// `ProtocolConfig` bytes a client can hash or archive verbatim. `/v1/context`
/// has no request selector to bind against; the other three query results
/// each bind to their exact requested selector instead (see
/// [`HttpObjectQueryResult`], [`HttpReceiptQueryResult`], and
/// [`HttpNextNonceQueryResult`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpContextQueryResult {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    hash_suite_id: HashSuiteId,
    transaction_auth_profile_id: u16,
    signature_scheme_id: u16,
    address_binding_id: u16,
    domain: AtomicityDomainId,
    protocol_config_bytes: Vec<u8>,
}

impl HttpContextQueryResult {
    /// Creates a context query result from already-trusted composition
    /// values, rejecting a zero protocol version, hash-suite id,
    /// transaction-auth-profile id, signature-scheme id, or address-binding
    /// id; a chain id beyond node-core's `MAX_CHAIN_ID_BYTES`; and empty
    /// canonical `ProtocolConfig` bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        hash_suite_id: HashSuiteId,
        transaction_auth_profile_id: u16,
        signature_scheme_id: u16,
        address_binding_id: u16,
        domain: AtomicityDomainId,
        protocol_config_bytes: Vec<u8>,
    ) -> Result<Self, QueryResultError> {
        let result = Self {
            chain_id,
            protocol_version,
            epoch,
            hash_suite_id,
            transaction_auth_profile_id,
            signature_scheme_id,
            address_binding_id,
            domain,
            protocol_config_bytes,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), QueryResultError> {
        if self.protocol_version.get() == 0 {
            return Err(QueryResultError::ZeroProtocolVersion);
        }
        if self.hash_suite_id.get() == 0 {
            return Err(QueryResultError::ZeroHashSuiteId);
        }
        if self.transaction_auth_profile_id == 0 {
            return Err(QueryResultError::ZeroTransactionAuthProfileId);
        }
        if self.signature_scheme_id == 0 {
            return Err(QueryResultError::ZeroSignatureSchemeId);
        }
        if self.address_binding_id == 0 {
            return Err(QueryResultError::ZeroAddressBindingId);
        }
        let chain_id_length = self.chain_id.as_str().len();
        if chain_id_length > MAX_CHAIN_ID_BYTES {
            return Err(QueryResultError::ChainIdTooLong(chain_id_length));
        }
        if self.protocol_config_bytes.is_empty() {
            return Err(QueryResultError::EmptyProtocolConfigBytes);
        }
        Ok(())
    }

    /// Returns the trusted chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the trusted protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the trusted current epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the active hash-suite identifier.
    #[must_use]
    pub const fn hash_suite_id(&self) -> HashSuiteId {
        self.hash_suite_id
    }

    /// Returns the committed transaction-authentication profile identifier.
    #[must_use]
    pub const fn transaction_auth_profile_id(&self) -> u16 {
        self.transaction_auth_profile_id
    }

    /// Returns the committed signature-scheme identifier.
    #[must_use]
    pub const fn signature_scheme_id(&self) -> u16 {
        self.signature_scheme_id
    }

    /// Returns the committed address-binding identifier.
    #[must_use]
    pub const fn address_binding_id(&self) -> u16 {
        self.address_binding_id
    }

    /// Returns the single committed logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the exact canonical `ProtocolConfig` bytes.
    #[must_use]
    pub fn protocol_config_bytes(&self) -> &[u8] {
        &self.protocol_config_bytes
    }

    /// Encodes the canonical `0xE102` context query result.
    pub fn encode(&self) -> Result<Vec<u8>, QueryResultError> {
        let mut frame =
            CanonicalStruct::new(CONTEXT_QUERY_RESULT_TYPE_ID, QUERY_RESULT_ENCODING_VERSION);
        frame.field_str(1, self.chain_id.as_str())?;
        frame.field_u32(2, self.protocol_version.get())?;
        frame.field_u64(3, self.epoch.get())?;
        frame.field_u16(4, self.hash_suite_id.get())?;
        frame.field_u16(5, self.transaction_auth_profile_id)?;
        frame.field_u16(6, self.signature_scheme_id)?;
        frame.field_u16(7, self.address_binding_id)?;
        frame.field_bytes(8, self.domain.as_bytes().to_vec())?;
        frame.field_bytes(9, self.protocol_config_bytes.clone())?;
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one canonical context query result.
    pub fn decode(bytes: &[u8]) -> Result<Self, QueryResultError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(CONTEXT_QUERY_RESULT_TYPE_ID)?;
        frame.require_version(QUERY_RESULT_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;

        let chain_id =
            ChainId::new(frame.required_str(1)?).map_err(QueryResultError::InvalidChainId)?;
        let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
        let epoch = Epoch::new(frame.required_u64(3)?);
        let hash_suite_id = HashSuiteId::new(frame.required_u16(4)?);
        let transaction_auth_profile_id = frame.required_u16(5)?;
        let signature_scheme_id = frame.required_u16(6)?;
        let address_binding_id = frame.required_u16(7)?;
        let domain_bytes = frame.required_field(8)?;
        let domain_array: [u8; 32] = domain_bytes
            .try_into()
            .map_err(|_| QueryResultError::InvalidDomainLength(domain_bytes.len()))?;
        let domain =
            AtomicityDomainId::new(domain_array).map_err(QueryResultError::InvalidDomain)?;
        let protocol_config_bytes = frame.required_field(9)?.to_vec();

        Self::new(
            chain_id,
            protocol_version,
            epoch,
            hash_suite_id,
            transaction_auth_profile_id,
            signature_scheme_id,
            address_binding_id,
            domain,
            protocol_config_bytes,
        )
    }
}

/// Canonical `GET /v1/objects/{object_id}` result (DR-0082, type `0xE103`).
///
/// Absence, a retained tombstone, a verified current inline object, and a
/// current blob reference are represented explicitly; a blob-backed version
/// never claims to have verified an unavailable blob body. Every status
/// carries the exact `object_id` this result answers, so a caller can never
/// mistake it for the answer to a different selector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpObjectQueryResult {
    /// No head row has ever existed for the queried object identifier.
    Absent {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
    },
    /// A delete retained the last immutable version and head revision.
    Tombstoned {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the delete.
        head_revision: ObjectHeadRevision,
        /// Last immutable version reconstructed from retained history.
        last_object_version: DurableObjectVersion,
    },
    /// Historical encoding-v1 inline result. It lacks the immutable digest
    /// context and must never be treated as independently verified.
    HistoricalCurrentInline {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Recorded self-describing digest, not independently verified here.
        digest: Digest32,
        /// Exact canonical object bytes with id/version validation only.
        canonical_object_bytes: Vec<u8>,
    },
    /// A current, independently verified inline object.
    CurrentInline {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Self-describing digest of the current object version. The generic
        /// Rust client recomputes it before exposing this result.
        digest: Digest32,
        /// Creating chain identifier needed to independently recompute `digest`.
        creating_chain_id: ChainId,
        /// Creating protocol version needed to independently recompute `digest`.
        ///
        creating_protocol_version: ProtocolVersion,
        /// Exact canonical `objects::Object` bytes. Canonical decoding and
        /// nested id/version are checked here; digest verification is a client
        /// consumption responsibility using the accompanying context.
        canonical_object_bytes: Vec<u8>,
    },
    /// A current version whose body is stored externally as a blob.
    ///
    /// Neither `digest` nor `blob_digest` is verified against fetched bytes:
    /// both are the values recorded on the immutable version, cross-checked
    /// against the head.
    CurrentBlobReference {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Self-describing digest of the current object version, as recorded
        /// on the immutable version and cross-checked against the head. Not
        /// body-verified: the referenced body is never fetched.
        digest: Digest32,
        /// Self-describing digest of the externally stored blob content, as
        /// recorded on the immutable version. Never fetched or verified.
        blob_digest: Digest32,
    },
}

impl HttpObjectQueryResult {
    /// Returns the exact object identifier this result answers, regardless
    /// of status.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        match self {
            Self::Absent { object_id }
            | Self::Tombstoned { object_id, .. }
            | Self::HistoricalCurrentInline { object_id, .. }
            | Self::CurrentInline { object_id, .. }
            | Self::CurrentBlobReference { object_id, .. } => *object_id,
        }
    }
}

impl From<NodeObjectQueryResult> for HttpObjectQueryResult {
    fn from(value: NodeObjectQueryResult) -> Self {
        match value {
            NodeObjectQueryResult::Absent { object_id } => Self::Absent { object_id },
            NodeObjectQueryResult::Tombstoned {
                object_id,
                head_revision,
                last_object_version,
            } => Self::Tombstoned {
                object_id,
                head_revision,
                last_object_version,
            },
            NodeObjectQueryResult::CurrentInline {
                object_id,
                head_revision,
                object_version,
                digest,
                creating_chain_id,
                protocol_version,
                canonical_object_bytes,
            } => Self::CurrentInline {
                object_id,
                head_revision,
                object_version,
                digest,
                creating_chain_id,
                creating_protocol_version: protocol_version,
                canonical_object_bytes,
            },
            NodeObjectQueryResult::CurrentBlobReference {
                object_id,
                head_revision,
                object_version,
                digest,
                blob_digest,
            } => Self::CurrentBlobReference {
                object_id,
                head_revision,
                object_version,
                digest,
                blob_digest,
            },
        }
    }
}

impl HttpObjectQueryResult {
    /// Encodes the canonical `0xE103` object query result.
    pub fn encode(&self) -> Result<Vec<u8>, QueryResultError> {
        let encoding_version: u16 = match self {
            Self::HistoricalCurrentInline { .. }
            | Self::Absent { .. }
            | Self::Tombstoned { .. }
            | Self::CurrentBlobReference { .. } => OBJECT_QUERY_RESULT_ENCODING_VERSION_V1,
            Self::CurrentInline { .. } => OBJECT_QUERY_RESULT_ENCODING_VERSION_V2,
        };
        let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, encoding_version);
        match self {
            Self::Absent { object_id } => {
                frame.field_u16(1, ObjectQueryStatus::Absent.as_u16())?;
                frame.field_bytes(2, object_id.as_bytes().to_vec())?;
            }
            Self::Tombstoned {
                object_id,
                head_revision,
                last_object_version,
            } => {
                frame.field_u16(1, ObjectQueryStatus::Tombstoned.as_u16())?;
                frame.field_bytes(2, object_id.as_bytes().to_vec())?;
                frame.field_u64(3, head_revision.get())?;
                frame.field_u64(4, last_object_version.get())?;
            }
            Self::CurrentInline {
                object_id,
                head_revision,
                object_version,
                digest,
                creating_chain_id,
                creating_protocol_version,
                canonical_object_bytes,
            } => {
                frame.field_u16(1, ObjectQueryStatus::CurrentInline.as_u16())?;
                frame.field_bytes(2, object_id.as_bytes().to_vec())?;
                frame.field_u64(3, head_revision.get())?;
                frame.field_u64(4, object_version.get())?;
                encode_digest_fields(&mut frame, 5, 6, *digest)?;
                frame.field_bytes(7, canonical_object_bytes.clone())?;
                frame.field_str(10, creating_chain_id.as_str())?;
                frame.field_u32(11, creating_protocol_version.get())?;
            }
            Self::HistoricalCurrentInline {
                object_id,
                head_revision,
                object_version,
                digest,
                canonical_object_bytes,
            } => {
                frame.field_u16(1, ObjectQueryStatus::CurrentInline.as_u16())?;
                frame.field_bytes(2, object_id.as_bytes().to_vec())?;
                frame.field_u64(3, head_revision.get())?;
                frame.field_u64(4, object_version.get())?;
                encode_digest_fields(&mut frame, 5, 6, *digest)?;
                frame.field_bytes(7, canonical_object_bytes.clone())?;
            }
            Self::CurrentBlobReference {
                object_id,
                head_revision,
                object_version,
                digest,
                blob_digest,
            } => {
                frame.field_u16(1, ObjectQueryStatus::CurrentBlobReference.as_u16())?;
                frame.field_bytes(2, object_id.as_bytes().to_vec())?;
                frame.field_u64(3, head_revision.get())?;
                frame.field_u64(4, object_version.get())?;
                encode_digest_fields(&mut frame, 5, 6, *digest)?;
                encode_digest_fields(&mut frame, 8, 9, *blob_digest)?;
            }
        }
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one canonical object query result.
    ///
    /// A `CurrentInline` frame is rejected if its inline body exceeds
    /// node-core's `MAX_AUTHENTICATED_OBJECT_BODY_BYTES`, fails to decode as
    /// a canonical `objects::Object`, or decodes to an id/version other than
    /// the outer `object_id`/`object_version` fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, QueryResultError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(OBJECT_QUERY_RESULT_TYPE_ID)?;
        let encoding_version: u16 = frame.version();
        if encoding_version != OBJECT_QUERY_RESULT_ENCODING_VERSION_V1
            && encoding_version != OBJECT_QUERY_RESULT_ENCODING_VERSION_V2
        {
            return Err(QueryResultError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: OBJECT_QUERY_RESULT_ENCODING_VERSION_V2,
                    actual: encoding_version,
                },
            ));
        }
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;

        let status = ObjectQueryStatus::try_from(frame.required_u16(1)?)?;
        let object_id = decode_object_id_field(&frame, 2)?;
        match status {
            ObjectQueryStatus::Absent => {
                frame.require_only_fields(&[1, 2])?;
                Ok(Self::Absent { object_id })
            }
            ObjectQueryStatus::Tombstoned => {
                frame.require_only_fields(&[1, 2, 3, 4])?;
                let head_revision = decode_head_revision(frame.required_u64(3)?)?;
                let last_object_version = decode_object_version(frame.required_u64(4)?)?;
                Ok(Self::Tombstoned {
                    object_id,
                    head_revision,
                    last_object_version,
                })
            }
            ObjectQueryStatus::CurrentInline => {
                if encoding_version == OBJECT_QUERY_RESULT_ENCODING_VERSION_V1 {
                    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
                } else {
                    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 10, 11])?;
                }
                let head_revision = decode_head_revision(frame.required_u64(3)?)?;
                let object_version = decode_object_version(frame.required_u64(4)?)?;
                let digest = decode_digest_fields(&frame, 5, 6)?;
                let canonical_object_bytes = frame.required_field(7)?.to_vec();
                if canonical_object_bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
                    return Err(QueryResultError::ObjectBodyTooLarge {
                        actual: canonical_object_bytes.len(),
                        maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                    });
                }
                let nested = decode_object(&canonical_object_bytes)
                    .map_err(QueryResultError::InvalidCanonicalObject)?;
                if nested.id != object_id {
                    return Err(QueryResultError::ObjectIdentityMismatch {
                        expected: object_id,
                        actual: nested.id,
                    });
                }
                if nested.version != object_version.get() {
                    return Err(QueryResultError::ObjectVersionMismatch {
                        expected: object_version.get(),
                        actual: nested.version,
                    });
                }
                if encoding_version == OBJECT_QUERY_RESULT_ENCODING_VERSION_V1 {
                    return Ok(Self::HistoricalCurrentInline {
                        object_id,
                        head_revision,
                        object_version,
                        digest,
                        canonical_object_bytes,
                    });
                }
                let chain_id_str: &str = frame.required_str(10)?;
                if chain_id_str.len() > MAX_CHAIN_ID_BYTES {
                    return Err(QueryResultError::ChainIdTooLong(chain_id_str.len()));
                }
                let creating_chain_id: ChainId =
                    ChainId::new(chain_id_str).map_err(QueryResultError::InvalidChainId)?;
                let creating_protocol_version: ProtocolVersion =
                    ProtocolVersion::new(frame.required_u32(11)?);
                if creating_protocol_version.get() == 0 {
                    return Err(QueryResultError::ZeroProtocolVersion);
                }
                Ok(Self::CurrentInline {
                    object_id,
                    head_revision,
                    object_version,
                    digest,
                    creating_chain_id,
                    creating_protocol_version,
                    canonical_object_bytes,
                })
            }
            ObjectQueryStatus::CurrentBlobReference => {
                frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 8, 9])?;
                let head_revision = decode_head_revision(frame.required_u64(3)?)?;
                let object_version = decode_object_version(frame.required_u64(4)?)?;
                let digest = decode_digest_fields(&frame, 5, 6)?;
                let blob_digest = decode_digest_fields(&frame, 8, 9)?;
                Ok(Self::CurrentBlobReference {
                    object_id,
                    head_revision,
                    object_version,
                    digest,
                    blob_digest,
                })
            }
        }
    }
}

fn decode_head_revision(value: u64) -> Result<ObjectHeadRevision, QueryResultError> {
    ObjectHeadRevision::new(value).ok_or(QueryResultError::InvalidHeadRevision(value))
}

fn decode_object_version(value: u64) -> Result<DurableObjectVersion, QueryResultError> {
    DurableObjectVersion::new(value).ok_or(QueryResultError::InvalidObjectVersion(value))
}

/// Canonical `GET /v1/receipts/{request_id}` result (DR-0082, type `0xE104`).
///
/// Both statuses carry the exact `request_id` this result answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpReceiptQueryResult {
    /// No durable receipt exists for the queried request identifier.
    Absent {
        /// The exact request identifier this result answers.
        request_id: RequestId,
    },
    /// A durable receipt exists and was independently re-verified.
    Present {
        /// The exact request identifier this result answers.
        request_id: RequestId,
        /// Digest of the complete canonical input event that produced this receipt.
        event_digest: Digest32,
        /// The exact canonical `NodeDedupRecord` bytes, re-encoding-checked.
        dedup_record_bytes: Vec<u8>,
    },
}

impl HttpReceiptQueryResult {
    /// Returns the exact request identifier this result answers, regardless
    /// of status.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::Absent { request_id } | Self::Present { request_id, .. } => *request_id,
        }
    }

    /// Encodes the canonical `0xE104` receipt query result.
    pub fn encode(&self) -> Result<Vec<u8>, QueryResultError> {
        let mut frame =
            CanonicalStruct::new(RECEIPT_QUERY_RESULT_TYPE_ID, QUERY_RESULT_ENCODING_VERSION);
        match self {
            Self::Absent { request_id } => {
                frame.field_u16(1, ReceiptQueryStatus::Absent.as_u16())?;
                frame.field_bytes(2, request_id.as_bytes().to_vec())?;
            }
            Self::Present {
                request_id,
                event_digest,
                dedup_record_bytes,
            } => {
                frame.field_u16(1, ReceiptQueryStatus::Present.as_u16())?;
                frame.field_bytes(2, request_id.as_bytes().to_vec())?;
                encode_digest_fields(&mut frame, 3, 4, *event_digest)?;
                frame.field_bytes(5, dedup_record_bytes.clone())?;
            }
        }
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one canonical receipt query result.
    ///
    /// A `Present` frame is rejected if its dedup-record body exceeds
    /// `runtime::MAX_DURABLE_RECEIPT_BYTES`, fails to decode as a canonical
    /// `NodeDedupRecord`, decodes to a request id/event digest other than the
    /// outer fields, or does not re-encode to exactly its persisted bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, QueryResultError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(RECEIPT_QUERY_RESULT_TYPE_ID)?;
        frame.require_version(QUERY_RESULT_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let status = ReceiptQueryStatus::try_from(frame.required_u16(1)?)?;
        let request_id = decode_request_id_field(&frame, 2)?;
        match status {
            ReceiptQueryStatus::Absent => {
                frame.require_only_fields(&[1, 2])?;
                Ok(Self::Absent { request_id })
            }
            ReceiptQueryStatus::Present => {
                frame.require_only_fields(&[1, 2, 3, 4, 5])?;
                let event_digest = decode_digest_fields(&frame, 3, 4)?;
                let dedup_record_bytes = frame.required_field(5)?.to_vec();
                if dedup_record_bytes.len() > MAX_DURABLE_RECEIPT_BYTES {
                    return Err(QueryResultError::ReceiptTooLarge {
                        actual: dedup_record_bytes.len(),
                        maximum: MAX_DURABLE_RECEIPT_BYTES,
                    });
                }
                let nested = NodeDedupRecord::decode(&dedup_record_bytes)
                    .map_err(QueryResultError::InvalidDedupRecord)?;
                if nested.request_id() != request_id {
                    return Err(QueryResultError::RequestIdentityMismatch {
                        expected: request_id,
                        actual: nested.request_id(),
                    });
                }
                if nested.event_digest() != event_digest {
                    return Err(QueryResultError::EventDigestMismatch);
                }
                let re_encoded = nested
                    .encode()
                    .map_err(QueryResultError::InvalidDedupRecord)?;
                if re_encoded != dedup_record_bytes {
                    return Err(QueryResultError::NonCanonicalReEncoding);
                }
                Ok(Self::Present {
                    request_id,
                    event_digest,
                    dedup_record_bytes,
                })
            }
        }
    }
}

/// Converts a node-core receipt query result into its canonical HTTP form.
pub fn http_receipt_query_result(
    result: NodeReceiptQueryResult,
) -> Result<HttpReceiptQueryResult, NodeCoreError> {
    match result {
        NodeReceiptQueryResult::Absent { request_id } => {
            Ok(HttpReceiptQueryResult::Absent { request_id })
        }
        NodeReceiptQueryResult::Present {
            request_id,
            event_digest,
            record,
        } => Ok(HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes: record.encode()?,
        }),
    }
}

/// Canonical `GET /v1/senders/{sender}/next-nonce` result (DR-0082, type `0xE105`).
///
/// Carries the exact `sender` this result answers alongside the trusted
/// epoch it was resolved under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpNextNonceQueryResult {
    sender: Address,
    epoch: Epoch,
    next_nonce: u64,
}

impl HttpNextNonceQueryResult {
    /// Creates a next-nonce query result.
    #[must_use]
    pub const fn new(sender: Address, epoch: Epoch, next_nonce: u64) -> Self {
        Self {
            sender,
            epoch,
            next_nonce,
        }
    }

    /// Returns the exact sender this result answers.
    #[must_use]
    pub const fn sender(&self) -> Address {
        self.sender
    }

    /// Returns the current trusted epoch this next nonce was resolved under.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the next nonce expected from this sender at this epoch.
    #[must_use]
    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Encodes the canonical `0xE105` next-nonce query result.
    pub fn encode(&self) -> Result<Vec<u8>, QueryResultError> {
        let mut frame = CanonicalStruct::new(
            NEXT_NONCE_QUERY_RESULT_TYPE_ID,
            QUERY_RESULT_ENCODING_VERSION,
        );
        frame.field_bytes(1, self.sender.as_bytes().to_vec())?;
        frame.field_u64(2, self.epoch.get())?;
        frame.field_u64(3, self.next_nonce)?;
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one canonical next-nonce query result.
    pub fn decode(bytes: &[u8]) -> Result<Self, QueryResultError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NEXT_NONCE_QUERY_RESULT_TYPE_ID)?;
        frame.require_version(QUERY_RESULT_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let sender = decode_sender_field(&frame, 1)?;
        let epoch = Epoch::new(frame.required_u64(2)?);
        let next_nonce = frame.required_u64(3)?;
        Ok(Self::new(sender, epoch, next_nonce))
    }
}

fn take_list_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], HttpContractError> {
    let end = offset
        .checked_add(length)
        .ok_or(HttpContractError::TruncatedResponseList)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(HttpContractError::TruncatedResponseList)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT_STABLE_VECTOR_HEX: &str = concat!(
        "534e524502e10100090001000c00000073756e726973652d746573740200040000000300000003000800",
        "00000700000000000000040002000000010005000200000001000600020000000100070002000000010008",
        "0020000000111111111111111111111111111111111111111111111111111111111111111109000300000",
        "0aabbcc",
    );

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn context_codec_owns_and_round_trips_the_existing_server_vector() {
        let bytes = decode_hex(CONTEXT_STABLE_VECTOR_HEX);
        let result = HttpContextQueryResult::decode(&bytes).unwrap();

        assert_eq!(result.chain_id().as_str(), "sunrise-test");
        assert_eq!(result.protocol_version().get(), 3);
        assert_eq!(result.epoch().get(), 7);
        assert_eq!(result.protocol_config_bytes(), [0xAA, 0xBB, 0xCC]);
        assert_eq!(result.encode().unwrap(), bytes);
    }
}
