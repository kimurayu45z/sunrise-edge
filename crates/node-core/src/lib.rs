#![forbid(unsafe_code)]

//! Deterministic, runtime-neutral ingress and persistence boundary for one node event.
//!
//! The core consumes exactly one bounded canonical event, loads one explicit state
//! value, delegates a pure transition, and conditionally persists the returned
//! state with compare-and-swap. It deliberately does not sign, send, schedule,
//! spawn, retry, or keep process-local protocol state.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use hashing::{HashSuiteResolver, HashingError};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, ProtocolConfigError};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, ProtocolVersion, TypeError,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
    AtomicStateWriteSet, AtomicityDomainId, DomainTransactionalStateStore, DurableCommitOutcome,
    DurableCommitRejection, DurableInvocationError, DurableInvocationTransaction,
    DurableObjectChanges, DurableOperationContext, DurableOutboxBatch, DurableOutboxMessage,
    DurableReadError, DurableRequestId, DurableRequestReceipt, DurableStateTransaction,
    IndeterminateCommitReason, MAX_ATOMIC_STATE_WRITES, MAX_STATE_KEY_BYTES, PersistenceLayout,
    Runtime, RuntimeError, StateMutation, StateMutationEntry, StateReadAssertion, StateStore,
    StateWrite, StructuredDurableDomainStateStore, TransactionalStateStore, VersionedStateValue,
};
use std::collections::BTreeMap;
use std::error::Error;

pub mod transaction_auth;

pub use transaction_auth::{
    AuthenticatedTransaction, MAX_TRANSACTION_SIGNABLE_BYTES, TransactionAuthError,
    TrustedTransactionContext, authenticate_transaction_bytes,
};

const NODE_EVENT_TYPE_ID: u16 = 0xE001;
const NODE_RESPONSE_TYPE_ID: u16 = 0xE002;
const NODE_DEDUP_RECORD_TYPE_ID: u16 = 0xE003;
const NODE_OUTBOX_BATCH_TYPE_ID: u16 = 0xE004;
const NODE_OUTBOX_DELIVERY_TYPE_ID: u16 = 0xE005;
const ENCODING_VERSION: u16 = 1;

/// Maximum UTF-8 byte length of a chain identifier accepted at node ingress.
pub const MAX_CHAIN_ID_BYTES: usize = 128;
/// Maximum canonical payload length carried by one node event or response.
pub const MAX_NODE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical state value replaced by one node-core invocation.
pub const MAX_NODE_STATE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum responses or outbound messages produced by one invocation.
pub const MAX_NODE_OUTPUT_ITEMS: usize = 1_024;
/// Maximum aggregate payload bytes returned by one invocation.
pub const MAX_NODE_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum lease duration for one outbound delivery attempt.
pub const MAX_OUTBOX_LEASE_MILLIS: u64 = 5 * 60 * 1_000;

/// Errors returned by node-core validation, transition, and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCoreError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// Domain-separated event hashing failed.
    Hashing(HashingError),
    /// A decoded chain identifier was invalid.
    InvalidChainId(TypeError),
    /// A decoded hash algorithm identifier was invalid.
    InvalidHashAlgorithm(TypeError),
    /// A persisted digest had the wrong byte length.
    InvalidDigestLength(usize),
    /// A chain identifier exceeded the ingress resource bound.
    ChainIdTooLong(usize),
    /// A request identifier must not be all zeroes.
    ZeroRequestId,
    /// An outbox lease identifier must not be all zeroes.
    ZeroOutboxLeaseId,
    /// An outbox lease duration was zero or exceeded its bound.
    InvalidOutboxLeaseDuration(u64),
    /// A request identifier had the wrong encoded length.
    InvalidRequestIdLength(usize),
    /// An outbox lease identifier had the wrong encoded length.
    InvalidOutboxLeaseIdLength(usize),
    /// An event kind identifier is unknown.
    UnknownEventKind(u16),
    /// A response status identifier is unknown.
    UnknownResponseStatus(u16),
    /// The event belongs to a different chain.
    ChainMismatch {
        /// Configured chain.
        expected: ChainId,
        /// Event chain.
        actual: ChainId,
    },
    /// The event targets a different protocol version.
    ProtocolVersionMismatch {
        /// Configured protocol version.
        expected: ProtocolVersion,
        /// Event protocol version.
        actual: ProtocolVersion,
    },
    /// The event targets a different epoch.
    EpochMismatch {
        /// Configured epoch.
        expected: Epoch,
        /// Event epoch.
        actual: Epoch,
    },
    /// A persistence key was empty.
    EmptyStateKey,
    /// A transactional invocation declared no state access.
    EmptyStateAccessPlan,
    /// A transactional invocation declared too many state accesses.
    TooManyStateAccesses {
        /// Actual access count.
        count: usize,
        /// Maximum accepted access count.
        maximum: usize,
    },
    /// A transactional invocation declared the same state key twice.
    DuplicateStateAccessKey,
    /// A transactional transition returned no state updates.
    EmptyStateUpdates,
    /// A transactional transition returned too many state updates.
    TooManyStateUpdates {
        /// Actual update count.
        count: usize,
        /// Maximum accepted update count.
        maximum: usize,
    },
    /// A transactional transition returned the same state key twice.
    DuplicateStateUpdateKey,
    /// A transactional transition updated a key absent from its access plan.
    UndeclaredStateUpdate(Vec<u8>),
    /// A transactional transition attempted to update a read-only key.
    ReadOnlyStateUpdate(Vec<u8>),
    /// An application access plan attempted to claim a node-core metadata key.
    ReservedStateAccess(Vec<u8>),
    /// An event or response payload exceeded its resource bound.
    PayloadTooLarge(usize),
    /// A state value exceeded its resource bound.
    StateTooLarge(usize),
    /// Too many output items were returned by one transition.
    TooManyOutputItems {
        /// Output collection name.
        collection: &'static str,
        /// Actual item count.
        count: usize,
    },
    /// Aggregate output payload bytes exceeded their resource bound.
    OutputTooLarge(usize),
    /// The transition produced a response for another request.
    ResponseRequestMismatch {
        /// Event request identifier.
        expected: RequestId,
        /// Response request identifier.
        actual: RequestId,
    },
    /// The persisted state changed between read and conditional write.
    StateConflict,
    /// A request identifier was reused for different canonical event bytes.
    RequestIdReuse,
    /// Persisted deduplication/outbox state violated an invariant.
    PersistenceInvariant(&'static str),
    /// No persisted outbox exists for the requested invocation.
    OutboxNotFound,
    /// Another delivery attempt owns an unexpired lease.
    OutboxLeaseActive {
        /// Unix-millisecond lease deadline.
        expires_at_unix_millis: u64,
    },
    /// An acknowledgement did not match the active lease.
    OutboxLeaseMismatch,
    /// An acknowledgement did not match the next pending message index.
    OutboxIndexMismatch,
    /// Lease deadline or delivery-attempt arithmetic overflowed.
    OutboxArithmeticOverflow,
    /// A nested canonical-record item length could not be represented.
    NestedItemLengthOverflow(usize),
    /// Bytes remained after a declared nested canonical-record list.
    TrailingNestedListBytes(usize),
    /// A runtime storage operation failed.
    Runtime(RuntimeError),
    /// A durable storage read failed before a transition could commit.
    DurableRead(DurableReadError),
    /// A structured durable invocation failed validation before storage I/O.
    DurableInvocation(DurableInvocationError),
    /// Durable storage proved that the invocation did not commit.
    DurableCommitRejected(DurableCommitRejection),
    /// Durable storage could not prove whether the invocation committed.
    DurableCommitIndeterminate(IndeterminateCommitReason),
    /// Committed domain-placement configuration rejected routing.
    ProtocolConfig(ProtocolConfigError),
    /// Transaction authentication failed before any state-machine or storage work.
    TransactionAuth(TransactionAuthError),
    /// A generic handler received a transaction submission without an authenticated wrapper.
    UnauthenticatedTransactionSubmission,
    /// An authenticated transaction entrypoint received another node-event family.
    ExpectedSubmitTransaction,
    /// Ingress and committed protocol-version authorities disagreed.
    ProtocolConfigVersionMismatch {
        /// Version fixed by the node invocation configuration.
        node_config: ProtocolVersion,
        /// Version committed in protocol configuration.
        protocol_config: ProtocolVersion,
    },
    /// The application-specific state machine rejected the event.
    TransitionRejected(&'static str),
}

impl fmt::Display for NodeCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::Hashing(error) => write!(f, "node event hashing failed: {error}"),
            Self::InvalidChainId(error) => write!(f, "invalid chain id: {error}"),
            Self::InvalidHashAlgorithm(error) => {
                write!(f, "invalid hash algorithm: {error}")
            }
            Self::InvalidDigestLength(length) => {
                write!(f, "digest is {length} bytes, expected 32")
            }
            Self::ChainIdTooLong(length) => write!(
                f,
                "chain id is {length} bytes, maximum is {MAX_CHAIN_ID_BYTES}"
            ),
            Self::ZeroRequestId => f.write_str("request id must not be all zeroes"),
            Self::ZeroOutboxLeaseId => f.write_str("outbox lease id must not be all zeroes"),
            Self::InvalidOutboxLeaseDuration(duration) => write!(
                f,
                "outbox lease duration is {duration}ms, maximum is {MAX_OUTBOX_LEASE_MILLIS}ms"
            ),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "request id is {length} bytes, expected 32")
            }
            Self::InvalidOutboxLeaseIdLength(length) => {
                write!(f, "outbox lease id is {length} bytes, expected 32")
            }
            Self::UnknownEventKind(kind) => write!(f, "unknown node event kind: {kind:#06x}"),
            Self::UnknownResponseStatus(status) => {
                write!(f, "unknown node response status: {status:#06x}")
            }
            Self::ChainMismatch { expected, actual } => {
                write!(f, "event chain mismatch: expected {expected}, got {actual}")
            }
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "event protocol version mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "event epoch mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EmptyStateKey => f.write_str("node-core state key must not be empty"),
            Self::EmptyStateAccessPlan => {
                f.write_str("transactional node state access plan must not be empty")
            }
            Self::TooManyStateAccesses { count, maximum } => write!(
                f,
                "transactional node state access plan has {count} keys, maximum is {maximum}"
            ),
            Self::DuplicateStateAccessKey => {
                f.write_str("transactional node state access plan contains a duplicate key")
            }
            Self::EmptyStateUpdates => {
                f.write_str("transactional node transition must update at least one state key")
            }
            Self::TooManyStateUpdates { count, maximum } => write!(
                f,
                "transactional node transition has {count} updates, maximum is {maximum}"
            ),
            Self::DuplicateStateUpdateKey => {
                f.write_str("transactional node transition contains a duplicate update key")
            }
            Self::UndeclaredStateUpdate(key) => write!(
                f,
                "transactional node transition updated an undeclared {}-byte state key",
                key.len()
            ),
            Self::ReadOnlyStateUpdate(key) => write!(
                f,
                "transactional node transition updated a read-only {}-byte state key",
                key.len()
            ),
            Self::ReservedStateAccess(key) => write!(
                f,
                "transactional node access plan claimed a reserved {}-byte state key",
                key.len()
            ),
            Self::PayloadTooLarge(length) => write!(
                f,
                "node payload is {length} bytes, maximum is {MAX_NODE_PAYLOAD_BYTES}"
            ),
            Self::StateTooLarge(length) => write!(
                f,
                "node state is {length} bytes, maximum is {MAX_NODE_STATE_BYTES}"
            ),
            Self::TooManyOutputItems { collection, count } => write!(
                f,
                "node output has {count} {collection}, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::OutputTooLarge(length) => write!(
                f,
                "node output is {length} bytes, maximum is {MAX_NODE_OUTPUT_BYTES}"
            ),
            Self::ResponseRequestMismatch { expected, actual } => write!(
                f,
                "response request id mismatch: expected {expected}, got {actual}"
            ),
            Self::StateConflict => f.write_str("node state changed before the conditional write"),
            Self::RequestIdReuse => {
                f.write_str("request id was already committed for a different event")
            }
            Self::PersistenceInvariant(reason) => {
                write!(f, "persisted node invocation invariant failed: {reason}")
            }
            Self::OutboxNotFound => f.write_str("outbox batch was not found"),
            Self::OutboxLeaseActive {
                expires_at_unix_millis,
            } => write!(
                f,
                "outbox message is leased until unix millisecond {expires_at_unix_millis}"
            ),
            Self::OutboxLeaseMismatch => f.write_str("outbox acknowledgement lease does not match"),
            Self::OutboxIndexMismatch => f.write_str("outbox acknowledgement index does not match"),
            Self::OutboxArithmeticOverflow => f.write_str("outbox delivery arithmetic overflow"),
            Self::NestedItemLengthOverflow(length) => {
                write!(
                    f,
                    "nested canonical item length cannot be represented: {length}"
                )
            }
            Self::TrailingNestedListBytes(length) => {
                write!(f, "nested canonical list has {length} trailing bytes")
            }
            Self::Runtime(error) => write!(f, "runtime operation failed: {error}"),
            Self::DurableRead(error) => write!(f, "durable read failed: {error:?}"),
            Self::DurableInvocation(error) => {
                write!(f, "durable invocation validation failed: {error}")
            }
            Self::DurableCommitRejected(error) => {
                write!(f, "durable commit was rejected: {error:?}")
            }
            Self::DurableCommitIndeterminate(reason) => {
                write!(f, "durable commit outcome is indeterminate: {reason:?}")
            }
            Self::ProtocolConfig(error) => {
                write!(f, "protocol configuration rejected routing: {error}")
            }
            Self::TransactionAuth(error) => {
                write!(f, "transaction authentication failed: {error}")
            }
            Self::UnauthenticatedTransactionSubmission => {
                f.write_str("SubmitTransaction requires an authenticated transaction entrypoint")
            }
            Self::ExpectedSubmitTransaction => {
                f.write_str("authenticated transaction entrypoint requires SubmitTransaction")
            }
            Self::ProtocolConfigVersionMismatch {
                node_config,
                protocol_config,
            } => write!(
                f,
                "node config protocol version {} does not match committed protocol version {}",
                node_config.get(),
                protocol_config.get()
            ),
            Self::TransitionRejected(reason) => write!(f, "node transition rejected: {reason}"),
        }
    }
}

impl Error for NodeCoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::InvalidChainId(error) => Some(error),
            Self::InvalidHashAlgorithm(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::ProtocolConfig(error) => Some(error),
            Self::TransactionAuth(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalEncodingError> for NodeCoreError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for NodeCoreError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<HashingError> for NodeCoreError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<RuntimeError> for NodeCoreError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<DurableReadError> for NodeCoreError {
    fn from(value: DurableReadError) -> Self {
        Self::DurableRead(value)
    }
}

impl From<DurableInvocationError> for NodeCoreError {
    fn from(value: DurableInvocationError) -> Self {
        Self::DurableInvocation(value)
    }
}

impl From<ProtocolConfigError> for NodeCoreError {
    fn from(value: ProtocolConfigError) -> Self {
        Self::ProtocolConfig(value)
    }
}

impl From<TransactionAuthError> for NodeCoreError {
    fn from(value: TransactionAuthError) -> Self {
        Self::TransactionAuth(value)
    }
}

/// Stable, caller-supplied idempotency identifier for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 32]);

impl RequestId {
    /// Creates a non-zero request identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, NodeCoreError> {
        if bytes == [0; 32] {
            return Err(NodeCoreError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed node event families routed to application-specific schema decoders.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeEventKind {
    /// Client transaction submission.
    SubmitTransaction = 0x0001,
    /// Validator vote delivery.
    ReceiveVote = 0x0002,
    /// Certificate delivery.
    ReceiveCertificate = 0x0003,
    /// Shared-object consensus message delivery.
    ReceiveConsensusMessage = 0x0004,
    /// Governance certificate application.
    ApplyGovernanceCertificate = 0x0005,
    /// Protocol-upgrade certificate application.
    ApplyProtocolUpgrade = 0x0006,
    /// Validator-set change certificate application.
    ApplyValidatorSetChange = 0x0007,
    /// Untrusted liveness tick delivery.
    Tick = 0x0008,
}

impl NodeEventKind {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeEventKind {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SubmitTransaction),
            0x0002 => Ok(Self::ReceiveVote),
            0x0003 => Ok(Self::ReceiveCertificate),
            0x0004 => Ok(Self::ReceiveConsensusMessage),
            0x0005 => Ok(Self::ApplyGovernanceCertificate),
            0x0006 => Ok(Self::ApplyProtocolUpgrade),
            0x0007 => Ok(Self::ApplyValidatorSetChange),
            0x0008 => Ok(Self::Tick),
            other => Err(NodeCoreError::UnknownEventKind(other)),
        }
    }
}

/// One replay-bounded, canonical input to the node state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEvent {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    request_id: RequestId,
    kind: NodeEventKind,
    payload: Vec<u8>,
}

impl NodeEvent {
    /// Creates a validated event around one canonical application payload.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        request_id: RequestId,
        kind: NodeEventKind,
        payload: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        validate_payload(&payload)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            request_id,
            kind,
            payload,
        })
    }

    /// Returns the replay-protected chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the replay-protected protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the replay-protected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event family.
    #[must_use]
    pub const fn kind(&self) -> NodeEventKind {
        self.kind
    }

    /// Returns the canonical application payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the event into its stable canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, self.chain_id.as_str())?;
        frame.field_u32(2, self.protocol_version.get())?;
        frame.field_u64(3, self.epoch.get())?;
        frame.field_bytes(4, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(5, self.kind.as_u16())?;
        frame.field_bytes(6, self.payload.clone())?;
        Ok(frame.finish()?)
    }

    /// Hashes the complete canonical event in its dedicated idempotency domain.
    pub fn digest(&self, resolver: &HashSuiteResolver) -> Result<Digest32, NodeCoreError> {
        if resolver.chain_id() != &self.chain_id {
            return Err(NodeCoreError::ChainMismatch {
                expected: resolver.chain_id().clone(),
                actual: self.chain_id.clone(),
            });
        }
        if resolver.protocol_version() != self.protocol_version {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: resolver.protocol_version(),
                actual: self.protocol_version,
            });
        }
        Ok(resolver.hash_for_purpose(self.epoch, HashPurpose::NodeEvent, &self.encode()?)?)
    }

    /// Decodes and validates exactly one canonical event frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_EVENT_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;

        let chain_id = ChainId::new(frame.required_str(1)?.to_owned())
            .map_err(NodeCoreError::InvalidChainId)?;
        let request_bytes = frame.required_field(4)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            chain_id,
            ProtocolVersion::new(frame.required_u32(2)?),
            Epoch::new(frame.required_u64(3)?),
            RequestId::new(request_array)?,
            NodeEventKind::try_from(frame.required_u16(5)?)?,
            frame.required_field(6)?.to_vec(),
        )
    }

    fn validate_context(&self, config: &NodeConfig) -> Result<(), NodeCoreError> {
        if self.chain_id != config.chain_id {
            return Err(NodeCoreError::ChainMismatch {
                expected: config.chain_id.clone(),
                actual: self.chain_id.clone(),
            });
        }
        if self.protocol_version != config.protocol_version {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: config.protocol_version,
                actual: self.protocol_version,
            });
        }
        if self.epoch != config.epoch {
            return Err(NodeCoreError::EpochMismatch {
                expected: config.epoch,
                actual: self.epoch,
            });
        }
        Ok(())
    }
}

/// Immutable invocation context supplied by the runtime adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    state_key: Vec<u8>,
}

impl NodeConfig {
    /// Creates a node-core invocation configuration.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        state_key: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        if state_key.is_empty() {
            return Err(NodeCoreError::EmptyStateKey);
        }
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            state_key,
        })
    }

    /// Returns the configured chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the configured epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the explicit persistence key used by this state machine.
    #[must_use]
    pub fn state_key(&self) -> &[u8] {
        &self.state_key
    }
}

/// A `SubmitTransaction` event whose canonical inner transaction has been
/// authenticated against the same trusted ingress and committed protocol
/// configuration.
///
/// The fields are private and there is no public constructor. Callers must use
/// [`authenticate_submit_transaction_event`], and durable processing consumes
/// this wrapper through
/// [`handle_authenticated_resolved_durable_submit_transaction`]. The committed
/// placement is captured at authentication time so a caller cannot authenticate
/// under one `ProtocolConfig` and route storage through another manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedSubmitTransaction {
    event: NodeEvent,
    transaction: AuthenticatedTransaction,
    placement: DomainPlacementManifest,
}

impl AuthenticatedSubmitTransaction {
    /// Returns the authenticated outer node event.
    #[must_use]
    pub const fn event(&self) -> &NodeEvent {
        &self.event
    }

    /// Returns the strictly decoded and signature-verified transaction.
    #[must_use]
    pub const fn transaction(&self) -> &AuthenticatedTransaction {
        &self.transaction
    }
}

/// Authenticates one `SubmitTransaction` event before any machine or storage
/// operation can begin.
///
/// The outer event is first matched against `NodeConfig`. Its protocol version
/// must also equal the committed `ProtocolConfig` version. The inner canonical
/// transaction is then authenticated with the outer trusted chain and epoch,
/// while protocol-version and profile authority come only from
/// `ProtocolConfig`. The returned wrapper captures that configuration's domain
/// placement for the later durable commit.
pub fn authenticate_submit_transaction_event(
    event: NodeEvent,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> Result<AuthenticatedSubmitTransaction, NodeCoreError> {
    event.validate_context(config)?;
    if event.kind() != NodeEventKind::SubmitTransaction {
        return Err(NodeCoreError::ExpectedSubmitTransaction);
    }
    if config.protocol_version() != protocol_config.protocol_version {
        return Err(NodeCoreError::ProtocolConfigVersionMismatch {
            node_config: config.protocol_version(),
            protocol_config: protocol_config.protocol_version,
        });
    }

    let trusted_context =
        TrustedTransactionContext::new(config.chain_id().clone(), config.epoch(), protocol_config);
    let transaction = authenticate_transaction_bytes(event.payload(), &trusted_context)?;
    let placement = protocol_config
        .domain_placement
        .clone()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)?;

    Ok(AuthenticatedSubmitTransaction {
        event,
        transaction,
        placement,
    })
}

/// Stable status returned to the request adapter.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeResponseStatus {
    /// The event was accepted and persisted.
    Accepted = 0x0001,
    /// The authenticated event was deterministically rejected by application logic.
    Rejected = 0x0002,
}

impl NodeResponseStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeResponseStatus {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Accepted),
            0x0002 => Ok(Self::Rejected),
            other => Err(NodeCoreError::UnknownResponseStatus(other)),
        }
    }
}

/// Adapter-neutral response produced by a successful state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeResponse {
    request_id: RequestId,
    status: NodeResponseStatus,
    payload: Option<Vec<u8>>,
}

impl NodeResponse {
    /// Creates a bounded response. A present payload must be a canonical frame.
    pub fn new(
        request_id: RequestId,
        status: NodeResponseStatus,
        payload: Option<Vec<u8>>,
    ) -> Result<Self, NodeCoreError> {
        if let Some(bytes) = &payload {
            validate_payload(bytes)?;
        }
        Ok(Self {
            request_id,
            status,
            payload,
        })
    }

    /// Returns the matching request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> NodeResponseStatus {
        self.status
    }

    /// Returns the optional canonical response payload.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Encodes this response into its adapter-neutral canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_RESPONSE_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.status.as_u16())?;
        if let Some(payload) = &self.payload {
            frame.field_bytes(3, payload.clone())?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes one adapter-neutral canonical response.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_RESPONSE_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            RequestId::new(request_array)?,
            NodeResponseStatus::try_from(frame.required_u16(2)?)?,
            frame.field(3).map(<[u8]>::to_vec),
        )
    }
}

/// Adapter-neutral outbound delivery request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundMessage {
    event: NodeEvent,
}

impl OutboundMessage {
    /// Creates an outbound message around a fully framed node event.
    #[must_use]
    pub const fn new(event: NodeEvent) -> Self {
        Self { event }
    }

    /// Returns the event to deliver through an untrusted transport.
    #[must_use]
    pub const fn event(&self) -> &NodeEvent {
        &self.event
    }
}

/// Canonical completed-request record used for persisted idempotency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDedupRecord {
    request_id: RequestId,
    event_digest: Digest32,
    responses: Vec<NodeResponse>,
}

impl NodeDedupRecord {
    /// Creates a completed request record with replayable adapter responses.
    pub fn new(
        request_id: RequestId,
        event_digest: Digest32,
        responses: Vec<NodeResponse>,
    ) -> Result<Self, NodeCoreError> {
        NodeOutput::new(responses.clone(), Vec::new())?;
        for response in &responses {
            if response.request_id() != request_id {
                return Err(NodeCoreError::ResponseRequestMismatch {
                    expected: request_id,
                    actual: response.request_id(),
                });
            }
        }
        Ok(Self {
            request_id,
            event_digest,
            responses,
        })
    }

    /// Returns the stable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the digest of the complete canonical input event.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the responses replayed for a matching duplicate request.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Encodes the completed request record canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let response_list = encode_nested_items(
            self.responses
                .iter()
                .map(NodeResponse::encode)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let response_count =
            u32::try_from(self.responses.len()).map_err(|_| NodeCoreError::TooManyOutputItems {
                collection: "dedup responses",
                count: self.responses.len(),
            })?;
        let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, response_count)?;
        frame.field_bytes(5, response_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates one completed request record.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_DEDUP_RECORD_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let count = bounded_nested_count(frame.required_u32(4)?, "dedup responses")?;
        let responses = decode_nested_items(frame.required_field(5)?, count, NodeResponse::decode)?;
        Self::new(request_id, event_digest, responses)
    }
}

/// Canonical at-least-once outbound batch persisted with one request commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeOutboxBatch {
    request_id: RequestId,
    event_digest: Digest32,
    messages: Vec<OutboundMessage>,
}

impl NodeOutboxBatch {
    /// Creates the complete ordered outbound batch for one committed request.
    pub fn new(
        request_id: RequestId,
        event_digest: Digest32,
        messages: Vec<OutboundMessage>,
    ) -> Result<Self, NodeCoreError> {
        NodeOutput::new(Vec::new(), messages.clone())?;
        Ok(Self {
            request_id,
            event_digest,
            messages,
        })
    }

    /// Returns the request that created this batch.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the digest of the input event that created this batch.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns outbound messages in deterministic transition order.
    #[must_use]
    pub fn messages(&self) -> &[OutboundMessage] {
        &self.messages
    }

    /// Encodes the outbound batch canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let message_list = encode_nested_items(
            self.messages
                .iter()
                .map(|message| message.event().encode())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let message_count =
            u32::try_from(self.messages.len()).map_err(|_| NodeCoreError::TooManyOutputItems {
                collection: "outbox messages",
                count: self.messages.len(),
            })?;
        let mut frame = CanonicalStruct::new(NODE_OUTBOX_BATCH_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, message_count)?;
        frame.field_bytes(5, message_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates one persisted outbound batch.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_OUTBOX_BATCH_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let count = bounded_nested_count(frame.required_u32(4)?, "outbox messages")?;
        let events = decode_nested_items(frame.required_field(5)?, count, NodeEvent::decode)?;
        let messages = events.into_iter().map(OutboundMessage::new).collect();
        Self::new(request_id, event_digest, messages)
    }
}

/// Non-zero caller-generated identity for one bounded outbox lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutboxLeaseId([u8; 32]);

impl OutboxLeaseId {
    /// Creates a non-zero lease identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, NodeCoreError> {
        if bytes == [0; 32] {
            return Err(NodeCoreError::ZeroOutboxLeaseId);
        }
        Ok(Self(bytes))
    }

    /// Returns the lease identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Mutable delivery cursor committed beside an immutable outbox batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeOutboxDelivery {
    request_id: RequestId,
    event_digest: Digest32,
    next_index: u32,
    attempts: u32,
    lease: Option<(OutboxLeaseId, u64)>,
}

impl NodeOutboxDelivery {
    fn pending(request_id: RequestId, event_digest: Digest32) -> Self {
        Self {
            request_id,
            event_digest,
            next_index: 0,
            attempts: 0,
            lease: None,
        }
    }

    /// Returns the request that owns this delivery cursor.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event digest shared with the immutable outbox batch.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the next message index that requires delivery.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Returns the number of leases granted for this batch.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the active lease and deadline, if present.
    #[must_use]
    pub const fn lease(&self) -> Option<(OutboxLeaseId, u64)> {
        self.lease
    }

    /// Encodes the delivery cursor canonically.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_OUTBOX_DELIVERY_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, self.next_index)?;
        frame.field_u32(5, self.attempts)?;
        if let Some((lease_id, expires_at)) = self.lease {
            frame.field_bytes(6, lease_id.as_bytes().to_vec())?;
            frame.field_u64(7, expires_at)?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes and validates one delivery cursor.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_OUTBOX_DELIVERY_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
        let request_id = decode_request_id(frame.required_field(1)?)?;
        let event_digest = decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let lease = match (frame.field(6), frame.field(7)) {
            (None, None) => None,
            (Some(id), Some(expires)) => {
                let id: [u8; 32] = id
                    .try_into()
                    .map_err(|_| NodeCoreError::InvalidOutboxLeaseIdLength(id.len()))?;
                let expires: [u8; 8] =
                    expires
                        .try_into()
                        .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                            field_id: 7,
                            expected: 8,
                            actual: expires.len(),
                        })?;
                Some((OutboxLeaseId::new(id)?, u64::from_le_bytes(expires)))
            }
            _ => {
                return Err(NodeCoreError::PersistenceInvariant(
                    "outbox lease id and deadline must appear together",
                ));
            }
        };
        Ok(Self {
            request_id,
            event_digest,
            next_index: frame.required_u32(4)?,
            attempts: frame.required_u32(5)?,
            lease,
        })
    }
}

/// One leased outbound message. Delivery is at-least-once until acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxClaim {
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
    expires_at_unix_millis: u64,
    message: OutboundMessage,
}

impl OutboxClaim {
    /// Returns the originating request.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the ordered message index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the lease identity required for acknowledgement.
    #[must_use]
    pub const fn lease_id(&self) -> OutboxLeaseId {
        self.lease_id
    }

    /// Returns the lease deadline.
    #[must_use]
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }

    /// Returns the message to send through an untrusted relay.
    #[must_use]
    pub const fn message(&self) -> &OutboundMessage {
        &self.message
    }
}

/// Bounded side effects returned only after state persistence succeeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeOutput {
    responses: Vec<NodeResponse>,
    outbound_messages: Vec<OutboundMessage>,
}

impl NodeOutput {
    /// Creates and validates one invocation's output.
    pub fn new(
        responses: Vec<NodeResponse>,
        outbound_messages: Vec<OutboundMessage>,
    ) -> Result<Self, NodeCoreError> {
        if responses.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "responses",
                count: responses.len(),
            });
        }
        if outbound_messages.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "outbound messages",
                count: outbound_messages.len(),
            });
        }

        let response_bytes = responses.iter().filter_map(|item| item.payload.as_ref());
        let outbound_bytes = outbound_messages.iter().map(|item| item.event.payload());
        let total = response_bytes
            .map(Vec::len)
            .chain(outbound_bytes.map(<[u8]>::len))
            .try_fold(0_usize, usize::checked_add)
            .ok_or(NodeCoreError::OutputTooLarge(usize::MAX))?;
        if total > MAX_NODE_OUTPUT_BYTES {
            return Err(NodeCoreError::OutputTooLarge(total));
        }

        Ok(Self {
            responses,
            outbound_messages,
        })
    }

    /// Returns adapter responses in deterministic application order.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Returns outbound events in deterministic application order.
    #[must_use]
    pub fn outbound_messages(&self) -> &[OutboundMessage] {
        &self.outbound_messages
    }
}

/// Persisted node output paired with the committed logical atomicity domain.
///
/// Adapters carry this domain into outbox claim/ack instead of accepting a
/// domain selected by the request or independently rerunning placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNodeOutput {
    domain: AtomicityDomainId,
    output: NodeOutput,
}

impl ResolvedNodeOutput {
    fn new(domain: AtomicityDomainId, output: NodeOutput) -> Self {
        Self { domain, output }
    }

    /// Returns the manifest-resolved logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns output released after the domain transaction committed.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }

    /// Consumes the wrapper and returns the persisted output.
    #[must_use]
    pub fn into_output(self) -> NodeOutput {
        self.output
    }
}

/// Storage access granted to one deterministic transactional transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStateAccessMode {
    /// The transition may inspect but not mutate the key.
    ReadOnly,
    /// The transition may inspect and conditionally mutate the key.
    ReadWrite,
}

/// One key in a transactional node invocation's declared state access plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateAccess {
    key: Vec<u8>,
    mode: NodeStateAccessMode,
}

impl NodeStateAccess {
    /// Creates a bounded state-access declaration.
    pub fn new(key: Vec<u8>, mode: NodeStateAccessMode) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        Ok(Self { key, mode })
    }

    /// Returns the storage key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the allowed access mode.
    #[must_use]
    pub const fn mode(&self) -> NodeStateAccessMode {
        self.mode
    }
}

/// Bounded, unique, canonically key-ordered state access plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateAccessPlan {
    accesses: Vec<NodeStateAccess>,
}

impl NodeStateAccessPlan {
    /// Validates and sorts an event-specific state access plan.
    pub fn new(mut accesses: Vec<NodeStateAccess>) -> Result<Self, NodeCoreError> {
        if accesses.is_empty() {
            return Err(NodeCoreError::EmptyStateAccessPlan);
        }
        if accesses.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateAccesses {
                count: accesses.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        accesses.sort_by(|left, right| left.key.cmp(&right.key));
        if accesses.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(NodeCoreError::DuplicateStateAccessKey);
        }
        Ok(Self { accesses })
    }

    /// Returns state accesses in deterministic raw-key order.
    #[must_use]
    pub fn accesses(&self) -> &[NodeStateAccess] {
        &self.accesses
    }

    fn access(&self, key: &[u8]) -> Option<&NodeStateAccess> {
        self.accesses
            .binary_search_by(|access| access.key.as_slice().cmp(key))
            .ok()
            .map(|index| &self.accesses[index])
    }
}

/// Immutable versioned snapshot supplied to a pure transactional transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateSnapshot {
    values: BTreeMap<Vec<u8>, VersionedStateValue>,
}

impl NodeStateSnapshot {
    /// Returns the observation for a key declared by the access plan.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&VersionedStateValue> {
        self.values.get(key)
    }

    /// Iterates over observations in deterministic raw-key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &VersionedStateValue)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_slice(), value))
    }
}

/// One state mutation produced by a pure transactional transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateUpdate {
    key: Vec<u8>,
    mutation: StateMutation,
}

impl NodeStateUpdate {
    /// Creates a bounded canonical state replacement.
    pub fn put(key: Vec<u8>, value: Vec<u8>) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        validate_state(&value)?;
        Ok(Self {
            key,
            mutation: StateMutation::Put(value),
        })
    }

    /// Creates a state deletion that will retain a storage revision tombstone.
    pub fn delete(key: Vec<u8>) -> Result<Self, NodeCoreError> {
        validate_transactional_state_key(&key)?;
        Ok(Self {
            key,
            mutation: StateMutation::Delete,
        })
    }

    /// Returns the storage key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the requested mutation.
    #[must_use]
    pub const fn mutation(&self) -> &StateMutation {
        &self.mutation
    }
}

/// Candidate multi-key transition and outputs held until atomic commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionalNodeTransition {
    updates: Vec<NodeStateUpdate>,
    output: NodeOutput,
}

impl TransactionalNodeTransition {
    /// Creates a bounded, unique, canonically key-ordered state transition.
    pub fn new(
        mut updates: Vec<NodeStateUpdate>,
        output: NodeOutput,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        updates.sort_by(|left, right| left.key.cmp(&right.key));
        if updates.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self { updates, output })
    }

    /// Creates a transition that publishes only a receipt after asserting reads.
    ///
    /// This is accepted by the structured durable handler, whose receipt write
    /// makes the overall invocation non-empty. Compatibility transaction
    /// handlers may reject it because their storage envelopes require a state
    /// mutation.
    #[must_use]
    pub const fn read_only(output: NodeOutput) -> Self {
        Self {
            updates: Vec::new(),
            output,
        }
    }

    /// Returns state updates in deterministic raw-key order.
    #[must_use]
    pub fn updates(&self) -> &[NodeStateUpdate] {
        &self.updates
    }

    /// Returns output held until every state update commits.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }
}

/// Application transition over a declared, versioned multi-key snapshot.
pub trait TransactionalNodeStateMachine {
    /// Derives the bounded state keys and modes required by one validated event.
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError>;

    /// Computes one pure transition without performing I/O or retaining state.
    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError>;
}

/// One validated candidate state replacement and its deferred outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeTransition {
    next_state: Vec<u8>,
    output: NodeOutput,
}

impl NodeTransition {
    /// Creates a transition around one bounded canonical state value.
    pub fn new(next_state: Vec<u8>, output: NodeOutput) -> Result<Self, NodeCoreError> {
        validate_state(&next_state)?;
        Ok(Self { next_state, output })
    }

    /// Returns the candidate persisted state.
    #[must_use]
    pub fn next_state(&self) -> &[u8] {
        &self.next_state
    }

    /// Returns output held until compare-and-swap succeeds.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }
}

/// Application-specific deterministic transition over explicit persisted bytes.
pub trait NodeStateMachine {
    /// Computes one transition without performing I/O or retaining protocol state.
    fn transition(
        &self,
        current_state: Option<&[u8]>,
        event: &NodeEvent,
    ) -> Result<NodeTransition, NodeCoreError>;
}

fn asserted_transition_writes(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<Vec<StateWrite>, NodeCoreError> {
    let mut mutations = BTreeMap::new();
    for update in updates {
        let Some(access) = plan.access(update.key()) else {
            return Err(NodeCoreError::UndeclaredStateUpdate(update.key));
        };
        if access.mode() != NodeStateAccessMode::ReadWrite {
            return Err(NodeCoreError::ReadOnlyStateUpdate(update.key));
        }
        mutations.insert(update.key, update.mutation);
    }

    let mut writes = Vec::with_capacity(plan.accesses().len());
    for access in plan.accesses() {
        let observed = snapshot
            .get(access.key())
            .ok_or(NodeCoreError::PersistenceInvariant(
                "declared access missing from snapshot",
            ))?;
        let mutation = mutations
            .remove(access.key())
            .unwrap_or(StateMutation::Assert);
        writes.push(StateWrite::new(
            access.key().to_vec(),
            observed.revision(),
            mutation,
        )?);
    }
    Ok(writes)
}

fn domain_transition_parts(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<(Vec<StateReadAssertion>, Vec<StateMutationEntry>), NodeCoreError> {
    let mut mutations = Vec::with_capacity(updates.len());
    for update in updates {
        let Some(access) = plan.access(update.key()) else {
            return Err(NodeCoreError::UndeclaredStateUpdate(update.key));
        };
        if access.mode() != NodeStateAccessMode::ReadWrite {
            return Err(NodeCoreError::ReadOnlyStateUpdate(update.key));
        }
        mutations.push(StateMutationEntry::new(update.key, update.mutation)?);
    }

    let reads = plan
        .accesses()
        .iter()
        .map(|access| {
            let observed =
                snapshot
                    .get(access.key())
                    .ok_or(NodeCoreError::PersistenceInvariant(
                        "declared access missing from snapshot",
                    ))?;
            Ok(StateReadAssertion::new(
                access.key().to_vec(),
                observed.revision(),
            )?)
        })
        .collect::<Result<Vec<_>, NodeCoreError>>()?;
    Ok((reads, mutations))
}

fn validate_generic_event(event: &NodeEvent, config: &NodeConfig) -> Result<(), NodeCoreError> {
    event.validate_context(config)?;
    if event.kind() == NodeEventKind::SubmitTransaction {
        return Err(NodeCoreError::UnauthenticatedTransactionSubmission);
    }
    Ok(())
}

/// Handles one event inside one explicit atomicity domain.
///
/// This is the domain-aware successor to [`handle_transactional_event`]. Every
/// declared observation enters the dedicated read set, while only returned
/// updates enter the mutation set. Conflicts publish neither state nor output.
pub fn handle_domain_transactional_event<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    handle_domain_transactional_event_with_plan(runtime, domain, config, event, machine, plan)
}

/// Resolves one event's domain from committed protocol configuration.
///
/// The access plan is derived exactly once before storage reads. The resolved
/// domain is returned beside committed output for subsequent outbox delivery.
pub fn handle_resolved_transactional_event<R, M>(
    runtime: &R,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output =
        handle_domain_transactional_event_with_plan(runtime, domain, config, event, machine, plan)?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

fn handle_domain_transactional_event_with_plan<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime
            .state_store()
            .get_versioned_in_domain(domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot { values };

    let transition = machine.transition(&snapshot, &event)?;
    validate_output_context(transition.output(), &event, config)?;
    let (reads, mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match runtime.state_store().commit_transaction(transaction)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one event through a declared multi-key atomic state transition.
///
/// The event context and access plan are validated before storage reads. Every
/// observed revision, including read-only and absent state, is asserted in the
/// final transaction, and output remains private until all writes commit.
/// Conflicts are surfaced without retry.
pub fn handle_transactional_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime.state_store().get_versioned(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot { values };

    let transition = machine.transition(&snapshot, &event)?;
    validate_output_context(transition.output(), &event, config)?;

    let writes = asserted_transition_writes(&plan, &snapshot, transition.updates)?;

    let write_set = AtomicStateWriteSet::new(writes)?;
    match runtime.state_store().commit_atomic(write_set)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one event with atomic state, deduplication, and outbox persistence.
///
/// A matching committed duplicate returns its persisted responses without
/// re-running the state machine or re-enqueuing outbound messages. Reusing a
/// request identifier for different canonical event bytes fails closed.
pub fn handle_idempotent_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let event_digest = event.digest(resolver)?;
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    let request_bytes = *event.request_id.as_bytes();
    let dedup_key = layout.request_dedup_key(request_bytes);
    let outbox_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);

    let plan = machine.access_plan(&event)?;
    let maximum_application_accesses = MAX_ATOMIC_STATE_WRITES - 3;
    if plan.accesses.len() > maximum_application_accesses {
        return Err(NodeCoreError::TooManyStateAccesses {
            count: plan.accesses.len(),
            maximum: maximum_application_accesses,
        });
    }
    for reserved in [&dedup_key, &outbox_key, &delivery_key] {
        if plan.access(reserved).is_some() {
            return Err(NodeCoreError::ReservedStateAccess(reserved.clone()));
        }
    }

    let dedup = runtime.state_store().get_versioned(&dedup_key)?;
    let outbox = runtime.state_store().get_versioned(&outbox_key)?;
    let delivery = runtime.state_store().get_versioned(&delivery_key)?;

    if let Some(bytes) = dedup.value() {
        let record = NodeDedupRecord::decode(bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid dedup record"))?;
        if record.request_id() != event.request_id() || record.event_digest() != event_digest {
            return Err(NodeCoreError::RequestIdReuse);
        }
        let batch_bytes = outbox.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox",
        ))?;
        let batch = NodeOutboxBatch::decode(batch_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
        if batch.request_id() != event.request_id() || batch.event_digest() != event_digest {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox identities differ",
            ));
        }
        for message in batch.messages() {
            message.event().validate_context(config)?;
        }
        let delivery_bytes = delivery.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox delivery state",
        ))?;
        let delivery_record = NodeOutboxDelivery::decode(delivery_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
        if delivery_record.request_id != event.request_id()
            || delivery_record.event_digest != event_digest
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox delivery identities differ",
            ));
        }
        return NodeOutput::new(record.responses().to_vec(), Vec::new());
    }
    if outbox.value().is_some() || delivery.value().is_some() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox state exists without dedup",
        ));
    }

    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime.state_store().get_versioned(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot { values };
    let transition = machine.transition(&snapshot, &event)?;
    validate_output_context(transition.output(), &event, config)?;
    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let outbox_batch = NodeOutboxBatch::new(
        event.request_id(),
        event_digest,
        transition.output.outbound_messages.clone(),
    )?;
    let outbox_delivery = NodeOutboxDelivery::pending(event.request_id(), event_digest);

    let mut writes = asserted_transition_writes(&plan, &snapshot, transition.updates)?;
    writes.push(StateWrite::new(
        dedup_key,
        dedup.revision(),
        StateMutation::Put(dedup_record.encode()?),
    )?);
    writes.push(StateWrite::new(
        outbox_key,
        outbox.revision(),
        StateMutation::Put(outbox_batch.encode()?),
    )?);
    writes.push(StateWrite::new(
        delivery_key,
        delivery.revision(),
        StateMutation::Put(outbox_delivery.encode()?),
    )?);

    let write_set = AtomicStateWriteSet::new(writes)?;
    match runtime.state_store().commit_atomic(write_set)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Handles one idempotent event inside one explicit atomicity domain.
///
/// Application state, the request receipt, the immutable outbox batch, and its
/// initial delivery cursor share one complete read set and one atomic commit.
/// A matching replay returns persisted responses without re-running the state
/// machine. This additive path does not change legacy unscoped storage.
pub fn handle_domain_idempotent_event<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    handle_domain_idempotent_event_with_plan(
        runtime, domain, config, resolver, event, machine, plan,
    )
}

/// Resolves and commits one idempotent event from protocol configuration.
///
/// The returned domain is the only valid domain for delivering the committed
/// outbox. Placement is evaluated once from the non-empty bounded access plan
/// before any storage read.
pub fn handle_resolved_idempotent_event<R, M>(
    runtime: &R,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output = handle_domain_idempotent_event_with_plan(
        runtime, domain, config, resolver, event, machine, plan,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// Resolves and commits one idempotent event through the normalized durable boundary.
///
/// The access plan and logical domain are resolved before storage I/O. A typed
/// completed-request receipt is checked before application state is loaded, so
/// an exact replay returns only its persisted responses without rerunning the
/// transition. New application state, the receipt, and any ordered outbox are
/// then submitted as one structured invocation. Output is never released for a
/// rejected or indeterminate commit.
pub fn handle_resolved_durable_idempotent_event<S, M>(
    store: &S,
    context: &DurableOperationContext,
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let plan = machine.access_plan(&event)?;
    let domain = placement.resolve_domain(event.epoch(), plan.accesses().len())?;
    let output = handle_durable_idempotent_event_with_plan(
        store, context, domain, resolver, event, machine, plan,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// Commits one previously authenticated `SubmitTransaction` through the
/// normalized durable boundary.
///
/// Unlike [`handle_resolved_durable_idempotent_event`], this entrypoint accepts
/// only the unforgeable [`AuthenticatedSubmitTransaction`] wrapper. The access
/// plan is derived only after authentication, and its logical domain comes from
/// the same committed placement captured when the wrapper was constructed.
/// Exact duplicates are still authenticated before receipt reconciliation.
pub fn handle_authenticated_resolved_durable_submit_transaction<S, M>(
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    let plan = machine.access_plan(submission.event())?;
    let domain = submission
        .placement
        .resolve_domain(submission.event().epoch(), plan.accesses().len())?;
    let AuthenticatedSubmitTransaction {
        event,
        transaction: _authenticated_transaction,
        placement: _,
    } = submission;
    let output = handle_durable_idempotent_event_with_plan(
        store, context, domain, resolver, event, machine, plan,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

fn handle_durable_idempotent_event_with_plan<S, M>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
) -> Result<NodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    let event_digest = event.digest(resolver)?;
    let request_id = DurableRequestId::new(*event.request_id().as_bytes()).map_err(|_| {
        NodeCoreError::PersistenceInvariant("validated request id failed durable projection")
    })?;

    if let Some(receipt) = store.get_request_receipt(context, domain, request_id)? {
        if receipt.request_id() != request_id {
            return Err(NodeCoreError::PersistenceInvariant(
                "durable receipt lookup returned another request",
            ));
        }
        if receipt.event_digest() != event_digest {
            return Err(NodeCoreError::RequestIdReuse);
        }
        let record = NodeDedupRecord::decode(receipt.canonical_bytes())
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid durable receipt"))?;
        if record.request_id() != event.request_id() || record.event_digest() != event_digest {
            return Err(NodeCoreError::PersistenceInvariant(
                "durable receipt projection and canonical record differ",
            ));
        }
        return NodeOutput::new(record.responses().to_vec(), Vec::new());
    }

    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = store.get_versioned_durable(context, domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot { values };
    let transition = machine.transition(&snapshot, &event)?;
    validate_output_event_context(transition.output(), &event)?;

    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let receipt = DurableRequestReceipt::new(request_id, event_digest, dedup_record.encode()?)?;
    let outbox = if transition.output.outbound_messages.is_empty() {
        None
    } else {
        let messages = transition
            .output
            .outbound_messages
            .iter()
            .map(|message| {
                let payload_digest = message.event().digest(resolver)?;
                Ok(DurableOutboxMessage::new(
                    payload_digest,
                    message.event().encode()?,
                )?)
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        Some(DurableOutboxBatch::new(request_id, event_digest, messages)?)
    };
    let (reads, mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    let state = DurableStateTransaction::new(domain, AtomicStateReadSet::new(reads)?, mutations)?;
    let invocation = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt,
        outbox,
    )?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(transition.output),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(NodeCoreError::StateConflict),
        DurableCommitOutcome::Rejected(reason) => Err(NodeCoreError::DurableCommitRejected(reason)),
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason))
        }
    }
}

fn handle_domain_idempotent_event_with_plan<R, M>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
{
    let event_digest = event.digest(resolver)?;
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    let request_bytes = *event.request_id.as_bytes();
    let dedup_key = layout.request_dedup_key(request_bytes);
    let outbox_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);

    let maximum_application_accesses = MAX_ATOMIC_STATE_WRITES - 3;
    if plan.accesses.len() > maximum_application_accesses {
        return Err(NodeCoreError::TooManyStateAccesses {
            count: plan.accesses.len(),
            maximum: maximum_application_accesses,
        });
    }
    for reserved in [&dedup_key, &outbox_key, &delivery_key] {
        if plan.access(reserved).is_some() {
            return Err(NodeCoreError::ReservedStateAccess(reserved.clone()));
        }
    }

    let store = runtime.state_store();
    let dedup = store.get_versioned_in_domain(domain, &dedup_key)?;
    let outbox = store.get_versioned_in_domain(domain, &outbox_key)?;
    let delivery = store.get_versioned_in_domain(domain, &delivery_key)?;

    if let Some(bytes) = dedup.value() {
        let record = NodeDedupRecord::decode(bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid dedup record"))?;
        if record.request_id() != event.request_id() || record.event_digest() != event_digest {
            return Err(NodeCoreError::RequestIdReuse);
        }
        let batch_bytes = outbox.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox",
        ))?;
        let batch = NodeOutboxBatch::decode(batch_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
        if batch.request_id() != event.request_id() || batch.event_digest() != event_digest {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox identities differ",
            ));
        }
        for message in batch.messages() {
            message.event().validate_context(config)?;
        }
        let delivery_bytes = delivery.value().ok_or(NodeCoreError::PersistenceInvariant(
            "dedup exists without outbox delivery state",
        ))?;
        let delivery_record = NodeOutboxDelivery::decode(delivery_bytes)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
        if delivery_record.request_id != event.request_id()
            || delivery_record.event_digest != event_digest
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "dedup and outbox delivery identities differ",
            ));
        }
        return NodeOutput::new(record.responses().to_vec(), Vec::new());
    }
    if outbox.value().is_some() || delivery.value().is_some() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox state exists without dedup",
        ));
    }

    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = store.get_versioned_in_domain(domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot { values };
    let transition = machine.transition(&snapshot, &event)?;
    validate_output_context(transition.output(), &event, config)?;
    let dedup_record = NodeDedupRecord::new(
        event.request_id(),
        event_digest,
        transition.output.responses.clone(),
    )?;
    let outbox_batch = NodeOutboxBatch::new(
        event.request_id(),
        event_digest,
        transition.output.outbound_messages.clone(),
    )?;
    let outbox_delivery = NodeOutboxDelivery::pending(event.request_id(), event_digest);

    let (mut reads, mut mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    reads.extend([
        StateReadAssertion::new(dedup_key.clone(), dedup.revision())?,
        StateReadAssertion::new(outbox_key.clone(), outbox.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery.revision())?,
    ]);
    mutations.extend([
        StateMutationEntry::new(dedup_key, StateMutation::Put(dedup_record.encode()?))?,
        StateMutationEntry::new(outbox_key, StateMutation::Put(outbox_batch.encode()?))?,
        StateMutationEntry::new(delivery_key, StateMutation::Put(outbox_delivery.encode()?))?,
    ]);
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_transaction(transaction)? {
        AtomicStateWriteResult::Committed => Ok(transition.output),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

fn commit_legacy_transaction_parts<S>(
    store: &S,
    reads: Vec<StateReadAssertion>,
    mutations: Vec<StateMutationEntry>,
) -> Result<AtomicStateWriteResult, NodeCoreError>
where
    S: TransactionalStateStore,
{
    let mut mutations = mutations
        .iter()
        .map(|mutation| (mutation.key().to_vec(), mutation.mutation().clone()))
        .collect::<BTreeMap<_, _>>();
    let writes = reads
        .iter()
        .map(|read| {
            StateWrite::new(
                read.key().to_vec(),
                read.expected_revision(),
                mutations
                    .remove(read.key())
                    .unwrap_or(StateMutation::Assert),
            )
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    if !mutations.is_empty() {
        return Err(RuntimeError::StateMutationWithoutRead.into());
    }
    Ok(store.commit_atomic(AtomicStateWriteSet::new(writes)?)?)
}

fn claim_next_outbox_message_inner<G, C>(
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
    mut get_versioned: G,
    commit: C,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    G: FnMut(&[u8]) -> Result<VersionedStateValue, RuntimeError>,
    C: FnOnce(
        Vec<StateReadAssertion>,
        Vec<StateMutationEntry>,
    ) -> Result<AtomicStateWriteResult, NodeCoreError>,
{
    if lease_duration_millis == 0 || lease_duration_millis > MAX_OUTBOX_LEASE_MILLIS {
        return Err(NodeCoreError::InvalidOutboxLeaseDuration(
            lease_duration_millis,
        ));
    }
    let request_bytes = *request_id.as_bytes();
    let batch_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);
    let batch_value = get_versioned(&batch_key)?;
    let delivery_value = get_versioned(&delivery_key)?;
    let batch = NodeOutboxBatch::decode(batch_value.value().ok_or(NodeCoreError::OutboxNotFound)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
    let mut delivery = NodeOutboxDelivery::decode(
        delivery_value
            .value()
            .ok_or(NodeCoreError::OutboxNotFound)?,
    )
    .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
    validate_outbox_identity(request_id, &batch, &delivery)?;

    let index = usize::try_from(delivery.next_index)
        .map_err(|_| NodeCoreError::OutboxArithmeticOverflow)?;
    if index > batch.messages.len() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox cursor exceeds batch length",
        ));
    }
    if index == batch.messages.len() {
        return Ok(None);
    }
    if let Some((_, expires_at)) = delivery.lease
        && expires_at > now_unix_millis
    {
        return Err(NodeCoreError::OutboxLeaseActive {
            expires_at_unix_millis: expires_at,
        });
    }

    let expires_at_unix_millis = now_unix_millis
        .checked_add(lease_duration_millis)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    delivery.attempts = delivery
        .attempts
        .checked_add(1)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    delivery.lease = Some((lease_id, expires_at_unix_millis));
    let reads = vec![
        StateReadAssertion::new(batch_key, batch_value.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery_value.revision())?,
    ];
    let mutations = vec![StateMutationEntry::new(
        delivery_key,
        StateMutation::Put(delivery.encode()?),
    )?];
    if !matches!(commit(reads, mutations)?, AtomicStateWriteResult::Committed) {
        return Err(NodeCoreError::StateConflict);
    }

    Ok(Some(OutboxClaim {
        request_id,
        index: delivery.next_index,
        lease_id,
        expires_at_unix_millis,
        message: batch.messages[index].clone(),
    }))
}

/// Atomically leases the next pending message from one persisted outbox batch.
///
/// Expired leases may be replaced, intentionally providing at-least-once
/// delivery. The immutable batch revision is asserted in the same transaction.
pub fn claim_next_outbox_message<S>(
    store: &S,
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    S: TransactionalStateStore,
{
    claim_next_outbox_message_inner(
        layout,
        request_id,
        lease_id,
        now_unix_millis,
        lease_duration_millis,
        |key| store.get_versioned(key),
        |reads, mutations| commit_legacy_transaction_parts(store, reads, mutations),
    )
}

/// Atomically leases one pending outbox message inside an explicit domain.
pub fn claim_next_outbox_message_in_domain<S>(
    store: &S,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    request_id: RequestId,
    lease_id: OutboxLeaseId,
    now_unix_millis: u64,
    lease_duration_millis: u64,
) -> Result<Option<OutboxClaim>, NodeCoreError>
where
    S: DomainTransactionalStateStore,
{
    claim_next_outbox_message_inner(
        layout,
        request_id,
        lease_id,
        now_unix_millis,
        lease_duration_millis,
        |key| store.get_versioned_in_domain(domain, key),
        |reads, mutations| {
            let transaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(reads)?,
                AtomicStateMutationSet::new(mutations)?,
            )?;
            Ok(store.commit_transaction(transaction)?)
        },
    )
}

fn acknowledge_outbox_message_inner<G, C>(
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
    mut get_versioned: G,
    commit: C,
) -> Result<(), NodeCoreError>
where
    G: FnMut(&[u8]) -> Result<VersionedStateValue, RuntimeError>,
    C: FnOnce(
        Vec<StateReadAssertion>,
        Vec<StateMutationEntry>,
    ) -> Result<AtomicStateWriteResult, NodeCoreError>,
{
    let request_bytes = *request_id.as_bytes();
    let batch_key = layout.outbox_batch_key(request_bytes);
    let delivery_key = layout.outbox_delivery_key(request_bytes);
    let batch_value = get_versioned(&batch_key)?;
    let delivery_value = get_versioned(&delivery_key)?;
    let batch = NodeOutboxBatch::decode(batch_value.value().ok_or(NodeCoreError::OutboxNotFound)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox batch"))?;
    let mut delivery = NodeOutboxDelivery::decode(
        delivery_value
            .value()
            .ok_or(NodeCoreError::OutboxNotFound)?,
    )
    .map_err(|_| NodeCoreError::PersistenceInvariant("invalid outbox delivery state"))?;
    validate_outbox_identity(request_id, &batch, &delivery)?;

    if delivery.next_index != index {
        return Err(NodeCoreError::OutboxIndexMismatch);
    }
    if delivery.lease.map(|(active, _)| active) != Some(lease_id) {
        return Err(NodeCoreError::OutboxLeaseMismatch);
    }
    let next_index = index
        .checked_add(1)
        .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    let next_index_usize =
        usize::try_from(next_index).map_err(|_| NodeCoreError::OutboxArithmeticOverflow)?;
    if next_index_usize > batch.messages.len() {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox acknowledgement exceeds batch length",
        ));
    }
    delivery.next_index = next_index;
    delivery.lease = None;

    let reads = vec![
        StateReadAssertion::new(batch_key, batch_value.revision())?,
        StateReadAssertion::new(delivery_key.clone(), delivery_value.revision())?,
    ];
    let mutations = vec![StateMutationEntry::new(
        delivery_key,
        StateMutation::Put(delivery.encode()?),
    )?];
    match commit(reads, mutations)? {
        AtomicStateWriteResult::Committed => Ok(()),
        AtomicStateWriteResult::Conflict { .. } => Err(NodeCoreError::StateConflict),
    }
}

/// Acknowledges one leased message and advances the durable delivery cursor.
///
/// A send followed by a crash before this commit is deliberately redelivered.
pub fn acknowledge_outbox_message<S>(
    store: &S,
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
) -> Result<(), NodeCoreError>
where
    S: TransactionalStateStore,
{
    acknowledge_outbox_message_inner(
        layout,
        request_id,
        index,
        lease_id,
        |key| store.get_versioned(key),
        |reads, mutations| commit_legacy_transaction_parts(store, reads, mutations),
    )
}

/// Acknowledges one leased message inside an explicit atomicity domain.
pub fn acknowledge_outbox_message_in_domain<S>(
    store: &S,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    request_id: RequestId,
    index: u32,
    lease_id: OutboxLeaseId,
) -> Result<(), NodeCoreError>
where
    S: DomainTransactionalStateStore,
{
    acknowledge_outbox_message_inner(
        layout,
        request_id,
        index,
        lease_id,
        |key| store.get_versioned_in_domain(domain, key),
        |reads, mutations| {
            let transaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(reads)?,
                AtomicStateMutationSet::new(mutations)?,
            )?;
            Ok(store.commit_transaction(transaction)?)
        },
    )
}

fn validate_outbox_identity(
    request_id: RequestId,
    batch: &NodeOutboxBatch,
    delivery: &NodeOutboxDelivery,
) -> Result<(), NodeCoreError> {
    if batch.request_id != request_id
        || delivery.request_id != request_id
        || batch.event_digest != delivery.event_digest
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "outbox batch and delivery identities differ",
        ));
    }
    Ok(())
}

/// Handles exactly one event and atomically persists its deterministic transition.
///
/// Outputs are returned only after compare-and-swap succeeds. The caller may then
/// sign or deliver them. A conflict is surfaced to the adapter; node-core never
/// retries because retry policy and invocation budgets belong to the adapter.
pub fn handle_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    M: NodeStateMachine,
{
    validate_generic_event(&event, config)?;
    let current = runtime.state_store().get(config.state_key())?;
    if let Some(bytes) = &current {
        validate_state(bytes)?;
    }

    let transition = machine.transition(current.as_deref(), &event)?;
    validate_output_context(&transition.output, &event, config)?;

    let result = runtime.state_store().compare_and_swap(
        config.state_key.clone(),
        current,
        transition.next_state,
    )?;
    if !result.swapped {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(transition.output)
}

fn validate_output_context(
    output: &NodeOutput,
    event: &NodeEvent,
    config: &NodeConfig,
) -> Result<(), NodeCoreError> {
    validate_output_event_context(output, event)?;
    for message in output.outbound_messages() {
        message.event().validate_context(config)?;
    }
    Ok(())
}

fn validate_output_event_context(
    output: &NodeOutput,
    event: &NodeEvent,
) -> Result<(), NodeCoreError> {
    for response in output.responses() {
        if response.request_id() != event.request_id() {
            return Err(NodeCoreError::ResponseRequestMismatch {
                expected: event.request_id(),
                actual: response.request_id(),
            });
        }
    }
    for message in output.outbound_messages() {
        let outbound = message.event();
        if outbound.chain_id() != event.chain_id() {
            return Err(NodeCoreError::ChainMismatch {
                expected: event.chain_id().clone(),
                actual: outbound.chain_id().clone(),
            });
        }
        if outbound.protocol_version() != event.protocol_version() {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: event.protocol_version(),
                actual: outbound.protocol_version(),
            });
        }
        if outbound.epoch() != event.epoch() {
            return Err(NodeCoreError::EpochMismatch {
                expected: event.epoch(),
                actual: outbound.epoch(),
            });
        }
    }
    Ok(())
}

fn validate_chain_id(chain_id: &ChainId) -> Result<(), NodeCoreError> {
    let length = chain_id.as_str().len();
    if length > MAX_CHAIN_ID_BYTES {
        return Err(NodeCoreError::ChainIdTooLong(length));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), NodeCoreError> {
    if payload.len() > MAX_NODE_PAYLOAD_BYTES {
        return Err(NodeCoreError::PayloadTooLarge(payload.len()));
    }
    decode_canonical_frame(payload)?;
    Ok(())
}

fn validate_state(state: &[u8]) -> Result<(), NodeCoreError> {
    if state.len() > MAX_NODE_STATE_BYTES {
        return Err(NodeCoreError::StateTooLarge(state.len()));
    }
    decode_canonical_frame(state)?;
    Ok(())
}

fn validate_transactional_state_key(key: &[u8]) -> Result<(), NodeCoreError> {
    if key.is_empty() {
        return Err(NodeCoreError::EmptyStateKey);
    }
    if key.len() > MAX_STATE_KEY_BYTES {
        return Err(NodeCoreError::Runtime(RuntimeError::StateKeyTooLong {
            length: key.len(),
            maximum: MAX_STATE_KEY_BYTES,
        }));
    }
    Ok(())
}

fn decode_request_id(bytes: &[u8]) -> Result<RequestId, NodeCoreError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeCoreError::InvalidRequestIdLength(bytes.len()))?;
    RequestId::new(array)
}

fn decode_digest(algorithm: u16, bytes: &[u8]) -> Result<Digest32, NodeCoreError> {
    let algorithm =
        HashAlgorithmId::try_from(algorithm).map_err(NodeCoreError::InvalidHashAlgorithm)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NodeCoreError::InvalidDigestLength(bytes.len()))?;
    Ok(Digest32::new(algorithm, bytes))
}

fn bounded_nested_count(count: u32, collection: &'static str) -> Result<usize, NodeCoreError> {
    let count = usize::try_from(count).map_err(|_| NodeCoreError::TooManyOutputItems {
        collection,
        count: usize::MAX,
    })?;
    if count > MAX_NODE_OUTPUT_ITEMS {
        return Err(NodeCoreError::TooManyOutputItems { collection, count });
    }
    Ok(count)
}

fn encode_nested_items(items: Vec<Vec<u8>>) -> Result<Vec<u8>, NodeCoreError> {
    let capacity = items.iter().try_fold(0_usize, |total, item| {
        total.checked_add(4)?.checked_add(item.len())
    });
    let capacity = capacity.ok_or(NodeCoreError::StateTooLarge(usize::MAX))?;
    if capacity > MAX_NODE_STATE_BYTES {
        return Err(NodeCoreError::StateTooLarge(capacity));
    }

    let mut encoded = Vec::with_capacity(capacity);
    for item in items {
        let length = u32::try_from(item.len())
            .map_err(|_| NodeCoreError::NestedItemLengthOverflow(item.len()))?;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&item);
    }
    Ok(encoded)
}

fn decode_nested_items<T, F>(
    bytes: &[u8],
    count: usize,
    mut decode: F,
) -> Result<Vec<T>, NodeCoreError>
where
    F: FnMut(&[u8]) -> Result<T, NodeCoreError>,
{
    let mut offset = 0_usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let length_bytes = take_nested_bytes(bytes, &mut offset, 4)?;
        let length = usize::try_from(u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]))
        .map_err(|_| NodeCoreError::NestedItemLengthOverflow(usize::MAX))?;
        items.push(decode(take_nested_bytes(bytes, &mut offset, length)?)?);
    }
    if offset != bytes.len() {
        return Err(NodeCoreError::TrailingNestedListBytes(bytes.len() - offset));
    }
    Ok(items)
}

fn take_nested_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], NodeCoreError> {
    let end = offset
        .checked_add(length)
        .ok_or(NodeCoreError::NestedItemLengthOverflow(usize::MAX))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(CanonicalDecodingError::Truncated {
            offset: *offset,
            needed: length,
            remaining: bytes.len().saturating_sub(*offset),
        })?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashSuite, HashSuiteSchedule};
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, MemoryRuntime, StateRevision, StateStore,
        StorageCorrelationId, StorageDeadline, TransactionalStateStore, WriterFenceGeneration,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    const TEST_STATE_TYPE_ID: u16 = 0xEF01;
    const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF02;

    fn canonical(type_id: u16, value: u64) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(type_id, 1);
        frame.field_u64(1, value).unwrap();
        frame.finish().unwrap()
    }

    fn request(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    fn domain(byte: u8) -> AtomicityDomainId {
        AtomicityDomainId::new([byte; 32]).unwrap()
    }

    fn placement(byte: u8, activation_epoch: u64) -> DomainPlacementManifest {
        DomainPlacementManifest::single_domain(1, domain(byte), Epoch::new(activation_epoch))
            .unwrap()
    }

    fn durable_context() -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(1).unwrap(),
            StorageDeadline::new(10_000).unwrap(),
            StorageCorrelationId::new([0xA5; 16]).unwrap(),
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn event(chain: &str, request_id: RequestId) -> NodeEvent {
        event_value(chain, request_id, 9)
    }

    fn submit_event(chain: &str, request_id: RequestId) -> NodeEvent {
        NodeEvent::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap()
    }

    fn event_value(chain: &str, request_id: RequestId, value: u64) -> NodeEvent {
        NodeEvent::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            NodeEventKind::ReceiveVote,
            canonical(TEST_PAYLOAD_TYPE_ID, value),
        )
        .unwrap()
    }

    fn config(chain: &str) -> NodeConfig {
        NodeConfig::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            b"node/state".to_vec(),
        )
        .unwrap()
    }

    fn resolver(chain: &str) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    struct IncrementMachine;

    impl NodeStateMachine for IncrementMachine {
        fn transition(
            &self,
            current_state: Option<&[u8]>,
            event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let value = match current_state {
                Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
                None => 0,
            };
            let next = value
                .checked_add(1)
                .ok_or(NodeCoreError::TransitionRejected("test counter overflow"))?;
            let response = NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
            )?;
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, next),
                NodeOutput::new(vec![response], Vec::new())?,
            )
        }
    }

    #[test]
    fn event_round_trip_has_stable_encoding() {
        let event = submit_event("sunrise-test", request(0x11));
        let encoded = event.encode().unwrap();
        let decoded = NodeEvent::decode(&encoded).unwrap();

        assert_eq!(decoded, event);
        assert_eq!(
            hex(&encoded),
            "534e524501e00100060001000c00000073756e726973652d7465737402000400000003000000\
             03000800000007000000000000000400200000001111111111111111111111111111111111111111\
             1111111111111111111111110500020000000100060018000000534e524502ef0100010001000800\
             00000900000000000000"
                .replace(' ', "")
        );
    }

    #[test]
    fn node_event_digest_is_stable_and_context_bound() {
        let event = submit_event("sunrise-test", request(0x12));
        let digest = event.digest(&resolver("sunrise-test")).unwrap();

        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
        assert_eq!(
            hex(&digest.bytes()),
            "657a106559c95a487c1bf33c245d6eded71706b4d4921fd9b938552b5e1aa281"
        );
        assert!(matches!(
            event.digest(&resolver("other-chain")),
            Err(NodeCoreError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn dedup_and_outbox_records_have_stable_canonical_vectors() {
        let request_id = request(0x21);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
        let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
        let dedup = NodeDedupRecord::new(request_id, digest, vec![response]).unwrap();
        let dedup_bytes = dedup.encode().unwrap();
        assert_eq!(NodeDedupRecord::decode(&dedup_bytes).unwrap(), dedup);
        assert_eq!(
            hex(&dedup_bytes),
            concat!(
                "534e524503e001000500010020000000",
                "2121212121212121212121212121212121212121212121212121212121212121",
                "0200020000000100",
                "0300200000002222222222222222222222222222222222222222222222222222222222222222",
                "04000400000001000000",
                "05003c00000038000000534e524502e001000200010020000000",
                "2121212121212121212121212121212121212121212121212121212121212121",
                "0200020000000100"
            )
        );

        let outbox = NodeOutboxBatch::new(request_id, digest, Vec::new()).unwrap();
        let outbox_bytes = outbox.encode().unwrap();
        assert_eq!(NodeOutboxBatch::decode(&outbox_bytes).unwrap(), outbox);
        assert_eq!(
            hex(&outbox_bytes),
            concat!(
                "534e524504e001000500010020000000",
                "2121212121212121212121212121212121212121212121212121212121212121",
                "0200020000000100",
                "0300200000002222222222222222222222222222222222222222222222222222222222222222",
                "04000400000000000000",
                "050000000000"
            )
        );

        let delivery = NodeOutboxDelivery::pending(request_id, digest);
        let delivery_bytes = delivery.encode().unwrap();
        assert_eq!(
            NodeOutboxDelivery::decode(&delivery_bytes).unwrap(),
            delivery
        );
        assert_eq!(
            hex(&delivery_bytes),
            concat!(
                "534e524505e001000500010020000000",
                "2121212121212121212121212121212121212121212121212121212121212121",
                "0200020000000100",
                "0300200000002222222222222222222222222222222222222222222222222222222222222222",
                "04000400000000000000",
                "05000400000000000000"
            )
        );
    }

    #[test]
    fn event_decode_rejects_unknown_kind_and_schema_fields() {
        let payload = canonical(TEST_PAYLOAD_TYPE_ID, 1);
        let mut unknown_kind = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        unknown_kind.field_str(1, "sunrise-test").unwrap();
        unknown_kind.field_u32(2, 3).unwrap();
        unknown_kind.field_u64(3, 7).unwrap();
        unknown_kind.field_bytes(4, [0x22; 32]).unwrap();
        unknown_kind.field_u16(5, 0xFFFF).unwrap();
        unknown_kind.field_bytes(6, payload.clone()).unwrap();
        assert_eq!(
            NodeEvent::decode(&unknown_kind.finish().unwrap()).unwrap_err(),
            NodeCoreError::UnknownEventKind(0xFFFF)
        );

        let mut extra_field = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        extra_field.field_str(1, "sunrise-test").unwrap();
        extra_field.field_u32(2, 3).unwrap();
        extra_field.field_u64(3, 7).unwrap();
        extra_field.field_bytes(4, [0x22; 32]).unwrap();
        extra_field.field_u16(5, 1).unwrap();
        extra_field.field_bytes(6, payload).unwrap();
        extra_field.field_u16(7, 0).unwrap();
        assert!(matches!(
            NodeEvent::decode(&extra_field.finish().unwrap()),
            Err(NodeCoreError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(7)
            ))
        ));
    }

    #[test]
    fn event_requires_non_zero_request_and_canonical_payload() {
        assert_eq!(RequestId::new([0; 32]), Err(NodeCoreError::ZeroRequestId));
        assert!(matches!(
            NodeEvent::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3),
                Epoch::new(7),
                request(1),
                NodeEventKind::Tick,
                vec![1, 2, 3],
            ),
            Err(NodeCoreError::CanonicalDecoding(_))
        ));
    }

    #[test]
    fn response_round_trip_preserves_optional_payload() {
        let response = NodeResponse::new(
            request(0x21),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, 42)),
        )
        .unwrap();
        let encoded = response.encode().unwrap();

        assert_eq!(NodeResponse::decode(&encoded).unwrap(), response);
        assert_eq!(
            hex(&encoded),
            "534e524502e001000300010020000000212121212121212121212121212121212121212121212121\
             21212121212121210200020000000100030018000000534e524502ef010001000100080000002a00\
             000000000000"
                .replace(' ', "")
        );

        let empty = NodeResponse::new(request(0x22), NodeResponseStatus::Rejected, None).unwrap();
        assert_eq!(
            NodeResponse::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn handle_event_persists_before_returning_output() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        let event = event("sunrise-test", request(0x33));

        let output = handle_event(&runtime, &config, event, &IncrementMachine).unwrap();
        let persisted = runtime
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();

        assert_eq!(
            decode_canonical_frame(&persisted).unwrap().required_u64(1),
            Ok(1)
        );
        assert_eq!(output.responses().len(), 1);
        assert!(output.outbound_messages().is_empty());
    }

    #[test]
    fn generic_handler_rejects_submit_before_transition_or_storage() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        let error = handle_event(
            &runtime,
            &config,
            submit_event("sunrise-test", request(0x34)),
            &IncrementMachine,
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::UnauthenticatedTransactionSubmission);
        assert_eq!(runtime.state_store().get(config.state_key()).unwrap(), None);
    }

    #[test]
    fn wrong_context_is_rejected_before_transition() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("expected-chain"),
            event("other-chain", request(0x55)),
            &IncrementMachine,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }

    struct ConflictingMachine<'a> {
        runtime: &'a MemoryRuntime,
        state_key: Vec<u8>,
    }

    impl NodeStateMachine for ConflictingMachine<'_> {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            self.runtime
                .state_store()
                .put(self.state_key.clone(), canonical(TEST_STATE_TYPE_ID, 99))?;
            NodeTransition::new(canonical(TEST_STATE_TYPE_ID, 1), NodeOutput::default())
        }
    }

    #[test]
    fn compare_and_swap_conflict_discards_transition_output() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        runtime
            .state_store()
            .put(
                config.state_key().to_vec(),
                canonical(TEST_STATE_TYPE_ID, 0),
            )
            .unwrap();
        let machine = ConflictingMachine {
            runtime: &runtime,
            state_key: config.state_key().to_vec(),
        };

        let error = handle_event(
            &runtime,
            &config,
            event("sunrise-test", request(0x66)),
            &machine,
        )
        .unwrap_err();
        let persisted = runtime
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();

        assert_eq!(error, NodeCoreError::StateConflict);
        assert_eq!(
            decode_canonical_frame(&persisted).unwrap().required_u64(1),
            Ok(99)
        );
    }

    struct MultiKeyMachine;

    impl TransactionalNodeStateMachine for MultiKeyMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![
                NodeStateAccess::new(b"state/b".to_vec(), NodeStateAccessMode::ReadWrite)?,
                NodeStateAccess::new(b"state/a".to_vec(), NodeStateAccessMode::ReadWrite)?,
            ])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            _event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let value = |key: &[u8]| -> Result<u64, NodeCoreError> {
                match state.get(key).and_then(VersionedStateValue::value) {
                    Some(bytes) => Ok(decode_canonical_frame(bytes)?.required_u64(1)?),
                    None => Ok(0),
                }
            };
            TransactionalNodeTransition::new(
                vec![
                    NodeStateUpdate::put(
                        b"state/b".to_vec(),
                        canonical(TEST_STATE_TYPE_ID, value(b"state/b")? + 2),
                    )?,
                    NodeStateUpdate::put(
                        b"state/a".to_vec(),
                        canonical(TEST_STATE_TYPE_ID, value(b"state/a")? + 1),
                    )?,
                ],
                NodeOutput::default(),
            )
        }
    }

    #[test]
    fn transactional_handler_commits_declared_multi_key_transition() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        handle_transactional_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x67)),
            &MultiKeyMachine,
        )
        .unwrap();

        let a = runtime.state_store().get(b"state/a").unwrap().unwrap();
        let b = runtime.state_store().get(b"state/b").unwrap().unwrap();
        assert_eq!(decode_canonical_frame(&a).unwrap().required_u64(1), Ok(1));
        assert_eq!(decode_canonical_frame(&b).unwrap().required_u64(1), Ok(2));
        assert_eq!(
            runtime
                .state_store()
                .get_versioned(b"state/a")
                .unwrap()
                .revision(),
            StateRevision::new(1)
        );
    }

    #[test]
    fn domain_transactional_handler_isolates_identical_keys() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let first_domain = domain(0xA1);
        let second_domain = domain(0xA2);
        handle_domain_transactional_event(
            &runtime,
            first_domain,
            &config("sunrise-test"),
            event("sunrise-test", request(0x81)),
            &MultiKeyMachine,
        )
        .unwrap();

        let first = runtime
            .state_store()
            .get_versioned_in_domain(first_domain, b"state/a")
            .unwrap();
        let second = runtime
            .state_store()
            .get_versioned_in_domain(second_domain, b"state/a")
            .unwrap();
        assert_eq!(
            decode_canonical_frame(first.value().unwrap())
                .unwrap()
                .required_u64(1),
            Ok(1)
        );
        assert_eq!(
            second,
            VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
        );
        assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
    }

    struct CountingPlanMachine {
        access_plans: AtomicUsize,
    }

    impl TransactionalNodeStateMachine for CountingPlanMachine {
        fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            self.access_plans.fetch_add(1, Ordering::SeqCst);
            MultiKeyMachine.access_plan(event)
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            MultiKeyMachine.transition(state, event)
        }
    }

    #[test]
    fn resolved_transactional_handler_derives_the_access_plan_once() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = CountingPlanMachine {
            access_plans: AtomicUsize::new(0),
        };
        let result = handle_resolved_transactional_event(
            &runtime,
            &placement(0xA3, 7),
            &config("sunrise-test"),
            event("sunrise-test", request(0x87)),
            &machine,
        )
        .unwrap();

        assert_eq!(machine.access_plans.load(Ordering::SeqCst), 1);
        assert_eq!(result.domain(), domain(0xA3));
        assert!(result.output().responses().is_empty());
        assert!(
            runtime
                .state_store()
                .get_versioned_in_domain(result.domain(), b"state/a")
                .unwrap()
                .value()
                .is_some()
        );
    }

    struct IdempotentMachine {
        calls: AtomicUsize,
    }

    impl TransactionalNodeStateMachine for IdempotentMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/idempotent".to_vec(),
                NodeStateAccessMode::ReadWrite,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let current = match state
                .get(b"state/idempotent")
                .and_then(VersionedStateValue::value)
            {
                Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
                None => 0,
            };
            let next = current + 1;
            let response = NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
            )?;
            let outbound = OutboundMessage::new(NodeEvent::new(
                event.chain_id().clone(),
                event.protocol_version(),
                event.epoch(),
                request(0xFE),
                NodeEventKind::Tick,
                canonical(TEST_PAYLOAD_TYPE_ID, next),
            )?);
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    b"state/idempotent".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, next),
                )?],
                NodeOutput::new(vec![response], vec![outbound])?,
            )
        }
    }

    struct ScriptedDurableStore {
        receipt: Mutex<Option<DurableRequestReceipt>>,
        commits: Mutex<Vec<DurableInvocationTransaction>>,
        state_reads: AtomicUsize,
        commit_outcome: DurableCommitOutcome,
    }

    impl ScriptedDurableStore {
        fn new(commit_outcome: DurableCommitOutcome) -> Self {
            Self {
                receipt: Mutex::new(None),
                commits: Mutex::new(Vec::new()),
                state_reads: AtomicUsize::new(0),
                commit_outcome,
            }
        }
    }

    impl DurableDomainStateStore for ScriptedDurableStore {
        fn get_versioned_durable(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            _key: &[u8],
        ) -> Result<VersionedStateValue, DurableReadError> {
            self.state_reads.fetch_add(1, Ordering::SeqCst);
            VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                .map_err(DurableReadError::InvalidRequest)
        }

        fn commit_durable(
            &self,
            _context: &DurableOperationContext,
            _transaction: AtomicStateTransaction,
        ) -> DurableCommitOutcome {
            DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
        }
    }

    impl StructuredDurableDomainStateStore for ScriptedDurableStore {
        fn get_request_receipt(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            _request_id: DurableRequestId,
        ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
            Ok(self.receipt.lock().unwrap().clone())
        }

        fn commit_invocation(
            &self,
            _context: &DurableOperationContext,
            transaction: DurableInvocationTransaction,
        ) -> DurableCommitOutcome {
            self.commits.lock().unwrap().push(transaction);
            self.commit_outcome.clone()
        }
    }

    #[test]
    fn durable_idempotent_handler_builds_typed_sections_and_replays_receipt() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let input = event("sunrise-test", request(0x91));
        let resolver = resolver("sunrise-test");
        let first = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC1, 7),
            &config("sunrise-test"),
            &resolver,
            input.clone(),
            &machine,
        )
        .unwrap();

        assert_eq!(first.domain(), domain(0xC1));
        assert_eq!(first.output().outbound_messages().len(), 1);
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        let commits = store.commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        let invocation = &commits[0];
        let state = invocation.state().unwrap();
        assert_eq!(state.domain(), domain(0xC1));
        assert_eq!(state.reads().len(), 1);
        assert_eq!(state.mutations().len(), 1);
        assert!(invocation.objects().is_empty());
        let receipt = invocation.receipt().clone();
        assert_eq!(
            NodeDedupRecord::decode(receipt.canonical_bytes())
                .unwrap()
                .responses()
                .len(),
            1
        );
        let outbox = invocation.outbox().unwrap();
        assert_eq!(outbox.messages().len(), 1);
        let outbound_event = NodeEvent::decode(outbox.messages()[0].canonical_payload()).unwrap();
        assert_eq!(
            outbox.messages()[0].payload_digest(),
            outbound_event.digest(&resolver).unwrap()
        );
        drop(commits);

        store.receipt.lock().unwrap().replace(receipt);
        let replay = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC1, 7),
            &config("sunrise-test"),
            &resolver,
            input.clone(),
            &machine,
        )
        .unwrap();
        assert_eq!(replay.output().responses(), first.output().responses());
        assert!(replay.output().outbound_messages().is_empty());
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 1);
        assert_eq!(store.commits.lock().unwrap().len(), 1);

        assert_eq!(
            handle_resolved_durable_idempotent_event(
                &store,
                &durable_context(),
                &placement(0xC1, 7),
                &config("sunrise-test"),
                &resolver,
                event_value("sunrise-test", request(0x91), 10),
                &machine,
            ),
            Err(NodeCoreError::RequestIdReuse)
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn durable_idempotent_handler_conforms_against_memory_store() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let input = event("sunrise-test", request(0x93));
        let context = durable_context();
        let first = handle_resolved_durable_idempotent_event(
            &store,
            &context,
            &placement(0xC3, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            input.clone(),
            &machine,
        )
        .unwrap();
        let replay = handle_resolved_durable_idempotent_event(
            &store,
            &context,
            &placement(0xC3, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            input,
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.output().responses(), replay.output().responses());
        assert!(replay.output().outbound_messages().is_empty());
        let persisted = store
            .get_versioned_durable(&context, domain(0xC3), b"state/idempotent")
            .unwrap();
        assert_eq!(persisted.revision(), StateRevision::new(1));
        assert_eq!(
            decode_canonical_frame(persisted.value().unwrap())
                .unwrap()
                .required_u64(1),
            Ok(1)
        );
    }

    struct ReadOnlyMachine;

    impl TransactionalNodeStateMachine for ReadOnlyMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/read-only".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?))
        }
    }

    #[test]
    fn durable_idempotent_handler_asserts_read_only_state_and_hides_ambiguity() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Indeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ));
        let result = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC2, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event("sunrise-test", request(0x92)),
            &ReadOnlyMachine,
        );

        assert_eq!(
            result,
            Err(NodeCoreError::DurableCommitIndeterminate(
                IndeterminateCommitReason::ConnectionLost
            ))
        );
        let commits = store.commits.lock().unwrap();
        let state = commits[0].state().unwrap();
        assert_eq!(state.reads().len(), 1);
        assert!(state.mutations().is_empty());
        assert!(commits[0].outbox().is_none());
    }

    #[test]
    fn durable_concurrent_receipt_publication_requests_reconciliation_retry() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(
            DurableCommitRejection::RequestAlreadyCommitted,
        ));
        let result = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC2, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event("sunrise-test", request(0x93)),
            &ReadOnlyMachine,
        );

        assert_eq!(result, Err(NodeCoreError::StateConflict));
    }

    #[test]
    fn idempotent_handler_commits_dedup_and_outbox_and_replays_response() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let event = event("sunrise-test", request(0x6B));
        let resolver = resolver("sunrise-test");
        let first = handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
        let replay = handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.responses(), replay.responses());
        assert_eq!(first.outbound_messages().len(), 1);
        assert!(replay.outbound_messages().is_empty());
        let persisted = runtime
            .state_store()
            .get(b"state/idempotent")
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_canonical_frame(&persisted).unwrap().required_u64(1),
            Ok(1)
        );

        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        let dedup = runtime
            .state_store()
            .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
            .unwrap()
            .unwrap();
        let outbox = runtime
            .state_store()
            .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
            .unwrap()
            .unwrap();
        let delivery = runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(
            NodeDedupRecord::decode(&dedup).unwrap().responses().len(),
            1
        );
        assert_eq!(
            NodeOutboxBatch::decode(&outbox).unwrap().messages().len(),
            1
        );
        assert_eq!(
            NodeOutboxDelivery::decode(&delivery).unwrap().next_index(),
            0
        );

        assert_eq!(
            handle_idempotent_event(
                &runtime,
                &config("sunrise-test"),
                &resolver,
                event_value("sunrise-test", request(0x6B), 10),
                &machine,
            ),
            Err(NodeCoreError::RequestIdReuse)
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn domain_idempotent_handler_scopes_state_receipt_and_outbox() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let first_domain = domain(0xB1);
        let second_domain = domain(0xB2);
        let event = event("sunrise-test", request(0x82));
        let resolver = resolver("sunrise-test");

        let first = handle_domain_idempotent_event(
            &runtime,
            first_domain,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
        let replay = handle_domain_idempotent_event(
            &runtime,
            first_domain,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
        handle_domain_idempotent_event(
            &runtime,
            second_domain,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 2);
        assert_eq!(first.responses(), replay.responses());
        assert!(replay.outbound_messages().is_empty());
        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        for active_domain in [first_domain, second_domain] {
            for key in [
                b"state/idempotent".to_vec(),
                layout.request_dedup_key(*event.request_id().as_bytes()),
                layout.outbox_batch_key(*event.request_id().as_bytes()),
                layout.outbox_delivery_key(*event.request_id().as_bytes()),
            ] {
                assert!(
                    runtime
                        .state_store()
                        .get_versioned_in_domain(active_domain, &key)
                        .unwrap()
                        .value()
                        .is_some()
                );
                assert_eq!(runtime.state_store().get(&key).unwrap(), None);
            }
        }
    }

    #[test]
    fn resolved_idempotent_handler_uses_committed_domain_and_returns_it() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let placement = placement(0xB4, 7);
        let event = event("sunrise-test", request(0x85));
        let resolver = resolver("sunrise-test");

        let first = handle_resolved_idempotent_event(
            &runtime,
            &placement,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
        let replay = handle_resolved_idempotent_event(
            &runtime,
            &placement,
            &config("sunrise-test"),
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.domain(), placement.domain());
        assert_eq!(replay.domain(), placement.domain());
        assert_eq!(first.output().responses(), replay.output().responses());
        assert_eq!(first.output().outbound_messages().len(), 1);
        assert!(replay.output().outbound_messages().is_empty());
        assert_eq!(replay.clone().into_output(), replay.output);

        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        assert!(
            claim_next_outbox_message_in_domain(
                runtime.state_store(),
                first.domain(),
                &layout,
                event.request_id(),
                OutboxLeaseId::new([0x45; 32]).unwrap(),
                100,
                10,
            )
            .unwrap()
            .is_some()
        );
        assert_eq!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain(0xB5), b"state/idempotent")
                .unwrap()
                .value(),
            None
        );
    }

    #[test]
    fn resolved_handler_rejects_inactive_manifest_before_transition_or_read() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let event = event("sunrise-test", request(0x86));
        let error = handle_resolved_idempotent_event(
            &runtime,
            &placement(0xB6, 8),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event,
            &machine,
        )
        .unwrap_err();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            error,
            NodeCoreError::ProtocolConfig(ProtocolConfigError::InactiveDomainPlacement {
                activation_epoch: Epoch::new(8),
                event_epoch: Epoch::new(7),
            })
        );
        assert_eq!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain(0xB6), b"state/idempotent")
                .unwrap()
                .value(),
            None
        );
    }

    #[test]
    fn outbox_lease_expiry_redelivers_and_matching_ack_advances_cursor() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let event = event("sunrise-test", request(0x6D));
        handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event.clone(),
            &machine,
        )
        .unwrap();
        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        let first_lease = OutboxLeaseId::new([0x31; 32]).unwrap();
        let second_lease = OutboxLeaseId::new([0x32; 32]).unwrap();
        assert_eq!(
            OutboxLeaseId::new([0; 32]),
            Err(NodeCoreError::ZeroOutboxLeaseId)
        );
        assert_eq!(
            claim_next_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                first_lease,
                100,
                0,
            ),
            Err(NodeCoreError::InvalidOutboxLeaseDuration(0))
        );

        let first = claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            first_lease,
            100,
            10,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(first.expires_at_unix_millis(), 110);
        assert_eq!(
            claim_next_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                second_lease,
                109,
                10,
            ),
            Err(NodeCoreError::OutboxLeaseActive {
                expires_at_unix_millis: 110,
            })
        );

        let redelivered = claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            second_lease,
            110,
            10,
        )
        .unwrap()
        .unwrap();
        assert_eq!(redelivered.index(), first.index());
        assert_eq!(redelivered.message(), first.message());
        assert_eq!(
            acknowledge_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                1,
                second_lease,
            ),
            Err(NodeCoreError::OutboxIndexMismatch)
        );
        assert_eq!(
            acknowledge_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                0,
                first_lease,
            ),
            Err(NodeCoreError::OutboxLeaseMismatch)
        );
        acknowledge_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            0,
            second_lease,
        )
        .unwrap();
        assert_eq!(
            claim_next_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                OutboxLeaseId::new([0x33; 32]).unwrap(),
                121,
                10,
            )
            .unwrap(),
            None
        );

        let delivery = runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
            .unwrap()
            .unwrap();
        let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
        assert_eq!(delivery.next_index(), 1);
        assert_eq!(delivery.attempts(), 2);
        assert_eq!(delivery.lease(), None);
    }

    #[test]
    fn domain_outbox_claim_and_ack_never_cross_domain_boundaries() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let first_domain = domain(0xC1);
        let second_domain = domain(0xC2);
        let event = event("sunrise-test", request(0x84));
        let config = config("sunrise-test");
        let resolver = resolver("sunrise-test");
        for active_domain in [first_domain, second_domain] {
            handle_domain_idempotent_event(
                &runtime,
                active_domain,
                &config,
                &resolver,
                event.clone(),
                &machine,
            )
            .unwrap();
        }
        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        let lease = OutboxLeaseId::new([0x41; 32]).unwrap();
        let claim = claim_next_outbox_message_in_domain(
            runtime.state_store(),
            first_domain,
            &layout,
            event.request_id(),
            lease,
            100,
            10,
        )
        .unwrap()
        .unwrap();
        acknowledge_outbox_message_in_domain(
            runtime.state_store(),
            first_domain,
            &layout,
            event.request_id(),
            claim.index(),
            lease,
        )
        .unwrap();

        assert_eq!(
            claim_next_outbox_message_in_domain(
                runtime.state_store(),
                first_domain,
                &layout,
                event.request_id(),
                OutboxLeaseId::new([0x42; 32]).unwrap(),
                111,
                10,
            )
            .unwrap(),
            None
        );
        let second_claim = claim_next_outbox_message_in_domain(
            runtime.state_store(),
            second_domain,
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x43; 32]).unwrap(),
            111,
            10,
        )
        .unwrap();
        assert!(second_claim.is_some());
        assert_eq!(
            claim_next_outbox_message(
                runtime.state_store(),
                &layout,
                event.request_id(),
                OutboxLeaseId::new([0x44; 32]).unwrap(),
                111,
                10,
            ),
            Err(NodeCoreError::OutboxNotFound)
        );
    }

    #[test]
    fn idempotent_conflict_does_not_publish_dedup_or_outbox_records() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let event = event("sunrise-test", request(0x6C));
        let error = handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event.clone(),
            &TransactionalConflictMachine { runtime: &runtime },
        )
        .unwrap_err();
        assert_eq!(error, NodeCoreError::StateConflict);

        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        assert_eq!(
            runtime
                .state_store()
                .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
                .unwrap(),
            None
        );
        assert_eq!(
            runtime
                .state_store()
                .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
                .unwrap(),
            None
        );
        assert_eq!(
            runtime
                .state_store()
                .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
                .unwrap(),
            None
        );
    }

    struct InvalidAccessMachine {
        plan_mode: NodeStateAccessMode,
        update_key: &'static [u8],
    }

    impl TransactionalNodeStateMachine for InvalidAccessMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/a".to_vec(),
                self.plan_mode,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            _event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    self.update_key.to_vec(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?],
                NodeOutput::default(),
            )
        }
    }

    #[test]
    fn transactional_handler_rejects_undeclared_and_read_only_updates() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let undeclared = handle_transactional_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x68)),
            &InvalidAccessMachine {
                plan_mode: NodeStateAccessMode::ReadWrite,
                update_key: b"state/b",
            },
        );
        assert_eq!(
            undeclared,
            Err(NodeCoreError::UndeclaredStateUpdate(b"state/b".to_vec()))
        );

        let read_only = handle_transactional_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x69)),
            &InvalidAccessMachine {
                plan_mode: NodeStateAccessMode::ReadOnly,
                update_key: b"state/a",
            },
        );
        assert_eq!(
            read_only,
            Err(NodeCoreError::ReadOnlyStateUpdate(b"state/a".to_vec()))
        );
        assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
        assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
    }

    struct TransactionalConflictMachine<'a> {
        runtime: &'a MemoryRuntime,
    }

    impl TransactionalNodeStateMachine for TransactionalConflictMachine<'_> {
        fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            MultiKeyMachine.access_plan(event)
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.runtime
                .state_store()
                .put(b"state/a".to_vec(), canonical(TEST_STATE_TYPE_ID, 99))?;
            MultiKeyMachine.transition(state, event)
        }
    }

    #[test]
    fn transactional_conflict_applies_none_of_the_candidate_updates() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_transactional_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x6A)),
            &TransactionalConflictMachine { runtime: &runtime },
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::StateConflict);
        let a = runtime.state_store().get(b"state/a").unwrap().unwrap();
        assert_eq!(decode_canonical_frame(&a).unwrap().required_u64(1), Ok(99));
        assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
    }

    struct ReadDependencyConflictMachine<'a> {
        runtime: &'a MemoryRuntime,
    }

    impl TransactionalNodeStateMachine for ReadDependencyConflictMachine<'_> {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![
                NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
                NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
            ])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            _event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            assert_eq!(
                state
                    .get(b"state/dependency")
                    .and_then(VersionedStateValue::value),
                None
            );
            self.runtime.state_store().put(
                b"state/dependency".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 99),
            )?;
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    b"state/result".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?],
                NodeOutput::default(),
            )
        }
    }

    #[test]
    fn transactional_handler_asserts_read_only_absence_before_commit() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_transactional_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x7B)),
            &ReadDependencyConflictMachine { runtime: &runtime },
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::StateConflict);
        assert!(
            runtime
                .state_store()
                .get(b"state/dependency")
                .unwrap()
                .is_some()
        );
        assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
    }

    #[test]
    fn idempotent_handler_asserts_read_only_absence_before_commit() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let event = event("sunrise-test", request(0x7C));
        let error = handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event.clone(),
            &ReadDependencyConflictMachine { runtime: &runtime },
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::StateConflict);
        assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        for key in [
            layout.request_dedup_key(*event.request_id().as_bytes()),
            layout.outbox_batch_key(*event.request_id().as_bytes()),
            layout.outbox_delivery_key(*event.request_id().as_bytes()),
        ] {
            assert_eq!(runtime.state_store().get(&key).unwrap(), None);
        }
    }

    struct DomainReadDependencyConflictMachine<'a> {
        runtime: &'a MemoryRuntime,
        domain: AtomicityDomainId,
    }

    impl TransactionalNodeStateMachine for DomainReadDependencyConflictMachine<'_> {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![
                NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
                NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
            ])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            _event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let dependency =
                state
                    .get(b"state/dependency")
                    .ok_or(NodeCoreError::PersistenceInvariant(
                        "dependency missing from snapshot",
                    ))?;
            let competing = AtomicStateTransaction::new(
                self.domain,
                AtomicStateReadSet::new(vec![StateReadAssertion::new(
                    b"state/dependency".to_vec(),
                    dependency.revision(),
                )?])?,
                AtomicStateMutationSet::new(vec![StateMutationEntry::new(
                    b"state/dependency".to_vec(),
                    StateMutation::Put(canonical(TEST_STATE_TYPE_ID, 99)),
                )?])?,
            )?;
            assert_eq!(
                self.runtime.state_store().commit_transaction(competing)?,
                AtomicStateWriteResult::Committed
            );
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    b"state/result".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?],
                NodeOutput::default(),
            )
        }
    }

    #[test]
    fn domain_idempotent_conflict_publishes_neither_result_receipt_nor_outbox() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let domain = domain(0xB3);
        let event = event("sunrise-test", request(0x83));
        let error = handle_domain_idempotent_event(
            &runtime,
            domain,
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event.clone(),
            &DomainReadDependencyConflictMachine {
                runtime: &runtime,
                domain,
            },
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::StateConflict);
        assert!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain, b"state/dependency")
                .unwrap()
                .value()
                .is_some()
        );
        let layout = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        for key in [
            b"state/result".to_vec(),
            layout.request_dedup_key(*event.request_id().as_bytes()),
            layout.outbox_batch_key(*event.request_id().as_bytes()),
            layout.outbox_delivery_key(*event.request_id().as_bytes()),
        ] {
            assert_eq!(
                runtime
                    .state_store()
                    .get_versioned_in_domain(domain, &key)
                    .unwrap()
                    .value(),
                None
            );
        }
    }

    #[test]
    fn transactional_access_and_update_sets_are_bounded_and_unique() {
        let access =
            NodeStateAccess::new(b"state/a".to_vec(), NodeStateAccessMode::ReadWrite).unwrap();
        assert_eq!(
            NodeStateAccessPlan::new(vec![access.clone(), access]),
            Err(NodeCoreError::DuplicateStateAccessKey)
        );
        assert_eq!(
            NodeStateAccessPlan::new(Vec::new()),
            Err(NodeCoreError::EmptyStateAccessPlan)
        );

        let update = NodeStateUpdate::delete(b"state/a".to_vec()).unwrap();
        assert_eq!(
            TransactionalNodeTransition::new(vec![update.clone(), update], NodeOutput::default(),),
            Err(NodeCoreError::DuplicateStateUpdateKey)
        );
        assert_eq!(
            TransactionalNodeTransition::new(Vec::new(), NodeOutput::default()),
            Err(NodeCoreError::EmptyStateUpdates)
        );
    }

    #[test]
    fn response_must_match_event_request() {
        struct WrongResponseMachine;

        impl NodeStateMachine for WrongResponseMachine {
            fn transition(
                &self,
                _current_state: Option<&[u8]>,
                _event: &NodeEvent,
            ) -> Result<NodeTransition, NodeCoreError> {
                let response =
                    NodeResponse::new(request(0x77), NodeResponseStatus::Accepted, None)?;
                NodeTransition::new(
                    canonical(TEST_STATE_TYPE_ID, 1),
                    NodeOutput::new(vec![response], Vec::new())?,
                )
            }
        }

        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x78)),
            &WrongResponseMachine,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::ResponseRequestMismatch { .. }
        ));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }

    #[test]
    fn outbound_event_must_match_invocation_context() {
        struct CrossChainOutputMachine;

        impl NodeStateMachine for CrossChainOutputMachine {
            fn transition(
                &self,
                _current_state: Option<&[u8]>,
                _event: &NodeEvent,
            ) -> Result<NodeTransition, NodeCoreError> {
                let outbound = OutboundMessage::new(event("other-chain", request(0x79)));
                NodeTransition::new(
                    canonical(TEST_STATE_TYPE_ID, 1),
                    NodeOutput::new(Vec::new(), vec![outbound])?,
                )
            }
        }

        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x7A)),
            &CrossChainOutputMachine,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }
}
