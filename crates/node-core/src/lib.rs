#![forbid(unsafe_code)]

//! Deterministic, runtime-neutral ingress and persistence boundary for one node event.
//!
//! The core consumes exactly one bounded canonical event, loads one explicit state
//! value, delegates a pure transition, and conditionally persists the returned
//! state with compare-and-swap. It deliberately does not sign, send, schedule,
//! spawn, retry, or keep process-local protocol state.

use abi::AccessEntry;
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use execution::{
    ExecutionEngine, ExecutionError, ExecutionStatus, Transaction, WasmExecutionEngine,
    encode_execution_effects, hash_transaction,
};
use hashing::{HashSuiteResolver, HashingError};
use objects::{AccessMode, Address, Object, ObjectId, ObjectRef, Owner};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, ProtocolConfigError};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, ProtocolVersion, TypeError,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
    AtomicStateWriteSet, AtomicityDomainId, DomainTransactionalStateStore, DurableCommitOutcome,
    DurableCommitRejection, DurableInlineObject, DurableInvocationError,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectPayload,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableOutboxBatch,
    DurableOutboxMessage, DurableReadError, DurableRequestId, DurableRequestReceipt,
    DurableStateTransaction, IndeterminateCommitReason, MAX_ATOMIC_STATE_READS,
    MAX_ATOMIC_STATE_WRITES, MAX_STATE_KEY_BYTES, PersistenceLayout, Runtime, RuntimeError,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StateStore, StateWrite,
    StructuredDurableDomainStateStore, TransactionalStateStore, VersionedStateValue,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use system_modules::{ModuleId, SystemModule, SystemModuleError};

mod authenticated_object_effects;
mod preinstalled_wasm;
mod query;
pub mod transaction_auth;

use authenticated_object_effects::{
    LoadedAuthenticatedObjects, translate_authenticated_object_effects,
};
use preinstalled_wasm::{
    check_preinstalled_module_gas_limit, normalize_trapped_preinstalled_execution,
    resolve_preinstalled_module,
};

pub use execution::{ObjectEffect, ResolvedObject};
pub use preinstalled_wasm::{
    MAX_PREINSTALLED_MODULE_GAS_LIMIT, MAX_PREINSTALLED_MODULE_WASM_BYTES,
    MAX_PREINSTALLED_MODULES, PreinstalledModuleCatalog, PreinstalledModuleCatalogEntry,
    reconcile_preinstalled_registry_and_catalog,
};
pub use query::{
    ObjectQueryResult, ReceiptQueryResult, query_object, query_request_receipt,
    query_sender_next_nonce,
};
pub use transaction_auth::{
    AuthenticatedTransaction, MAX_TRANSACTION_SIGNABLE_BYTES, TRANSACTION_V1_MESSAGE_TYPE,
    TransactionAuthError, TrustedTransactionContext, authenticate_transaction_bytes,
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
/// Pre-activation cap on authenticated object reads in one invocation.
///
/// Each entry costs two durable round-trips (head then version). Raising this
/// bound requires measured evidence and a decision record; see the PR83
/// design note on the `MAX_TRANSACTION_MANIFEST_ENTRIES`/
/// `MAX_DURABLE_OBJECT_READS` envelope.
const MAX_AUTHENTICATED_OBJECT_READS: usize = 32;
/// Per-object inline body bound applied before any hashing work.
///
/// Pre-activation admission budget, not a measured capacity limit: hashing is
/// attacker-influenced work over up to `MAX_STATE_VALUE_BYTES` (32 MiB) per
/// entry times the `MAX_AUTHENTICATED_OBJECT_READS` fan-out. Raising this
/// bound requires capacity evidence and a decision record.
pub const MAX_AUTHENTICATED_OBJECT_BODY_BYTES: usize = 1024 * 1024;
/// Aggregate inline body budget for one authenticated invocation.
///
/// Pre-activation admission budget: bounds worst-case per-request hashing
/// work to 8 MiB, below the 16 MiB HTTP body limit already accepted by
/// `native-http`. Raising this bound requires capacity evidence and a
/// decision record.
pub const MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES: usize = 8 * 1024 * 1024;

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
    /// A submitted transaction's declared nonce did not match the persisted
    /// next expected nonce for its sender and epoch.
    SenderNonceMismatch {
        /// Sender address bytes.
        sender: [u8; 32],
        /// Persisted next expected nonce.
        expected: u64,
        /// Nonce declared by the submitted transaction.
        actual: u64,
    },
    /// Incrementing a sender's persisted next nonce would overflow.
    SenderNonceOverflow {
        /// Sender address bytes.
        sender: [u8; 32],
    },
    /// A signed object reference named an object absent (or tombstoned) in
    /// the resolved domain.
    ObjectNotFound {
        /// Object identifier that could not be found.
        object_id: ObjectId,
    },
    /// The current object version did not match the signed reference.
    ObjectVersionMismatch {
        /// Object identifier.
        object_id: ObjectId,
        /// Version declared by the signed reference.
        expected: u64,
        /// Version observed on the current head.
        actual: u64,
    },
    /// The current object digest did not match the signed reference.
    ObjectDigestMismatch {
        /// Object identifier.
        object_id: ObjectId,
        /// Digest declared by the signed reference.
        expected: Digest32,
        /// Digest observed on the current head.
        actual: Digest32,
    },
    /// The object's typed owner did not authorize the transaction sender.
    ObjectOwnerMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// A manifest entry requested an access mode this slice cannot honor.
    ObjectAccessModeUnsupported {
        /// Object identifier.
        object_id: ObjectId,
        /// Requested access mode.
        mode: AccessMode,
    },
    /// A manifest entry named a shared or system-owned object.
    ObjectOwnerKindUnsupported {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// A manifest entry resolved to a blob-backed payload this slice cannot read.
    ObjectBodyUnavailable {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// An authenticated transaction declared more object accesses than the
    /// pre-activation resource bound.
    ObjectManifestTooLarge {
        /// Declared access count.
        count: usize,
        /// Maximum accepted access count.
        maximum: usize,
    },
    /// An authenticated transaction's manifest declared the same object twice.
    DuplicateObjectAccess {
        /// Duplicated object identifier.
        object_id: ObjectId,
    },
    /// A manifest entry declared an object version that cannot be non-zero.
    InvalidObjectVersion {
        /// Object identifier.
        object_id: ObjectId,
        /// Declared version.
        version: u64,
    },
    /// Durable storage proved that an object-head assertion no longer
    /// matched and the commit did not apply.
    ObjectConflict {
        /// First conflicting object in canonical identifier order.
        object_id: ObjectId,
    },
    /// A current object head pointed at an immutable version record that
    /// storage does not have.
    ObjectRecordMissing {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// A persisted immutable object-version record disagreed with its own
    /// head, or an inline object disagreed with its own version record.
    ObjectRecordMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// The object's stored digest algorithm is not implemented, so this node
    /// cannot verify the body it was handed.
    ObjectDigestUnverifiable {
        /// Object identifier.
        object_id: ObjectId,
        /// Unimplemented digest algorithm recorded on the stored digest.
        algorithm: HashAlgorithmId,
    },
    /// The stored canonical body does not hash to the digest recorded for it.
    ObjectBodyDigestMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// The version record's creating chain does not match the trusted event chain.
    ObjectProvenanceMismatch {
        /// Object identifier.
        object_id: ObjectId,
    },
    /// One inline body exceeded the pre-activation verification bound.
    ObjectBodyTooLarge {
        /// Object identifier.
        object_id: ObjectId,
        /// Actual inline body length in bytes.
        actual: usize,
        /// Maximum accepted inline body length in bytes.
        maximum: usize,
    },
    /// Deterministic execution returned two effects for the same object.
    DuplicateObjectEffect {
        /// Duplicated object identifier.
        object_id: ObjectId,
    },
    /// Deterministic execution returned more effects than one invocation permits.
    TooManyObjectEffects {
        /// Number of effects supplied by execution.
        actual: usize,
        /// Maximum accepted effects per invocation.
        maximum: usize,
    },
    /// Deterministic execution returned an effect for an undeclared object.
    UndeclaredObjectEffect {
        /// Undeclared object identifier.
        object_id: ObjectId,
    },
    /// A declared object access and its deterministic execution effect disagreed.
    ObjectEffectMismatch {
        /// Object whose declared access and effect disagreed.
        object_id: ObjectId,
        /// Stable, non-secret rejection reason.
        reason: &'static str,
    },
    /// Incrementing an object's immutable version would overflow.
    ObjectVersionOverflow {
        /// Object whose version cannot advance.
        object_id: ObjectId,
    },
    /// Object effects that create a new identity are outside this MVP slice.
    ObjectCreationUnsupported {
        /// Created object identifier.
        object_id: ObjectId,
    },
    /// A mutation effect was supplied without trusted creation context.
    ObjectMutationContextMissing {
        /// Object requiring a new immutable version.
        object_id: ObjectId,
    },
    /// A new immutable object version attempted to move its creation checkpoint backwards.
    ObjectCreatedCheckpointRegression {
        /// Object whose checkpoint would regress.
        object_id: ObjectId,
        /// Checkpoint stored on the previous immutable version.
        previous_created_checkpoint: u64,
        /// Checkpoint proposed for the new immutable version.
        attempted_created_checkpoint: u64,
    },
    /// A governance-installed system-module registry or manifest operation failed.
    SystemModules(SystemModuleError),
    /// Deterministic WASM execution or transaction hashing failed.
    Execution(ExecutionError),
    /// One preinstalled catalog entry's WASM bytes exceeded the bound.
    PreinstalledModuleWasmTooLarge {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Actual WASM byte length.
        actual: usize,
        /// Maximum accepted WASM byte length.
        maximum: usize,
    },
    /// A preinstalled catalog entry's manifest named a different module id.
    PreinstalledModuleManifestIdMismatch {
        /// Module identifier the entry is keyed under.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// A preinstalled catalog declared more module versions than the bound.
    PreinstalledModuleCatalogTooLarge {
        /// Declared entry count.
        count: usize,
        /// Maximum accepted entry count.
        maximum: usize,
    },
    /// A preinstalled catalog declared the same `(module_id, version)` twice.
    DuplicatePreinstalledModule {
        /// Duplicated module identifier.
        module_id: ModuleId,
        /// Duplicated module version.
        version: u64,
    },
    /// `Transaction.module_ref` named a `(module_id, version)` absent from the
    /// committed system-module registry.
    PreinstalledModuleUnknown {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The registered module version exists but is not `Active`.
    PreinstalledModuleInactive {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The registered module version is `Active` but not yet activated at the
    /// transaction's epoch.
    PreinstalledModuleNotYetActive {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Earliest activation epoch.
        activation_epoch: Epoch,
        /// Transaction epoch.
        current_epoch: Epoch,
    },
    /// The registered module version has no matching caller-supplied catalog entry.
    PreinstalledModuleNotCataloged {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// `Transaction.module_ref.digest` disagreed with the registry's committed
    /// `canonical_code_hash`.
    PreinstalledModuleReferenceDigestMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's WASM bytes did not rehash to the registry's
    /// committed `canonical_code_hash`.
    PreinstalledModuleCodeHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's manifest did not rehash to the registry's
    /// committed `manifest_hash`.
    PreinstalledModuleManifestHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The catalog entry's `semantics_hash` disagreed with the registry's
    /// committed `semantics_hash`.
    PreinstalledModuleSemanticsHashMismatch {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
    },
    /// The transaction's `args` exceeded the resolved manifest's
    /// `max_input_size`.
    PreinstalledModuleArgsTooLarge {
        /// Module identifier.
        module_id: ModuleId,
        /// Module version.
        version: u64,
        /// Actual argument byte length.
        actual: u64,
        /// Maximum accepted argument byte length.
        maximum: u64,
    },
    /// The transaction's `gas_limit` exceeded the pre-activation preinstalled
    /// WASM ceiling.
    PreinstalledModuleGasLimitExceedsCeiling {
        /// Requested gas limit.
        requested: u64,
        /// Maximum accepted gas limit.
        maximum: u64,
    },
    /// A preinstalled-WASM call declared zero authenticated object accesses.
    /// This MVP path requires at least one.
    PreinstalledModuleZeroObjectAccess,
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
            Self::SenderNonceMismatch {
                sender,
                expected,
                actual,
            } => write!(
                f,
                "sender {} nonce mismatch: expected {expected}, got {actual}",
                hex32(*sender)
            ),
            Self::SenderNonceOverflow { sender } => {
                write!(f, "sender {} next nonce overflowed", hex32(*sender))
            }
            Self::ObjectNotFound { object_id } => {
                write!(f, "object {object_id} was not found")
            }
            Self::ObjectVersionMismatch {
                object_id,
                expected,
                actual,
            } => write!(
                f,
                "object {object_id} version mismatch: expected {expected}, got {actual}"
            ),
            Self::ObjectDigestMismatch {
                object_id,
                expected,
                actual,
            } => write!(
                f,
                "object {object_id} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ObjectOwnerMismatch { object_id } => {
                write!(f, "object {object_id} owner did not authorize the sender")
            }
            Self::ObjectAccessModeUnsupported { object_id, mode } => write!(
                f,
                "object {object_id} requested unsupported access mode {mode:?}"
            ),
            Self::ObjectOwnerKindUnsupported { object_id } => write!(
                f,
                "object {object_id} owner kind is not supported by this slice"
            ),
            Self::ObjectBodyUnavailable { object_id } => {
                write!(f, "object {object_id} payload is not locally available")
            }
            Self::ObjectManifestTooLarge { count, maximum } => write!(
                f,
                "authenticated object manifest has {count} entries, maximum is {maximum}"
            ),
            Self::DuplicateObjectAccess { object_id } => write!(
                f,
                "authenticated object manifest declared object {object_id} twice"
            ),
            Self::InvalidObjectVersion { object_id, version } => {
                write!(f, "object {object_id} declared invalid version {version}")
            }
            Self::ObjectConflict { object_id } => write!(
                f,
                "object {object_id} head changed before the conditional write"
            ),
            Self::ObjectRecordMissing { object_id } => write!(
                f,
                "object {object_id} head referenced a missing version record"
            ),
            Self::ObjectRecordMismatch { object_id } => write!(
                f,
                "object {object_id} version record disagreed with its head"
            ),
            Self::ObjectDigestUnverifiable {
                object_id,
                algorithm,
            } => write!(
                f,
                "object {object_id} digest algorithm {algorithm} is not implemented by this node"
            ),
            Self::ObjectBodyDigestMismatch { object_id } => write!(
                f,
                "object {object_id} stored body does not hash to its recorded digest"
            ),
            Self::ObjectProvenanceMismatch { object_id } => write!(
                f,
                "object {object_id} version provenance chain does not match the event chain"
            ),
            Self::ObjectBodyTooLarge {
                object_id,
                actual,
                maximum,
            } => write!(
                f,
                "object {object_id} inline body is {actual} bytes, maximum is {maximum}"
            ),
            Self::DuplicateObjectEffect { object_id } => {
                write!(
                    f,
                    "execution returned duplicate effects for object {object_id}"
                )
            }
            Self::TooManyObjectEffects { actual, maximum } => write!(
                f,
                "execution returned {actual} object effects, maximum is {maximum}"
            ),
            Self::UndeclaredObjectEffect { object_id } => {
                write!(
                    f,
                    "execution returned an effect for undeclared object {object_id}"
                )
            }
            Self::ObjectEffectMismatch { object_id, reason } => {
                write!(f, "object {object_id} effect mismatch: {reason}")
            }
            Self::ObjectVersionOverflow { object_id } => {
                write!(f, "object {object_id} version overflowed")
            }
            Self::ObjectCreationUnsupported { object_id } => {
                write!(f, "creating object {object_id} is outside this MVP slice")
            }
            Self::ObjectMutationContextMissing { object_id } => write!(
                f,
                "object {object_id} mutation is missing trusted creation context"
            ),
            Self::ObjectCreatedCheckpointRegression {
                object_id,
                previous_created_checkpoint,
                attempted_created_checkpoint,
            } => write!(
                f,
                "object {object_id} creation checkpoint regressed from {previous_created_checkpoint} to {attempted_created_checkpoint}"
            ),
            Self::SystemModules(error) => write!(f, "system module error: {error}"),
            Self::Execution(error) => write!(f, "execution error: {error}"),
            Self::PreinstalledModuleWasmTooLarge {
                module_id,
                version,
                actual,
                maximum,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} wasm bytes are {actual}, maximum is {maximum}"
            ),
            Self::PreinstalledModuleManifestIdMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} manifest names a different module id"
            ),
            Self::PreinstalledModuleCatalogTooLarge { count, maximum } => write!(
                f,
                "preinstalled module catalog has {count} entries, maximum is {maximum}"
            ),
            Self::DuplicatePreinstalledModule { module_id, version } => write!(
                f,
                "preinstalled module catalog declares {module_id} version {version} twice"
            ),
            Self::PreinstalledModuleUnknown { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is not registered"
            ),
            Self::PreinstalledModuleInactive { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is not active"
            ),
            Self::PreinstalledModuleNotYetActive {
                module_id,
                version,
                activation_epoch,
                current_epoch,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} activates at epoch {}, current epoch is {}",
                activation_epoch.get(),
                current_epoch.get()
            ),
            Self::PreinstalledModuleNotCataloged { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} is registered but not cataloged"
            ),
            Self::PreinstalledModuleReferenceDigestMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} declared digest disagrees with the registry"
            ),
            Self::PreinstalledModuleCodeHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} wasm bytes do not hash to the registered code hash"
            ),
            Self::PreinstalledModuleManifestHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} manifest does not hash to the registered manifest hash"
            ),
            Self::PreinstalledModuleSemanticsHashMismatch { module_id, version } => write!(
                f,
                "preinstalled module {module_id} version {version} semantics hash disagrees with the registry"
            ),
            Self::PreinstalledModuleArgsTooLarge {
                module_id,
                version,
                actual,
                maximum,
            } => write!(
                f,
                "preinstalled module {module_id} version {version} args are {actual} bytes, maximum is {maximum}"
            ),
            Self::PreinstalledModuleGasLimitExceedsCeiling { requested, maximum } => write!(
                f,
                "preinstalled module gas_limit {requested} exceeds the pre-activation ceiling of {maximum}"
            ),
            Self::PreinstalledModuleZeroObjectAccess => write!(
                f,
                "preinstalled module call declared zero authenticated object accesses, at least one is required"
            ),
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
            Self::SystemModules(error) => Some(error),
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SystemModuleError> for NodeCoreError {
    fn from(value: SystemModuleError) -> Self {
        Self::SystemModules(value)
    }
}

impl From<ExecutionError> for NodeCoreError {
    fn from(value: ExecutionError) -> Self {
        Self::Execution(value)
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
/// placement and exact matching system-module record are captured at
/// authentication time so
/// a caller cannot authenticate under one `ProtocolConfig` and later route
/// storage or execute code through different committed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedSubmitTransaction {
    event: NodeEvent,
    transaction: AuthenticatedTransaction,
    placement: DomainPlacementManifest,
    committed_system_module: Option<SystemModule>,
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
/// placement and exact matching system-module record (or its committed absence)
/// for the later durable commit and module resolution.
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
    let module_ref: &ObjectRef = &transaction.transaction().module_ref;
    let module_id: ModuleId = ModuleId::new(*module_ref.id.as_bytes());
    let committed_system_module: Option<SystemModule> = protocol_config
        .system_modules
        .get(module_id, module_ref.version)
        .cloned();
    let placement = protocol_config
        .domain_placement
        .clone()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)?;

    Ok(AuthenticatedSubmitTransaction {
        event,
        transaction,
        placement,
        committed_system_module,
    })
}

/// Sender-nonce enforcement input for one durable submit-transaction
/// invocation.
///
/// The fields are private and there is no public constructor. The only way to
/// obtain a value is [`Self::from_authenticated_transaction`], so a caller can
/// never assert a nonce reservation for a sender or nonce it did not
/// cryptographically authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SenderNonceReservation {
    sender: [u8; 32],
    epoch: Epoch,
    nonce: u64,
}

impl SenderNonceReservation {
    /// Derives the reservation directly from the authenticated inner
    /// transaction's sender, epoch, and declared nonce.
    fn from_authenticated_transaction(transaction: &AuthenticatedTransaction) -> Self {
        let inner = transaction.transaction();
        Self {
            sender: *inner.sender.as_bytes(),
            epoch: inner.epoch,
            nonce: inner.nonce,
        }
    }
}

/// One read-only object access declared by a signed transaction manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedObjectAccess {
    object_ref: ObjectRef,
    mode: AccessMode,
}

/// Authenticated, pre-I/O-validated object dispatch input for one durable
/// submit-transaction invocation.
///
/// The fields are private and there is no public constructor. The only way to
/// obtain a value is [`Self::from_authenticated_transaction`], so a caller can
/// never authorize an object access against an authority or manifest it did
/// not cryptographically authenticate. `accesses` retains the signed manifest
/// declaration order, is deduplicated by [`ObjectId`], and has every entry's
/// version and access mode validated, so later per-entry storage I/O never
/// needs to re-check them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedObjectDispatch {
    authority: Address,
    accesses: Vec<AuthenticatedObjectAccess>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticatedObjectPolicy {
    ReadOnly,
    OwnedMutations { created_checkpoint: u64 },
}

impl AuthenticatedObjectDispatch {
    /// Derives and validates the dispatch descriptor from the authenticated
    /// inner transaction's sender and declared object-access manifest.
    ///
    /// Every check here is pure and requires zero storage I/O: bounding the
    /// declared access count, rejecting a duplicate object identifier without
    /// changing signed declaration order, requiring a non-zero object version,
    /// and enforcing the selected internal access policy. The established
    /// public entrypoint uses read-only policy; only the additive owned-effects
    /// entrypoint enables Write/Consume.
    fn from_authenticated_transaction(
        transaction: &AuthenticatedTransaction,
        policy: AuthenticatedObjectPolicy,
    ) -> Result<Self, NodeCoreError> {
        let inner = transaction.transaction();
        let authority: Address = inner.sender;
        let accesses = validate_object_entries(inner.access_manifest.entries.as_slice(), policy)?;
        Ok(Self {
            authority,
            accesses,
        })
    }
}

/// Pure, zero-I/O validation of one declared object-access manifest.
///
/// Bounds the declared access count, rejects a duplicate object identifier
/// without changing signed declaration order, requires a non-zero object
/// version, and enforces the selected internal access policy.
///
/// Split out of [`AuthenticatedObjectDispatch::from_authenticated_transaction`]
/// so it can be exercised directly with hand-built entries: the authenticated
/// decode path already rejects a duplicate `ObjectId` in
/// [`abi::decode_access_manifest`] before a manifest ever reaches here, so the
/// duplicate defense in this function is otherwise unreachable through the
/// full authenticated submission path.
fn validate_object_entries(
    entries: &[AccessEntry],
    policy: AuthenticatedObjectPolicy,
) -> Result<Vec<AuthenticatedObjectAccess>, NodeCoreError> {
    if entries.len() > MAX_AUTHENTICATED_OBJECT_READS {
        return Err(NodeCoreError::ObjectManifestTooLarge {
            count: entries.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        });
    }

    let accesses: Vec<AuthenticatedObjectAccess> = entries
        .iter()
        .map(|entry: &AccessEntry| AuthenticatedObjectAccess {
            object_ref: entry.object_ref.clone(),
            mode: entry.mode,
        })
        .collect();
    let mut seen_ids: BTreeSet<ObjectId> = BTreeSet::new();
    for access in &accesses {
        if !seen_ids.insert(access.object_ref.id) {
            return Err(NodeCoreError::DuplicateObjectAccess {
                object_id: access.object_ref.id,
            });
        }
    }

    for access in &accesses {
        if DurableObjectVersion::new(access.object_ref.version).is_none() {
            return Err(NodeCoreError::InvalidObjectVersion {
                object_id: access.object_ref.id,
                version: access.object_ref.version,
            });
        }
        if matches!(policy, AuthenticatedObjectPolicy::ReadOnly) && access.mode != AccessMode::Read
        {
            return Err(NodeCoreError::ObjectAccessModeUnsupported {
                object_id: access.object_ref.id,
                mode: access.mode,
            });
        }
    }

    Ok(accesses)
}

const SENDER_NONCE_RECORD_TYPE_ID: u16 = 0xE006;

/// Canonical persisted next-nonce record bound to one exact sender and epoch.
///
/// Binding `sender` and `epoch` inside the record, not only in the derived
/// storage key, lets a reader cross-check the persisted bytes against the
/// key that addressed them and fail closed on a corrupt or misbound record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SenderNonceRecord {
    sender: [u8; 32],
    epoch: Epoch,
    next_nonce: u64,
}

impl SenderNonceRecord {
    fn new(sender: [u8; 32], epoch: Epoch, next_nonce: u64) -> Self {
        Self {
            sender,
            epoch,
            next_nonce,
        }
    }

    /// Encodes the record canonically.
    fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(SENDER_NONCE_RECORD_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.sender.to_vec())?;
        frame.field_u64(2, self.epoch.get())?;
        frame.field_u64(3, self.next_nonce)?;
        Ok(frame.finish()?)
    }

    /// Decodes and strictly validates one persisted next-nonce record.
    fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(SENDER_NONCE_RECORD_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let sender_bytes = frame.required_field(1)?;
        let sender: [u8; 32] =
            sender_bytes
                .try_into()
                .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                    field_id: 1,
                    expected: 32,
                    actual: sender_bytes.len(),
                })?;
        Ok(Self::new(
            sender,
            Epoch::new(frame.required_u64(2)?),
            frame.required_u64(3)?,
        ))
    }
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
    resolved_objects: Vec<ResolvedObject>,
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

    /// Returns authenticated, integrity-checked object inputs in signed
    /// manifest declaration order. Generic event handlers always provide an
    /// empty slice.
    #[must_use]
    pub fn resolved_objects(&self) -> &[ResolvedObject] {
        &self.resolved_objects
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
    object_effects: Vec<ObjectEffect>,
    output: NodeOutput,
    /// `true` only for [`Self::rejected_with_no_object_mutation`]. Every
    /// other constructor leaves this `false`, preserving the existing rule
    /// that a declared `Write`/`Consume` access with no matching effect is a
    /// fail-closed [`NodeCoreError::ObjectEffectMismatch`].
    bypass_object_effect_matching: bool,
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
        Ok(Self {
            updates,
            object_effects: Vec::new(),
            output,
            bypass_object_effect_matching: false,
        })
    }

    /// Creates a bounded transition that also requests deterministic owned-
    /// object mutations on the authenticated transaction path.
    ///
    /// The handler independently validates every effect against the signed
    /// access manifest and verified object versions before atomic commit.
    pub fn with_object_effects(
        mut updates: Vec<NodeStateUpdate>,
        object_effects: Vec<ObjectEffect>,
        output: NodeOutput,
    ) -> Result<Self, NodeCoreError> {
        if updates.is_empty() && object_effects.is_empty() {
            return Err(NodeCoreError::EmptyStateUpdates);
        }
        if updates.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(NodeCoreError::TooManyStateUpdates {
                count: updates.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        if object_effects.len() > MAX_AUTHENTICATED_OBJECT_READS {
            return Err(NodeCoreError::TooManyObjectEffects {
                actual: object_effects.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            });
        }
        updates.sort_by(|left: &NodeStateUpdate, right: &NodeStateUpdate| left.key.cmp(&right.key));
        if updates
            .windows(2)
            .any(|pair: &[NodeStateUpdate]| pair[0].key == pair[1].key)
        {
            return Err(NodeCoreError::DuplicateStateUpdateKey);
        }
        Ok(Self {
            updates,
            object_effects,
            output,
            bypass_object_effect_matching: false,
        })
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
            object_effects: Vec::new(),
            output,
            bypass_object_effect_matching: false,
        }
    }

    /// Creates a transition for a deterministically rejected (e.g. trapped)
    /// execution that must still commit a receipt, sender nonce, and every
    /// already-loaded object's head-read assertion, but produces no object
    /// mutation regardless of any `Write`/`Consume` access the transaction
    /// declared.
    ///
    /// Every other constructor requires an exact one-to-one match between a
    /// declared `Write`/`Consume` access and a returned effect
    /// ([`NodeCoreError::ObjectEffectMismatch`] otherwise). That rule assumes
    /// a machine that always produces effects when it succeeds; it cannot
    /// hold for genuine execution failure, where
    /// [`execution::ExecutionStatus::Failure`] discards every candidate
    /// effect by construction (see `execution::wasm_engine`). This
    /// constructor is the explicit, narrow escape hatch for exactly that
    /// case: it is only used by the preinstalled-WASM composition on a
    /// trapped call, never by a caller that is simply missing an effect it
    /// should have produced.
    #[must_use]
    pub(crate) const fn rejected_with_no_object_mutation(output: NodeOutput) -> Self {
        Self {
            updates: Vec::new(),
            object_effects: Vec::new(),
            output,
            bypass_object_effect_matching: true,
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

    /// Returns deterministic object effects held until the same atomic commit
    /// as state, nonce, receipt, and outbox.
    #[must_use]
    pub fn object_effects(&self) -> &[ObjectEffect] {
        &self.object_effects
    }

    /// Returns `true` only for [`Self::rejected_with_no_object_mutation`].
    #[must_use]
    const fn bypasses_object_effect_matching(&self) -> bool {
        self.bypass_object_effect_matching
    }
}

fn reject_object_effects_without_authenticated_dispatch(
    effects: &[ObjectEffect],
) -> Result<(), NodeCoreError> {
    let mutations: Vec<DurableObjectMutationEntry> =
        translate_authenticated_object_effects(&[], effects, None, 0)?;
    debug_assert!(mutations.is_empty());
    Ok(())
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

fn validate_sender_nonce_namespace(
    plan: &NodeStateAccessPlan,
    layout: &PersistenceLayout,
) -> Result<(), NodeCoreError> {
    let nonce_prefix = layout.sender_nonce_prefix();
    for access in plan.accesses() {
        if access.key().starts_with(nonce_prefix.as_slice()) {
            return Err(NodeCoreError::ReservedStateAccess(access.key().to_vec()));
        }
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
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    validate_sender_nonce_namespace(&plan, &layout)?;
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
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };

    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
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
    let layout = PersistenceLayout::new(config.chain_id.clone(), config.protocol_version);
    validate_sender_nonce_namespace(&plan, &layout)?;
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = runtime.state_store().get_versioned(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };

    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
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
    validate_sender_nonce_namespace(&plan, &layout)?;
    let maximum_application_accesses =
        core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(3);
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
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
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
        store, context, domain, resolver, event, machine, plan, None, None, None,
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
/// Exact duplicates are still authenticated before receipt reconciliation. A
/// fresh request must match the persisted per-sender, per-epoch next nonce; its
/// checked increment commits atomically with the application state, receipt,
/// and outbox. The transaction's signed object-access manifest is loaded and
/// authorized against the same authenticated sender: every declared entry
/// must resolve, through its exact current head and immutable version, to a
/// typed object whose owner is that sender's address or is immutable, and the
/// resulting head-read assertions commit atomically alongside everything
/// else. This established entrypoint remains read-only; `Write`/`Consume`,
/// shared/system owners, and blob payloads fail closed rather than silently
/// downgrade. Use the explicit owned-effects entrypoint for the bounded MVP
/// mutation surface.
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
    handle_authenticated_submit_transaction_with_policy(
        store,
        context,
        resolver,
        submission,
        machine,
        AuthenticatedObjectPolicy::ReadOnly,
    )
}

/// Commits authenticated owned inline-object Write/Consume effects through the
/// same durable invocation as sender nonce, application state, receipt, and
/// outbox.
///
/// `created_checkpoint` is trusted node composition, never request input. The
/// caller must derive it from its already-validated chain progress. Node-core
/// rejects a value lower than the previous immutable object's checkpoint.
/// Create, shared/system ownership, immutable mutations, and blob bodies remain
/// unsupported and fail closed.
pub fn handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects<S, M>(
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    created_checkpoint: u64,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    handle_authenticated_submit_transaction_with_policy(
        store,
        context,
        resolver,
        submission,
        machine,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint },
    )
}

/// The internal `TransactionalNodeStateMachine` behind
/// [`handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`].
///
/// This machine declares no opaque application state key: it is object-only.
/// [`Self::access_plan`] returns the crate-private empty
/// [`NodeStateAccessPlan`] representation directly (bypassing the public
/// [`NodeStateAccessPlan::new`], which still rejects an empty plan for every
/// other caller) instead of asserting a dummy/fake state key purely to
/// satisfy that constructor.
struct PreinstalledWasmMachine<'a> {
    transaction: &'a Transaction,
    resolver: &'a HashSuiteResolver,
    registered_module: Option<&'a SystemModule>,
    catalog: &'a PreinstalledModuleCatalog,
    engine: &'a WasmExecutionEngine,
}

impl TransactionalNodeStateMachine for PreinstalledWasmMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        Ok(NodeStateAccessPlan {
            accesses: Vec::new(),
        })
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let epoch = event.epoch();
        let module = resolve_preinstalled_module(
            &self.transaction.module_ref,
            self.registered_module,
            self.catalog,
            epoch,
            self.resolver,
        )?;
        let max_input_size = module.manifest().max_input_size;
        let args_len = self.transaction.args.len() as u64;
        if args_len > max_input_size {
            return Err(NodeCoreError::PreinstalledModuleArgsTooLarge {
                module_id: module.module_id(),
                version: module.version(),
                actual: args_len,
                maximum: max_input_size,
            });
        }
        check_preinstalled_module_gas_limit(self.transaction.gas_limit)?;

        let tx_hash = hash_transaction(self.transaction, self.resolver)?;
        let effects = self.engine.execute(
            self.transaction.protocol_version,
            tx_hash,
            module.wasm_bytes(),
            &self.transaction.entrypoint,
            state.resolved_objects(),
            &self.transaction.args,
            self.transaction.gas_limit,
        )?;

        // A trap's raw reason/gas accounting is untrusted, engine-dependent
        // text; normalize before it is ever canonically encoded or
        // persisted. See `preinstalled_wasm::normalize_trapped_preinstalled_execution`.
        let effects = match effects.status {
            ExecutionStatus::Success => effects,
            ExecutionStatus::Failure { .. } => normalize_trapped_preinstalled_execution(
                effects.tx_hash,
                self.transaction.gas_limit,
            ),
        };

        let status = match &effects.status {
            ExecutionStatus::Success => NodeResponseStatus::Accepted,
            ExecutionStatus::Failure { .. } => NodeResponseStatus::Rejected,
        };
        let response_payload: Vec<u8> = encode_execution_effects(&effects)?;
        let response = NodeResponse::new(event.request_id(), status, Some(response_payload))?;
        let output = NodeOutput::new(vec![response], Vec::new())?;

        match effects.status {
            // `WasmExecutionEngine` discards every candidate object effect on
            // a trap (see `execution::wasm_engine`), so a declared
            // `Write`/`Consume` access can never be matched here; commit the
            // deterministic rejection with no object mutation instead of
            // failing the whole invocation.
            ExecutionStatus::Failure { .. } => {
                Ok(TransactionalNodeTransition::rejected_with_no_object_mutation(output))
            }
            ExecutionStatus::Success if !effects.object_effects.is_empty() => {
                TransactionalNodeTransition::with_object_effects(
                    Vec::new(),
                    effects.object_effects,
                    output,
                )
            }
            ExecutionStatus::Success => Ok(TransactionalNodeTransition::read_only(output)),
        }
    }
}

/// Commits one preinstalled deterministic WASM contract call through the same
/// durable invocation as sender nonce, application state, receipt, and
/// outbox, passing its object effects to the same fail-closed owned-effects
/// translation already used by
/// [`handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects`].
///
/// `Transaction.module_ref` is resolved against the system-module registry
/// captured from committed `ProtocolConfig` during authentication and the
/// trusted `catalog` through [`resolve_preinstalled_module`] (see that
/// function's docs for the exact MVP `module_id`/`version`/`digest` mapping
/// and every commitment check). `created_checkpoint` is trusted node
/// composition, never request input, exactly like the owned-effects
/// entrypoint. This composition is object-only: it declares no opaque
/// application state key, and domain placement uses the authenticated
/// object-access count rather than an opaque state-key count. A call that
/// declares zero authenticated object accesses is rejected with
/// [`NodeCoreError::PreinstalledModuleZeroObjectAccess`] before domain
/// resolution; this MVP path requires at least one.
///
/// `Transaction.gas_limit` is rejected before the WASM engine ever runs if it
/// exceeds the conservative pre-activation [`MAX_PREINSTALLED_MODULE_GAS_LIMIT`]
/// ceiling (see [`NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling`]);
/// this is not a production fee-weighted gas schedule, which remains
/// deferred.
///
/// A deterministically trapped/rejected execution still commits: it produces
/// a `Rejected` [`NodeResponse`] whose canonically encoded body is a
/// normalized, engine-independent closed failure (fixed reason, full
/// `gas_limit` charge, empty effects/events — see
/// `preinstalled_wasm::normalize_trapped_preinstalled_execution`), and,
/// because [`ExecutionStatus::Failure`] discards every object effect before
/// this function ever sees them, no object mutation. Exact request replay is
/// reconciled from the persisted receipt before any module resolution,
/// object load, or execution, identical to every other structured durable
/// entrypoint.
///
/// An additive `native_http::preinstalled_wasm_structured_durable_router`
/// wires this entrypoint over HTTP (see `ARCHITECTURE.md` DR-0080);
/// `native_http::structured_durable_router` remains on the read-only
/// entrypoint. Create, Shared/System ownership, blob bodies, and production
/// gas metering remain unimplemented and fail closed or are simply not
/// reachable from this MVP slice.
pub fn handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution<
    S,
>(
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    catalog: &PreinstalledModuleCatalog,
    engine: &WasmExecutionEngine,
    submission: AuthenticatedSubmitTransaction,
    created_checkpoint: u64,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let dispatch = AuthenticatedObjectDispatch::from_authenticated_transaction(
        &submission.transaction,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint },
    )?;
    // This MVP preinstalled-WASM path requires at least one authenticated
    // object; reject before domain resolution rather than resolving a
    // domain for a call the machine could never usefully service.
    if dispatch.accesses.is_empty() {
        return Err(NodeCoreError::PreinstalledModuleZeroObjectAccess);
    }
    // Object-only composition: domain placement uses the authenticated
    // object-access count instead of an opaque application state-key count,
    // because this machine declares no state keys (see
    // `PreinstalledWasmMachine::access_plan`).
    let domain = submission
        .placement
        .resolve_domain(submission.event().epoch(), dispatch.accesses.len())?;
    let reservation =
        SenderNonceReservation::from_authenticated_transaction(&submission.transaction);
    let AuthenticatedSubmitTransaction {
        event,
        transaction,
        placement: _,
        committed_system_module,
    } = submission;
    let machine = PreinstalledWasmMachine {
        transaction: transaction.transaction(),
        resolver,
        registered_module: committed_system_module.as_ref(),
        catalog,
        engine,
    };
    let plan = machine.access_plan(&event)?;
    let output = handle_durable_idempotent_event_with_plan(
        store,
        context,
        domain,
        resolver,
        event,
        &machine,
        plan,
        Some(reservation),
        Some(dispatch),
        Some(created_checkpoint),
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

#[allow(clippy::too_many_arguments)]
fn handle_authenticated_submit_transaction_with_policy<S, M>(
    store: &S,
    context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    submission: AuthenticatedSubmitTransaction,
    machine: &M,
    object_policy: AuthenticatedObjectPolicy,
) -> Result<ResolvedNodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    let created_checkpoint: Option<u64> = match object_policy {
        AuthenticatedObjectPolicy::ReadOnly => None,
        AuthenticatedObjectPolicy::OwnedMutations { created_checkpoint } => {
            Some(created_checkpoint)
        }
    };
    let plan = machine.access_plan(submission.event())?;
    let domain = submission
        .placement
        .resolve_domain(submission.event().epoch(), plan.accesses().len())?;
    let reservation =
        SenderNonceReservation::from_authenticated_transaction(&submission.transaction);
    let dispatch = AuthenticatedObjectDispatch::from_authenticated_transaction(
        &submission.transaction,
        object_policy,
    )?;
    let AuthenticatedSubmitTransaction {
        event,
        transaction: _authenticated_transaction,
        placement: _,
        committed_system_module: _,
    } = submission;
    let output = handle_durable_idempotent_event_with_plan(
        store,
        context,
        domain,
        resolver,
        event,
        machine,
        plan,
        Some(reservation),
        Some(dispatch),
        created_checkpoint,
    )?;
    Ok(ResolvedNodeOutput::new(domain, output))
}

/// One pending sender-nonce read assertion and canonical next-nonce write,
/// merged into the same [`DurableStateTransaction`] as the application state.
struct PendingSenderNonceWrite {
    key: Vec<u8>,
    read_revision: StateRevision,
    record: SenderNonceRecord,
}

#[allow(clippy::too_many_arguments)]
fn handle_durable_idempotent_event_with_plan<S, M>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    event: NodeEvent,
    machine: &M,
    plan: NodeStateAccessPlan,
    reservation: Option<SenderNonceReservation>,
    dispatch: Option<AuthenticatedObjectDispatch>,
    created_checkpoint: Option<u64>,
) -> Result<NodeOutput, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
    M: TransactionalNodeStateMachine,
{
    // Constructed from the validated event's own chain/version. Every
    // application plan key is rejected under this prefix for every event
    // family, including exact receipt replays: application state machines
    // must never claim the sender-nonce namespace.
    let layout = PersistenceLayout::new(event.chain_id().clone(), event.protocol_version());
    validate_sender_nonce_namespace(&plan, &layout)?;
    let nonce_prefix = layout.sender_nonce_prefix();

    if reservation.is_some() {
        let maximum_application_accesses =
            core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(1);
        if plan.accesses().len() > maximum_application_accesses {
            return Err(NodeCoreError::TooManyStateAccesses {
                count: plan.accesses().len(),
                maximum: maximum_application_accesses,
            });
        }
    }

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

    // A new request reads only the sender-nonce record, before any
    // application state, so a stale or replayed nonce fails before any app
    // state read, transition, or commit attempt.
    let pending_nonce = match reservation {
        Some(reservation) => {
            let nonce_key = layout.sender_nonce_key(reservation.sender, reservation.epoch);
            let observation = query::read_sender_next_nonce(
                store,
                context,
                domain,
                &nonce_key,
                reservation.sender,
                reservation.epoch,
            )?;
            let expected_next_nonce = observation.next_nonce;
            if reservation.nonce != expected_next_nonce {
                return Err(NodeCoreError::SenderNonceMismatch {
                    sender: reservation.sender,
                    expected: expected_next_nonce,
                    actual: reservation.nonce,
                });
            }
            let next_nonce =
                reservation
                    .nonce
                    .checked_add(1)
                    .ok_or(NodeCoreError::SenderNonceOverflow {
                        sender: reservation.sender,
                    })?;
            Some(PendingSenderNonceWrite {
                key: nonce_key,
                read_revision: observation.revision,
                record: SenderNonceRecord::new(reservation.sender, reservation.epoch, next_nonce),
            })
        }
        None => None,
    };

    // Object reads happen only after the receipt and nonce checks above, so a
    // stale or replayed request never spends the fan-out cost of the
    // per-entry head/version storage round-trips. Only this authenticated
    // path supplies verified typed object inputs to the pure transition;
    // generic handlers always supply an empty object slice.
    let loaded_objects: LoadedAuthenticatedObjects = match &dispatch {
        Some(dispatch) => {
            load_and_authorize_objects(store, context, domain, event.chain_id(), dispatch)?
        }
        None => LoadedAuthenticatedObjects::default(),
    };
    let mut values = BTreeMap::new();
    for access in plan.accesses() {
        let observed = store.get_versioned_durable(context, domain, access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key.clone(), observed);
    }
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: loaded_objects.resolved_objects(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    validate_output_event_context(transition.output(), &event)?;
    let mutation_context: Option<authenticated_object_effects::TrustedObjectMutationContext<'_>> =
        created_checkpoint.map(|created_checkpoint: u64| {
            authenticated_object_effects::TrustedObjectMutationContext {
                resolver,
                chain_id: event.chain_id(),
                protocol_version: event.protocol_version(),
                epoch: event.epoch(),
                created_checkpoint,
            }
        });
    // `bypasses_object_effect_matching` is only set by
    // `TransactionalNodeTransition::rejected_with_no_object_mutation`, which
    // also always returns empty `object_effects()`; every other transition
    // still requires an exact declared-access/effect match.
    let object_mutations: Vec<DurableObjectMutationEntry> =
        if transition.bypasses_object_effect_matching() {
            debug_assert!(transition.object_effects().is_empty());
            Vec::new()
        } else {
            translate_authenticated_object_effects(
                loaded_objects.verified(),
                transition.object_effects(),
                mutation_context.as_ref(),
                loaded_objects.total_body_bytes(),
            )?
        };

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
    let (mut reads, mut mutations) = domain_transition_parts(&plan, &snapshot, transition.updates)?;
    if let Some(mutation) = mutations
        .iter()
        .find(|mutation| mutation.key().starts_with(nonce_prefix.as_slice()))
    {
        return Err(NodeCoreError::ReservedStateAccess(mutation.key().to_vec()));
    }
    if let Some(pending) = pending_nonce {
        reads.push(StateReadAssertion::new(
            pending.key.clone(),
            pending.read_revision,
        )?);
        mutations.push(StateMutationEntry::new(
            pending.key,
            StateMutation::Put(pending.record.encode()?),
        )?);
    }
    let state = DurableStateTransaction::new(domain, AtomicStateReadSet::new(reads)?, mutations)?;
    let objects = DurableObjectChanges::new(loaded_objects.into_reads(), object_mutations)?;
    let invocation =
        DurableInvocationTransaction::new(domain, Some(state), objects, receipt, outbox)?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(transition.output),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(NodeCoreError::StateConflict),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id,
            ..
        }) => Err(NodeCoreError::ObjectConflict { object_id }),
        DurableCommitOutcome::Rejected(reason) => Err(NodeCoreError::DurableCommitRejected(reason)),
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason))
        }
    }
}

/// Loads and authorizes every entry in `dispatch.accesses` against
/// `dispatch.authority`, returning one exact [`runtime::DurableObjectHeadRead`] per
/// entry in the same signed manifest declaration order. The runtime durable
/// envelope canonicalizes storage assertions independently before commit.
///
/// Every check fails closed:
///
/// * an absent or tombstoned head, a version/digest disagreement with the
///   signed reference, a blob-backed payload, or an unauthorized owner all
///   reject before any assertion is recorded;
/// * a current head that points at a missing or disagreeing immutable
///   version record, or an inline object that disagrees with its own version
///   record, is treated as storage corruption distinct from authorization
///   failure;
/// * the record's own stored provenance must name the trusted event `chain_id`
///   — a mismatch means a misbound namespace, a cross-chain body transplant,
///   or adapter corruption, never a legitimate historical object;
/// * this node independently recomputes the object digest from the record's
///   own stored provenance and canonical body using [`hashing::verify_digest`],
///   which selects the algorithm recorded self-describingly in the digest
///   itself. It never uses the reader's epoch-selected hash suite, which
///   would misjudge a legitimate object created under a different suite or
///   protocol version; inline bodies are bounded before hashing.
fn load_and_authorize_objects<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    dispatch: &AuthenticatedObjectDispatch,
) -> Result<LoadedAuthenticatedObjects, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let mut loaded: LoadedAuthenticatedObjects =
        LoadedAuthenticatedObjects::with_capacity(dispatch.accesses.len());
    let mut total_body_bytes: usize = 0;
    for access in &dispatch.accesses {
        let object_id: ObjectId = access.object_ref.id;
        let head: DurableObjectHead = store.get_object_head(context, domain, object_id)?;
        let (object_version, digest): (DurableObjectVersion, Digest32) = match &head {
            DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
                return Err(NodeCoreError::ObjectNotFound { object_id });
            }
            DurableObjectHead::Current {
                object_version,
                digest,
                ..
            } => (*object_version, *digest),
        };

        if object_version.get() != access.object_ref.version {
            return Err(NodeCoreError::ObjectVersionMismatch {
                object_id,
                expected: access.object_ref.version,
                actual: object_version.get(),
            });
        }
        if digest != access.object_ref.digest {
            return Err(NodeCoreError::ObjectDigestMismatch {
                object_id,
                expected: access.object_ref.digest,
                actual: digest,
            });
        }

        let record: DurableObjectVersionRecord = store
            .get_object_version(context, domain, object_id, object_version)?
            .ok_or(NodeCoreError::ObjectRecordMissing { object_id })?;
        if record.object_id() != object_id
            || record.object_version() != object_version
            || record.digest() != digest
        {
            return Err(NodeCoreError::ObjectRecordMismatch { object_id });
        }

        let inline: &DurableInlineObject = match record.payload() {
            DurableObjectPayload::BlobReference(_) => {
                return Err(NodeCoreError::ObjectBodyUnavailable { object_id });
            }
            DurableObjectPayload::Inline(inline) => inline,
        };
        let object: &Object = inline.object();
        if object.id != object_id
            || object.version != access.object_ref.version
            || record.schema_version() != object.schema_version
        {
            return Err(NodeCoreError::ObjectRecordMismatch { object_id });
        }

        // Objects never migrate chains: the event chain is already validated
        // trusted input, so a mismatch here means a misbound namespace, a
        // cross-chain body transplant, or adapter corruption, never a
        // legitimate object. No equivalent check exists for the recorded
        // protocol version: a legitimately older object must still verify.
        if record.provenance().chain_id() != chain_id {
            return Err(NodeCoreError::ObjectProvenanceMismatch { object_id });
        }

        let body_length: usize = inline.canonical_bytes().len();
        if body_length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(NodeCoreError::ObjectBodyTooLarge {
                object_id,
                actual: body_length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
        total_body_bytes =
            total_body_bytes
                .checked_add(body_length)
                .ok_or(NodeCoreError::ObjectBodyTooLarge {
                    object_id,
                    actual: usize::MAX,
                    maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
                })?;
        if total_body_bytes > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES {
            return Err(NodeCoreError::ObjectBodyTooLarge {
                object_id,
                actual: total_body_bytes,
                maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            });
        }

        let verified: bool = hashing::verify_digest(
            &record.digest(),
            HashPurpose::Object,
            record.provenance().protocol_version(),
            record.provenance().chain_id(),
            inline.canonical_bytes(),
        )
        .map_err(|error| match error {
            HashingError::UnsupportedAlgorithm(algorithm) => {
                NodeCoreError::ObjectDigestUnverifiable {
                    object_id,
                    algorithm,
                }
            }
            other => NodeCoreError::Hashing(other),
        })?;
        if !verified {
            return Err(NodeCoreError::ObjectBodyDigestMismatch { object_id });
        }

        // Corruption guard, not authorization: mirrors
        // `validate_object_transition`'s owner-projection cross-check. An
        // absent projection is corruption, not a trust-the-inline fallback.
        if head
            .owner_projection()
            .and_then(DurableObjectOwnerProjection::owner)
            != Some(&object.owner)
        {
            return Err(NodeCoreError::ObjectRecordMismatch { object_id });
        }

        match &object.owner {
            Owner::Address(owner_address) => {
                if *owner_address != dispatch.authority {
                    return Err(NodeCoreError::ObjectOwnerMismatch { object_id });
                }
            }
            Owner::Immutable if access.mode == AccessMode::Read => {}
            Owner::Immutable => {
                return Err(NodeCoreError::ObjectOwnerKindUnsupported { object_id });
            }
            Owner::Shared | Owner::System => {
                return Err(NodeCoreError::ObjectOwnerKindUnsupported { object_id });
            }
        }

        loaded.push(
            object_id,
            access.mode,
            head,
            object.clone(),
            record.created_checkpoint(),
        );
    }
    loaded.set_total_body_bytes(total_body_bytes);
    Ok(loaded)
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

    validate_sender_nonce_namespace(&plan, &layout)?;
    let maximum_application_accesses =
        core::cmp::min(MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_WRITES).saturating_sub(3);
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
    let snapshot = NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    };
    let transition = machine.transition(&snapshot, &event)?;
    reject_object_effects_without_authenticated_dispatch(transition.object_effects())?;
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

fn hex32(bytes: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
    use abi::{AccessEntry, AccessManifest};
    use ed25519_zebra::SigningKey;
    use execution::{Transaction, encode_transaction, encode_transaction_signable};
    use hashing::{BuiltinHashFunction, HashFunction};
    use objects::{AccessMode, Address, ObjectId, ObjectRef, encode_object};
    use protocol_config::TransactionAuthProfile;
    use protocol_types::{HashSuite, HashSuiteId, HashSuiteSchedule, SignatureSchemeId};
    use runtime::{
        DurableDomainStateStore, DurableObjectProvenance, DurableObjectRoutingProjection,
        MemoryDurableStateStore, MemoryRuntime, StateRevision, StateStore, StorageCorrelationId,
        StorageDeadline, TransactionalStateStore, WriterFenceGeneration,
    };
    use std::sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use system_modules::SystemModuleRegistry;

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

    /// Same as [`resolver`], but with a second SHA3-256 hash-suite schedule
    /// entry activating at `rotation_epoch`.
    fn resolver_with_rotation(chain: &str, rotation_epoch: Epoch) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: rotation_epoch,
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap()
    }

    /// A committed protocol configuration whose `protocol_version` matches
    /// [`config`] and whose `transaction_auth_profile` is active, used to
    /// authenticate a `SubmitTransaction` event.
    fn active_protocol_config(byte: u8) -> ProtocolConfig {
        let mut protocol_config = ProtocolConfig::genesis();
        protocol_config.protocol_version = ProtocolVersion::new(3);
        protocol_config.domain_placement =
            Some(DomainPlacementManifest::single_domain(1, domain(byte), Epoch::new(0)).unwrap());
        protocol_config.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_address_is_public_key());
        protocol_config
    }

    /// A dev-only deterministic signer built directly on the exact-pinned
    /// workspace `ed25519-zebra` `SigningKey`. Test infrastructure only,
    /// mirroring `transaction_auth`'s own test-only signer.
    fn dev_signing_key(seed: u8) -> SigningKey {
        SigningKey::from([seed; 32])
    }

    fn dev_sender_address(signing_key: &SigningKey) -> Address {
        let verification_key = ed25519_zebra::VerificationKey::from(signing_key);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(verification_key.as_ref());
        Address::new(bytes)
    }

    fn sample_object_ref(id_byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [id_byte; 32]),
        }
    }

    fn test_object(id: ObjectId, version: u64, owner: Owner, byte: u8) -> Object {
        Object {
            id,
            version,
            owner,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
            schema_version: u32::from(byte),
            data: vec![byte],
        }
    }

    /// Hashes `object`'s canonical bytes with the production object-digest
    /// suite, returning the version record ready to commit alongside the
    /// exact digest a signed [`ObjectRef`] must declare to match it.
    fn hashed_object_version(
        object: Object,
        chain: &str,
        checkpoint: u64,
    ) -> (DurableObjectVersionRecord, Digest32) {
        hashed_object_version_with_protocol_version(
            object,
            chain,
            ProtocolVersion::new(3),
            checkpoint,
        )
    }

    /// Same as [`hashed_object_version`] but with an explicit creating
    /// protocol version, for exercising cross-version provenance.
    fn hashed_object_version_with_protocol_version(
        object: Object,
        chain: &str,
        protocol_version: ProtocolVersion,
        checkpoint: u64,
    ) -> (DurableObjectVersionRecord, Digest32) {
        let canonical_bytes = encode_object(&object).unwrap();
        let chain_id = ChainId::new(chain).unwrap();
        let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                protocol_version,
                &chain_id,
                &canonical_bytes,
            )
            .unwrap();
        let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
        (
            DurableObjectVersionRecord::from_inline_object(object, digest, provenance, checkpoint)
                .unwrap(),
            digest,
        )
    }

    fn manifest_with(entries: Vec<AccessEntry>) -> AccessManifest {
        let mut manifest = AccessManifest::new();
        for entry in entries {
            manifest.push(entry);
        }
        manifest
    }

    /// Builds an unsigned transaction with an empty object-access manifest,
    /// so tests that only exercise nonce/replay/idempotency semantics are not
    /// also subject to object-dispatch authorization. Tests that specifically
    /// exercise object dispatch use [`unsigned_transaction_with_manifest`].
    fn unsigned_transaction(
        sender: Address,
        chain: ChainId,
        epoch: Epoch,
        nonce: u64,
    ) -> Transaction {
        unsigned_transaction_with_manifest(sender, chain, epoch, nonce, AccessManifest::new())
    }

    fn unsigned_transaction_with_manifest(
        sender: Address,
        chain: ChainId,
        epoch: Epoch,
        nonce: u64,
        access_manifest: AccessManifest,
    ) -> Transaction {
        Transaction {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            sender,
            nonce,
            access_manifest,
            module_ref: sample_object_ref(0xDD),
            entrypoint: "transfer".to_string(),
            args: vec![1, 2, 3, 4],
            gas_limit: 100_000,
            fee_payment: None,
            signature: Vec::new(),
        }
    }

    /// Builds and authenticates one `SubmitTransaction` event for `sender` at
    /// `nonce` under the shared test chain/epoch/protocol-config fixtures.
    fn authenticated_submission(
        chain: &str,
        request_id: RequestId,
        signing_key: &SigningKey,
        epoch: Epoch,
        nonce: u64,
        config: &NodeConfig,
        protocol_config: &ProtocolConfig,
    ) -> AuthenticatedSubmitTransaction {
        let sender = dev_sender_address(signing_key);
        let tx = unsigned_transaction(sender, ChainId::new(chain).unwrap(), epoch, nonce);
        authenticated_submission_from_transaction(
            chain,
            request_id,
            signing_key,
            epoch,
            tx,
            config,
            protocol_config,
        )
    }

    /// Same as [`authenticated_submission`], but with an explicit
    /// object-access manifest, for tests that exercise object dispatch.
    #[allow(clippy::too_many_arguments)]
    fn authenticated_submission_with_manifest(
        chain: &str,
        request_id: RequestId,
        signing_key: &SigningKey,
        epoch: Epoch,
        nonce: u64,
        access_manifest: AccessManifest,
        config: &NodeConfig,
        protocol_config: &ProtocolConfig,
    ) -> AuthenticatedSubmitTransaction {
        let sender = dev_sender_address(signing_key);
        let tx = unsigned_transaction_with_manifest(
            sender,
            ChainId::new(chain).unwrap(),
            epoch,
            nonce,
            access_manifest,
        );
        authenticated_submission_from_transaction(
            chain,
            request_id,
            signing_key,
            epoch,
            tx,
            config,
            protocol_config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticated_submission_from_transaction(
        chain: &str,
        request_id: RequestId,
        signing_key: &SigningKey,
        epoch: Epoch,
        tx: Transaction,
        config: &NodeConfig,
        protocol_config: &ProtocolConfig,
    ) -> AuthenticatedSubmitTransaction {
        let payload = signed_transaction_bytes(signing_key, &tx);
        let event = NodeEvent::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            epoch,
            request_id,
            NodeEventKind::SubmitTransaction,
            payload,
        )
        .unwrap();
        authenticate_submit_transaction_event(event, config, protocol_config).unwrap()
    }

    /// Signs `tx` under the exact production `SignatureDomain` that
    /// `authenticate_transaction_bytes` itself builds (`tx.chain_id`,
    /// protocol version 3, `tx.epoch`, message family `"transaction-v1"`,
    /// Ed25519), matching `transaction_auth`'s own test-only signer, and
    /// returns the fully encoded transaction bytes.
    fn signed_transaction_bytes(signing_key: &SigningKey, tx: &Transaction) -> Vec<u8> {
        let signable = encode_transaction_signable(tx).unwrap();
        let domain = crypto::SignatureDomain {
            chain_id: tx.chain_id.clone(),
            protocol_version: ProtocolVersion::new(3),
            epoch: tx.epoch,
            message_type: crypto::SignatureMessageType::new("transaction-v1").unwrap(),
            signature_scheme_id: SignatureSchemeId::Ed25519,
        };
        let framed = crypto::frame_signature_message(&domain, &signable).unwrap();
        let signature = signing_key.sign(&framed);
        let mut signed = tx.clone();
        signed.signature = signature.to_bytes().to_vec();
        encode_transaction(&signed).unwrap()
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
    fn sender_nonce_record_has_stable_canonical_vector_and_key_cross_check() {
        let sender = [0x33; 32];
        let record = SenderNonceRecord::new(sender, Epoch::new(7), 9);
        let bytes = record.encode().unwrap();
        assert_eq!(SenderNonceRecord::decode(&bytes).unwrap(), record);
        assert_eq!(
            hex(&bytes),
            concat!(
                "534e524506e001000300010020000000",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "0200080000000700000000000000",
                "0300080000000900000000000000"
            )
        );

        // The persisted key derived for this exact sender/epoch is the one a
        // reader must use to address this record.
        let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
        assert!(
            key.starts_with(
                PersistenceLayout::new(
                    ChainId::new("sunrise-test").unwrap(),
                    ProtocolVersion::new(3)
                )
                .sender_nonce_prefix()
                .as_slice()
            )
        );

        let mut wrong_type = CanonicalStruct::new(0xDEAD, ENCODING_VERSION);
        wrong_type.field_bytes(1, sender.to_vec()).unwrap();
        wrong_type.field_u64(2, 7).unwrap();
        wrong_type.field_u64(3, 9).unwrap();
        assert!(matches!(
            SenderNonceRecord::decode(&wrong_type.finish().unwrap()).unwrap_err(),
            NodeCoreError::CanonicalDecoding(_)
        ));

        let mut short_sender = CanonicalStruct::new(SENDER_NONCE_RECORD_TYPE_ID, ENCODING_VERSION);
        short_sender.field_bytes(1, vec![0x01; 31]).unwrap();
        short_sender.field_u64(2, 7).unwrap();
        short_sender.field_u64(3, 9).unwrap();
        assert!(matches!(
            SenderNonceRecord::decode(&short_sender.finish().unwrap()).unwrap_err(),
            NodeCoreError::CanonicalDecoding(_)
        ));
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
    fn all_eight_generic_handlers_reject_submit_before_machine_or_storage_work() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        let resolver = resolver("sunrise-test");
        let event_domain = domain(0xD4);
        let event_placement = placement(0xD4, 7);
        let machine = CountingPlanMachine {
            access_plans: AtomicUsize::new(0),
        };

        let domain_transactional_error = handle_domain_transactional_event(
            &runtime,
            event_domain,
            &config,
            submit_event("sunrise-test", request(0xB1)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            domain_transactional_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let resolved_transactional_error = handle_resolved_transactional_event(
            &runtime,
            &event_placement,
            &config,
            submit_event("sunrise-test", request(0xB2)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            resolved_transactional_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let transactional_error = handle_transactional_event(
            &runtime,
            &config,
            submit_event("sunrise-test", request(0xB3)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            transactional_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let idempotent_error = handle_idempotent_event(
            &runtime,
            &config,
            &resolver,
            submit_event("sunrise-test", request(0xB4)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            idempotent_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let domain_idempotent_error = handle_domain_idempotent_event(
            &runtime,
            event_domain,
            &config,
            &resolver,
            submit_event("sunrise-test", request(0xB5)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            domain_idempotent_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let resolved_idempotent_error = handle_resolved_idempotent_event(
            &runtime,
            &event_placement,
            &config,
            &resolver,
            submit_event("sunrise-test", request(0xB6)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            resolved_idempotent_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let resolved_durable_idempotent_error = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &event_placement,
            &config,
            &resolver,
            submit_event("sunrise-test", request(0xB7)),
            &machine,
        )
        .unwrap_err();
        assert_eq!(
            resolved_durable_idempotent_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );
        assert!(store.commits.lock().unwrap().is_empty());
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);

        let event_error = handle_event(
            &runtime,
            &config,
            submit_event("sunrise-test", request(0xB8)),
            &IncrementMachine,
        )
        .unwrap_err();
        assert_eq!(
            event_error,
            NodeCoreError::UnauthenticatedTransactionSubmission
        );

        assert_eq!(machine.access_plans.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.state_store().get(config.state_key()).unwrap(), None);
        assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
        assert_eq!(
            runtime.state_store().get(b"state/idempotent").unwrap(),
            None
        );
        assert!(
            runtime
                .state_store()
                .get_versioned_in_domain(event_domain, b"state/a")
                .unwrap()
                .value()
                .is_none()
        );
    }

    #[test]
    fn authenticate_submit_transaction_event_rejects_wrong_kind() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xD5);

        let error = authenticate_submit_transaction_event(
            event("sunrise-test", request(0xA1)),
            &config,
            &protocol_config,
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::ExpectedSubmitTransaction);
    }

    #[test]
    fn authenticate_submit_transaction_event_rejects_protocol_config_version_mismatch() {
        let config = config("sunrise-test");
        let mut protocol_config = active_protocol_config(0xD6);
        protocol_config.protocol_version = ProtocolVersion::new(2);

        let error = authenticate_submit_transaction_event(
            submit_event("sunrise-test", request(0xA2)),
            &config,
            &protocol_config,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ProtocolConfigVersionMismatch {
                node_config: ProtocolVersion::new(3),
                protocol_config: ProtocolVersion::new(2),
            }
        );
    }

    #[test]
    fn authenticate_submit_transaction_event_happy_path_authenticates_transaction() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xD7);
        let signing_key = dev_signing_key(0x71);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
        );
        let payload = signed_transaction_bytes(&signing_key, &tx);
        let event = NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request(0xA3),
            NodeEventKind::SubmitTransaction,
            payload,
        )
        .unwrap();

        let authenticated =
            authenticate_submit_transaction_event(event.clone(), &config, &protocol_config)
                .unwrap();

        assert_eq!(authenticated.event(), &event);
        assert_eq!(authenticated.transaction().transaction().nonce, 0);

        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let resolved = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated,
            &machine,
        )
        .unwrap();

        assert_eq!(resolved.domain(), domain(0xD7));
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        // One read for the sender-nonce record and one for the machine's
        // single declared application state key.
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 2);
        let commits = store.commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        let state = commits[0].state().unwrap();
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let nonce_key = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        )
        .sender_nonce_key(sender_bytes, Epoch::new(7));
        let nonce_mutation = state
            .mutations()
            .iter()
            .find(|mutation| mutation.key() == nonce_key.as_slice())
            .expect("sender nonce mutation is committed alongside app state");
        match nonce_mutation.mutation() {
            StateMutation::Put(bytes) => {
                let record = SenderNonceRecord::decode(bytes).unwrap();
                assert_eq!(record.sender, sender_bytes);
                assert_eq!(record.epoch, Epoch::new(7));
                assert_eq!(record.next_nonce, 1);
            }
            other => panic!("expected a nonce put mutation, got {other:?}"),
        }
    }

    fn sender_nonce_key_for(chain: &str, sender: [u8; 32], epoch: Epoch) -> Vec<u8> {
        PersistenceLayout::new(ChainId::new(chain).unwrap(), ProtocolVersion::new(3))
            .sender_nonce_key(sender, epoch)
    }

    #[test]
    fn sender_nonce_sequential_submissions_advance_persisted_next_nonce() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE1);
        let signing_key = dev_signing_key(0x91);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let context = durable_context();
        let resolver = resolver("sunrise-test");

        let first = authenticated_submission(
            "sunrise-test",
            request(0xC0),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        handle_authenticated_resolved_durable_submit_transaction(
            &store, &context, &resolver, first, &machine,
        )
        .unwrap();

        let second = authenticated_submission(
            "sunrise-test",
            request(0xC1),
            &signing_key,
            Epoch::new(7),
            1,
            &config,
            &protocol_config,
        );
        handle_authenticated_resolved_durable_submit_transaction(
            &store, &context, &resolver, second, &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 2);
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&context, domain(0xE1), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.next_nonce, 2);
    }

    #[test]
    fn sender_nonce_sequence_isolated_by_epoch() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let protocol_config = active_protocol_config(0xEE);
        let signing_key = dev_signing_key(0x9E);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let epoch_seven_config = config("sunrise-test");
        let epoch_eight_config = NodeConfig::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(8),
            b"node/state".to_vec(),
        )
        .unwrap();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let context = durable_context();
        let resolver = resolver("sunrise-test");

        for (request_id, epoch, config) in [
            (request(0xCE), Epoch::new(7), &epoch_seven_config),
            (request(0xCF), Epoch::new(8), &epoch_eight_config),
        ] {
            let submission = authenticated_submission(
                "sunrise-test",
                request_id,
                &signing_key,
                epoch,
                0,
                config,
                &protocol_config,
            );
            handle_authenticated_resolved_durable_submit_transaction(
                &store, &context, &resolver, submission, &machine,
            )
            .unwrap();
        }

        for epoch in [Epoch::new(7), Epoch::new(8)] {
            let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, epoch);
            let persisted = store
                .get_versioned_durable(&context, domain(0xEE), &nonce_key)
                .unwrap();
            let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
            assert_eq!(record.epoch, epoch);
            assert_eq!(record.next_nonce, 1);
        }
    }

    struct ConcurrentNonceMachine {
        barrier: Arc<Barrier>,
    }

    impl TransactionalNodeStateMachine for ConcurrentNonceMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/concurrent-nonce".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.barrier.wait();
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

    fn run_concurrent_nonce_submissions(
        store: Arc<MemoryDurableStateStore>,
        resolver: HashSuiteResolver,
        context: DurableOperationContext,
        first: AuthenticatedSubmitTransaction,
        second: AuthenticatedSubmitTransaction,
        machine: Arc<ConcurrentNonceMachine>,
    ) -> [Result<ResolvedNodeOutput, NodeCoreError>; 2] {
        let first_handle = {
            let store = Arc::clone(&store);
            let machine = Arc::clone(&machine);
            let resolver = resolver.clone();
            std::thread::spawn(move || {
                handle_authenticated_resolved_durable_submit_transaction(
                    store.as_ref(),
                    &context,
                    &resolver,
                    first,
                    machine.as_ref(),
                )
            })
        };
        let second_handle = {
            let store = Arc::clone(&store);
            let machine = Arc::clone(&machine);
            std::thread::spawn(move || {
                handle_authenticated_resolved_durable_submit_transaction(
                    store.as_ref(),
                    &context,
                    &resolver,
                    second,
                    machine.as_ref(),
                )
            })
        };

        [first_handle.join().unwrap(), second_handle.join().unwrap()]
    }

    fn assert_one_nonce_commit_and_one_conflict(
        results: &[Result<ResolvedNodeOutput, NodeCoreError>; 2],
    ) {
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(NodeCoreError::StateConflict)))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_first_nonce_submissions_commit_at_most_once() {
        let store = Arc::new(MemoryDurableStateStore::new(
            WriterFenceGeneration::new(1).unwrap(),
        ));
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xEF);
        let signing_key = dev_signing_key(0x9F);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let first = authenticated_submission(
            "sunrise-test",
            request(0xD0),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let second = authenticated_submission(
            "sunrise-test",
            request(0xD1),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let machine = Arc::new(ConcurrentNonceMachine {
            barrier: Arc::new(Barrier::new(2)),
        });
        let resolver = resolver("sunrise-test");
        let context = durable_context();

        let results = run_concurrent_nonce_submissions(
            Arc::clone(&store),
            resolver,
            context,
            first,
            second,
            machine,
        );
        assert_one_nonce_commit_and_one_conflict(&results);

        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&durable_context(), domain(0xEF), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.next_nonce, 1);
    }

    #[test]
    fn concurrent_existing_nonce_submissions_commit_at_most_once() {
        let store = Arc::new(MemoryDurableStateStore::new(
            WriterFenceGeneration::new(1).unwrap(),
        ));
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF0);
        let signing_key = dev_signing_key(0xA0);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let resolver = resolver("sunrise-test");
        let context = durable_context();

        let initial = authenticated_submission(
            "sunrise-test",
            request(0xD2),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        handle_authenticated_resolved_durable_submit_transaction(
            store.as_ref(),
            &context,
            &resolver,
            initial,
            &IdempotentMachine {
                calls: AtomicUsize::new(0),
            },
        )
        .unwrap();

        let first = authenticated_submission(
            "sunrise-test",
            request(0xD3),
            &signing_key,
            Epoch::new(7),
            1,
            &config,
            &protocol_config,
        );
        let second = authenticated_submission(
            "sunrise-test",
            request(0xD4),
            &signing_key,
            Epoch::new(7),
            1,
            &config,
            &protocol_config,
        );
        let machine = Arc::new(ConcurrentNonceMachine {
            barrier: Arc::new(Barrier::new(2)),
        });
        let results = run_concurrent_nonce_submissions(
            Arc::clone(&store),
            resolver,
            context,
            first,
            second,
            machine,
        );
        assert_one_nonce_commit_and_one_conflict(&results);

        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&durable_context(), domain(0xF0), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.next_nonce, 2);
    }

    #[test]
    fn stale_nonce_on_fresh_request_id_rejects_before_app_state_read_transition_or_commit() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE2);
        let signing_key = dev_signing_key(0x92);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC2),
            &signing_key,
            Epoch::new(7),
            1,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::SenderNonceMismatch {
                sender: sender_bytes,
                expected: 0,
                actual: 1,
            }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
        // Only the sender-nonce record is read before the mismatch is
        // detected; the machine's declared application state key is never
        // touched.
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exact_request_replay_returns_persisted_output_without_reconsuming_nonce() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE3);
        let signing_key = dev_signing_key(0x93);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let context = durable_context();
        let resolver = resolver("sunrise-test");

        let first_submission = authenticated_submission(
            "sunrise-test",
            request(0xC3),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let first = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &context,
            &resolver,
            first_submission,
            &machine,
        )
        .unwrap();

        let replay_submission = authenticated_submission(
            "sunrise-test",
            request(0xC3),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let replay = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &context,
            &resolver,
            replay_submission,
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.output().responses(), replay.output().responses());

        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&context, domain(0xE3), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.next_nonce, 1);
    }

    #[test]
    fn skipped_nonce_rejects_with_exact_expected_and_actual() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE4);
        let signing_key = dev_signing_key(0x94);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC4),
            &signing_key,
            Epoch::new(7),
            5,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::SenderNonceMismatch {
                sender: sender_bytes,
                expected: 0,
                actual: 5,
            }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonce_at_u64_max_overflows_instead_of_wrapping() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE5);
        let signing_key = dev_signing_key(0x95);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let record = SenderNonceRecord::new(sender_bytes, Epoch::new(7), u64::MAX);
        store.preload(nonce_key, StateRevision::new(1), record.encode().unwrap());
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC5),
            &signing_key,
            Epoch::new(7),
            u64::MAX,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::SenderNonceOverflow {
                sender: sender_bytes,
            }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn corrupt_nonce_record_bytes_reject_before_app_state_or_commit() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE6);
        let signing_key = dev_signing_key(0x96);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        store.preload(nonce_key, StateRevision::new(1), vec![0xFF, 0x00, 0x01]);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC6),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::PersistenceInvariant("invalid persisted sender nonce record")
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn nonce_tombstone_never_resets_an_accepted_epoch_to_zero() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xED);
        let signing_key = dev_signing_key(0x9D);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        store.preload_tombstone(nonce_key, StateRevision::new(2));
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let submission = authenticated_submission(
            "sunrise-test",
            request(0xCD),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );

        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::PersistenceInvariant(
                "persisted sender nonce record was deleted while its epoch may be accepted"
            )
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn misbound_nonce_record_sender_rejects_as_persistence_invariant() {
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE7);
        let signing_key = dev_signing_key(0x97);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        // A record correctly addressed by this sender/epoch's key, but whose
        // own bound fields describe a different sender: corruption or a
        // storage-layer misbinding bug, not an ordinary nonce mismatch.
        let misbound = SenderNonceRecord::new([0xAA; 32], Epoch::new(7), 0);
        store.preload(nonce_key, StateRevision::new(1), misbound.encode().unwrap());
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC7),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::PersistenceInvariant(
                "persisted sender nonce record does not match its key's sender/epoch"
            )
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }

    struct PrefixClaimingMachine {
        key: Vec<u8>,
    }

    impl TransactionalNodeStateMachine for PrefixClaimingMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                self.key.clone(),
                NodeStateAccessMode::ReadWrite,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    self.key.clone(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?],
                NodeOutput::new(
                    vec![NodeResponse::new(
                        event.request_id(),
                        NodeResponseStatus::Accepted,
                        None,
                    )?],
                    Vec::new(),
                )?,
            )
        }
    }

    #[test]
    fn app_plan_key_under_sender_nonce_prefix_is_rejected_for_non_submit_event_kind() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let victim_sender = [0x77; 32];
        // A different epoch than the event's own epoch (7): the prefix
        // rejection must not depend on matching the reservation-less caller
        // to any particular sender or epoch.
        let key = sender_nonce_key_for("sunrise-test", victim_sender, Epoch::new(9));
        let machine = PrefixClaimingMachine { key };
        // `event(..)` builds a `ReceiveVote` event: a non-`SubmitTransaction`
        // family, proving the shared helper does not branch on event kind.
        let input = event("sunrise-test", request(0xC8));

        let error = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xE8, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            input,
            &machine,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::ReservedStateAccess(_)));
        assert!(store.commits.lock().unwrap().is_empty());
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_transactional_handlers_also_reject_sender_nonce_prefix() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        let resolver = resolver("sunrise-test");
        let key = sender_nonce_key_for("sunrise-test", [0x78; 32], Epoch::new(9));
        let machine = PrefixClaimingMachine { key };

        let errors = [
            handle_transactional_event(
                &runtime,
                &config,
                event("sunrise-test", request(0xB0)),
                &machine,
            )
            .unwrap_err(),
            handle_idempotent_event(
                &runtime,
                &config,
                &resolver,
                event("sunrise-test", request(0xB1)),
                &machine,
            )
            .unwrap_err(),
            handle_domain_transactional_event(
                &runtime,
                domain(0xB2),
                &config,
                event("sunrise-test", request(0xB2)),
                &machine,
            )
            .unwrap_err(),
            handle_domain_idempotent_event(
                &runtime,
                domain(0xB3),
                &config,
                &resolver,
                event("sunrise-test", request(0xB3)),
                &machine,
            )
            .unwrap_err(),
        ];

        assert!(
            errors
                .iter()
                .all(|error| matches!(error, NodeCoreError::ReservedStateAccess(_)))
        );
    }

    struct RejectingMachine;

    impl TransactionalNodeStateMachine for RejectingMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/reject".to_vec(),
                NodeStateAccessMode::ReadWrite,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let response =
                NodeResponse::new(event.request_id(), NodeResponseStatus::Rejected, None)?;
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    b"state/reject".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, 0),
                )?],
                NodeOutput::new(vec![response], Vec::new())?,
            )
        }
    }

    #[test]
    fn committed_deterministic_rejection_still_consumes_the_nonce() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xE9);
        let signing_key = dev_signing_key(0x99);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let context = durable_context();

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xC9),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let resolved = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &context,
            &resolver("sunrise-test"),
            submission,
            &RejectingMachine,
        )
        .unwrap();

        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Rejected
        );
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&context, domain(0xE9), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.next_nonce, 1);
    }

    struct ErrMachine;

    impl TransactionalNodeStateMachine for ErrMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/err".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            _event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            Err(NodeCoreError::TransitionRejected("test rejection"))
        }
    }

    #[test]
    fn transition_error_does_not_consume_the_nonce() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xEA);
        let signing_key = dev_signing_key(0x9A);
        let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
        let context = durable_context();
        let resolver = resolver("sunrise-test");

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xCA),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &context,
            &resolver,
            submission,
            &ErrMachine,
        )
        .unwrap_err();
        assert_eq!(error, NodeCoreError::TransitionRejected("test rejection"));

        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
        let persisted = store
            .get_versioned_durable(&context, domain(0xEA), &nonce_key)
            .unwrap();
        assert!(persisted.value().is_none());

        // The still-expected nonce 0 now succeeds for a fresh request.
        let retry = authenticated_submission(
            "sunrise-test",
            request(0xCB),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        handle_authenticated_resolved_durable_submit_transaction(
            &store, &context, &resolver, retry, &machine,
        )
        .unwrap();
    }

    struct WideMachine {
        count: usize,
    }

    impl TransactionalNodeStateMachine for WideMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            let accesses = (0..self.count)
                .map(|index| {
                    NodeStateAccess::new(
                        format!("state/wide/{index:05}").into_bytes(),
                        NodeStateAccessMode::ReadOnly,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            NodeStateAccessPlan::new(accesses)
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
    fn app_plan_at_max_atomic_state_writes_exceeds_reserved_nonce_capacity() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xEB);
        let signing_key = dev_signing_key(0x9B);
        let machine = WideMachine {
            count: MAX_ATOMIC_STATE_WRITES,
        };

        let submission = authenticated_submission(
            "sunrise-test",
            request(0xCC),
            &signing_key,
            Epoch::new(7),
            0,
            &config,
            &protocol_config,
        );
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::TooManyStateAccesses {
                count: MAX_ATOMIC_STATE_WRITES,
                maximum: MAX_ATOMIC_STATE_WRITES - 1,
            }
        );
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());

        // The identical plan is accepted by the generic durable caller, which
        // passes no reservation and therefore does not reserve nonce write
        // capacity.
        let generic_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let generic_machine = WideMachine {
            count: MAX_ATOMIC_STATE_WRITES,
        };
        let output = handle_resolved_durable_idempotent_event(
            &generic_store,
            &durable_context(),
            &placement(0xEC, 7),
            &config,
            &resolver("sunrise-test"),
            event("sunrise-test", request(0xCD)),
            &generic_machine,
        )
        .unwrap();
        assert_eq!(output.output().responses().len(), 1);
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

    type ScriptedStateReads = BTreeMap<Vec<u8>, (StateRevision, Option<Vec<u8>>)>;

    struct ScriptedDurableStore {
        receipt: Mutex<Option<DurableRequestReceipt>>,
        commits: Mutex<Vec<DurableInvocationTransaction>>,
        state_reads: AtomicUsize,
        object_head_reads: AtomicUsize,
        object_heads: Mutex<BTreeMap<ObjectId, DurableObjectHead>>,
        object_versions: Mutex<BTreeMap<(ObjectId, u64), DurableObjectVersionRecord>>,
        commit_outcome: DurableCommitOutcome,
        preloaded: Mutex<ScriptedStateReads>,
    }

    impl ScriptedDurableStore {
        fn new(commit_outcome: DurableCommitOutcome) -> Self {
            Self {
                receipt: Mutex::new(None),
                commits: Mutex::new(Vec::new()),
                state_reads: AtomicUsize::new(0),
                object_head_reads: AtomicUsize::new(0),
                object_heads: Mutex::new(BTreeMap::new()),
                object_versions: Mutex::new(BTreeMap::new()),
                commit_outcome,
                preloaded: Mutex::new(BTreeMap::new()),
            }
        }

        /// Scripts a fixed read response for one exact key, overriding the
        /// default absent/`INITIAL` response used by every other key.
        fn preload(&self, key: Vec<u8>, revision: StateRevision, value: Vec<u8>) {
            self.preloaded
                .lock()
                .unwrap()
                .insert(key, (revision, Some(value)));
        }

        fn preload_tombstone(&self, key: Vec<u8>, revision: StateRevision) {
            self.preloaded.lock().unwrap().insert(key, (revision, None));
        }

        fn preload_object(
            &self,
            object_id: ObjectId,
            head: DurableObjectHead,
            version: Option<DurableObjectVersionRecord>,
        ) {
            self.object_heads.lock().unwrap().insert(object_id, head);
            if let Some(version) = version {
                self.object_versions
                    .lock()
                    .unwrap()
                    .insert((object_id, version.object_version().get()), version);
            }
        }
    }

    impl DurableDomainStateStore for ScriptedDurableStore {
        fn get_versioned_durable(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            key: &[u8],
        ) -> Result<VersionedStateValue, DurableReadError> {
            self.state_reads.fetch_add(1, Ordering::SeqCst);
            match self.preloaded.lock().unwrap().get(key) {
                Some((revision, value)) => {
                    VersionedStateValue::from_persisted_parts(*revision, value.clone())
                        .map_err(DurableReadError::InvalidRequest)
                }
                None => VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                    .map_err(DurableReadError::InvalidRequest),
            }
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

        fn get_object_head(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            object_id: ObjectId,
        ) -> Result<DurableObjectHead, DurableReadError> {
            self.object_head_reads.fetch_add(1, Ordering::SeqCst);
            self.object_heads
                .lock()
                .unwrap()
                .get(&object_id)
                .cloned()
                .ok_or(DurableReadError::InvalidRequest(
                    RuntimeError::UnsupportedObjectStorage,
                ))
        }

        fn get_object_version(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            object_id: ObjectId,
            object_version: DurableObjectVersion,
        ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
            Ok(self
                .object_versions
                .lock()
                .unwrap()
                .get(&(object_id, object_version.get()))
                .cloned())
        }
    }

    fn preload_inline_object(
        store: &ScriptedDurableStore,
        chain: &str,
        object_id: ObjectId,
        owner: Owner,
        byte: u8,
    ) -> (ObjectRef, DurableObjectHead) {
        let object: Object = test_object(object_id, 1, owner.clone(), byte);
        let (record, digest): (DurableObjectVersionRecord, Digest32) =
            hashed_object_version(object, chain, 1);
        let head: DurableObjectHead = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head.clone(), Some(record));
        (
            ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            head,
        )
    }

    fn commit_memory_inline_object(
        store: &MemoryDurableStateStore,
        context: &DurableOperationContext,
        object_domain: AtomicityDomainId,
        object: Object,
        chain: &str,
        created_checkpoint: u64,
        receipt_byte: u8,
    ) -> ObjectRef {
        let object_id: ObjectId = object.id;
        let object_version: u64 = object.version;
        let owner: Owner = object.owner.clone();
        let (record, digest): (DurableObjectVersionRecord, Digest32) =
            hashed_object_version(object, chain, created_checkpoint);
        let changes: DurableObjectChanges = DurableObjectChanges::new(
            vec![runtime::DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![runtime::DurableObjectMutationEntry::new(
                object_id,
                runtime::DurableObjectMutation::Create {
                    version: record,
                    owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .unwrap();
        let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
            DurableRequestId::new([receipt_byte; 32]).unwrap(),
            Digest32::new(
                HashAlgorithmId::Sha2_256,
                [receipt_byte.wrapping_add(1); 32],
            ),
            vec![receipt_byte.wrapping_add(2)],
        )
        .unwrap();
        let invocation: DurableInvocationTransaction =
            DurableInvocationTransaction::new(object_domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(context, invocation),
            DurableCommitOutcome::Committed
        );
        ObjectRef {
            id: object_id,
            version: object_version,
            digest,
        }
    }

    struct OwnedObjectEffectMachine {
        expected_inputs: Vec<(ObjectId, AccessMode)>,
        replacement_byte: u8,
        calls: AtomicUsize,
    }

    impl TransactionalNodeStateMachine for OwnedObjectEffectMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/owned-object-effects".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let actual_inputs: Vec<(ObjectId, AccessMode)> = state
                .resolved_objects()
                .iter()
                .map(|input: &ResolvedObject| (input.object.id, input.mode))
                .collect();
            assert_eq!(actual_inputs, self.expected_inputs);

            let mut effects: Vec<ObjectEffect> = Vec::new();
            for input in state.resolved_objects() {
                match input.mode {
                    AccessMode::Read => {}
                    AccessMode::Write => {
                        let mut new_object: Object = input.object.clone();
                        new_object.version = new_object.version.checked_add(1).unwrap();
                        new_object.data = vec![self.replacement_byte];
                        effects.push(ObjectEffect::Mutated {
                            previous_version: input.object.version,
                            new_object,
                        });
                    }
                    AccessMode::Consume => effects.push(ObjectEffect::Deleted {
                        id: input.object.id,
                        version: input.object.version,
                    }),
                }
            }
            let output: NodeOutput = NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?;
            TransactionalNodeTransition::with_object_effects(Vec::new(), effects, output)
        }
    }

    struct UndeclaredObjectEffectMachine;

    impl TransactionalNodeStateMachine for UndeclaredObjectEffectMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/undeclared-object-effect".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            assert!(state.resolved_objects().is_empty());
            let object_id: ObjectId = ObjectId::new([0xA1; 32]);
            let effect: ObjectEffect = ObjectEffect::Deleted {
                id: object_id,
                version: 1,
            };
            let output: NodeOutput = NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?;
            TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
        }
    }

    struct ReadObjectEffectMachine;

    impl TransactionalNodeStateMachine for ReadObjectEffectMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/read-object-effect".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let [input]: &[ResolvedObject] = state.resolved_objects() else {
                panic!("expected one authenticated read object");
            };
            let effect: ObjectEffect = ObjectEffect::Deleted {
                id: input.object.id,
                version: input.object.version,
            };
            let output: NodeOutput = NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?;
            TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
        }
    }

    #[test]
    fn authenticated_read_only_manifest_commits_sorted_exact_head_assertions() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF1);
        let signing_key = dev_signing_key(0xB1);
        let sender: Address = dev_sender_address(&signing_key);
        let higher_id: ObjectId = ObjectId::new([0x31; 32]);
        let lower_id: ObjectId = ObjectId::new([0x21; 32]);
        let (higher_ref, higher_head): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            higher_id,
            Owner::Address(sender),
            0x31,
        );
        let (lower_ref, lower_head): (ObjectRef, DurableObjectHead) =
            preload_inline_object(&store, "sunrise-test", lower_id, Owner::Immutable, 0x21);
        let manifest: AccessManifest = manifest_with(vec![
            AccessEntry {
                object_ref: higher_ref,
                mode: AccessMode::Read,
            },
            AccessEntry {
                object_ref: lower_ref,
                mode: AccessMode::Read,
            },
        ]);
        let submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xD1),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 2);
        let commits = store.commits.lock().unwrap();
        let object_changes: &DurableObjectChanges = commits[0].object_changes();
        assert!(object_changes.mutations().is_empty());
        assert_eq!(
            object_changes.reads(),
            &[
                runtime::DurableObjectHeadRead::new(lower_id, lower_head),
                runtime::DurableObjectHeadRead::new(higher_id, higher_head),
            ]
        );
    }

    /// Every pure, zero-I/O rejection in [`validate_object_entries`]. The
    /// duplicate-`ObjectId` branch is otherwise unreachable through
    /// [`authenticated_submission_with_manifest`], since
    /// [`abi::decode_access_manifest`] already rejects a duplicate id while
    /// decoding the authenticated transaction, so it is exercised directly
    /// against the extracted validator here.
    #[test]
    fn validate_object_entries_rejects_every_pure_branch() {
        fn entry(byte: u8, version: u64, mode: AccessMode) -> AccessEntry {
            AccessEntry {
                object_ref: ObjectRef {
                    id: ObjectId::new([byte; 32]),
                    version,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
                },
                mode,
            }
        }

        let accepted: Vec<AccessEntry> = (0..32u8)
            .map(|byte| entry(byte, 1, AccessMode::Read))
            .collect();
        let accesses =
            validate_object_entries(&accepted, AuthenticatedObjectPolicy::ReadOnly).unwrap();
        assert_eq!(accesses.len(), 32);
        assert!(
            accesses
                .windows(2)
                .all(|pair| pair[0].object_ref.id < pair[1].object_ref.id)
        );

        let too_many: Vec<AccessEntry> = (0..33u8)
            .map(|byte| entry(byte, 1, AccessMode::Read))
            .collect();
        assert_eq!(
            validate_object_entries(&too_many, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
            NodeCoreError::ObjectManifestTooLarge {
                count: 33,
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            }
        );

        let duplicate_id = ObjectId::new([0x09; 32]);
        let duplicate = vec![
            AccessEntry {
                object_ref: ObjectRef {
                    id: duplicate_id,
                    version: 1,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
                },
                mode: AccessMode::Read,
            },
            AccessEntry {
                object_ref: ObjectRef {
                    id: duplicate_id,
                    version: 2,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
                },
                mode: AccessMode::Read,
            },
        ];
        assert_eq!(
            validate_object_entries(&duplicate, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
            NodeCoreError::DuplicateObjectAccess {
                object_id: duplicate_id
            }
        );

        let zero_version_id = ObjectId::new([0x0A; 32]);
        assert_eq!(
            validate_object_entries(
                &[entry(0x0A, 0, AccessMode::Read)],
                AuthenticatedObjectPolicy::ReadOnly,
            )
            .unwrap_err(),
            NodeCoreError::InvalidObjectVersion {
                object_id: zero_version_id,
                version: 0,
            }
        );

        for mode in [AccessMode::Write, AccessMode::Consume] {
            let object_id = ObjectId::new([0x0B; 32]);
            assert_eq!(
                validate_object_entries(
                    &[entry(0x0B, 1, mode)],
                    AuthenticatedObjectPolicy::ReadOnly,
                )
                .unwrap_err(),
                NodeCoreError::ObjectAccessModeUnsupported { object_id, mode }
            );
        }

        let owned_modes = validate_object_entries(
            &[
                entry(0x0D, 1, AccessMode::Consume),
                entry(0x0C, 1, AccessMode::Write),
            ],
            AuthenticatedObjectPolicy::OwnedMutations {
                created_checkpoint: 1,
            },
        )
        .unwrap();
        assert_eq!(owned_modes.len(), 2);
        assert_eq!(owned_modes[0].object_ref.id, ObjectId::new([0x0D; 32]));
        assert_eq!(owned_modes[1].object_ref.id, ObjectId::new([0x0C; 32]));
    }

    /// Every storage-facing branch of `load_and_authorize_objects` that only
    /// runs once the pure manifest validation above has already passed:
    /// unsupported access modes, absence, tombstones, version/digest
    /// disagreement with the signed reference, unsupported owner kinds,
    /// unreadable blob bodies, a missing immutable version record, and every
    /// distinct shape of storage corruption the corruption guard must catch
    /// — including an owner projection that disagreed with the inline
    /// object's owner and one that was absent entirely.
    #[test]
    fn authenticated_object_dispatch_fails_closed_for_every_pure_and_storage_branch() {
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF2);
        let signing_key = dev_signing_key(0xB2);
        let sender: Address = dev_sender_address(&signing_key);

        // `expect_zero_object_io`: true only for manifest entries rejected by
        // the pure, zero-I/O `validate_object_entries` stage, before
        // `load_and_authorize_objects` ever calls `get_object_head`.
        type DispatchCase = (
            &'static str,
            Box<dyn Fn() -> (ScriptedDurableStore, AccessManifest, NodeCoreError)>,
            bool,
        );

        fn current_head_with_owner_projection(
            head: DurableObjectHead,
            owner_projection: DurableObjectOwnerProjection,
        ) -> DurableObjectHead {
            match head {
                DurableObjectHead::Current {
                    head_revision,
                    object_version,
                    digest,
                    routing_projection,
                    ..
                } => DurableObjectHead::Current {
                    head_revision,
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                },
                other => panic!("expected current head, got {other:?}"),
            }
        }

        let cases: Vec<DispatchCase> = vec![
            (
                "write mode unsupported",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_ref = sample_object_ref(0x41);
                    let object_id = object_ref.id;
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Write,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectAccessModeUnsupported {
                            object_id,
                            mode: AccessMode::Write,
                        },
                    )
                }),
                true,
            ),
            (
                "consume mode unsupported",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_ref = sample_object_ref(0x4A);
                    let object_id = object_ref.id;
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Consume,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectAccessModeUnsupported {
                            object_id,
                            mode: AccessMode::Consume,
                        },
                    )
                }),
                true,
            ),
            (
                "absent object",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x42; 32]);
                    store.preload_object(object_id, DurableObjectHead::Absent, None);
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: sample_object_ref(0x42),
                        mode: AccessMode::Read,
                    }]);
                    (store, manifest, NodeCoreError::ObjectNotFound { object_id })
                }),
                false,
            ),
            (
                "tombstoned object",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x48; 32]);
                    store.preload_object(
                        object_id,
                        DurableObjectHead::Tombstoned {
                            head_revision: runtime::ObjectHeadRevision::FIRST,
                            last_object_version: DurableObjectVersion::FIRST,
                        },
                        None,
                    );
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: sample_object_ref(0x48),
                        mode: AccessMode::Read,
                    }]);
                    (store, manifest, NodeCoreError::ObjectNotFound { object_id })
                }),
                false,
            ),
            (
                "object version mismatch",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x49; 32]);
                    let (mut object_ref, _head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Address(sender),
                        0x49,
                    );
                    object_ref.version = 2;
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectVersionMismatch {
                            object_id,
                            expected: 2,
                            actual: 1,
                        },
                    )
                }),
                false,
            ),
            (
                "object digest mismatch",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x4B; 32]);
                    let (mut object_ref, _head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Address(sender),
                        0x4B,
                    );
                    let actual_digest = object_ref.digest;
                    let wrong_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xFE; 32]);
                    object_ref.digest = wrong_digest;
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectDigestMismatch {
                            object_id,
                            expected: wrong_digest,
                            actual: actual_digest,
                        },
                    )
                }),
                false,
            ),
            (
                "owner mismatch",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x43; 32]);
                    let (object_ref, _head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Address(Address::new([0xEE; 32])),
                        0x43,
                    );
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectOwnerMismatch { object_id },
                    )
                }),
                false,
            ),
            (
                "shared owner rejected",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x4C; 32]);
                    let (object_ref, _head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Shared,
                        0x4C,
                    );
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                    )
                }),
                false,
            ),
            (
                "system owner rejected",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x4D; 32]);
                    let (object_ref, _head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::System,
                        0x4D,
                    );
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                    )
                }),
                false,
            ),
            (
                "blob body unavailable",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x44; 32]);
                    let blob_digest: Digest32 =
                        Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]);
                    let blob_record: DurableObjectVersionRecord =
                        DurableObjectVersionRecord::from_blob_reference(
                            object_id,
                            DurableObjectVersion::FIRST,
                            blob_digest,
                            1,
                            DurableObjectProvenance::new(
                                ChainId::new("sunrise-test").unwrap(),
                                ProtocolVersion::new(3),
                            ),
                            1,
                            Digest32::new(HashAlgorithmId::Sha3_256, [0x46; 32]),
                        );
                    let blob_head: DurableObjectHead = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest: blob_digest,
                        owner_projection: DurableObjectOwnerProjection::default(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, blob_head, Some(blob_record));
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest: blob_digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectBodyUnavailable { object_id },
                    )
                }),
                false,
            ),
            (
                "missing version record",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x4E; 32]);
                    let object = test_object(object_id, 1, Owner::Address(sender), 0x4E);
                    let (_, digest) = hashed_object_version(object, "sunrise-test", 1);
                    let head = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                            sender,
                        ))
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, head, None);
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectRecordMissing { object_id },
                    )
                }),
                false,
            ),
            (
                "record identity disagrees with owner projection",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x47; 32]);
                    let (object_ref, head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Address(sender),
                        0x47,
                    );
                    let corrupt_head = current_head_with_owner_projection(
                        head,
                        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(
                            [0xEF; 32],
                        )))
                        .unwrap(),
                    );
                    store.preload_object(object_id, corrupt_head, None);
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectRecordMismatch { object_id },
                    )
                }),
                false,
            ),
            (
                "absent owner projection",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x4F; 32]);
                    let (object_ref, head) = preload_inline_object(
                        &store,
                        "sunrise-test",
                        object_id,
                        Owner::Address(sender),
                        0x4F,
                    );
                    let corrupt_head = current_head_with_owner_projection(
                        head,
                        DurableObjectOwnerProjection::default(),
                    );
                    store.preload_object(object_id, corrupt_head, None);
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectRecordMismatch { object_id },
                    )
                }),
                false,
            ),
            (
                "object body substitution",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x61; 32]);
                    let genuine_object = test_object(object_id, 1, Owner::Address(sender), 0x61);
                    let (_, digest) =
                        hashed_object_version(genuine_object.clone(), "sunrise-test", 1);
                    let mut substituted_object = genuine_object;
                    substituted_object.data = vec![0xFF; 4];
                    let provenance = DurableObjectProvenance::new(
                        ChainId::new("sunrise-test").unwrap(),
                        ProtocolVersion::new(3),
                    );
                    let tampered_record = DurableObjectVersionRecord::from_inline_object(
                        substituted_object,
                        digest,
                        provenance,
                        1,
                    )
                    .unwrap();
                    let head = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                            sender,
                        ))
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, head, Some(tampered_record));
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectBodyDigestMismatch { object_id },
                    )
                }),
                false,
            ),
            (
                "object provenance chain mismatch",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x64; 32]);
                    let object = test_object(object_id, 1, Owner::Address(sender), 0x64);
                    let (record, digest) = hashed_object_version(object, "sunrise-other-chain", 1);
                    let head = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                            sender,
                        ))
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, head, Some(record));
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectProvenanceMismatch { object_id },
                    )
                }),
                false,
            ),
            (
                "unsupported digest algorithm",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x65; 32]);
                    let object = test_object(object_id, 1, Owner::Address(sender), 0x65);
                    let digest = Digest32::new(HashAlgorithmId::Blake3_256, [0x66; 32]);
                    let provenance = DurableObjectProvenance::new(
                        ChainId::new("sunrise-test").unwrap(),
                        ProtocolVersion::new(3),
                    );
                    let record = DurableObjectVersionRecord::from_inline_object(
                        object, digest, provenance, 1,
                    )
                    .unwrap();
                    let head = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                            sender,
                        ))
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, head, Some(record));
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectDigestUnverifiable {
                            object_id,
                            algorithm: HashAlgorithmId::Blake3_256,
                        },
                    )
                }),
                false,
            ),
            (
                "object body over per-object bound",
                Box::new(move || {
                    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                    let object_id = ObjectId::new([0x67; 32]);
                    let mut object = test_object(object_id, 1, Owner::Address(sender), 0x67);
                    object.data = Vec::new();
                    let empty_length = encode_object(&object).unwrap().len();
                    object.data = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1 - empty_length];
                    let body_length = encode_object(&object).unwrap().len();
                    let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
                    let head = DurableObjectHead::Current {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                            sender,
                        ))
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    };
                    store.preload_object(object_id, head, Some(record));
                    let manifest = manifest_with(vec![AccessEntry {
                        object_ref: ObjectRef {
                            id: object_id,
                            version: 1,
                            digest,
                        },
                        mode: AccessMode::Read,
                    }]);
                    (
                        store,
                        manifest,
                        NodeCoreError::ObjectBodyTooLarge {
                            object_id,
                            actual: body_length,
                            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                        },
                    )
                }),
                false,
            ),
        ];

        for (index, (name, build, expect_zero_object_io)) in cases.into_iter().enumerate() {
            let (store, manifest, expected_error) = build();
            let machine = IdempotentMachine {
                calls: AtomicUsize::new(0),
            };
            let request_byte = 0xD2u8.wrapping_add(u8::try_from(index).unwrap());
            let error = handle_authenticated_resolved_durable_submit_transaction(
                &store,
                &durable_context(),
                &resolver("sunrise-test"),
                authenticated_submission_with_manifest(
                    "sunrise-test",
                    request(request_byte),
                    &signing_key,
                    Epoch::new(7),
                    0,
                    manifest,
                    &node_config,
                    &protocol_config,
                ),
                &machine,
            )
            .unwrap_err();
            assert_eq!(error, expected_error, "case: {name}");
            assert_eq!(machine.calls.load(Ordering::SeqCst), 0, "case: {name}");
            if expect_zero_object_io {
                assert_eq!(store.state_reads.load(Ordering::SeqCst), 0, "case: {name}");
                assert_eq!(
                    store.object_head_reads.load(Ordering::SeqCst),
                    0,
                    "case: {name}"
                );
            }
        }
    }

    /// An object created under a different protocol version than the current
    /// event still verifies, because node-core recomputes with the record's
    /// own stored provenance and never with the reader's epoch-selected hash
    /// suite. This is the regression test that forbids reintroducing
    /// `HashSuiteResolver`-based digest recomputation.
    #[test]
    fn object_created_under_an_older_protocol_version_still_verifies() {
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF5);
        let signing_key = dev_signing_key(0xB5);
        let sender: Address = dev_sender_address(&signing_key);
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x62; 32]);
        let object = test_object(object_id, 1, Owner::Address(sender), 0x62);
        let (record, digest) = hashed_object_version_with_protocol_version(
            object,
            "sunrise-test",
            ProtocolVersion::new(2),
            1,
        );
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            mode: AccessMode::Read,
        }]);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated_submission_with_manifest(
                "sunrise-test",
                request(0xE1),
                &signing_key,
                Epoch::new(7),
                0,
                manifest,
                &node_config,
                &protocol_config,
            ),
            &machine,
        )
        .unwrap();
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.commits.lock().unwrap().len(), 1);
    }

    /// A stored digest whose algorithm differs from the reader's active epoch
    /// suite still verifies, because the algorithm comes from the
    /// self-describing stored digest, not the epoch suite.
    #[test]
    fn object_digest_algorithm_differing_from_reader_epoch_suite_still_verifies() {
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF6);
        let signing_key = dev_signing_key(0xB6);
        let sender: Address = dev_sender_address(&signing_key);
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x63; 32]);
        let object = test_object(object_id, 1, Owner::Address(sender), 0x63);
        let canonical_bytes = encode_object(&object).unwrap();
        let chain_id = ChainId::new("sunrise-test").unwrap();
        let protocol_version = ProtocolVersion::new(3);
        let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha3_256)
            .hash(
                HashPurpose::Object,
                protocol_version,
                &chain_id,
                &canonical_bytes,
            )
            .unwrap();
        let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
        let record =
            DurableObjectVersionRecord::from_inline_object(object, digest, provenance, 1).unwrap();
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            mode: AccessMode::Read,
        }]);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated_submission_with_manifest(
                "sunrise-test",
                request(0xE2),
                &signing_key,
                Epoch::new(7),
                0,
                manifest,
                &node_config,
                &protocol_config,
            ),
            &machine,
        )
        .unwrap();
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    }

    /// 32 entries individually under the per-object bound whose sum crosses
    /// the aggregate bound are rejected without ever reaching the transition.
    #[test]
    fn object_bodies_over_aggregate_bound_reject_before_transition_or_commit() {
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xFA);
        let signing_key = dev_signing_key(0xBA);
        let sender: Address = dev_sender_address(&signing_key);
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        const PER_OBJECT_BYTES: usize = 300_000;
        const _: () = assert!(PER_OBJECT_BYTES < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
        const _: () = assert!(
            MAX_AUTHENTICATED_OBJECT_READS * PER_OBJECT_BYTES
                > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES
        );
        let mut entries: Vec<AccessEntry> = Vec::with_capacity(MAX_AUTHENTICATED_OBJECT_READS);
        for index in 0..MAX_AUTHENTICATED_OBJECT_READS {
            let byte = u8::try_from(index).unwrap();
            let object_id = ObjectId::new([byte; 32]);
            let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
            object.data = Vec::new();
            let empty_length = encode_object(&object).unwrap().len();
            object.data = vec![0; PER_OBJECT_BYTES - empty_length];
            let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
            let head = DurableObjectHead::Current {
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            };
            store.preload_object(object_id, head, Some(record));
            entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: object_id,
                    version: 1,
                    digest,
                },
                mode: AccessMode::Read,
            });
        }
        let manifest = manifest_with(entries);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated_submission_with_manifest(
                "sunrise-test",
                request(0xE6),
                &signing_key,
                Epoch::new(7),
                0,
                manifest,
                &node_config,
                &protocol_config,
            ),
            &machine,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NodeCoreError::ObjectBodyTooLarge {
                maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
                ..
            }
        ));
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn receipt_and_nonce_short_circuit_before_authenticated_object_reads() {
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF3);
        let signing_key = dev_signing_key(0xB3);
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x51),
            mode: AccessMode::Read,
        }]);
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let stale_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let stale_submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xD7),
            &signing_key,
            Epoch::new(7),
            1,
            manifest.clone(),
            &node_config,
            &protocol_config,
        );
        assert!(matches!(
            handle_authenticated_resolved_durable_submit_transaction(
                &stale_store,
                &durable_context(),
                &resolver("sunrise-test"),
                stale_submission,
                &machine,
            ),
            Err(NodeCoreError::SenderNonceMismatch { .. })
        ));
        assert_eq!(stale_store.object_head_reads.load(Ordering::SeqCst), 0);

        let replay_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let replay_submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xD8),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let event_digest: Digest32 = replay_submission
            .event()
            .digest(&resolver("sunrise-test"))
            .unwrap();
        let response: NodeResponse = NodeResponse::new(
            replay_submission.event().request_id(),
            NodeResponseStatus::Accepted,
            None,
        )
        .unwrap();
        let record: NodeDedupRecord = NodeDedupRecord::new(
            replay_submission.event().request_id(),
            event_digest,
            vec![response],
        )
        .unwrap();
        replay_store.receipt.lock().unwrap().replace(
            DurableRequestReceipt::new(
                DurableRequestId::new(*replay_submission.event().request_id().as_bytes()).unwrap(),
                event_digest,
                record.encode().unwrap(),
            )
            .unwrap(),
        );
        let replay = handle_authenticated_resolved_durable_submit_transaction(
            &replay_store,
            &durable_context(),
            &resolver("sunrise-test"),
            replay_submission,
            &machine,
        )
        .unwrap();
        assert_eq!(replay.output().responses().len(), 1);
        assert_eq!(replay_store.state_reads.load(Ordering::SeqCst), 0);
        assert_eq!(replay_store.object_head_reads.load(Ordering::SeqCst), 0);
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authenticated_object_head_conflict_is_retryable_and_distinct() {
        let object_id: ObjectId = ObjectId::new([0x61; 32]);
        let conflict = DurableCommitRejection::ObjectConflict {
            object_id,
            current: runtime::DurableObjectHeadSummary::Absent,
        };
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(conflict));
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF4);
        let signing_key = dev_signing_key(0xB4);
        let sender: Address = dev_sender_address(&signing_key);
        let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            object_id,
            Owner::Address(sender),
            0x61,
        );
        let submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xD9),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Read,
            }]),
            &node_config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let error = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::ObjectConflict { object_id });
        assert_eq!(store.commits.lock().unwrap().len(), 1);
        assert!(store.receipt.lock().unwrap().is_none());
    }

    /// Commits an object directly against a real [`MemoryDurableStateStore`]
    /// (bypassing node-core, which does not implement object writes), then
    /// authorizes and commits a non-empty read-only manifest referencing it
    /// through the full authenticated submit-transaction path.
    #[test]
    fn memory_store_authenticated_read_only_manifest_commits_against_real_object_store() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF7);
        let signing_key = dev_signing_key(0xC7);
        let sender: Address = dev_sender_address(&signing_key);
        let context = durable_context();
        let resolver = resolver("sunrise-test");
        let object_domain = domain(0xF7);
        let object_id = ObjectId::new([0x81; 32]);

        let object = test_object(object_id, 1, Owner::Address(sender), 0x81);
        let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
        let create_mutation = runtime::DurableObjectMutation::Create {
            version: record,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        let create_changes = DurableObjectChanges::new(
            vec![runtime::DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![runtime::DurableObjectMutationEntry::new(
                object_id,
                create_mutation,
            )],
        )
        .unwrap();
        let create_receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0x21; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            vec![0x23],
        )
        .unwrap();
        let create_invocation = DurableInvocationTransaction::new(
            object_domain,
            None,
            create_changes,
            create_receipt,
            None,
        )
        .unwrap();
        assert_eq!(
            store.commit_invocation(&context, create_invocation),
            DurableCommitOutcome::Committed
        );

        let manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            mode: AccessMode::Read,
        }]);
        let submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE5),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let resolved = handle_authenticated_resolved_durable_submit_transaction(
            &store, &context, &resolver, submission, &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolved.domain(), object_domain);
        assert_eq!(resolved.output().responses().len(), 1);

        let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let persisted_nonce = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record = SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
    }

    #[test]
    fn memory_store_authenticated_owned_write_commits_atomically_and_replays_receipt() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFA);
        let signing_key: SigningKey = dev_signing_key(0xCA);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xFA);
        let read_id: ObjectId = ObjectId::new([0x84; 32]);
        let write_id: ObjectId = ObjectId::new([0x94; 32]);
        let read_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(read_id, 1, Owner::Immutable, 0x84),
            "sunrise-test",
            4,
            0x31,
        );
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0x94),
            "sunrise-test",
            5,
            0x34,
        );
        let manifest: AccessManifest = manifest_with(vec![
            AccessEntry {
                object_ref: write_ref,
                mode: AccessMode::Write,
            },
            AccessEntry {
                object_ref: read_ref,
                mode: AccessMode::Read,
            },
        ]);
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE8),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
        let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
            expected_inputs: vec![(write_id, AccessMode::Write), (read_id, AccessMode::Read)],
            replacement_byte: 0xA4,
            calls: AtomicUsize::new(0),
        };

        let first: ResolvedNodeOutput =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &store,
                &context,
                &hash_resolver,
                submission,
                6,
                &machine,
            )
            .unwrap();
        let replay: ResolvedNodeOutput =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &store,
                &context,
                &hash_resolver,
                replay_submission,
                999,
                &machine,
            )
            .unwrap();

        assert_eq!(first, replay);
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
        let write_v2: DurableObjectVersionRecord = store
            .get_object_version(
                &context,
                object_domain,
                write_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(write_v2.created_checkpoint(), 6);
        assert_eq!(
            write_v2.payload().inline().unwrap().object().data,
            vec![0xA4]
        );
        let read_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, read_id)
            .unwrap();
        assert_eq!(read_head.object_version(), DurableObjectVersion::new(1));
        let nonce_key: Vec<u8> =
            sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let persisted_nonce: VersionedStateValue = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record: SenderNonceRecord =
            SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
    }

    // ── preinstalled WASM composition (Developer MVP step 3) ────────────────

    /// A contract that overwrites `object[0]`'s data with a fixed byte,
    /// exactly like `execution::wasm_engine`'s own `write_object_contract`
    /// test fixture.
    fn preinstalled_write_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (data (i32.const 0) "\CA\FE")
                (func (export "run")
                  (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))))"#,
        )
        .unwrap()
    }

    /// A contract that always traps via `abort`.
    fn preinstalled_trap_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (data (i32.const 0) "contract-secret-abort-marker")
                (func (export "run")
                  (call $abort (i32.const 0) (i32.const 28))))"#,
        )
        .unwrap()
    }

    /// A contract that succeeds without touching any resolved object, even
    /// though the transaction may declare `Write`/`Consume` access.
    fn preinstalled_noop_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory 1)
                (export "memory" (memory 0))
                (func (export "run")))"#,
        )
        .unwrap()
    }

    /// A contract that consumes `object[0]`.
    fn preinstalled_consume_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (func (export "run")
                  (drop (call $consume_object (i32.const 0)))))"#,
        )
        .unwrap()
    }

    /// A contract that calls `create_object` once, matching
    /// `execution::wasm_engine`'s own `create_object` test fixture layout
    /// (34-byte type hash at offset 0, one data byte at offset 34).
    fn preinstalled_create_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF")
                (func (export "run")
                  (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))))"#,
        )
        .unwrap()
    }

    fn preinstalled_manifest(
        module_id: ModuleId,
        max_input_size: u64,
    ) -> system_modules::SystemModuleManifest {
        system_modules::SystemModuleManifest {
            module_id,
            input_schema: system_modules::TypeSchema {
                descriptor: "counter.input.v1".to_string(),
                schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
            },
            output_schema: system_modules::TypeSchema {
                descriptor: "counter.output.v1".to_string(),
                schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            },
            max_input_size,
            gas_model: system_modules::GasModel {
                base_cost: 1,
                per_input_byte_cost: 1,
            },
            zk_hint: None,
        }
    }

    /// Builds a committed [`SystemModuleRegistry`] entry and a matching
    /// [`PreinstalledModuleCatalog`] entry whose commitments agree, plus the
    /// `ObjectRef` an authenticated transaction must declare as `module_ref`
    /// to reference it (see [`preinstalled_wasm::resolve_preinstalled_module`]
    /// for the exact mapping).
    fn preinstalled_module_fixture(
        resolver: &HashSuiteResolver,
        module_id: ModuleId,
        version: u64,
        wasm_bytes: Vec<u8>,
        max_input_size: u64,
        activation_epoch: Epoch,
        status: system_modules::ModuleStatus,
    ) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
        let manifest = preinstalled_manifest(module_id, max_input_size);
        let semantics_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
        let code_hash = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, &wasm_bytes)
            .unwrap();
        let manifest_bytes = system_modules::encode_system_module_manifest(&manifest).unwrap();
        let manifest_hash = resolver
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::SystemModuleManifest,
                &manifest_bytes,
            )
            .unwrap();
        let module = system_modules::SystemModule {
            module_id,
            version,
            canonical_code_hash: code_hash,
            semantics_hash,
            manifest_hash,
            activation_epoch,
            status,
        };
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(
            module_id,
            version,
            wasm_bytes,
            manifest,
            semantics_hash,
        )
        .unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
        let module_ref = ObjectRef {
            id: ObjectId::new(*module_id.as_bytes()),
            version,
            digest: code_hash,
        };
        (registry, catalog, module_ref)
    }

    fn preinstalled_transaction(
        sender: Address,
        chain: ChainId,
        epoch: Epoch,
        nonce: u64,
        access_manifest: AccessManifest,
        module_ref: ObjectRef,
        args: Vec<u8>,
    ) -> Transaction {
        Transaction {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            sender,
            nonce,
            access_manifest,
            module_ref,
            entrypoint: "run".to_string(),
            args,
            gas_limit: 1_000_000,
            fee_payment: None,
            signature: Vec::new(),
        }
    }

    #[test]
    fn preinstalled_wasm_owned_write_commits_object_nonce_and_receipt() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xFD);
        let signing_key: SigningKey = dev_signing_key(0xDA);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xFD);
        let module_id = ModuleId::new([0x70; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let write_id: ObjectId = ObjectId::new([0x95; 32]);
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0x95),
            "sunrise-test",
            9,
            0x3A,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xF0),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let resolved = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();

        assert_eq!(resolved.output().responses().len(), 1);
        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        assert!(resolved.output().responses()[0].payload().is_some());
        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
        let write_v2: DurableObjectVersionRecord = store
            .get_object_version(
                &context,
                object_domain,
                write_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            write_v2.payload().inline().unwrap().object().data,
            vec![0xCA, 0xFE]
        );
        let nonce_key: Vec<u8> =
            sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let persisted_nonce: VersionedStateValue = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record: SenderNonceRecord =
            SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
    }

    #[test]
    fn preinstalled_wasm_exact_replay_does_not_reexecute_or_reapply() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xFE);
        let signing_key: SigningKey = dev_signing_key(0xDB);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xFE);
        let module_id = ModuleId::new([0x71; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let write_id: ObjectId = ObjectId::new([0x96; 32]);
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0x96),
            "sunrise-test",
            9,
            0x3B,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xF1),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
        let engine = WasmExecutionEngine;

        let first = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();
        // An empty catalog and a different composition-trusted checkpoint on
        // replay prove that the persisted receipt short-circuits before module
        // resolution, object load, checkpoint validation, or execution.
        let empty_catalog: PreinstalledModuleCatalog =
            PreinstalledModuleCatalog::new(Vec::new()).unwrap();
        let replay = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &empty_catalog,
            &engine,
            replay_submission,
            999,
        )
        .unwrap();

        assert_eq!(first, replay);
        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
        assert!(
            store
                .get_object_version(
                    &context,
                    object_domain,
                    write_id,
                    DurableObjectVersion::new(3).unwrap(),
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn preinstalled_wasm_rejects_unknown_inactive_and_not_yet_active_module_before_commit() {
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFF);
        let signing_key: SigningKey = dev_signing_key(0xDC);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x72; 32]);
        let engine = WasmExecutionEngine;

        // Unknown: empty registry, nonempty catalog.
        let (_, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let empty_registry = SystemModuleRegistry::new();
        let run_case = |registry: &SystemModuleRegistry,
                        catalog: &PreinstalledModuleCatalog,
                        module_ref: ObjectRef,
                        request_byte: u8|
         -> (NodeCoreError, usize) {
            let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
            let (object_ref, _) = preload_inline_object(
                &store,
                "sunrise-test",
                ObjectId::new([request_byte; 32]),
                Owner::Address(sender),
                request_byte,
            );
            let manifest = manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Read,
            }]);
            let tx = preinstalled_transaction(
                sender,
                ChainId::new("sunrise-test").unwrap(),
                Epoch::new(7),
                0,
                manifest,
                module_ref,
                vec![1, 2],
            );
            let submission = authenticated_submission_from_transaction(
                "sunrise-test",
                request(request_byte),
                &signing_key,
                Epoch::new(7),
                tx,
                &node_config,
                &{
                    let mut committed_config: ProtocolConfig = protocol_config.clone();
                    committed_config.system_modules = registry.clone();
                    committed_config
                },
            );
            let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
                &store,
                &durable_context(),
                &hash_resolver,
                catalog,
                &engine,
                submission,
                9,
            )
            .unwrap_err();
            (error, store.commits.lock().unwrap().len())
        };

        let (error, commits) = run_case(&empty_registry, &catalog, module_ref.clone(), 0xA0);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleUnknown {
                module_id,
                version: 1
            }
        );
        assert_eq!(commits, 0);

        // Pending (not yet activated / not Active): registry has the module,
        // but its status is Pending.
        let (pending_registry, _, pending_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            2,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Pending,
        );
        let pending_entry = PreinstalledModuleCatalogEntry::new(
            module_id,
            2,
            preinstalled_write_wasm_bytes(),
            preinstalled_manifest(module_id, 64),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
        )
        .unwrap();
        let pending_catalog = PreinstalledModuleCatalog::new(vec![pending_entry]).unwrap();
        let (error, commits) = run_case(&pending_registry, &pending_catalog, pending_ref, 0xA1);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleInactive {
                module_id,
                version: 2
            }
        );
        assert_eq!(commits, 0);

        // Active but not yet activated at the transaction's epoch (7).
        let (future_registry, future_catalog, future_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            3,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(8),
            system_modules::ModuleStatus::Active,
        );
        let (error, commits) = run_case(&future_registry, &future_catalog, future_ref, 0xA2);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleNotYetActive {
                module_id,
                version: 3,
                activation_epoch: Epoch::new(8),
                current_epoch: Epoch::new(7),
            }
        );
        assert_eq!(commits, 0);
    }

    #[test]
    fn preinstalled_wasm_rejects_reference_digest_code_manifest_and_semantics_mismatch_before_commit()
     {
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xF6);
        let signing_key: SigningKey = dev_signing_key(0xDD);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let engine = WasmExecutionEngine;

        let run_case = |registry: SystemModuleRegistry,
                        catalog: PreinstalledModuleCatalog,
                        module_ref: ObjectRef,
                        request_byte: u8|
         -> (NodeCoreError, usize) {
            let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
            let (object_ref, _) = preload_inline_object(
                &store,
                "sunrise-test",
                ObjectId::new([request_byte; 32]),
                Owner::Address(sender),
                request_byte,
            );
            let manifest = manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Read,
            }]);
            let tx = preinstalled_transaction(
                sender,
                ChainId::new("sunrise-test").unwrap(),
                Epoch::new(7),
                0,
                manifest,
                module_ref,
                vec![1, 2],
            );
            let submission = authenticated_submission_from_transaction(
                "sunrise-test",
                request(request_byte),
                &signing_key,
                Epoch::new(7),
                tx,
                &node_config,
                &{
                    let mut committed_config: ProtocolConfig = protocol_config.clone();
                    committed_config.system_modules = registry.clone();
                    committed_config
                },
            );
            let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
                &store,
                &durable_context(),
                &hash_resolver,
                &catalog,
                &engine,
                submission,
                9,
            )
            .unwrap_err();
            (error, store.commits.lock().unwrap().len())
        };

        // Declared `module_ref.digest` disagrees with the registry commitment.
        let module_id_a = ModuleId::new([0x73; 32]);
        let (registry_a, catalog_a, ref_a) = preinstalled_module_fixture(
            &hash_resolver,
            module_id_a,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let mut tampered_ref = ref_a.clone();
        tampered_ref.digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
        let (error, commits) = run_case(registry_a, catalog_a, tampered_ref, 0xB0);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
                module_id: module_id_a,
                version: 1
            }
        );
        assert_eq!(commits, 0);

        // Not cataloged: registry commits it, but no catalog entry exists.
        let module_id_b = ModuleId::new([0x74; 32]);
        let (registry_b, _catalog_b, ref_b) = preinstalled_module_fixture(
            &hash_resolver,
            module_id_b,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let empty_catalog = PreinstalledModuleCatalog::new(vec![]).unwrap();
        let (error, commits) = run_case(registry_b, empty_catalog, ref_b, 0xB1);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleNotCataloged {
                module_id: module_id_b,
                version: 1
            }
        );
        assert_eq!(commits, 0);

        // Registry code hash disagrees with the catalog's actual WASM bytes.
        let module_id_c = ModuleId::new([0x75; 32]);
        let (mut registry_c, catalog_c, mut ref_c) = preinstalled_module_fixture(
            &hash_resolver,
            module_id_c,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let mut tampered_module = registry_c.get(module_id_c, 1).unwrap().clone();
        tampered_module.canonical_code_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
        registry_c = SystemModuleRegistry::new();
        registry_c.add_module(tampered_module.clone()).unwrap();
        ref_c.digest = tampered_module.canonical_code_hash;
        let (error, commits) = run_case(registry_c, catalog_c, ref_c, 0xB2);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: module_id_c,
                version: 1
            }
        );
        assert_eq!(commits, 0);

        // Registry manifest hash disagrees with the catalog's actual manifest.
        let module_id_d = ModuleId::new([0x76; 32]);
        let (mut registry_d, catalog_d, ref_d) = preinstalled_module_fixture(
            &hash_resolver,
            module_id_d,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let mut tampered_manifest_module = registry_d.get(module_id_d, 1).unwrap().clone();
        tampered_manifest_module.manifest_hash =
            Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
        registry_d = SystemModuleRegistry::new();
        registry_d.add_module(tampered_manifest_module).unwrap();
        let (error, commits) = run_case(registry_d, catalog_d, ref_d, 0xB3);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleManifestHashMismatch {
                module_id: module_id_d,
                version: 1
            }
        );
        assert_eq!(commits, 0);

        // Registry semantics hash disagrees with the catalog entry.
        let module_id_e = ModuleId::new([0x77; 32]);
        let (mut registry_e, catalog_e, ref_e) = preinstalled_module_fixture(
            &hash_resolver,
            module_id_e,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        let mut tampered_semantics_module = registry_e.get(module_id_e, 1).unwrap().clone();
        tampered_semantics_module.semantics_hash =
            Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
        registry_e = SystemModuleRegistry::new();
        registry_e.add_module(tampered_semantics_module).unwrap();
        let (error, commits) = run_case(registry_e, catalog_e, ref_e, 0xB4);
        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
                module_id: module_id_e,
                version: 1
            }
        );
        assert_eq!(commits, 0);
    }

    #[test]
    fn preinstalled_wasm_rejects_oversized_args_before_execution() {
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xF8);
        let signing_key: SigningKey = dev_signing_key(0xDE);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x78; 32]);
        // max_input_size = 1, but args below are 2 bytes.
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            1,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([0x98; 32]),
            Owner::Address(sender),
            0x98,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xB5),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleArgsTooLarge {
                module_id,
                version: 1,
                actual: 2,
                maximum: 1,
            }
        );
        assert_eq!(store.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn preinstalled_wasm_trapped_execution_commits_deterministic_rejected_receipt_without_object_mutation()
     {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xF9);
        let signing_key: SigningKey = dev_signing_key(0xDF);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xF9);
        let module_id = ModuleId::new([0x79; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_trap_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let write_id: ObjectId = ObjectId::new([0x99; 32]);
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0x99),
            "sunrise-test",
            9,
            0x3C,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let expected_tx_hash: Digest32 = hash_transaction(&tx, &hash_resolver).unwrap();
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xB6),
            &signing_key,
            Epoch::new(7),
            tx.clone(),
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let resolved = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();

        assert_eq!(resolved.output().responses().len(), 1);
        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Rejected
        );
        let payload: &[u8] = resolved.output().responses()[0].payload().unwrap();

        // The contract's own abort message must never reach the persisted
        // payload, and neither must engine-internal (`wasmi`) text: every
        // trap is normalized to one fixed, engine-independent reason before
        // encoding (see `preinstalled_wasm::normalize_trapped_preinstalled_execution`).
        let payload_text = String::from_utf8_lossy(payload);
        assert!(!payload_text.contains("contract-secret-abort-marker"));
        assert!(!payload_text.contains("wasmi"));

        // The encoded payload is stable: it is exactly the canonical
        // encoding of the normalized closed failure (fixed reason, full
        // `gas_limit` charge, empty effects/events), independent of exactly
        // where inside the contract execution trapped.
        let expected_effects = execution::ExecutionEffects {
            tx_hash: expected_tx_hash,
            status: ExecutionStatus::Failure {
                reason: "preinstalled module execution trapped".to_string(),
            },
            object_effects: Vec::new(),
            events: Vec::new(),
            gas_used: tx.gas_limit,
        };
        let expected_payload = encode_execution_effects(&expected_effects).unwrap();
        assert_eq!(payload, expected_payload.as_slice());

        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
        let nonce_key: Vec<u8> =
            sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let persisted_nonce: VersionedStateValue = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record: SenderNonceRecord =
            SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
    }

    #[test]
    fn preinstalled_wasm_zero_object_access_is_rejected_before_domain_resolution() {
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE0);
        let signing_key: SigningKey = dev_signing_key(0xE0);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x7A; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_noop_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        // No access-manifest entries at all: this MVP path requires at least
        // one authenticated object.
        let manifest = manifest_with(Vec::new());
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC0),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::PreinstalledModuleZeroObjectAccess);
        assert_eq!(store.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn preinstalled_wasm_consume_commits_tombstone_end_to_end() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE2);
        let signing_key: SigningKey = dev_signing_key(0xE2);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xE2);
        let module_id = ModuleId::new([0x7C; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_consume_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let consume_id: ObjectId = ObjectId::new([0x9B; 32]);
        let consume_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(consume_id, 1, Owner::Address(sender), 0x9B),
            "sunrise-test",
            9,
            0x3E,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: consume_ref,
            mode: AccessMode::Consume,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC1),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let resolved = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();

        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let head: DurableObjectHead = store
            .get_object_head(&context, object_domain, consume_id)
            .unwrap();
        assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
    }

    #[test]
    fn preinstalled_wasm_create_effect_is_fail_closed() {
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE3);
        let signing_key: SigningKey = dev_signing_key(0xE3);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x7D; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_create_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([0xC2; 32]),
            Owner::Address(sender),
            0xC2,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC2),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::ObjectCreationUnsupported { .. }
        ));
        assert_eq!(store.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn preinstalled_wasm_missing_entrypoint_is_rejected() {
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE4);
        let signing_key: SigningKey = dev_signing_key(0xE4);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x7E; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([0xC3; 32]),
            Owner::Address(sender),
            0xC3,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let mut tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        tx.entrypoint = "does-not-exist".to_string();
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC4),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::Execution(ExecutionError::MissingEntrypoint(_))
        ));
        assert_eq!(store.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn preinstalled_wasm_gas_limit_exact_ceiling_succeeds_and_over_ceiling_is_rejected() {
        // Over the ceiling: rejected before the engine ever runs, no commit.
        let node_config: NodeConfig = config("sunrise-test");
        let mut over_protocol_config: ProtocolConfig = active_protocol_config(0xE5);
        let signing_key: SigningKey = dev_signing_key(0xE5);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let over_module_id = ModuleId::new([0x7F; 32]);
        let (over_registry, over_catalog, over_module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            over_module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        over_protocol_config.system_modules = over_registry;
        let over_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (over_object_ref, _) = preload_inline_object(
            &over_store,
            "sunrise-test",
            ObjectId::new([0xC5; 32]),
            Owner::Address(sender),
            0xC5,
        );
        let over_manifest = manifest_with(vec![AccessEntry {
            object_ref: over_object_ref,
            mode: AccessMode::Read,
        }]);
        let mut over_tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            over_manifest,
            over_module_ref,
            vec![1, 2],
        );
        over_tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1;
        let over_submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC6),
            &signing_key,
            Epoch::new(7),
            over_tx,
            &node_config,
            &over_protocol_config,
        );
        let engine = WasmExecutionEngine;

        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &over_store,
            &durable_context(),
            &hash_resolver,
            &over_catalog,
            &engine,
            over_submission,
            9,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
                requested: MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1,
                maximum: MAX_PREINSTALLED_MODULE_GAS_LIMIT,
            }
        );
        assert_eq!(over_store.commits.lock().unwrap().len(), 0);

        // Exactly at the ceiling: accepted and committed end-to-end.
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE6);
        let context: DurableOperationContext = durable_context();
        let object_domain: AtomicityDomainId = domain(0xE6);
        let module_id = ModuleId::new([0x80; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let write_id: ObjectId = ObjectId::new([0xC7; 32]);
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0xC7),
            "sunrise-test",
            9,
            0x3F,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        }]);
        let mut tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT;
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC7),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );

        let resolved = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();

        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    }

    #[test]
    fn preinstalled_wasm_successful_noop_on_declared_write_is_fail_closed_non_commit() {
        let node_config: NodeConfig = config("sunrise-test");
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE7);
        let signing_key: SigningKey = dev_signing_key(0xE7);
        let sender: Address = dev_sender_address(&signing_key);
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let module_id = ModuleId::new([0x81; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_noop_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([0xC8; 32]),
            Owner::Address(sender),
            0xC8,
        );
        let write_object_id = object_ref.id;
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC8),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        // The contract runs to completion without trapping (a genuine
        // `ExecutionStatus::Success`) but never calls `write_object_data`, so
        // it produces no effect for the declared `Write` access. This must
        // still fail closed instead of silently committing as a no-op.
        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectEffectMismatch {
                object_id: write_object_id,
                reason: "write access requires exactly one mutated effect",
            }
        );
        assert_eq!(store.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn preinstalled_wasm_resolves_end_to_end_across_hash_suite_rotation() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = NodeConfig::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(15),
            b"node/state".to_vec(),
        )
        .unwrap();
        let mut protocol_config: ProtocolConfig = active_protocol_config(0xE8);
        let signing_key: SigningKey = dev_signing_key(0xE8);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver =
            resolver_with_rotation("sunrise-test", Epoch::new(10));
        let object_domain: AtomicityDomainId = domain(0xE8);
        let module_id = ModuleId::new([0x82; 32]);
        // Committed while the SHA2-256 genesis suite is active (epoch 0, see
        // `preinstalled_module_fixture`).
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &hash_resolver,
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
            Epoch::new(0),
            system_modules::ModuleStatus::Active,
        );
        protocol_config.system_modules = registry;
        let write_id: ObjectId = ObjectId::new([0xC9; 32]);
        let write_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(write_id, 1, Owner::Address(sender), 0xC9),
            "sunrise-test",
            9,
            0x40,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        }]);
        // Epoch 15 is well after the resolver's SHA3-256 rotation at epoch
        // 10, even though the module was committed under the SHA2-256
        // genesis suite; resolution must still succeed (see
        // `hashing::verify_digest`).
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(15),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
            "sunrise-test",
            request(0xC9),
            &signing_key,
            Epoch::new(15),
            tx,
            &node_config,
            &protocol_config,
        );
        let engine = WasmExecutionEngine;

        let resolved = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
        )
        .unwrap();

        assert_eq!(
            resolved.output().responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let write_head: DurableObjectHead = store
            .get_object_head(&context, object_domain, write_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    }

    #[test]
    fn memory_store_authenticated_owned_consume_commits_tombstone_with_nonce() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFB);
        let signing_key: SigningKey = dev_signing_key(0xCB);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
        let object_domain: AtomicityDomainId = domain(0xFB);
        let object_id: ObjectId = ObjectId::new([0x85; 32]);
        let object_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(object_id, 1, Owner::Address(sender), 0x85),
            "sunrise-test",
            5,
            0x37,
        );
        let manifest: AccessManifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Consume,
        }]);
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE9),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
            expected_inputs: vec![(object_id, AccessMode::Consume)],
            replacement_byte: 0,
            calls: AtomicUsize::new(0),
        };

        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &store,
            &context,
            &hash_resolver,
            submission,
            6,
            &machine,
        )
        .unwrap();

        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        let head: DurableObjectHead = store
            .get_object_head(&context, object_domain, object_id)
            .unwrap();
        assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
        let nonce_key: Vec<u8> =
            sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let persisted_nonce: VersionedStateValue = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record: SenderNonceRecord =
            SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
    }

    #[test]
    fn authenticated_owned_write_requires_exact_effect_before_commit() {
        let store: ScriptedDurableStore =
            ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
        let signing_key: SigningKey = dev_signing_key(0xCC);
        let sender: Address = dev_sender_address(&signing_key);
        let object_id: ObjectId = ObjectId::new([0x86; 32]);
        let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            object_id,
            Owner::Address(sender),
            0x86,
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xEA),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Write,
            }]),
            &node_config,
            &protocol_config,
        );
        let machine: IdempotentMachine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let error: NodeCoreError =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &store,
                &durable_context(),
                &resolver("sunrise-test"),
                submission,
                2,
                &machine,
            )
            .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectEffectMismatch {
                object_id,
                reason: "write access requires exactly one mutated effect",
            }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        assert!(store.commits.lock().unwrap().is_empty());
        assert!(store.receipt.lock().unwrap().is_none());
    }

    #[test]
    fn authenticated_read_only_object_rejects_machine_effect_before_commit() {
        let store: ScriptedDurableStore =
            ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
        let signing_key: SigningKey = dev_signing_key(0xCE);
        let sender: Address = dev_sender_address(&signing_key);
        let object_id: ObjectId = ObjectId::new([0xA1; 32]);
        let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            object_id,
            Owner::Address(sender),
            0xA1,
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xEC),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Read,
            }]),
            &node_config,
            &protocol_config,
        );

        let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &ReadObjectEffectMachine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectEffectMismatch {
                object_id,
                reason: "read access produced a mutation effect",
            }
        );
        assert!(store.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn authenticated_owned_modes_reject_immutable_object_before_transition() {
        for (mode, request_byte) in [(AccessMode::Write, 0xED_u8), (AccessMode::Consume, 0xEE_u8)] {
            let store: ScriptedDurableStore =
                ScriptedDurableStore::new(DurableCommitOutcome::Committed);
            let node_config: NodeConfig = config("sunrise-test");
            let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
            let signing_key: SigningKey = dev_signing_key(0xCF);
            let object_id: ObjectId = ObjectId::new([request_byte; 32]);
            let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
                &store,
                "sunrise-test",
                object_id,
                Owner::Immutable,
                request_byte,
            );
            let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
                "sunrise-test",
                request(request_byte),
                &signing_key,
                Epoch::new(7),
                0,
                manifest_with(vec![AccessEntry { object_ref, mode }]),
                &node_config,
                &protocol_config,
            );
            let machine: IdempotentMachine = IdempotentMachine {
                calls: AtomicUsize::new(0),
            };

            let error: NodeCoreError =
                handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                    &store,
                    &durable_context(),
                    &resolver("sunrise-test"),
                    submission,
                    2,
                    &machine,
                )
                .unwrap_err();

            assert_eq!(
                error,
                NodeCoreError::ObjectOwnerKindUnsupported { object_id }
            );
            assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
            assert!(store.commits.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn authenticated_owned_write_checkpoint_regression_commits_nothing() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xF9);
        let signing_key: SigningKey = dev_signing_key(0xCD);
        let sender: Address = dev_sender_address(&signing_key);
        let context: DurableOperationContext = durable_context();
        let object_domain: AtomicityDomainId = domain(0xF9);
        let object_id: ObjectId = ObjectId::new([0x87; 32]);
        let object_ref: ObjectRef = commit_memory_inline_object(
            &store,
            &context,
            object_domain,
            test_object(object_id, 1, Owner::Address(sender), 0x87),
            "sunrise-test",
            18,
            0x3A,
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xEF),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry {
                object_ref,
                mode: AccessMode::Write,
            }]),
            &node_config,
            &protocol_config,
        );
        let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
            expected_inputs: vec![(object_id, AccessMode::Write)],
            replacement_byte: 0xA7,
            calls: AtomicUsize::new(0),
        };

        let error: NodeCoreError =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &store,
                &context,
                &resolver("sunrise-test"),
                submission,
                17,
                &machine,
            )
            .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectCreatedCheckpointRegression {
                object_id,
                previous_created_checkpoint: 18,
                attempted_created_checkpoint: 17,
            }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
        let head: DurableObjectHead = store
            .get_object_head(&context, object_domain, object_id)
            .unwrap();
        assert_eq!(head.object_version(), DurableObjectVersion::new(1));
        let nonce_key: Vec<u8> =
            sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        assert!(
            store
                .get_versioned_durable(&context, object_domain, &nonce_key)
                .unwrap()
                .value()
                .is_none()
        );
    }

    #[test]
    fn generic_durable_handler_rejects_object_effects_without_dispatch() {
        let store: ScriptedDurableStore =
            ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id: ObjectId = ObjectId::new([0xA1; 32]);

        let error: NodeCoreError = handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xFD, 7),
            &config("sunrise-test"),
            &resolver("sunrise-test"),
            event("sunrise-test", request(0xEB)),
            &UndeclaredObjectEffectMachine,
        )
        .unwrap_err();

        assert_eq!(error, NodeCoreError::UndeclaredObjectEffect { object_id });
        assert!(store.commits.lock().unwrap().is_empty());
    }

    /// One machine implementation used only to inject a genuine, deterministic
    /// TOCTOU race into a single-threaded owned-object Write test:
    /// `transition()` runs strictly after `load_and_authorize_objects` has
    /// captured its object-head snapshot and strictly before the outer
    /// invocation commits. It commits a competing update, then returns its own
    /// conflicting update effect against the stale verified input.
    struct StaleHeadRaceMachine<'a> {
        store: &'a MemoryDurableStateStore,
        context: DurableOperationContext,
        racing_invocation: Mutex<Option<DurableInvocationTransaction>>,
        calls: AtomicUsize,
    }

    impl TransactionalNodeStateMachine for StaleHeadRaceMachine<'_> {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                b"state/stale-head-race".to_vec(),
                NodeStateAccessMode::ReadOnly,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let racing_invocation = self
                .racing_invocation
                .lock()
                .unwrap()
                .take()
                .expect("the racing invocation commits exactly once");
            assert_eq!(
                self.store
                    .commit_invocation(&self.context, racing_invocation),
                DurableCommitOutcome::Committed
            );
            let [input]: &[ResolvedObject] = state.resolved_objects() else {
                panic!("expected one authenticated Write object");
            };
            assert_eq!(input.mode, AccessMode::Write);
            let mut new_object: Object = input.object.clone();
            new_object.version = new_object.version.checked_add(1).unwrap();
            new_object.data = vec![0x84];
            TransactionalNodeTransition::with_object_effects(
                Vec::new(),
                vec![ObjectEffect::Mutated {
                    previous_version: input.object.version,
                    new_object,
                }],
                NodeOutput::new(
                    vec![NodeResponse::new(
                        event.request_id(),
                        NodeResponseStatus::Accepted,
                        None,
                    )?],
                    Vec::new(),
                )?,
            )
        }
    }

    #[test]
    fn memory_store_stale_head_race_yields_object_conflict_without_consuming_nonce_then_retries() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xF8);
        let signing_key = dev_signing_key(0xC8);
        let sender: Address = dev_sender_address(&signing_key);
        let context = durable_context();
        let resolver = resolver("sunrise-test");
        let object_domain = domain(0xF8);
        let object_id = ObjectId::new([0x82; 32]);

        let object_v1 = test_object(object_id, 1, Owner::Address(sender), 0x82);
        let (record_v1, digest_v1) = hashed_object_version(object_v1, "sunrise-test", 1);
        let owner_projection =
            DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap();
        let create_mutation = runtime::DurableObjectMutation::Create {
            version: record_v1,
            owner_projection: owner_projection.clone(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        let create_changes = DurableObjectChanges::new(
            vec![runtime::DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![runtime::DurableObjectMutationEntry::new(
                object_id,
                create_mutation,
            )],
        )
        .unwrap();
        let create_receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0x24; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x25; 32]),
            vec![0x26],
        )
        .unwrap();
        let create_invocation = DurableInvocationTransaction::new(
            object_domain,
            None,
            create_changes,
            create_receipt,
            None,
        )
        .unwrap();
        assert_eq!(
            store.commit_invocation(&context, create_invocation),
            DurableCommitOutcome::Committed
        );
        let head_v1 = store
            .get_object_head(&context, object_domain, object_id)
            .unwrap();

        let object_v2 = test_object(object_id, 2, Owner::Address(sender), 0x83);
        let (record_v2, digest_v2) = hashed_object_version(object_v2, "sunrise-test", 2);
        let racing_mutation = runtime::DurableObjectMutation::Update {
            version: record_v2,
            owner_projection,
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        let racing_changes = DurableObjectChanges::new(
            vec![runtime::DurableObjectHeadRead::new(object_id, head_v1)],
            vec![runtime::DurableObjectMutationEntry::new(
                object_id,
                racing_mutation,
            )],
        )
        .unwrap();
        let racing_receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0x27; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x28; 32]),
            vec![0x29],
        )
        .unwrap();
        let racing_invocation = DurableInvocationTransaction::new(
            object_domain,
            None,
            racing_changes,
            racing_receipt,
            None,
        )
        .unwrap();

        let racing_machine = StaleHeadRaceMachine {
            store: &store,
            context,
            racing_invocation: Mutex::new(Some(racing_invocation)),
            calls: AtomicUsize::new(0),
        };
        let stale_manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest: digest_v1,
            },
            mode: AccessMode::Write,
        }]);
        let stale_submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE6),
            &signing_key,
            Epoch::new(7),
            0,
            stale_manifest,
            &node_config,
            &protocol_config,
        );

        let race_error =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &store,
                &context,
                &resolver,
                stale_submission,
                2,
                &racing_machine,
            )
            .unwrap_err();
        assert_eq!(race_error, NodeCoreError::ObjectConflict { object_id });
        assert_eq!(racing_machine.calls.load(Ordering::SeqCst), 1);

        // The outer commit was rejected atomically, so the racing write's own
        // (state-free) invocation is the only thing that committed: the
        // sender-nonce key was never written and the same nonce is still
        // expected next.
        let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
        let nonce_after_conflict = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        assert!(nonce_after_conflict.value().is_none());

        let head_v2 = store
            .get_object_head(&context, object_domain, object_id)
            .unwrap();
        assert_eq!(head_v2.object_version(), DurableObjectVersion::new(2));

        let retry_manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 2,
                digest: digest_v2,
            },
            mode: AccessMode::Read,
        }]);
        let retry_submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE7),
            &signing_key,
            Epoch::new(7),
            0,
            retry_manifest,
            &node_config,
            &protocol_config,
        );
        let retry_machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let resolved = handle_authenticated_resolved_durable_submit_transaction(
            &store,
            &context,
            &resolver,
            retry_submission,
            &retry_machine,
        )
        .unwrap();
        assert_eq!(retry_machine.calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolved.output().responses().len(), 1);

        let nonce_after_retry = store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap();
        let nonce_record = SenderNonceRecord::decode(nonce_after_retry.value().unwrap()).unwrap();
        assert_eq!(nonce_record.next_nonce, 1);
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
        assert_eq!(
            TransactionalNodeTransition::with_object_effects(
                Vec::new(),
                Vec::new(),
                NodeOutput::default(),
            ),
            Err(NodeCoreError::EmptyStateUpdates)
        );
        let effects: Vec<ObjectEffect> = (0..=MAX_AUTHENTICATED_OBJECT_READS)
            .map(|index: usize| {
                ObjectEffect::Created(test_object(
                    ObjectId::new([u8::try_from(index).unwrap(); 32]),
                    1,
                    Owner::Immutable,
                    u8::try_from(index).unwrap(),
                ))
            })
            .collect();
        assert_eq!(
            TransactionalNodeTransition::with_object_effects(
                Vec::new(),
                effects,
                NodeOutput::default(),
            ),
            Err(NodeCoreError::TooManyObjectEffects {
                actual: MAX_AUTHENTICATED_OBJECT_READS + 1,
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            })
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

    // --- DR-0082 bounded Developer MVP query API -------------------------

    #[test]
    fn query_next_nonce_true_absence_returns_zero() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let context = durable_context();

        let next_nonce = query_sender_next_nonce(
            &store,
            &context,
            domain(0xF1),
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            [0x11; 32],
        )
        .unwrap();

        assert_eq!(next_nonce, 0);
    }

    #[test]
    fn query_next_nonce_returns_advanced_persisted_value() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let context = durable_context();
        let sender = [0x12; 32];
        let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
        let record = SenderNonceRecord::new(sender, Epoch::new(7), 5);
        let transaction = AtomicStateTransaction::new(
            domain(0xF2),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(record.encode().unwrap())).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );

        let next_nonce = query_sender_next_nonce(
            &store,
            &context,
            domain(0xF2),
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            sender,
        )
        .unwrap();

        assert_eq!(next_nonce, 5);
    }

    #[test]
    fn query_next_nonce_deleted_record_fails_closed() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let context = durable_context();
        let sender = [0x13; 32];
        let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
        // A delete from true absence still installs a non-`INITIAL` revision
        // with no value: the exact "deleted while its epoch may be accepted"
        // corruption this query must fail closed on, distinct from true
        // absence (which is `INITIAL` with no value).
        let transaction = AtomicStateTransaction::new(
            domain(0xF3),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );

        let error = query_sender_next_nonce(
            &store,
            &context,
            domain(0xF3),
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            sender,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
    }

    #[test]
    fn query_next_nonce_corrupt_record_fails_closed() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        store.set_time(100);
        let context = durable_context();
        let sender = [0x14; 32];
        let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
        let transaction = AtomicStateTransaction::new(
            domain(0xF4),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(vec![0xFF, 0x00, 0x01])).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );

        let error = query_sender_next_nonce(
            &store,
            &context,
            domain(0xF4),
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            sender,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
    }

    #[test]
    fn query_object_true_absence() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x21; 32]);
        store.preload_object(object_id, DurableObjectHead::Absent, None);
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let result = query_object(&store, &context, domain(0x61), &chain_id, object_id).unwrap();

        assert_eq!(result, ObjectQueryResult::Absent { object_id });
        assert_eq!(result.object_id(), object_id);
    }

    #[test]
    fn query_object_retained_tombstone() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x22; 32]);
        let head = DurableObjectHead::Tombstoned {
            head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
            last_object_version: DurableObjectVersion::new(2).unwrap(),
        };
        store.preload_object(object_id, head, None);
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let result = query_object(&store, &context, domain(0x62), &chain_id, object_id).unwrap();

        assert_eq!(
            result,
            ObjectQueryResult::Tombstoned {
                object_id,
                head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
                last_object_version: DurableObjectVersion::new(2).unwrap(),
            }
        );
        assert_eq!(result.object_id(), object_id);
    }

    #[test]
    fn query_object_verified_current_inline() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x23; 32]);
        let owner = Owner::Address(Address::new([0x24; 32]));
        let (object_ref, _head) =
            preload_inline_object(&store, "sunrise-test", object_id, owner, 0x25);
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let result = query_object(&store, &context, domain(0x63), &chain_id, object_id).unwrap();

        match &result {
            ObjectQueryResult::CurrentInline {
                object_id: result_object_id,
                head_revision,
                object_version,
                digest,
                canonical_object_bytes,
            } => {
                assert_eq!(*result_object_id, object_id);
                assert_eq!(*head_revision, runtime::ObjectHeadRevision::FIRST);
                assert_eq!(*object_version, DurableObjectVersion::FIRST);
                assert_eq!(*digest, object_ref.digest);
                let decoded = objects::decode_object(canonical_object_bytes).unwrap();
                assert_eq!(decoded.id, object_id);
                assert_eq!(decoded.version, 1);
            }
            other => panic!("expected verified current inline object, got {other:?}"),
        }
        assert_eq!(result.object_id(), object_id);
    }

    #[test]
    fn query_object_current_blob_reference_returns_metadata_without_fetching_body() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x26; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x27; 32]);
        let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x28; 32]);
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::FIRST,
            digest,
            1,
            DurableObjectProvenance::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3),
            ),
            1,
            blob_digest,
        );
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::default(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let result = query_object(&store, &context, domain(0x64), &chain_id, object_id).unwrap();

        assert_eq!(
            result,
            ObjectQueryResult::CurrentBlobReference {
                object_id,
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                blob_digest,
            }
        );
        assert_eq!(result.object_id(), object_id);
    }

    #[test]
    fn query_object_wrong_chain_blob_reference_fails_closed() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x2C; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x2D; 32]);
        let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x2E; 32]);
        // Provenance names a different chain than the trusted chain the
        // query is scoped to: this must fail closed before ever branching on
        // inline vs. blob payload, even though a blob body is never fetched.
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::FIRST,
            digest,
            1,
            DurableObjectProvenance::new(
                ChainId::new("other-chain").unwrap(),
                ProtocolVersion::new(3),
            ),
            1,
            blob_digest,
        );
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::default(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let error = query_object(&store, &context, domain(0x6D), &chain_id, object_id).unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::ObjectProvenanceMismatch { object_id: id } if id == object_id
        ));
    }

    #[test]
    fn query_object_tampered_digest_fails_closed() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let object_id = ObjectId::new([0x29; 32]);
        let owner = Owner::Address(Address::new([0x2A; 32]));
        let object = test_object(object_id, 1, owner.clone(), 0x2B);
        let (record, _correct_digest) = hashed_object_version(object, "sunrise-test", 1);
        let inline = record.payload().inline().unwrap().clone();
        // A digest that disagrees with the actual canonical body, while head
        // and version still agree with each other, so only the independent
        // recomputation against the body itself can catch the tamper.
        let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
        let tampered_record = DurableObjectVersionRecord::from_inline_canonical_bytes(
            inline.canonical_bytes().to_vec(),
            tampered_digest,
            record.provenance().clone(),
            record.created_checkpoint(),
        )
        .unwrap();
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest: tampered_digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(tampered_record));
        let context = durable_context();
        let chain_id = ChainId::new("sunrise-test").unwrap();

        let error = query_object(&store, &context, domain(0x65), &chain_id, object_id).unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::ObjectBodyDigestMismatch { object_id: id } if id == object_id
        ));
    }

    #[test]
    fn query_receipt_true_absence() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let context = durable_context();
        let req = request(0x31);

        let result = query_request_receipt(&store, &context, domain(0x71), req).unwrap();

        assert_eq!(result, ReceiptQueryResult::Absent { request_id: req });
        assert_eq!(result.request_id(), req);
    }

    #[test]
    fn query_receipt_present_is_independently_reverified() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let context = durable_context();
        let req = request(0x32);
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
        let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
        let dedup = NodeDedupRecord::new(req, event_digest, vec![response]).unwrap();
        let canonical_bytes = dedup.encode().unwrap();
        let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
        let receipt =
            DurableRequestReceipt::new(durable_request_id, event_digest, canonical_bytes.clone())
                .unwrap();
        store.receipt.lock().unwrap().replace(receipt);

        let result = query_request_receipt(&store, &context, domain(0x72), req).unwrap();

        match &result {
            ReceiptQueryResult::Present {
                request_id: result_request_id,
                event_digest: got_digest,
                record,
            } => {
                assert_eq!(*result_request_id, req);
                assert_eq!(*got_digest, event_digest);
                assert_eq!(record.encode().unwrap(), canonical_bytes);
            }
            other => panic!("expected present receipt, got {other:?}"),
        }
        assert_eq!(result.request_id(), req);
    }

    #[test]
    fn query_receipt_corrupt_bytes_fail_closed() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let context = durable_context();
        let req = request(0x34);
        let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x35; 32]);
        let receipt =
            DurableRequestReceipt::new(durable_request_id, event_digest, vec![0xEE, 0x00]).unwrap();
        store.receipt.lock().unwrap().replace(receipt);

        let error = query_request_receipt(&store, &context, domain(0x73), req).unwrap_err();

        assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
    }

    #[test]
    fn query_receipt_outer_digest_mismatch_fails_closed() {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let context = durable_context();
        let req = request(0x36);
        let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
        let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x37; 32]);
        let outer_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x38; 32]);
        let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
        let dedup = NodeDedupRecord::new(req, record_digest, vec![response]).unwrap();
        let canonical_bytes = dedup.encode().unwrap();
        let receipt =
            DurableRequestReceipt::new(durable_request_id, outer_digest, canonical_bytes).unwrap();
        store.receipt.lock().unwrap().replace(receipt);

        let error = query_request_receipt(&store, &context, domain(0x74), req).unwrap_err();

        assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
    }
}
