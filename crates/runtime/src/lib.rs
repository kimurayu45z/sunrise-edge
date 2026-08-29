#![forbid(unsafe_code)]

//! Runtime abstraction and in-memory adapters for serverless-safe node execution.

#[cfg(any(test, feature = "durable-conformance"))]
pub mod conformance;

use core::{fmt, mem::size_of};
pub use objects::ObjectId;
use objects::{
    OBJECT_CANONICAL_TYPE_ID, Object, ObjectError, Owner, decode_object, decode_owner,
    encode_object, encode_owner,
};
pub use protocol_types::{AtomicityDomainId, ValidatorId};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors produced by runtime adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// State keys must not be empty.
    EmptyKey,
    /// Scheduled payloads must not be empty.
    EmptyScheduledPayload,
    /// Atomic state transactions must contain at least one write.
    EmptyWriteSet,
    /// Domain transactions must assert at least one state read.
    EmptyReadSet,
    /// A domain transaction exceeded its read-count bound.
    TooManyStateReads {
        /// Actual read count.
        count: usize,
        /// Maximum accepted read count.
        maximum: usize,
    },
    /// A domain transaction exceeded its aggregate byte bound.
    StateTransactionTooLarge {
        /// Aggregate bytes represented by the transaction envelope.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// An atomic state transaction exceeded its write-count bound.
    TooManyStateWrites {
        /// Actual write count.
        count: usize,
        /// Maximum accepted write count.
        maximum: usize,
    },
    /// A state key exceeded its byte-length bound.
    StateKeyTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// A state value exceeded its byte-length bound.
    StateValueTooLarge {
        /// Actual byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// An atomic state transaction contained the same key more than once.
    DuplicateStateWriteKey,
    /// A domain transaction contained the same read key more than once.
    DuplicateStateReadKey,
    /// A domain mutation had no matching read assertion.
    StateMutationWithoutRead,
    /// A revision-only assertion was supplied as a domain mutation.
    StateAssertionAsMutation,
    /// A state revision could not be incremented without wrapping.
    StateRevisionOverflow,
    /// The system clock appears to be before unix epoch.
    ClockBeforeUnixEpoch,
    /// The system clock value exceeds supported range.
    ClockOverflow,
    /// The configured outbound transport is temporarily unavailable.
    TransportUnavailable,
    /// A durable state store could not complete the requested operation.
    DurableStoreUnavailable,
    /// This durable adapter has not implemented typed object-head storage.
    UnsupportedObjectStorage,
    /// Persisted state violated the runtime revision/value invariants.
    InvalidPersistedState,
    /// An operation named a domain other than the store's bound domain.
    AtomicityDomainMismatch,
    /// A state-key scan requested more keys than one page permits.
    StateScanLimitTooLarge {
        /// Requested page size.
        requested: usize,
        /// Maximum supported page size.
        maximum: usize,
    },
    /// A state-key scan cursor did not belong to the requested prefix.
    StateScanCursorOutsidePrefix,
    /// A store returned an invalid, unordered, or out-of-range scan page.
    InvalidStateScanPage,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => write!(f, "state keys must not be empty"),
            Self::EmptyScheduledPayload => write!(f, "scheduled payloads must not be empty"),
            Self::EmptyWriteSet => write!(f, "atomic state write set must not be empty"),
            Self::EmptyReadSet => write!(f, "atomic state read set must not be empty"),
            Self::TooManyStateReads { count, maximum } => write!(
                f,
                "atomic state read set has {count} reads, maximum is {maximum}"
            ),
            Self::StateTransactionTooLarge { bytes, maximum } => write!(
                f,
                "atomic state transaction represents {bytes} bytes, maximum is {maximum}"
            ),
            Self::TooManyStateWrites { count, maximum } => write!(
                f,
                "atomic state write set has {count} writes, maximum is {maximum}"
            ),
            Self::StateKeyTooLong { length, maximum } => {
                write!(f, "state key is {length} bytes, maximum is {maximum}")
            }
            Self::StateValueTooLarge { length, maximum } => {
                write!(f, "state value is {length} bytes, maximum is {maximum}")
            }
            Self::DuplicateStateWriteKey => {
                write!(f, "atomic state write set contains a duplicate key")
            }
            Self::DuplicateStateReadKey => {
                write!(f, "atomic state read set contains a duplicate key")
            }
            Self::StateMutationWithoutRead => {
                write!(f, "atomic state mutation has no matching read assertion")
            }
            Self::StateAssertionAsMutation => {
                write!(f, "revision assertion cannot be used as a state mutation")
            }
            Self::StateRevisionOverflow => write!(f, "state revision overflow"),
            Self::ClockBeforeUnixEpoch => write!(f, "clock is before unix epoch"),
            Self::ClockOverflow => write!(f, "clock value exceeds u64 milliseconds range"),
            Self::TransportUnavailable => write!(f, "outbound transport is unavailable"),
            Self::DurableStoreUnavailable => write!(f, "durable state store is unavailable"),
            Self::UnsupportedObjectStorage => {
                write!(f, "durable adapter does not support typed object storage")
            }
            Self::InvalidPersistedState => write!(f, "persisted state violates runtime invariants"),
            Self::AtomicityDomainMismatch => {
                write!(
                    f,
                    "operation atomicity domain does not match store authority"
                )
            }
            Self::StateScanLimitTooLarge { requested, maximum } => write!(
                f,
                "state scan requested {requested} keys, maximum is {maximum}"
            ),
            Self::StateScanCursorOutsidePrefix => {
                write!(f, "state scan cursor is outside the requested prefix")
            }
            Self::InvalidStateScanPage => {
                write!(f, "state store returned an invalid key scan page")
            }
        }
    }
}

impl Error for RuntimeError {}

/// Maximum key size accepted by one transactional state operation.
pub const MAX_STATE_KEY_BYTES: usize = 4 * 1024;
/// Maximum value size accepted by one transactional state operation.
pub const MAX_STATE_VALUE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum distinct keys mutated by one atomic state transaction.
pub const MAX_ATOMIC_STATE_WRITES: usize = 4_096;
/// Maximum distinct keys observed by one atomic state transaction.
pub const MAX_ATOMIC_STATE_READS: usize = 4_096;
/// Maximum aggregate key, revision, tag, value, and domain bytes in one domain transaction.
pub const MAX_ATOMIC_STATE_TRANSACTION_BYTES: usize = 64 * 1024 * 1024;
/// Maximum keys returned by one bounded state scan page.
pub const MAX_STATE_SCAN_KEYS: usize = 1_024;
/// Maximum lease window accepted by the indexed durable outbox contract.
pub const MAX_DURABLE_OUTBOX_LEASE_MILLIS: u64 = 5 * 60 * 1_000;
/// Maximum ordered outbound messages in one structured durable invocation.
pub const MAX_DURABLE_OUTBOX_MESSAGES: usize = 1_024;
/// Maximum canonical receipt bytes in one structured durable invocation.
pub const MAX_DURABLE_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum object-head assertions in one structured durable invocation.
pub const MAX_DURABLE_OBJECT_READS: usize = 4_096;
/// Maximum object-head mutations in one structured durable invocation.
pub const MAX_DURABLE_OBJECT_MUTATIONS: usize = 4_096;
/// Maximum inline canonical bytes for one durable object version.
pub const MAX_DURABLE_INLINE_OBJECT_BYTES: usize = MAX_STATE_VALUE_BYTES;
/// Maximum bytes in one owner or routing head projection.
pub const MAX_DURABLE_OBJECT_PROJECTION_BYTES: usize = 4 * 1024;
/// Maximum aggregate represented bytes in one durable object section.
pub const MAX_DURABLE_OBJECT_CHANGES_BYTES: usize = MAX_ATOMIC_STATE_TRANSACTION_BYTES;
/// Generation-one SQL `type_id` projection for canonical [`Object`] records.
///
/// This is not the logical [`Object::type_hash`], which remains inside the
/// canonical object payload.
pub const DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID: u32 = OBJECT_CANONICAL_TYPE_ID as u32;

/// Monotonic deployment-generation token for one domain's authoritative writer.
///
/// This token belongs to fenced deployment metadata, not canonical protocol
/// state. Generation zero is reserved so an omitted fence cannot authorize a
/// write accidentally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriterFenceGeneration(NonZeroU64);

impl WriterFenceGeneration {
    /// Creates a non-zero writer generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the deployment-metadata representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next generation without permitting wraparound.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Absolute storage-operation deadline in Unix milliseconds.
///
/// Adapters must propagate this deadline through acquisition, statements, and
/// commit. Expiry does not by itself prove that an already-dispatched commit
/// aborted; such a result is [`DurableCommitOutcome::Indeterminate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageDeadline(NonZeroU64);

impl StorageDeadline {
    /// Creates a non-zero absolute deadline.
    #[must_use]
    pub const fn new(unix_millis: u64) -> Option<Self> {
        match NonZeroU64::new(unix_millis) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the absolute Unix-millisecond deadline.
    #[must_use]
    pub const fn unix_millis(self) -> u64 {
        self.0.get()
    }

    /// Returns whether the deadline has elapsed at the supplied trusted time.
    #[must_use]
    pub const fn is_expired_at(self, now_unix_millis: u64) -> bool {
        now_unix_millis >= self.unix_millis()
    }
}

/// Bounded operational identity used to correlate one durable invocation.
///
/// Correlation IDs are observability metadata. They are not accepted as
/// request identity, deduplication identity, or a protocol authorization input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageCorrelationId([u8; 16]);

impl StorageCorrelationId {
    /// Creates a non-zero correlation identity.
    #[must_use]
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        if bytes == [0; 16] {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Returns the exact operational identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Authority and budget shared by every storage operation in one invocation.
///
/// The same context must be used for all reads and the corresponding commit.
/// A store must revalidate the writer fence at commit even if earlier reads
/// accepted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableOperationContext {
    writer_fence: WriterFenceGeneration,
    deadline: StorageDeadline,
    correlation_id: StorageCorrelationId,
}

/// Validation errors for the provider-neutral indexed outbox contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexedOutboxContractError {
    /// The projected canonical request identity must not be all zeroes.
    ZeroRequestId,
    /// Lease identity must not be all zeroes.
    ZeroLeaseId,
    /// A claimed canonical outbound payload must not be empty.
    EmptyPayload,
    /// A claimed outbound payload exceeded the shared value bound.
    PayloadTooLarge {
        /// Actual payload bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// Lease expiry was not after `now` or exceeded the shared lease bound.
    InvalidLeaseWindow,
}

impl fmt::Display for IndexedOutboxContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestId => f.write_str("outbox request id must not be all zeroes"),
            Self::ZeroLeaseId => f.write_str("outbox lease id must not be all zeroes"),
            Self::EmptyPayload => f.write_str("outbox payload must not be empty"),
            Self::PayloadTooLarge { length, maximum } => {
                write!(f, "outbox payload is {length} bytes, maximum is {maximum}")
            }
            Self::InvalidLeaseWindow => f.write_str("outbox lease window is invalid"),
        }
    }
}

impl Error for IndexedOutboxContractError {}

/// Operational projection of the canonical request identity owning an outbox.
///
/// This type does not redefine request identity. Node-core must copy the exact
/// canonical `RequestId` bytes into it; adapters must not synthesize another ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboxRequestId([u8; 32]);

impl OutboxRequestId {
    /// Creates a non-zero request projection.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IndexedOutboxContractError> {
        if bytes == [0; 32] {
            return Err(IndexedOutboxContractError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact canonical request identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Non-zero, restart-safe identity for one durable outbox claim attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableOutboxLeaseId([u8; 32]);

impl DurableOutboxLeaseId {
    /// Creates a non-zero durable lease identity.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IndexedOutboxContractError> {
        if bytes == [0; 32] {
            return Err(IndexedOutboxContractError::ZeroLeaseId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact lease identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One trusted-time, single-domain indexed due-work claim request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DueOutboxClaimRequest {
    domain: AtomicityDomainId,
    now_unix_millis: u64,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
}

impl DueOutboxClaimRequest {
    /// Creates a bounded claim request.
    ///
    /// `now` comes from trusted runtime composition, never the scheduler.
    pub fn new(
        domain: AtomicityDomainId,
        now_unix_millis: u64,
        lease_id: DurableOutboxLeaseId,
        lease_expires_at_unix_millis: u64,
    ) -> Result<Self, IndexedOutboxContractError> {
        let duration = lease_expires_at_unix_millis
            .checked_sub(now_unix_millis)
            .filter(|duration| *duration > 0)
            .ok_or(IndexedOutboxContractError::InvalidLeaseWindow)?;
        if duration > MAX_DURABLE_OUTBOX_LEASE_MILLIS {
            return Err(IndexedOutboxContractError::InvalidLeaseWindow);
        }
        Ok(Self {
            domain,
            now_unix_millis,
            lease_id,
            lease_expires_at_unix_millis,
        })
    }

    /// Returns the only domain that may be queried or mutated.
    #[must_use]
    pub const fn domain(self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns trusted time used for due-work eligibility.
    #[must_use]
    pub const fn now_unix_millis(self) -> u64 {
        self.now_unix_millis
    }

    /// Returns the restart-safe lease identity.
    #[must_use]
    pub const fn lease_id(self) -> DurableOutboxLeaseId {
        self.lease_id
    }

    /// Returns the bounded lease expiry installed by a successful claim.
    #[must_use]
    pub const fn lease_expires_at_unix_millis(self) -> u64 {
        self.lease_expires_at_unix_millis
    }
}

/// One trusted-time claim for the next message of one exact committed request.
///
/// Request-path delivery uses this contract so an older due row in the same
/// domain cannot be mistaken for the invocation that just committed. The
/// request identity is copied from node-core's canonical `RequestId`; domain,
/// time, lease, and deadline authority remain trusted composition inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestOutboxClaimRequest {
    domain: AtomicityDomainId,
    request_id: OutboxRequestId,
    now_unix_millis: u64,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
}

impl RequestOutboxClaimRequest {
    /// Creates one bounded exact-request claim.
    pub fn new(
        domain: AtomicityDomainId,
        request_id: OutboxRequestId,
        now_unix_millis: u64,
        lease_id: DurableOutboxLeaseId,
        lease_expires_at_unix_millis: u64,
    ) -> Result<Self, IndexedOutboxContractError> {
        let duration = lease_expires_at_unix_millis
            .checked_sub(now_unix_millis)
            .filter(|duration| *duration > 0)
            .ok_or(IndexedOutboxContractError::InvalidLeaseWindow)?;
        if duration > MAX_DURABLE_OUTBOX_LEASE_MILLIS {
            return Err(IndexedOutboxContractError::InvalidLeaseWindow);
        }
        Ok(Self {
            domain,
            request_id,
            now_unix_millis,
            lease_id,
            lease_expires_at_unix_millis,
        })
    }

    /// Returns the manifest-resolved invocation domain.
    #[must_use]
    pub const fn domain(self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the exact committed request to claim.
    #[must_use]
    pub const fn request_id(self) -> OutboxRequestId {
        self.request_id
    }

    /// Returns trusted claim time.
    #[must_use]
    pub const fn now_unix_millis(self) -> u64 {
        self.now_unix_millis
    }

    /// Returns the restart-safe lease identity.
    #[must_use]
    pub const fn lease_id(self) -> DurableOutboxLeaseId {
        self.lease_id
    }

    /// Returns the bounded lease expiry.
    #[must_use]
    pub const fn lease_expires_at_unix_millis(self) -> u64 {
        self.lease_expires_at_unix_millis
    }
}

/// One canonical outbound payload leased from the indexed durable repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableOutboxClaim {
    request_id: OutboxRequestId,
    message_index: u32,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
    canonical_payload: Vec<u8>,
}

impl DurableOutboxClaim {
    /// Reconstructs and validates one durable claim returned by an adapter.
    pub fn from_parts(
        request_id: OutboxRequestId,
        message_index: u32,
        lease_id: DurableOutboxLeaseId,
        lease_expires_at_unix_millis: u64,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, IndexedOutboxContractError> {
        if lease_expires_at_unix_millis == 0 {
            return Err(IndexedOutboxContractError::InvalidLeaseWindow);
        }
        if canonical_payload.is_empty() {
            return Err(IndexedOutboxContractError::EmptyPayload);
        }
        if canonical_payload.len() > MAX_STATE_VALUE_BYTES {
            return Err(IndexedOutboxContractError::PayloadTooLarge {
                length: canonical_payload.len(),
                maximum: MAX_STATE_VALUE_BYTES,
            });
        }
        Ok(Self {
            request_id,
            message_index,
            lease_id,
            lease_expires_at_unix_millis,
            canonical_payload,
        })
    }

    /// Returns the canonical request identity owning this work.
    #[must_use]
    pub const fn request_id(&self) -> OutboxRequestId {
        self.request_id
    }

    /// Returns the ordered message index inside the immutable outbox batch.
    #[must_use]
    pub const fn message_index(&self) -> u32 {
        self.message_index
    }

    /// Returns the identity required for acknowledgement.
    #[must_use]
    pub const fn lease_id(&self) -> DurableOutboxLeaseId {
        self.lease_id
    }

    /// Returns the installed lease expiry.
    #[must_use]
    pub const fn lease_expires_at_unix_millis(&self) -> u64 {
        self.lease_expires_at_unix_millis
    }

    /// Returns the exact canonical outbound payload to decode and transport.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

/// Identity required to acknowledge exactly one leased outbox message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableOutboxAcknowledgement {
    domain: AtomicityDomainId,
    request_id: OutboxRequestId,
    message_index: u32,
    lease_id: DurableOutboxLeaseId,
}

impl DurableOutboxAcknowledgement {
    /// Creates an exact acknowledgement identity.
    #[must_use]
    pub const fn new(
        domain: AtomicityDomainId,
        request_id: OutboxRequestId,
        message_index: u32,
        lease_id: DurableOutboxLeaseId,
    ) -> Self {
        Self {
            domain,
            request_id,
            message_index,
            lease_id,
        }
    }

    /// Returns the only domain that may be mutated.
    #[must_use]
    pub const fn domain(self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the canonical request identity.
    #[must_use]
    pub const fn request_id(self) -> OutboxRequestId {
        self.request_id
    }

    /// Returns the exact ordered message index.
    #[must_use]
    pub const fn message_index(self) -> u32 {
        self.message_index
    }

    /// Returns the lease identity that must still own the message.
    #[must_use]
    pub const fn lease_id(self) -> DurableOutboxLeaseId {
        self.lease_id
    }
}

/// Request identity used by structured durable receipt and outbox sections.
///
/// This is the same exact canonical request projection used by indexed outbox
/// operations; the alias avoids a second 32-byte identity type.
pub type DurableRequestId = OutboxRequestId;

/// Validation failures for a structured durable invocation envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableInvocationError {
    /// Canonical completed-receipt bytes were empty.
    EmptyReceipt,
    /// Canonical completed-receipt bytes exceeded the shared bound.
    ReceiptTooLarge {
        /// Actual canonical bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// One canonical outbound message was empty.
    EmptyOutboxMessage,
    /// One canonical outbound message exceeded the shared value bound.
    OutboxMessageTooLarge {
        /// Actual canonical bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// One batch contained too many ordered messages.
    TooManyOutboxMessages {
        /// Actual message count.
        count: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// Existing canonical object encoding or decoding failed.
    InvalidCanonicalObject(ObjectError),
    /// One existing object model value used reserved object version zero.
    ZeroObjectVersion,
    /// One inline canonical object body exceeded its per-version bound.
    ObjectBodyTooLarge {
        /// Actual canonical bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// One owner projection exceeded its head-row bound.
    ObjectOwnerProjectionTooLarge {
        /// Actual projection bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// One routing projection exceeded its head-row bound.
    ObjectRoutingProjectionTooLarge {
        /// Actual projection bytes.
        length: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// One object section contained too many head assertions.
    TooManyObjectReads {
        /// Actual assertion count.
        count: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// One object section contained too many mutations.
    TooManyObjectMutations {
        /// Actual mutation count.
        count: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// One object section asserted the same object identifier more than once.
    DuplicateObjectReadId,
    /// One object section mutated the same object identifier more than once.
    DuplicateObjectMutationId,
    /// One object mutation had no matching head assertion.
    ObjectMutationWithoutRead {
        /// Object missing from the read set.
        object_id: ObjectId,
    },
    /// One object mutation was incompatible with the asserted head state.
    InvalidObjectTransition {
        /// Object whose create/update/delete transition was invalid.
        object_id: ObjectId,
    },
    /// An asserted object version could not be incremented.
    ObjectVersionOverflow {
        /// Object whose next immutable version overflowed.
        object_id: ObjectId,
    },
    /// An asserted object-head revision could not be incremented.
    ObjectHeadRevisionOverflow {
        /// Object whose ABA-safe head revision overflowed.
        object_id: ObjectId,
    },
    /// One object section exceeded its aggregate represented-byte bound.
    ObjectChangesTooLarge {
        /// Aggregate represented bytes.
        bytes: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// State and invocation sections named different logical domains.
    StateDomainMismatch,
    /// Receipt and outbox request identities differed.
    RequestIdentityMismatch,
    /// Receipt and outbox event digests differed.
    EventDigestMismatch,
    /// Aggregate envelope accounting exceeded its shared bound.
    EnvelopeTooLarge {
        /// Aggregate represented bytes.
        bytes: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
}

impl fmt::Display for DurableInvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReceipt => f.write_str("durable request receipt must not be empty"),
            Self::ReceiptTooLarge { length, maximum } => write!(
                f,
                "durable request receipt is {length} bytes, maximum is {maximum}"
            ),
            Self::EmptyOutboxMessage => f.write_str("durable outbox message must not be empty"),
            Self::OutboxMessageTooLarge { length, maximum } => write!(
                f,
                "durable outbox message is {length} bytes, maximum is {maximum}"
            ),
            Self::TooManyOutboxMessages { count, maximum } => write!(
                f,
                "durable outbox has {count} messages, maximum is {maximum}"
            ),
            Self::InvalidCanonicalObject(error) => {
                write!(f, "invalid canonical durable object: {error}")
            }
            Self::ZeroObjectVersion => f.write_str("durable object version must be non-zero"),
            Self::ObjectBodyTooLarge { length, maximum } => write!(
                f,
                "durable object body is {length} bytes, maximum is {maximum}"
            ),
            Self::ObjectOwnerProjectionTooLarge { length, maximum } => write!(
                f,
                "durable object owner projection is {length} bytes, maximum is {maximum}"
            ),
            Self::ObjectRoutingProjectionTooLarge { length, maximum } => write!(
                f,
                "durable object routing projection is {length} bytes, maximum is {maximum}"
            ),
            Self::TooManyObjectReads { count, maximum } => write!(
                f,
                "durable object section has {count} reads, maximum is {maximum}"
            ),
            Self::TooManyObjectMutations { count, maximum } => write!(
                f,
                "durable object section has {count} mutations, maximum is {maximum}"
            ),
            Self::DuplicateObjectReadId => {
                f.write_str("durable object section contains a duplicate read identifier")
            }
            Self::DuplicateObjectMutationId => {
                f.write_str("durable object section contains a duplicate mutation identifier")
            }
            Self::ObjectMutationWithoutRead { object_id } => write!(
                f,
                "durable object mutation for {object_id} has no matching head assertion"
            ),
            Self::InvalidObjectTransition { object_id } => write!(
                f,
                "durable object mutation for {object_id} is incompatible with its asserted head"
            ),
            Self::ObjectVersionOverflow { object_id } => {
                write!(f, "durable object version overflow for {object_id}")
            }
            Self::ObjectHeadRevisionOverflow { object_id } => {
                write!(f, "durable object head revision overflow for {object_id}")
            }
            Self::ObjectChangesTooLarge { bytes, maximum } => write!(
                f,
                "durable object section represents {bytes} bytes, maximum is {maximum}"
            ),
            Self::StateDomainMismatch => {
                f.write_str("durable state section belongs to another domain")
            }
            Self::RequestIdentityMismatch => {
                f.write_str("durable receipt and outbox request identities differ")
            }
            Self::EventDigestMismatch => {
                f.write_str("durable receipt and outbox event digests differ")
            }
            Self::EnvelopeTooLarge { bytes, maximum } => write!(
                f,
                "durable invocation represents {bytes} bytes, maximum is {maximum}"
            ),
        }
    }
}

impl Error for DurableInvocationError {}

impl From<ObjectError> for DurableInvocationError {
    fn from(value: ObjectError) -> Self {
        Self::InvalidCanonicalObject(value)
    }
}

/// Typed completed-request insertion for a structured durable invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRequestReceipt {
    request_id: DurableRequestId,
    event_digest: Digest32,
    canonical_bytes: Vec<u8>,
}

impl DurableRequestReceipt {
    /// Creates one bounded canonical completed-request record.
    pub fn new(
        request_id: DurableRequestId,
        event_digest: Digest32,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, DurableInvocationError> {
        if canonical_bytes.is_empty() {
            return Err(DurableInvocationError::EmptyReceipt);
        }
        if canonical_bytes.len() > MAX_DURABLE_RECEIPT_BYTES {
            return Err(DurableInvocationError::ReceiptTooLarge {
                length: canonical_bytes.len(),
                maximum: MAX_DURABLE_RECEIPT_BYTES,
            });
        }
        Ok(Self {
            request_id,
            event_digest,
            canonical_bytes,
        })
    }

    /// Returns the canonical invocation request identity.
    #[must_use]
    pub const fn request_id(&self) -> DurableRequestId {
        self.request_id
    }

    /// Returns the digest of the complete canonical input event.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the exact canonical completed-request bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// One typed canonical outbound message projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableOutboxMessage {
    payload_digest: Digest32,
    canonical_payload: Vec<u8>,
}

impl DurableOutboxMessage {
    /// Creates one bounded canonical message and its verified-by-node digest.
    pub fn new(
        payload_digest: Digest32,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, DurableInvocationError> {
        if canonical_payload.is_empty() {
            return Err(DurableInvocationError::EmptyOutboxMessage);
        }
        if canonical_payload.len() > MAX_STATE_VALUE_BYTES {
            return Err(DurableInvocationError::OutboxMessageTooLarge {
                length: canonical_payload.len(),
                maximum: MAX_STATE_VALUE_BYTES,
            });
        }
        Ok(Self {
            payload_digest,
            canonical_payload,
        })
    }

    /// Returns the self-describing canonical payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Digest32 {
        self.payload_digest
    }

    /// Returns exact canonical outbound event bytes.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

/// Typed immutable outbox insertion for one structured invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableOutboxBatch {
    request_id: DurableRequestId,
    event_digest: Digest32,
    messages: Vec<DurableOutboxMessage>,
}

impl DurableOutboxBatch {
    /// Creates one bounded ordered message batch. Empty batches are explicit.
    pub fn new(
        request_id: DurableRequestId,
        event_digest: Digest32,
        messages: Vec<DurableOutboxMessage>,
    ) -> Result<Self, DurableInvocationError> {
        if messages.len() > MAX_DURABLE_OUTBOX_MESSAGES {
            return Err(DurableInvocationError::TooManyOutboxMessages {
                count: messages.len(),
                maximum: MAX_DURABLE_OUTBOX_MESSAGES,
            });
        }
        Ok(Self {
            request_id,
            event_digest,
            messages,
        })
    }

    /// Returns the owning canonical request identity.
    #[must_use]
    pub const fn request_id(&self) -> DurableRequestId {
        self.request_id
    }

    /// Returns the input event digest shared with the receipt.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns messages in deterministic transition order.
    #[must_use]
    pub fn messages(&self) -> &[DurableOutboxMessage] {
        &self.messages
    }
}

/// Non-zero immutable version of one protocol object.
///
/// This is distinct from [`ObjectHeadRevision`]: object versions identify
/// immutable bodies, while head revisions advance on every create, update,
/// delete, and recreate to prevent ABA matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableObjectVersion(NonZeroU64);

impl DurableObjectVersion {
    /// First version assigned to a never-before-created object.
    pub const FIRST: Self = Self(NonZeroU64::MIN);
    /// Largest representable immutable object version.
    pub const MAX: Self = Self(NonZeroU64::MAX);

    /// Creates a non-zero immutable object version.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the persisted unsigned representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next immutable version without permitting wraparound.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Non-zero ABA-safe revision of one mutable object-head row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHeadRevision(NonZeroU64);

impl ObjectHeadRevision {
    /// First revision installed by a create from true absence.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Creates a non-zero object-head revision.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the persisted unsigned representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next head revision without permitting wraparound.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Existing typed object plus its unchanged canonical [`objects::encode_object`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableInlineObject {
    object: Object,
    canonical_bytes: Vec<u8>,
}

impl DurableInlineObject {
    fn from_object(object: Object) -> Result<Self, DurableInvocationError> {
        let canonical_bytes: Vec<u8> = encode_object(&object)?;
        Self::from_parts(object, canonical_bytes)
    }

    fn from_canonical_bytes(canonical_bytes: Vec<u8>) -> Result<Self, DurableInvocationError> {
        if canonical_bytes.len() > MAX_DURABLE_INLINE_OBJECT_BYTES {
            return Err(DurableInvocationError::ObjectBodyTooLarge {
                length: canonical_bytes.len(),
                maximum: MAX_DURABLE_INLINE_OBJECT_BYTES,
            });
        }
        let object: Object = decode_object(&canonical_bytes)?;
        Self::from_parts(object, canonical_bytes)
    }

    fn from_parts(
        object: Object,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, DurableInvocationError> {
        if canonical_bytes.len() > MAX_DURABLE_INLINE_OBJECT_BYTES {
            return Err(DurableInvocationError::ObjectBodyTooLarge {
                length: canonical_bytes.len(),
                maximum: MAX_DURABLE_INLINE_OBJECT_BYTES,
            });
        }
        Ok(Self {
            object,
            canonical_bytes,
        })
    }

    /// Returns the existing typed object recovered from these canonical bytes.
    #[must_use]
    pub const fn object(&self) -> &Object {
        &self.object
    }

    /// Returns exact bytes produced by the existing canonical object encoder.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Generation-one object payload: exactly one inline object or blob reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableObjectPayload {
    /// Existing canonical [`Object`] bytes stored in the version row.
    Inline(DurableInlineObject),
    /// Self-describing digest of canonical [`Object`] bytes in the blob store.
    BlobReference(Digest32),
}

impl DurableObjectPayload {
    /// Returns the inline typed object when the payload is stored locally.
    #[must_use]
    pub const fn inline(&self) -> Option<&DurableInlineObject> {
        match self {
            Self::Inline(inline) => Some(inline),
            Self::BlobReference(_) => None,
        }
    }

    /// Returns the external canonical-object digest when this is a blob row.
    #[must_use]
    pub const fn blob_digest(&self) -> Option<Digest32> {
        match self {
            Self::Inline(_) => None,
            Self::BlobReference(digest) => Some(*digest),
        }
    }
}

/// Complete generation-one immutable object-version row projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableObjectVersionRecord {
    object_id: ObjectId,
    object_version: DurableObjectVersion,
    digest: Digest32,
    schema_version: u32,
    created_checkpoint: u64,
    payload: DurableObjectPayload,
}

impl DurableObjectVersionRecord {
    /// Builds one inline record from the existing typed object model and encoder.
    ///
    /// The digest is supplied by the trusted execution layer after hashing with
    /// its configured object-digest suite; storage does not select or recompute
    /// protocol hashes.
    pub fn from_inline_object(
        object: Object,
        digest: Digest32,
        created_checkpoint: u64,
    ) -> Result<Self, DurableInvocationError> {
        let object_version: DurableObjectVersion = DurableObjectVersion::new(object.version)
            .ok_or(DurableInvocationError::ZeroObjectVersion)?;
        let object_id: ObjectId = object.id;
        let schema_version: u32 = object.schema_version;
        let payload: DurableObjectPayload =
            DurableObjectPayload::Inline(DurableInlineObject::from_object(object)?);
        Ok(Self {
            object_id,
            object_version,
            digest,
            schema_version,
            created_checkpoint,
            payload,
        })
    }

    /// Reconstructs an inline row from persisted canonical object bytes.
    pub fn from_inline_canonical_bytes(
        canonical_bytes: Vec<u8>,
        digest: Digest32,
        created_checkpoint: u64,
    ) -> Result<Self, DurableInvocationError> {
        let inline: DurableInlineObject =
            DurableInlineObject::from_canonical_bytes(canonical_bytes)?;
        let object: &Object = inline.object();
        let object_version: DurableObjectVersion = DurableObjectVersion::new(object.version)
            .ok_or(DurableInvocationError::ZeroObjectVersion)?;
        Ok(Self {
            object_id: object.id,
            object_version,
            digest,
            schema_version: object.schema_version,
            created_checkpoint,
            payload: DurableObjectPayload::Inline(inline),
        })
    }

    /// Builds one existing-schema blob-reference row.
    ///
    /// The trusted execution layer must already have verified that the
    /// referenced canonical [`Object`] has this identity, version, schema, and
    /// object digest. Storage persists the self-describing reference and does
    /// not fetch blobs or select a protocol hash suite during commit.
    #[must_use]
    pub const fn from_blob_reference(
        object_id: ObjectId,
        object_version: DurableObjectVersion,
        digest: Digest32,
        schema_version: u32,
        created_checkpoint: u64,
        blob_digest: Digest32,
    ) -> Self {
        Self {
            object_id,
            object_version,
            digest,
            schema_version,
            created_checkpoint,
            payload: DurableObjectPayload::BlobReference(blob_digest),
        }
    }

    /// Returns the row's stable object identifier.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the immutable object version.
    #[must_use]
    pub const fn object_version(&self) -> DurableObjectVersion {
        self.object_version
    }

    /// Returns the verified self-describing digest of this object version.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Returns the explicit object schema version stored with this payload.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the generation-one canonical record type projection.
    ///
    /// This is the stable `objects::Object` frame identifier stored in the SQL
    /// `type_id` column, not the logical [`Object::type_hash`].
    #[must_use]
    pub const fn canonical_record_type_id(&self) -> u32 {
        DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID
    }

    /// Returns the checkpoint that created this immutable version.
    #[must_use]
    pub const fn created_checkpoint(&self) -> u64 {
        self.created_checkpoint
    }

    /// Returns the exactly-one inline/blob payload.
    #[must_use]
    pub const fn payload(&self) -> &DurableObjectPayload {
        &self.payload
    }

    /// Returns the logical type hash when inline bytes are locally available.
    ///
    /// Blob-backed rows recover this value by fetching and decoding the
    /// referenced canonical [`Object`] with [`objects::decode_object`].
    #[must_use]
    pub const fn inline_type_hash(&self) -> Option<Digest32> {
        match &self.payload {
            DurableObjectPayload::Inline(inline) => Some(inline.object().type_hash),
            DurableObjectPayload::BlobReference(_) => None,
        }
    }
}

/// Bounded optional typed owner projection stored on a current object head.
///
/// This projection supports routing and conflict assertions but is not an
/// authorization source. Execution must load the linked immutable version,
/// verify the head version/digest, decode an inline object, and compare its
/// typed owner. Blob-backed execution requires verified blob content first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurableObjectOwnerProjection {
    owner: Option<Owner>,
    canonical_bytes: Option<Vec<u8>>,
}

impl DurableObjectOwnerProjection {
    /// Derives a bounded projection through the existing canonical owner encoder.
    pub fn from_owner(owner: Owner) -> Result<Self, DurableInvocationError> {
        let canonical_bytes: Vec<u8> = encode_owner(&owner)?;
        Self::from_parts(Some(owner), Some(canonical_bytes))
    }

    /// Reconstructs an optional typed projection from an existing head row.
    pub fn from_canonical_bytes(
        canonical_bytes: Option<Vec<u8>>,
    ) -> Result<Self, DurableInvocationError> {
        if let Some(bytes) = &canonical_bytes
            && bytes.len() > MAX_DURABLE_OBJECT_PROJECTION_BYTES
        {
            return Err(DurableInvocationError::ObjectOwnerProjectionTooLarge {
                length: bytes.len(),
                maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
            });
        }
        let owner: Option<Owner> = canonical_bytes.as_deref().map(decode_owner).transpose()?;
        Self::from_parts(owner, canonical_bytes)
    }

    fn from_parts(
        owner: Option<Owner>,
        canonical_bytes: Option<Vec<u8>>,
    ) -> Result<Self, DurableInvocationError> {
        if let Some(bytes) = &canonical_bytes
            && bytes.len() > MAX_DURABLE_OBJECT_PROJECTION_BYTES
        {
            return Err(DurableInvocationError::ObjectOwnerProjectionTooLarge {
                length: bytes.len(),
                maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
            });
        }
        Ok(Self {
            owner,
            canonical_bytes,
        })
    }

    /// Returns the typed owner when the projection is present.
    #[must_use]
    pub const fn owner(&self) -> Option<&Owner> {
        self.owner.as_ref()
    }

    /// Returns the exact optional canonical owner bytes.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.canonical_bytes.as_deref()
    }
}

/// Bounded optional routing projection stored on a current object head.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurableObjectRoutingProjection(Option<Vec<u8>>);

impl DurableObjectRoutingProjection {
    /// Creates a bounded projection while preserving absent versus empty bytes.
    pub fn new(bytes: Option<Vec<u8>>) -> Result<Self, DurableInvocationError> {
        if let Some(bytes) = &bytes
            && bytes.len() > MAX_DURABLE_OBJECT_PROJECTION_BYTES
        {
            return Err(DurableInvocationError::ObjectRoutingProjectionTooLarge {
                length: bytes.len(),
                maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact optional routing projection bytes.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

/// Exact object-head observation, including absence and retained tombstones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableObjectHead {
    /// No head row has ever existed for this object identifier.
    Absent,
    /// A delete retained the last object version and an ABA-safe head revision.
    Tombstoned {
        /// Revision installed by the delete.
        head_revision: ObjectHeadRevision,
        /// Last immutable version reconstructed from retained version history.
        ///
        /// A normalized tombstone head stores current version/digest as NULL;
        /// adapters obtain this value from the locked immutable-version history.
        last_object_version: DurableObjectVersion,
    },
    /// The body-free head points to one current immutable object version.
    Current {
        /// Revision installed by the latest create, update, or recreate.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Verified self-describing digest of the current object version.
        digest: Digest32,
        /// Bounded ownership projection used by later routing/fast-path policy.
        owner_projection: DurableObjectOwnerProjection,
        /// Bounded logical routing projection; never physical placement authority.
        routing_projection: DurableObjectRoutingProjection,
    },
}

impl DurableObjectHead {
    /// Returns the ABA-safe revision, or `None` only for true absence.
    #[must_use]
    pub const fn head_revision(&self) -> Option<ObjectHeadRevision> {
        match self {
            Self::Absent => None,
            Self::Tombstoned { head_revision, .. } | Self::Current { head_revision, .. } => {
                Some(*head_revision)
            }
        }
    }

    /// Returns the current or retained last object version.
    #[must_use]
    pub const fn object_version(&self) -> Option<DurableObjectVersion> {
        match self {
            Self::Absent => None,
            Self::Tombstoned {
                last_object_version,
                ..
            } => Some(*last_object_version),
            Self::Current { object_version, .. } => Some(*object_version),
        }
    }

    /// Returns the current self-describing digest.
    #[must_use]
    pub const fn digest(&self) -> Option<Digest32> {
        match self {
            Self::Current { digest, .. } => Some(*digest),
            Self::Absent | Self::Tombstoned { .. } => None,
        }
    }

    /// Returns the current owner projection.
    #[must_use]
    pub const fn owner_projection(&self) -> Option<&DurableObjectOwnerProjection> {
        match self {
            Self::Current {
                owner_projection, ..
            } => Some(owner_projection),
            Self::Absent | Self::Tombstoned { .. } => None,
        }
    }

    /// Returns the current logical routing projection.
    #[must_use]
    pub const fn routing_projection(&self) -> Option<&DurableObjectRoutingProjection> {
        match self {
            Self::Current {
                routing_projection, ..
            } => Some(routing_projection),
            Self::Absent | Self::Tombstoned { .. } => None,
        }
    }
}

/// Body-free object-head projection suitable for typed conflict outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableObjectHeadSummary {
    /// No head row exists.
    Absent,
    /// A delete retained the last version and head revision.
    Tombstoned {
        /// Revision installed by the delete.
        head_revision: ObjectHeadRevision,
        /// Last immutable version reconstructed from retained history.
        last_object_version: DurableObjectVersion,
    },
    /// The head points to a current immutable version.
    Current {
        /// Revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable version.
        object_version: DurableObjectVersion,
    },
}

impl From<&DurableObjectHead> for DurableObjectHeadSummary {
    fn from(head: &DurableObjectHead) -> Self {
        match head {
            DurableObjectHead::Absent => Self::Absent,
            DurableObjectHead::Tombstoned {
                head_revision,
                last_object_version,
            } => Self::Tombstoned {
                head_revision: *head_revision,
                last_object_version: *last_object_version,
            },
            DurableObjectHead::Current {
                head_revision,
                object_version,
                ..
            } => Self::Current {
                head_revision: *head_revision,
                object_version: *object_version,
            },
        }
    }
}

/// One typed exact object-head assertion from a complete invocation read set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableObjectHeadRead {
    object_id: ObjectId,
    expected: DurableObjectHead,
}

impl DurableObjectHeadRead {
    /// Creates one exact object-head assertion.
    #[must_use]
    pub const fn new(object_id: ObjectId, expected: DurableObjectHead) -> Self {
        Self {
            object_id,
            expected,
        }
    }

    /// Returns the exact object identifier that was read.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the complete expected head observation.
    #[must_use]
    pub const fn expected(&self) -> &DurableObjectHead {
        &self.expected
    }
}

/// Create, update, or delete applied after the matching head assertion passes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableObjectMutation {
    /// Creates a truly absent object or recreates a retained tombstone.
    Create {
        /// New immutable version metadata and inline canonical body.
        version: DurableObjectVersionRecord,
        /// New bounded owner projection.
        owner_projection: DurableObjectOwnerProjection,
        /// New bounded logical routing projection.
        routing_projection: DurableObjectRoutingProjection,
    },
    /// Replaces one current object with its checked next immutable version.
    Update {
        /// New immutable version metadata and inline canonical body.
        version: DurableObjectVersionRecord,
        /// Replacement bounded owner projection.
        owner_projection: DurableObjectOwnerProjection,
        /// Replacement bounded logical routing projection.
        routing_projection: DurableObjectRoutingProjection,
    },
    /// Deletes one current object while retaining version and head tombstones.
    Delete,
}

impl DurableObjectMutation {
    /// Returns the new immutable version for create/update mutations.
    #[must_use]
    pub const fn object_version(&self) -> Option<DurableObjectVersion> {
        match self {
            Self::Create { version, .. } | Self::Update { version, .. } => {
                Some(version.object_version())
            }
            Self::Delete => None,
        }
    }

    /// Returns the new immutable record for create/update mutations.
    #[must_use]
    pub const fn version(&self) -> Option<&DurableObjectVersionRecord> {
        match self {
            Self::Create { version, .. } | Self::Update { version, .. } => Some(version),
            Self::Delete => None,
        }
    }
}

/// One object mutation keyed separately from its required read assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableObjectMutationEntry {
    object_id: ObjectId,
    mutation: DurableObjectMutation,
}

impl DurableObjectMutationEntry {
    /// Creates one typed object mutation.
    #[must_use]
    pub const fn new(object_id: ObjectId, mutation: DurableObjectMutation) -> Self {
        Self {
            object_id,
            mutation,
        }
    }

    /// Returns the object identifier to mutate.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the requested create/update/delete operation.
    #[must_use]
    pub const fn mutation(&self) -> &DurableObjectMutation {
        &self.mutation
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DurableObjectChangeData {
    reads: Vec<DurableObjectHeadRead>,
    mutations: Vec<DurableObjectMutationEntry>,
}

/// Bounded canonical object-head reads and contained object mutations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableObjectChanges {
    data: Option<Arc<DurableObjectChangeData>>,
    represented_bytes: usize,
}

impl Default for DurableObjectChanges {
    fn default() -> Self {
        Self::empty()
    }
}

impl DurableObjectChanges {
    /// Creates an explicit empty object section without allocating.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            data: None,
            represented_bytes: 0,
        }
    }

    /// Validates, canonicalizes, and bounds one complete object section.
    pub fn new(
        mut reads: Vec<DurableObjectHeadRead>,
        mut mutations: Vec<DurableObjectMutationEntry>,
    ) -> Result<Self, DurableInvocationError> {
        if reads.len() > MAX_DURABLE_OBJECT_READS {
            return Err(DurableInvocationError::TooManyObjectReads {
                count: reads.len(),
                maximum: MAX_DURABLE_OBJECT_READS,
            });
        }
        if mutations.len() > MAX_DURABLE_OBJECT_MUTATIONS {
            return Err(DurableInvocationError::TooManyObjectMutations {
                count: mutations.len(),
                maximum: MAX_DURABLE_OBJECT_MUTATIONS,
            });
        }
        if reads.is_empty() && mutations.is_empty() {
            return Ok(Self::empty());
        }

        reads.sort_by_key(DurableObjectHeadRead::object_id);
        if reads
            .windows(2)
            .any(|pair| pair[0].object_id() == pair[1].object_id())
        {
            return Err(DurableInvocationError::DuplicateObjectReadId);
        }
        mutations.sort_by_key(DurableObjectMutationEntry::object_id);
        if mutations
            .windows(2)
            .any(|pair| pair[0].object_id() == pair[1].object_id())
        {
            return Err(DurableInvocationError::DuplicateObjectMutationId);
        }

        for mutation in &mutations {
            let read_index: usize = reads
                .binary_search_by_key(&mutation.object_id(), DurableObjectHeadRead::object_id)
                .map_err(|_| DurableInvocationError::ObjectMutationWithoutRead {
                    object_id: mutation.object_id(),
                })?;
            validate_object_transition(&reads[read_index], mutation)?;
        }

        let represented_bytes: usize = represented_object_change_bytes(&reads, &mutations)?;
        Ok(Self {
            data: Some(Arc::new(DurableObjectChangeData { reads, mutations })),
            represented_bytes,
        })
    }

    /// Returns whether this invocation observes and mutates no objects.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_none()
    }

    /// Returns object-head assertions in canonical identifier order.
    #[must_use]
    pub fn reads(&self) -> &[DurableObjectHeadRead] {
        self.data.as_ref().map_or(&[], |data| data.reads.as_slice())
    }

    /// Returns object mutations in canonical identifier order.
    #[must_use]
    pub fn mutations(&self) -> &[DurableObjectMutationEntry] {
        self.data
            .as_ref()
            .map_or(&[], |data| data.mutations.as_slice())
    }

    /// Returns bytes covered by deterministic object-section accounting.
    #[must_use]
    pub const fn represented_bytes(&self) -> usize {
        self.represented_bytes
    }
}

fn validate_object_transition(
    read: &DurableObjectHeadRead,
    mutation: &DurableObjectMutationEntry,
) -> Result<(), DurableInvocationError> {
    let object_id: ObjectId = mutation.object_id();
    if let Some(version) = mutation.mutation().version() {
        if version.object_id() != object_id {
            return Err(DurableInvocationError::InvalidObjectTransition { object_id });
        }
        if let DurableObjectPayload::Inline(inline) = version.payload() {
            let projected_owner: Option<&Owner> = match mutation.mutation() {
                DurableObjectMutation::Create {
                    owner_projection, ..
                }
                | DurableObjectMutation::Update {
                    owner_projection, ..
                } => owner_projection.owner(),
                DurableObjectMutation::Delete => None,
            };
            if projected_owner != Some(&inline.object().owner) {
                return Err(DurableInvocationError::InvalidObjectTransition { object_id });
            }
        }
    }
    let next_head_revision: Option<ObjectHeadRevision> = match read.expected() {
        DurableObjectHead::Absent => Some(ObjectHeadRevision::FIRST),
        DurableObjectHead::Tombstoned { head_revision, .. }
        | DurableObjectHead::Current { head_revision, .. } => head_revision.checked_next(),
    };
    if next_head_revision.is_none() {
        return Err(DurableInvocationError::ObjectHeadRevisionOverflow { object_id });
    }

    match (read.expected(), mutation.mutation()) {
        (DurableObjectHead::Absent, DurableObjectMutation::Create { version, .. })
            if version.object_version() == DurableObjectVersion::FIRST =>
        {
            Ok(())
        }
        (
            DurableObjectHead::Tombstoned {
                last_object_version: previous,
                ..
            },
            DurableObjectMutation::Create { version, .. },
        ) => match previous.checked_next() {
            Some(expected) if expected == version.object_version() => Ok(()),
            Some(_) => Err(DurableInvocationError::InvalidObjectTransition { object_id }),
            None => Err(DurableInvocationError::ObjectVersionOverflow { object_id }),
        },
        (
            DurableObjectHead::Current {
                object_version: previous,
                ..
            },
            DurableObjectMutation::Update { version, .. },
        ) => match previous.checked_next() {
            Some(expected) if expected == version.object_version() => Ok(()),
            Some(_) => Err(DurableInvocationError::InvalidObjectTransition { object_id }),
            None => Err(DurableInvocationError::ObjectVersionOverflow { object_id }),
        },
        (DurableObjectHead::Current { .. }, DurableObjectMutation::Delete) => Ok(()),
        _ => Err(DurableInvocationError::InvalidObjectTransition { object_id }),
    }
}

fn represented_object_change_bytes(
    reads: &[DurableObjectHeadRead],
    mutations: &[DurableObjectMutationEntry],
) -> Result<usize, DurableInvocationError> {
    let mut bytes: usize = 2 * size_of::<u32>();
    for read in reads {
        bytes = checked_object_bytes(bytes, read.object_id().as_bytes().len().saturating_add(1))?;
        match read.expected() {
            DurableObjectHead::Absent => {}
            DurableObjectHead::Tombstoned { .. } => {
                bytes = checked_object_bytes(bytes, 2 * size_of::<u64>())?;
            }
            DurableObjectHead::Current {
                owner_projection,
                routing_projection,
                ..
            } => {
                bytes = checked_object_bytes(
                    bytes,
                    (2 * size_of::<u64>()).saturating_add(size_of::<u16>() + 32),
                )?;
                bytes = represented_object_projection_bytes(bytes, owner_projection.bytes())?;
                bytes = represented_object_projection_bytes(bytes, routing_projection.bytes())?;
            }
        }
    }
    for mutation in mutations {
        bytes = checked_object_bytes(
            bytes,
            mutation.object_id().as_bytes().len().saturating_add(1),
        )?;
        match mutation.mutation() {
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            }
            | DurableObjectMutation::Update {
                version,
                owner_projection,
                routing_projection,
            } => {
                bytes = represented_object_version_bytes(bytes, version)?;
                bytes = represented_object_projection_bytes(bytes, owner_projection.bytes())?;
                bytes = represented_object_projection_bytes(bytes, routing_projection.bytes())?;
            }
            DurableObjectMutation::Delete => {}
        }
    }
    Ok(bytes)
}

fn represented_object_version_bytes(
    bytes: usize,
    version: &DurableObjectVersionRecord,
) -> Result<usize, DurableInvocationError> {
    let bytes: usize = checked_object_bytes(
        bytes,
        version
            .object_id()
            .as_bytes()
            .len()
            .saturating_add(2 * size_of::<u64>())
            .saturating_add(2 * size_of::<u32>())
            .saturating_add(size_of::<u16>() + 32)
            .saturating_add(1),
    )?;
    match version.payload() {
        DurableObjectPayload::Inline(inline) => checked_object_bytes(
            bytes,
            size_of::<u32>().saturating_add(inline.canonical_bytes().len()),
        ),
        DurableObjectPayload::BlobReference(_) => {
            checked_object_bytes(bytes, size_of::<u16>() + 32)
        }
    }
}

fn represented_object_projection_bytes(
    bytes: usize,
    projection: Option<&[u8]>,
) -> Result<usize, DurableInvocationError> {
    let projection_bytes: usize = projection.map_or(0, <[u8]>::len);
    checked_object_bytes(
        bytes,
        1_usize
            .saturating_add(size_of::<u32>())
            .saturating_add(projection_bytes),
    )
}

fn checked_object_bytes(
    current: usize,
    additional: usize,
) -> Result<usize, DurableInvocationError> {
    let bytes: usize =
        current
            .checked_add(additional)
            .ok_or(DurableInvocationError::ObjectChangesTooLarge {
                bytes: usize::MAX,
                maximum: MAX_DURABLE_OBJECT_CHANGES_BYTES,
            })?;
    if bytes > MAX_DURABLE_OBJECT_CHANGES_BYTES {
        return Err(DurableInvocationError::ObjectChangesTooLarge {
            bytes,
            maximum: MAX_DURABLE_OBJECT_CHANGES_BYTES,
        });
    }
    Ok(bytes)
}

/// Structured, bounded input consumed directly by normalized durable stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableInvocationTransaction {
    domain: AtomicityDomainId,
    state: Option<DurableStateTransaction>,
    objects: DurableObjectChanges,
    receipt: DurableRequestReceipt,
    outbox: Option<DurableOutboxBatch>,
    represented_bytes: usize,
}

impl DurableInvocationTransaction {
    /// Validates one typed all-or-none invocation envelope.
    pub fn new(
        domain: AtomicityDomainId,
        state: Option<DurableStateTransaction>,
        objects: DurableObjectChanges,
        receipt: DurableRequestReceipt,
        outbox: Option<DurableOutboxBatch>,
    ) -> Result<Self, DurableInvocationError> {
        if state.as_ref().is_some_and(|state| state.domain() != domain) {
            return Err(DurableInvocationError::StateDomainMismatch);
        }
        if let Some(outbox) = &outbox {
            if outbox.request_id() != receipt.request_id() {
                return Err(DurableInvocationError::RequestIdentityMismatch);
            }
            if outbox.event_digest() != receipt.event_digest() {
                return Err(DurableInvocationError::EventDigestMismatch);
            }
        }

        let mut represented_bytes = domain
            .as_bytes()
            .len()
            .saturating_add(receipt.request_id().as_bytes().len())
            .saturating_add(2 * (size_of::<u16>() + 32))
            .saturating_add(size_of::<u32>())
            .saturating_add(receipt.canonical_bytes().len());
        if let Some(state) = &state {
            represented_bytes = represented_bytes.saturating_add(state.represented_bytes());
        }
        represented_bytes = represented_bytes.saturating_add(objects.represented_bytes());
        if let Some(outbox) = &outbox {
            represented_bytes = represented_bytes
                .saturating_add(outbox.request_id().as_bytes().len())
                .saturating_add(size_of::<u32>());
            for message in outbox.messages() {
                represented_bytes = represented_bytes
                    .saturating_add(size_of::<u32>())
                    .saturating_add(size_of::<u16>() + 32)
                    .saturating_add(size_of::<u64>())
                    .saturating_add(message.canonical_payload().len());
            }
        }
        if represented_bytes > MAX_ATOMIC_STATE_TRANSACTION_BYTES {
            return Err(DurableInvocationError::EnvelopeTooLarge {
                bytes: represented_bytes,
                maximum: MAX_ATOMIC_STATE_TRANSACTION_BYTES,
            });
        }
        Ok(Self {
            domain,
            state,
            objects,
            receipt,
            outbox,
            represented_bytes,
        })
    }

    /// Returns the only domain this invocation may read or mutate.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the optional exact state section.
    #[must_use]
    pub const fn state(&self) -> Option<&DurableStateTransaction> {
        self.state.as_ref()
    }

    /// Returns the explicit object section.
    #[must_use]
    pub fn objects(&self) -> DurableObjectChanges {
        self.objects.clone()
    }

    /// Borrows the explicit object section without cloning its shared backing.
    #[must_use]
    pub const fn object_changes(&self) -> &DurableObjectChanges {
        &self.objects
    }

    /// Returns the typed completed-request insertion.
    #[must_use]
    pub const fn receipt(&self) -> &DurableRequestReceipt {
        &self.receipt
    }

    /// Returns the optional typed immutable outbox insertion.
    #[must_use]
    pub const fn outbox(&self) -> Option<&DurableOutboxBatch> {
        self.outbox.as_ref()
    }

    /// Returns aggregate bytes covered by shared envelope accounting.
    #[must_use]
    pub const fn represented_bytes(&self) -> usize {
        self.represented_bytes
    }
}

impl DurableOperationContext {
    /// Creates the bounded operational context for one durable invocation.
    #[must_use]
    pub const fn new(
        writer_fence: WriterFenceGeneration,
        deadline: StorageDeadline,
        correlation_id: StorageCorrelationId,
    ) -> Self {
        Self {
            writer_fence,
            deadline,
            correlation_id,
        }
    }

    /// Returns the writer generation that the adapter must validate.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }

    /// Returns the deadline covering acquisition through commit resolution.
    #[must_use]
    pub const fn deadline(self) -> StorageDeadline {
        self.deadline
    }

    /// Returns the operational correlation identity.
    #[must_use]
    pub const fn correlation_id(self) -> StorageCorrelationId {
        self.correlation_id
    }
}

/// Trusted cooperative signal that can stop an invocation before storage dispatch.
///
/// Native compositions may consult this signal until the first durable storage
/// operation is dispatched. Durable stores deliberately do not receive it:
/// once that operation begins, cancellation cannot prove that a later commit
/// aborted and must not terminate started synchronous work.
pub trait InvocationCancellation: fmt::Debug + Send + Sync {
    /// Returns whether the composition should reject a not-yet-dispatched invocation.
    fn is_cancelled(&self) -> bool;
}

/// Explicit cancellation policy for compositions that never cancel dispatch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeverCancelled;

impl InvocationCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Monotonic optimistic-concurrency token for one state key.
///
/// Revision zero means that the key has never been written. Deletions retain a
/// tombstone revision so a delete/recreate cycle cannot cause an ABA match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateRevision(u64);

impl StateRevision {
    /// Revision returned for a key that has never been written.
    pub const INITIAL: Self = Self(0);

    /// Creates a revision from its storage representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the storage representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next revision without permitting wraparound.
    pub fn checked_next(self) -> Result<Self, RuntimeError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(RuntimeError::StateRevisionOverflow)
    }
}

/// One versioned state observation, including a retained deletion tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedStateValue {
    revision: StateRevision,
    value: Option<Vec<u8>>,
}

impl VersionedStateValue {
    /// Reconstructs one validated persisted state observation.
    pub fn from_persisted_parts(
        revision: StateRevision,
        value: Option<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        if revision == StateRevision::INITIAL && value.is_some() {
            return Err(RuntimeError::InvalidPersistedState);
        }
        if let Some(value) = value.as_deref() {
            validate_state_value(value)?;
        }
        Ok(Self { revision, value })
    }

    /// Returns the monotonic revision observed for this key.
    #[must_use]
    pub const fn revision(&self) -> StateRevision {
        self.revision
    }

    /// Returns the present value, or `None` for an unwritten/deleted key.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// Mutation applied after its expected revision has been validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateMutation {
    /// Checks the revision without changing the key.
    Assert,
    /// Stores or replaces a value.
    Put(Vec<u8>),
    /// Deletes a value while retaining a revision tombstone.
    Delete,
}

/// One conditional mutation in an atomic write set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateWrite {
    key: Vec<u8>,
    expected_revision: StateRevision,
    mutation: StateMutation,
}

impl StateWrite {
    /// Creates and validates one conditional state mutation.
    pub fn new(
        key: Vec<u8>,
        expected_revision: StateRevision,
        mutation: StateMutation,
    ) -> Result<Self, RuntimeError> {
        validate_state_key(&key)?;
        if let StateMutation::Put(value) = &mutation {
            validate_state_value(value)?;
        }
        Ok(Self {
            key,
            expected_revision,
            mutation,
        })
    }

    /// Returns the state key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the revision that must still be current at commit time.
    #[must_use]
    pub const fn expected_revision(&self) -> StateRevision {
        self.expected_revision
    }

    /// Returns the requested mutation.
    #[must_use]
    pub const fn mutation(&self) -> &StateMutation {
        &self.mutation
    }
}

/// Bounded, unique, canonically key-ordered atomic state write set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicStateWriteSet {
    writes: Vec<StateWrite>,
}

impl AtomicStateWriteSet {
    /// Validates, sorts, and constructs an atomic write set.
    pub fn new(mut writes: Vec<StateWrite>) -> Result<Self, RuntimeError> {
        if writes.is_empty() {
            return Err(RuntimeError::EmptyWriteSet);
        }
        if writes.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(RuntimeError::TooManyStateWrites {
                count: writes.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }

        writes.sort_by(|left, right| left.key.cmp(&right.key));
        if writes.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(RuntimeError::DuplicateStateWriteKey);
        }
        Ok(Self { writes })
    }

    /// Returns writes in deterministic key order.
    #[must_use]
    pub fn writes(&self) -> &[StateWrite] {
        &self.writes
    }
}

/// One exact revision assertion from a domain transaction's complete read set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateReadAssertion {
    key: Vec<u8>,
    expected_revision: StateRevision,
}

impl StateReadAssertion {
    /// Creates one bounded exact-key revision assertion.
    pub fn new(key: Vec<u8>, expected_revision: StateRevision) -> Result<Self, RuntimeError> {
        validate_state_key(&key)?;
        Ok(Self {
            key,
            expected_revision,
        })
    }

    /// Returns the exact state key read by the transition.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the revision that must remain current at commit time.
    #[must_use]
    pub const fn expected_revision(&self) -> StateRevision {
        self.expected_revision
    }
}

/// Bounded, unique, canonically key-ordered complete read set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicStateReadSet {
    reads: Vec<StateReadAssertion>,
}

impl AtomicStateReadSet {
    /// Validates and canonicalizes exact-key revision assertions.
    pub fn new(mut reads: Vec<StateReadAssertion>) -> Result<Self, RuntimeError> {
        if reads.is_empty() {
            return Err(RuntimeError::EmptyReadSet);
        }
        if reads.len() > MAX_ATOMIC_STATE_READS {
            return Err(RuntimeError::TooManyStateReads {
                count: reads.len(),
                maximum: MAX_ATOMIC_STATE_READS,
            });
        }
        reads.sort_by(|left, right| left.key.cmp(&right.key));
        if reads.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(RuntimeError::DuplicateStateReadKey);
        }
        Ok(Self { reads })
    }

    /// Returns all exact read assertions in canonical key order.
    #[must_use]
    pub fn reads(&self) -> &[StateReadAssertion] {
        &self.reads
    }
}

/// One state mutation separated from the transaction's revision assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMutationEntry {
    key: Vec<u8>,
    mutation: StateMutation,
}

impl StateMutationEntry {
    /// Creates one bounded put/delete mutation.
    pub fn new(key: Vec<u8>, mutation: StateMutation) -> Result<Self, RuntimeError> {
        validate_state_key(&key)?;
        match &mutation {
            StateMutation::Assert => return Err(RuntimeError::StateAssertionAsMutation),
            StateMutation::Put(value) => validate_state_value(value)?,
            StateMutation::Delete => {}
        }
        Ok(Self { key, mutation })
    }

    /// Returns the exact state key to mutate.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the put/delete mutation.
    #[must_use]
    pub const fn mutation(&self) -> &StateMutation {
        &self.mutation
    }
}

/// Bounded, unique, canonically key-ordered put/delete mutation set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicStateMutationSet {
    mutations: Vec<StateMutationEntry>,
}

impl AtomicStateMutationSet {
    /// Validates and canonicalizes put/delete mutations.
    pub fn new(mutations: Vec<StateMutationEntry>) -> Result<Self, RuntimeError> {
        if mutations.is_empty() {
            return Err(RuntimeError::EmptyWriteSet);
        }
        Self::new_allow_empty(mutations)
    }

    fn new_allow_empty(mut mutations: Vec<StateMutationEntry>) -> Result<Self, RuntimeError> {
        if mutations.len() > MAX_ATOMIC_STATE_WRITES {
            return Err(RuntimeError::TooManyStateWrites {
                count: mutations.len(),
                maximum: MAX_ATOMIC_STATE_WRITES,
            });
        }
        mutations.sort_by(|left, right| left.key.cmp(&right.key));
        if mutations.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(RuntimeError::DuplicateStateWriteKey);
        }
        Ok(Self { mutations })
    }

    /// Returns all put/delete mutations in canonical key order.
    #[must_use]
    pub fn mutations(&self) -> &[StateMutationEntry] {
        &self.mutations
    }
}

/// Bounded domain-scoped transaction with separate reads and mutations.
///
/// Every mutation key must appear in `reads`. Reads may additionally contain
/// untouched read-write, read-only, absent, and tombstoned observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicStateTransaction {
    domain: AtomicityDomainId,
    reads: AtomicStateReadSet,
    mutations: AtomicStateMutationSet,
    represented_bytes: usize,
}

impl AtomicStateTransaction {
    /// Validates and canonicalizes one complete domain transaction envelope.
    pub fn new(
        domain: AtomicityDomainId,
        reads: AtomicStateReadSet,
        mutations: AtomicStateMutationSet,
    ) -> Result<Self, RuntimeError> {
        if mutations.mutations().iter().any(|mutation| {
            reads
                .reads()
                .binary_search_by(|read| read.key.as_slice().cmp(mutation.key()))
                .is_err()
        }) {
            return Err(RuntimeError::StateMutationWithoutRead);
        }

        let represented_bytes = represented_transaction_bytes(domain, &reads, &mutations);
        if represented_bytes > MAX_ATOMIC_STATE_TRANSACTION_BYTES {
            return Err(RuntimeError::StateTransactionTooLarge {
                bytes: represented_bytes,
                maximum: MAX_ATOMIC_STATE_TRANSACTION_BYTES,
            });
        }

        Ok(Self {
            domain,
            reads,
            mutations,
            represented_bytes,
        })
    }

    /// Returns the only atomicity domain this transaction may affect.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns all exact read assertions in canonical key order.
    #[must_use]
    pub fn reads(&self) -> &[StateReadAssertion] {
        self.reads.reads()
    }

    /// Returns all put/delete mutations in canonical key order.
    #[must_use]
    pub fn mutations(&self) -> &[StateMutationEntry] {
        self.mutations.mutations()
    }

    /// Returns bytes covered by the shared envelope accounting rule.
    #[must_use]
    pub const fn represented_bytes(&self) -> usize {
        self.represented_bytes
    }
}

/// Complete state section of a structured durable invocation.
///
/// Unlike the compatibility [`AtomicStateTransaction`], this section may be
/// read-only. The enclosing receipt/outbox transaction still performs the
/// durable write while every observation remains revision-asserted. An
/// invocation with no state observations omits this section entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableStateTransaction {
    domain: AtomicityDomainId,
    reads: AtomicStateReadSet,
    mutations: AtomicStateMutationSet,
    represented_bytes: usize,
}

impl DurableStateTransaction {
    /// Creates a bounded state section with zero or more contained mutations.
    pub fn new(
        domain: AtomicityDomainId,
        reads: AtomicStateReadSet,
        mutations: Vec<StateMutationEntry>,
    ) -> Result<Self, RuntimeError> {
        let mutations = AtomicStateMutationSet::new_allow_empty(mutations)?;
        if mutations.mutations().iter().any(|mutation| {
            reads
                .reads()
                .binary_search_by(|read| read.key.as_slice().cmp(mutation.key()))
                .is_err()
        }) {
            return Err(RuntimeError::StateMutationWithoutRead);
        }
        let represented_bytes = represented_transaction_bytes(domain, &reads, &mutations);
        if represented_bytes > MAX_ATOMIC_STATE_TRANSACTION_BYTES {
            return Err(RuntimeError::StateTransactionTooLarge {
                bytes: represented_bytes,
                maximum: MAX_ATOMIC_STATE_TRANSACTION_BYTES,
            });
        }
        Ok(Self {
            domain,
            reads,
            mutations,
            represented_bytes,
        })
    }

    /// Returns the only logical domain this state section may access.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns every exact state observation in canonical key order.
    #[must_use]
    pub fn reads(&self) -> &[StateReadAssertion] {
        self.reads.reads()
    }

    /// Returns state mutations in canonical key order.
    #[must_use]
    pub fn mutations(&self) -> &[StateMutationEntry] {
        self.mutations.mutations()
    }

    /// Returns bytes covered by shared state-section accounting.
    #[must_use]
    pub const fn represented_bytes(&self) -> usize {
        self.represented_bytes
    }
}

impl From<AtomicStateTransaction> for DurableStateTransaction {
    fn from(transaction: AtomicStateTransaction) -> Self {
        Self {
            domain: transaction.domain,
            reads: transaction.reads,
            mutations: transaction.mutations,
            represented_bytes: transaction.represented_bytes,
        }
    }
}

fn represented_transaction_bytes(
    domain: AtomicityDomainId,
    reads: &AtomicStateReadSet,
    mutations: &AtomicStateMutationSet,
) -> usize {
    let mut bytes = domain.as_bytes().len().saturating_add(2 * size_of::<u32>());
    for read in reads.reads() {
        bytes = bytes
            .saturating_add(size_of::<u32>())
            .saturating_add(read.key().len())
            .saturating_add(size_of::<u64>());
    }
    for mutation in mutations.mutations() {
        bytes = bytes
            .saturating_add(size_of::<u32>())
            .saturating_add(mutation.key().len())
            .saturating_add(1);
        if let StateMutation::Put(value) = mutation.mutation() {
            bytes = bytes
                .saturating_add(size_of::<u64>())
                .saturating_add(value.len());
        }
    }
    bytes
}

/// Result of one atomic state transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtomicStateWriteResult {
    /// Every expected revision matched and every mutation committed.
    Committed,
    /// No mutation was applied because one key's revision did not match.
    Conflict {
        /// First conflicting key in canonical key order.
        key: Vec<u8>,
        /// Revision observed while holding the transaction lock.
        current_revision: StateRevision,
    },
}

/// Definite, all-or-none rejection of one durable commit.
///
/// Returning any variant proves that the transaction did not commit. An
/// adapter must not use this type after losing the ability to determine the
/// commit result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableCommitRejection {
    /// The complete read set no longer matched and no mutation was applied.
    Conflict {
        /// First conflicting key in canonical key order.
        key: Vec<u8>,
        /// Revision observed while the store held commit authority.
        current_revision: StateRevision,
    },
    /// One object-head assertion no longer matched and no section was applied.
    ObjectConflict {
        /// First conflicting object in canonical identifier order.
        object_id: ObjectId,
        /// Body-free head observed while holding commit authority.
        current: DurableObjectHeadSummary,
    },
    /// The request receipt appeared after the caller's replay read.
    RequestAlreadyCommitted,
    /// The transaction named a domain other than the store's bound domain.
    AtomicityDomainMismatch,
    /// The supplied writer generation was not the active generation.
    WriterFenced {
        /// Generation that is currently authoritative.
        active_generation: WriterFenceGeneration,
    },
    /// The deadline elapsed before the adapter dispatched the commit.
    DeadlineExceededBeforeCommit,
    /// The backend aborted a serialization attempt and the bounded retry budget ended.
    SerializationFailure,
    /// A mutation revision would overflow, so no row was changed.
    StateRevisionOverflow,
    /// The namespace commit sequence would overflow, so no row was changed.
    CommitSequenceOverflow,
    /// Persisted state or an operational projection violated invariants before commit.
    InvalidPersistedState,
    /// The durable schema identity or generation is unsupported by this adapter.
    SchemaMismatch,
    /// The backend was unavailable before any commit could be dispatched.
    UnavailableBeforeCommit,
}

/// Why a durable adapter can no longer prove whether a commit happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndeterminateCommitReason {
    /// The deadline elapsed after commit may already have been dispatched.
    DeadlineExceeded,
    /// The connection or response was lost across the commit boundary.
    ConnectionLost,
    /// Cancellation arrived after commit may already have been dispatched.
    CancellationRequested,
}

/// Exhaustive result of one production durable commit attempt.
///
/// Callers may retry a [`Self::Rejected`] transaction according to policy.
/// They must reconcile [`Self::Indeterminate`] by persisted request identity;
/// blindly rerunning the transition can duplicate effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableCommitOutcome {
    /// Every assertion matched and all rows committed atomically.
    Committed,
    /// The store proves that no mutation committed.
    Rejected(DurableCommitRejection),
    /// The store cannot prove whether all mutations committed.
    Indeterminate(IndeterminateCommitReason),
}

impl From<AtomicStateWriteResult> for DurableCommitOutcome {
    fn from(value: AtomicStateWriteResult) -> Self {
        match value {
            AtomicStateWriteResult::Committed => Self::Committed,
            AtomicStateWriteResult::Conflict {
                key,
                current_revision,
            } => Self::Rejected(DurableCommitRejection::Conflict {
                key,
                current_revision,
            }),
        }
    }
}

/// A read failure from the durable domain boundary.
///
/// Reads have no commit ambiguity. They may be retried only within the original
/// operation deadline and bounded adapter policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableReadError {
    /// The caller supplied an invalid bounded key before storage I/O began.
    InvalidRequest(RuntimeError),
    /// The supplied writer generation was not the active generation.
    WriterFenced {
        /// Generation that is currently authoritative.
        active_generation: WriterFenceGeneration,
    },
    /// The operation deadline elapsed before the read completed.
    DeadlineExceeded,
    /// The backend could not complete the read.
    Unavailable,
    /// Stored bytes or projections violated persistence invariants.
    InvalidPersistedState,
    /// The durable schema identity or generation is unsupported by this adapter.
    SchemaMismatch,
}

/// Definite rejection of an indexed due-outbox claim.
///
/// Every variant proves that no new lease was installed for this request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableOutboxClaimRejection {
    /// The supplied writer generation was not authoritative.
    WriterFenced {
        /// Generation that is currently authoritative.
        active_generation: WriterFenceGeneration,
    },
    /// The storage deadline elapsed before claim commit dispatch.
    DeadlineExceededBeforeCommit,
    /// The backend proved its serialization transaction aborted.
    SerializationFailure,
    /// Delivery-attempt or lease arithmetic overflowed before claim commit.
    ArithmeticOverflow,
    /// Persisted batch, delivery, or index projections violated invariants.
    InvalidPersistedState,
    /// The durable schema identity or generation is unsupported.
    SchemaMismatch,
    /// The backend was unavailable before claim commit dispatch.
    UnavailableBeforeCommit,
    /// The lease identity was already bound to different work.
    LeaseIdReuse,
}

/// Result of one bounded indexed due-outbox claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableOutboxClaimOutcome {
    /// One due message was atomically fenced by the supplied lease.
    Claimed(DurableOutboxClaim),
    /// No eligible row existed at the indexed claim point.
    NoDueWork,
    /// The store proves that it installed no new lease.
    Rejected(DurableOutboxClaimRejection),
    /// The store cannot prove whether it installed the lease.
    Indeterminate(IndeterminateCommitReason),
}

/// Definite rejection of one durable outbox acknowledgement.
///
/// Every variant proves that the delivery cursor did not advance for this
/// acknowledgement attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableOutboxAcknowledgementRejection {
    /// The supplied writer generation was not authoritative.
    WriterFenced {
        /// Generation that is currently authoritative.
        active_generation: WriterFenceGeneration,
    },
    /// The storage deadline elapsed before acknowledgement commit dispatch.
    DeadlineExceededBeforeCommit,
    /// The backend proved its serialization transaction aborted.
    SerializationFailure,
    /// Delivery-cursor arithmetic overflowed before acknowledgement commit.
    ArithmeticOverflow,
    /// The lease does not own the requested delivery cursor.
    LeaseMismatch,
    /// The message index is not the cursor's next index.
    IndexMismatch,
    /// Persisted batch, delivery, or index projections violated invariants.
    InvalidPersistedState,
    /// The durable schema identity or generation is unsupported.
    SchemaMismatch,
    /// The backend was unavailable before acknowledgement commit dispatch.
    UnavailableBeforeCommit,
}

/// Result of one exact durable outbox acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableOutboxAcknowledgementOutcome {
    /// The cursor advanced, or the same lease/index was already acknowledged.
    Acknowledged,
    /// The store proves that the cursor did not advance for this attempt.
    Rejected(DurableOutboxAcknowledgementRejection),
    /// The store cannot prove whether the cursor advanced.
    Indeterminate(IndeterminateCommitReason),
}

/// Versioned multi-key state interface for production node-core transactions.
pub trait TransactionalStateStore: StateStore {
    /// Reads a value and its ABA-safe revision token.
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError>;

    /// Atomically checks all revisions and then applies all or none of the writes.
    fn commit_atomic(
        &self,
        write_set: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError>;
}

/// Domain-aware transaction interface for production persistence adapters.
///
/// Implementations may host many domains, but one transaction is confined to
/// the single domain carried by [`AtomicStateTransaction`].
pub trait DomainTransactionalStateStore {
    /// Reads a value and revision from one explicit atomicity domain.
    fn get_versioned_in_domain(
        &self,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, RuntimeError>;

    /// Validates the complete read set and applies every mutation or none.
    fn commit_transaction(
        &self,
        transaction: AtomicStateTransaction,
    ) -> Result<AtomicStateWriteResult, RuntimeError>;
}

/// Fenced, deadline-aware boundary for production durable domain adapters.
///
/// This is additive while node-core, SQLite, and provider adapters migrate.
/// Implementations are bound at construction to one `(chain, validator)`
/// namespace. The logical domain comes from protocol placement; the operation
/// context comes from trusted deployment composition. Neither may be selected
/// by an untrusted transport request.
pub trait DurableDomainStateStore {
    /// Reads one exact key under the invocation's fence and deadline.
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError>;

    /// Revalidates the fence and complete read set, then commits all or none.
    ///
    /// Once commit is dispatched, deadline, cancellation, or connection loss
    /// must produce [`DurableCommitOutcome::Indeterminate`] unless the backend
    /// supplies authoritative evidence that the transaction aborted.
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome;
}

/// Structured invocation boundary for normalized production durable stores.
///
/// Implementations consume typed receipt/outbox sections directly. They must
/// not inspect generic state-key prefixes to infer relational record kinds.
pub trait StructuredDurableDomainStateStore: DurableDomainStateStore {
    /// Reads one exact typed object head under the invocation authority.
    ///
    /// Existing adapters fail closed until they implement normalized object
    /// heads and immutable versions; they must never infer objects from generic
    /// state-key prefixes. The returned owner/routing projections are body-free
    /// routing metadata, not authorization. Before authorizing execution, a
    /// caller must separately read the exact immutable version, verify its
    /// version/digest against this head, decode an inline object, and compare
    /// its typed owner. Blob references require verified content first.
    fn get_object_head(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        Err(DurableReadError::InvalidRequest(
            RuntimeError::UnsupportedObjectStorage,
        ))
    }

    /// Reads one exact immutable object-version payload record.
    ///
    /// Existing adapters fail closed until they implement normalized object
    /// versions. Blob-backed records return their typed external digest rather
    /// than inventing unavailable inline bytes.
    fn get_object_version(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _object_id: ObjectId,
        _object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        Err(DurableReadError::InvalidRequest(
            RuntimeError::UnsupportedObjectStorage,
        ))
    }

    /// Reads and validates one typed completed-request receipt projection.
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError>;

    /// Commits every typed invocation section atomically or reports ambiguity.
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome;
}

/// Bounded indexed repository for unattended production outbox recovery.
///
/// Implementations must select at most one eligible row in stable
/// `(available_at, request_id)` order through a due-work index and atomically
/// install the requested lease. Full state-key or table scans do not conform.
/// A scheduler supplies no cursor, domain, time, fence, or deadline authority.
///
/// Retrying `claim_due_outbox` with the same lease ID is also reconciliation:
/// while that lease still owns work, the repository returns the identical
/// claim. Reusing the ID for different work is rejected. Acknowledgement is
/// idempotent for the same `(request, index, lease)` so callers can reconcile
/// an indeterminate acknowledgement without skipping a message.
pub trait IndexedOutboxRepository: StructuredDurableDomainStateStore {
    /// Claims the next due message for one exact committed request.
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome;

    /// Claims at most one indexed due message under the operation authority.
    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome;

    /// Advances exactly one cursor only for the matching durable lease.
    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome;
}

/// The result of a compare-and-swap state operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndSwapResult {
    /// `true` when the swap was applied.
    pub swapped: bool,
    /// The value observed at the key before the attempt.
    pub current: Option<Vec<u8>>,
}

/// Persistent state interface for deterministic node-core transitions.
pub trait StateStore {
    /// Reads a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError>;

    /// Writes a value by key.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError>;

    /// Performs an atomic conditional update.
    fn compare_and_swap(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError>;
}

/// One validated, bounded, forward-only state-key scan request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateKeyScan {
    prefix: Vec<u8>,
    after: Option<Vec<u8>>,
    limit: NonZeroUsize,
}

impl StateKeyScan {
    /// Creates a scan over keys with `prefix`, strictly after an optional cursor.
    pub fn new(
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: NonZeroUsize,
    ) -> Result<Self, RuntimeError> {
        validate_state_key(&prefix)?;
        if limit.get() > MAX_STATE_SCAN_KEYS {
            return Err(RuntimeError::StateScanLimitTooLarge {
                requested: limit.get(),
                maximum: MAX_STATE_SCAN_KEYS,
            });
        }
        if let Some(after) = after.as_deref() {
            validate_state_key(after)?;
            if !after.starts_with(&prefix) {
                return Err(RuntimeError::StateScanCursorOutsidePrefix);
            }
        }
        Ok(Self {
            prefix,
            after,
            limit,
        })
    }

    /// Returns the required key prefix.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Returns the exclusive continuation cursor, when present.
    #[must_use]
    pub fn after(&self) -> Option<&[u8]> {
        self.after.as_deref()
    }

    /// Returns the maximum keys exposed by the page.
    #[must_use]
    pub const fn limit(&self) -> NonZeroUsize {
        self.limit
    }
}

/// One validated page of canonical state keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateKeyPage {
    keys: Vec<Vec<u8>>,
    continuation_cursor: Option<Vec<u8>>,
}

impl StateKeyPage {
    /// Validates and truncates at most one lookahead key from a store query.
    ///
    /// Store implementations query up to `scan.limit() + 1` keys. The extra
    /// key proves that another page exists but is not exposed to the caller.
    pub fn from_ordered_candidates(
        scan: &StateKeyScan,
        mut keys: Vec<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        let candidate_limit = scan.limit().get() + 1;
        if keys.len() > candidate_limit
            || keys.iter().any(|key| {
                validate_state_key(key).is_err()
                    || !key.starts_with(scan.prefix())
                    || scan.after().is_some_and(|after| key.as_slice() <= after)
            })
            || keys.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        let has_more = keys.len() > scan.limit().get();
        if has_more {
            keys.pop();
        }
        let continuation_cursor = has_more.then(|| keys.last().cloned()).flatten();
        Ok(Self {
            keys,
            continuation_cursor,
        })
    }

    /// Returns keys in strictly increasing byte order.
    #[must_use]
    pub fn keys(&self) -> &[Vec<u8>] {
        &self.keys
    }

    /// Returns the last exposed key when another page is known to exist.
    #[must_use]
    pub fn continuation_cursor(&self) -> Option<&[u8]> {
        self.continuation_cursor.as_deref()
    }
}

/// Optional bounded key discovery used by recovery and maintenance adapters.
///
/// This is separate from [`StateStore`] so protocol transitions retain their
/// point-read contract and stores that cannot support ordered scans need not
/// pretend otherwise. Implementations return revision-bearing tombstone keys
/// as well as present values. Pages are individually ordered but are not a
/// multi-page snapshot: recovery callers must periodically restart at the
/// prefix to discover keys inserted before a previous cursor.
pub trait StateKeyScanner: StateStore {
    /// Returns one canonical page for a validated scan request.
    fn scan_keys(&self, scan: &StateKeyScan) -> Result<StateKeyPage, RuntimeError>;
}

/// Content-addressed blob storage interface.
pub trait BlobStore {
    /// Stores a blob under its digest key.
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError>;

    /// Loads a blob by digest key.
    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError>;
}

/// Validator signer abstraction.
pub trait Signer {
    /// Returns the validator identifier bound to this signer.
    fn validator_id(&self) -> ValidatorId;

    /// Signs a canonical payload.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, RuntimeError>;
}

/// Outbound transport abstraction over untrusted relays.
pub trait Transport {
    /// Queues an outbound protocol message.
    fn send(&self, message: Vec<u8>) -> Result<(), RuntimeError>;

    /// Returns and removes queued outbound protocol messages.
    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError>;
}

/// Clock abstraction for deterministic scheduling boundaries.
pub trait Clock {
    /// Returns unix time in milliseconds.
    fn now_unix_millis(&self) -> Result<u64, RuntimeError>;
}

/// A payload scheduled for later delivery as a tick/event input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledPayload {
    /// Unix time in milliseconds when payload becomes ready.
    pub at_unix_millis: u64,
    /// The payload to deliver.
    pub payload: Vec<u8>,
}

/// Scheduler abstraction for deferred event triggers.
pub trait Scheduler {
    /// Adds a payload to the schedule.
    fn schedule(&self, at_unix_millis: u64, payload: Vec<u8>) -> Result<(), RuntimeError>;

    /// Returns and removes scheduled payloads ready at `now_unix_millis`.
    fn drain_ready(&self, now_unix_millis: u64) -> Result<Vec<ScheduledPayload>, RuntimeError>;
}

/// Runtime composition used by node-core.
pub trait Runtime {
    /// Concrete state store type.
    type State: StateStore;
    /// Concrete blob store type.
    type Blobs: BlobStore;
    /// Concrete signer type.
    type NodeSigner: Signer;
    /// Concrete transport type.
    type Network: Transport;
    /// Concrete clock type.
    type Time: Clock;
    /// Concrete scheduler type.
    type TaskScheduler: Scheduler;

    /// Returns state store.
    fn state_store(&self) -> &Self::State;
    /// Returns blob store.
    fn blob_store(&self) -> &Self::Blobs;
    /// Returns signer.
    fn signer(&self) -> &Self::NodeSigner;
    /// Returns transport.
    fn transport(&self) -> &Self::Network;
    /// Returns clock.
    fn clock(&self) -> &Self::Time;
    /// Returns scheduler.
    fn scheduler(&self) -> &Self::TaskScheduler;
}

/// In-memory `StateStore` implementation for tests and local execution.
type MemoryDomainState = BTreeMap<[u8; 32], BTreeMap<Vec<u8>, StoredStateValue>>;

#[derive(Clone, Debug, Default)]
pub struct MemoryStateStore {
    inner: Arc<RwLock<MemoryDomainState>>,
}

const LEGACY_MEMORY_DOMAIN: [u8; 32] = [0; 32];

#[derive(Clone, Debug)]
struct StoredStateValue {
    revision: StateRevision,
    value: Option<Vec<u8>>,
}

impl StateStore for MemoryStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        ensure_non_empty_key(key)?;
        let guard = self.inner.read().expect("state store lock poisoned");
        Ok(guard
            .get(&LEGACY_MEMORY_DOMAIN)
            .and_then(|state| state.get(key))
            .and_then(|stored| stored.value.clone()))
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
        ensure_non_empty_key(&key)?;
        validate_state_key(&key)?;
        validate_state_value(&value)?;
        let mut domains = self.inner.write().expect("state store lock poisoned");
        let state = domains.entry(LEGACY_MEMORY_DOMAIN).or_default();
        let revision = current_revision(state, &key).checked_next()?;
        state.insert(
            key,
            StoredStateValue {
                revision,
                value: Some(value),
            },
        );
        Ok(())
    }

    fn compare_and_swap(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError> {
        ensure_non_empty_key(&key)?;
        validate_state_key(&key)?;
        validate_state_value(&new_value)?;

        let mut domains = self.inner.write().expect("state store lock poisoned");
        let state = domains.entry(LEGACY_MEMORY_DOMAIN).or_default();
        let current = state.get(&key).and_then(|stored| stored.value.clone());
        if current == expected {
            let revision = current_revision(state, &key).checked_next()?;
            state.insert(
                key,
                StoredStateValue {
                    revision,
                    value: Some(new_value),
                },
            );
            return Ok(CompareAndSwapResult {
                swapped: true,
                current,
            });
        }

        Ok(CompareAndSwapResult {
            swapped: false,
            current,
        })
    }
}

impl StateKeyScanner for MemoryStateStore {
    fn scan_keys(&self, scan: &StateKeyScan) -> Result<StateKeyPage, RuntimeError> {
        let domains = self.inner.read().expect("state store lock poisoned");
        let candidates = domains
            .get(&LEGACY_MEMORY_DOMAIN)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .filter(|key| key.starts_with(scan.prefix()))
            .filter(|key| scan.after().is_none_or(|after| key.as_slice() > after))
            .take(scan.limit().get() + 1)
            .cloned()
            .collect();
        StateKeyPage::from_ordered_candidates(scan, candidates)
    }
}

impl TransactionalStateStore for MemoryStateStore {
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
        validate_state_key(key)?;
        let domains = self.inner.read().expect("state store lock poisoned");
        Ok(read_memory_versioned(
            domains.get(&LEGACY_MEMORY_DOMAIN),
            key,
        ))
    }

    fn commit_atomic(
        &self,
        write_set: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        let mut domains = self.inner.write().expect("state store lock poisoned");
        let state = domains.entry(LEGACY_MEMORY_DOMAIN).or_default();

        for write in write_set.writes() {
            let current = current_revision(state, write.key());
            if current != write.expected_revision() {
                return Ok(AtomicStateWriteResult::Conflict {
                    key: write.key().to_vec(),
                    current_revision: current,
                });
            }
        }

        let revisions = write_set
            .writes()
            .iter()
            .map(|write| match write.mutation() {
                StateMutation::Assert => Ok(None),
                StateMutation::Put(_) | StateMutation::Delete => {
                    current_revision(state, write.key())
                        .checked_next()
                        .map(Some)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (write, revision) in write_set.writes.into_iter().zip(revisions) {
            let Some(revision) = revision else {
                continue;
            };
            let value = match write.mutation {
                StateMutation::Assert => continue,
                StateMutation::Put(value) => Some(value),
                StateMutation::Delete => None,
            };
            state.insert(write.key, StoredStateValue { revision, value });
        }
        Ok(AtomicStateWriteResult::Committed)
    }
}

impl DomainTransactionalStateStore for MemoryStateStore {
    fn get_versioned_in_domain(
        &self,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, RuntimeError> {
        validate_state_key(key)?;
        let domains = self.inner.read().expect("state store lock poisoned");
        Ok(read_memory_versioned(domains.get(domain.as_bytes()), key))
    }

    fn commit_transaction(
        &self,
        transaction: AtomicStateTransaction,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        let mut domains = self.inner.write().expect("state store lock poisoned");
        let state = domains.entry(*transaction.domain.as_bytes()).or_default();

        for read in transaction.reads() {
            let current = current_revision(state, read.key());
            if current != read.expected_revision() {
                return Ok(AtomicStateWriteResult::Conflict {
                    key: read.key().to_vec(),
                    current_revision: current,
                });
            }
        }

        let revisions = transaction
            .mutations()
            .iter()
            .map(|mutation| current_revision(state, mutation.key()).checked_next())
            .collect::<Result<Vec<_>, _>>()?;

        for (mutation, revision) in transaction.mutations.mutations.into_iter().zip(revisions) {
            let value = match mutation.mutation {
                StateMutation::Assert => return Err(RuntimeError::StateAssertionAsMutation),
                StateMutation::Put(value) => Some(value),
                StateMutation::Delete => None,
            };
            state.insert(mutation.key, StoredStateValue { revision, value });
        }
        Ok(AtomicStateWriteResult::Committed)
    }
}

fn read_memory_versioned(
    state: Option<&BTreeMap<Vec<u8>, StoredStateValue>>,
    key: &[u8],
) -> VersionedStateValue {
    match state.and_then(|state| state.get(key)) {
        Some(stored) => VersionedStateValue {
            revision: stored.revision,
            value: stored.value.clone(),
        },
        None => VersionedStateValue {
            revision: StateRevision::INITIAL,
            value: None,
        },
    }
}

type MemoryDurableInvocationKey = ([u8; 32], [u8; 32]);
type MemoryDurableObjectHeadKey = ([u8; 32], ObjectId);
type MemoryDurableObjectVersionKey = ([u8; 32], ObjectId, DurableObjectVersion);

#[derive(Clone, Debug, PartialEq, Eq)]
enum MemoryStoredObjectHead {
    Tombstoned {
        head_revision: ObjectHeadRevision,
    },
    Current {
        head_revision: ObjectHeadRevision,
        object_version: DurableObjectVersion,
        digest: Digest32,
        owner_projection: DurableObjectOwnerProjection,
        routing_projection: DurableObjectRoutingProjection,
    },
}

#[derive(Clone, Debug)]
struct PreparedMemoryObjectMutation {
    object_id: ObjectId,
    head: MemoryStoredObjectHead,
    version: Option<DurableObjectVersionRecord>,
}

#[derive(Debug)]
struct MemoryDurableStoreData {
    bound_domain: Option<AtomicityDomainId>,
    active_writer_fence: WriterFenceGeneration,
    now_unix_millis: u64,
    state_domains: MemoryDomainState,
    object_heads: BTreeMap<MemoryDurableObjectHeadKey, MemoryStoredObjectHead>,
    object_versions: BTreeMap<MemoryDurableObjectVersionKey, DurableObjectVersionRecord>,
    receipts: BTreeMap<MemoryDurableInvocationKey, DurableRequestReceipt>,
    outboxes: BTreeMap<MemoryDurableInvocationKey, DurableOutboxBatch>,
    deliveries: BTreeMap<MemoryDurableInvocationKey, MemoryOutboxDelivery>,
    delivery_attempts: BTreeMap<[u8; 32], MemoryOutboxDeliveryAttempt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryOutboxDelivery {
    next_index: u32,
    available_at_unix_millis: u64,
    active_lease: Option<(DurableOutboxLeaseId, u64)>,
    attempt_count: u64,
    completed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryOutboxAttemptStatus {
    Claimed,
    Acknowledged,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryOutboxDeliveryAttempt {
    domain: AtomicityDomainId,
    request_id: OutboxRequestId,
    message_index: u32,
    lease_expires_at_unix_millis: u64,
    status: MemoryOutboxAttemptStatus,
}

/// In-memory conformance fixture for the fenced structured durable contract.
///
/// This store keeps state, typed receipts, and typed outboxes under one lock so
/// tests observe the same all-or-none commit boundary expected from durable
/// adapters. Trusted time and writer generation are explicitly injected. It is
/// not a production persistence implementation and does not survive restart.
#[derive(Clone, Debug)]
pub struct MemoryDurableStateStore {
    inner: Arc<RwLock<MemoryDurableStoreData>>,
}

impl MemoryDurableStateStore {
    /// Creates an empty fixture with one authoritative writer generation.
    #[must_use]
    pub fn new(active_writer_fence: WriterFenceGeneration) -> Self {
        Self::new_with_optional_domain(None, active_writer_fence)
    }

    /// Creates an empty fixture bound to one logical atomicity domain.
    ///
    /// This mirrors production adapters that reject a caller-selected domain
    /// before touching storage while preserving [`Self::new`] for tests that
    /// intentionally exercise multiple domains in one ephemeral store.
    #[must_use]
    pub fn new_bound(
        bound_domain: AtomicityDomainId,
        active_writer_fence: WriterFenceGeneration,
    ) -> Self {
        Self::new_with_optional_domain(Some(bound_domain), active_writer_fence)
    }

    fn new_with_optional_domain(
        bound_domain: Option<AtomicityDomainId>,
        active_writer_fence: WriterFenceGeneration,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MemoryDurableStoreData {
                bound_domain,
                active_writer_fence,
                now_unix_millis: 0,
                state_domains: BTreeMap::new(),
                object_heads: BTreeMap::new(),
                object_versions: BTreeMap::new(),
                receipts: BTreeMap::new(),
                outboxes: BTreeMap::new(),
                deliveries: BTreeMap::new(),
                delivery_attempts: BTreeMap::new(),
            })),
        }
    }

    /// Sets trusted fixture time used for deadline validation.
    pub fn set_time(&self, now_unix_millis: u64) {
        self.inner
            .write()
            .expect("durable state store lock poisoned")
            .now_unix_millis = now_unix_millis;
    }

    /// Replaces the authoritative writer generation to exercise fencing.
    pub fn set_active_writer_fence(&self, active_writer_fence: WriterFenceGeneration) {
        self.inner
            .write()
            .expect("durable state store lock poisoned")
            .active_writer_fence = active_writer_fence;
    }
}

fn validate_memory_durable_read_authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
) -> Result<(), DurableReadError> {
    if context.writer_fence() != data.active_writer_fence {
        return Err(DurableReadError::WriterFenced {
            active_generation: data.active_writer_fence,
        });
    }
    if context.deadline().is_expired_at(data.now_unix_millis) {
        return Err(DurableReadError::DeadlineExceeded);
    }
    Ok(())
}

fn validate_memory_durable_read_domain(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> Result<(), DurableReadError> {
    if data.bound_domain.is_some_and(|bound| bound != domain) {
        return Err(DurableReadError::InvalidRequest(
            RuntimeError::AtomicityDomainMismatch,
        ));
    }
    Ok(())
}

fn validate_memory_durable_commit_authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
) -> Result<(), DurableCommitRejection> {
    if context.writer_fence() != data.active_writer_fence {
        return Err(DurableCommitRejection::WriterFenced {
            active_generation: data.active_writer_fence,
        });
    }
    if context.deadline().is_expired_at(data.now_unix_millis) {
        return Err(DurableCommitRejection::DeadlineExceededBeforeCommit);
    }
    Ok(())
}

fn validate_memory_durable_commit_domain(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> Result<(), DurableCommitRejection> {
    if data.bound_domain.is_some_and(|bound| bound != domain) {
        return Err(DurableCommitRejection::AtomicityDomainMismatch);
    }
    Ok(())
}

fn validate_memory_durable_reads(
    state: Option<&BTreeMap<Vec<u8>, StoredStateValue>>,
    reads: &[StateReadAssertion],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current = state.map_or(StateRevision::INITIAL, |state| {
            current_revision(state, read.key())
        });
        if current != read.expected_revision() {
            return Err(DurableCommitRejection::Conflict {
                key: read.key().to_vec(),
                current_revision: current,
            });
        }
    }
    Ok(())
}

fn memory_durable_revisions(
    state: Option<&BTreeMap<Vec<u8>, StoredStateValue>>,
    mutations: &[StateMutationEntry],
) -> Result<Vec<StateRevision>, DurableCommitRejection> {
    mutations
        .iter()
        .map(|mutation| {
            if matches!(mutation.mutation(), StateMutation::Assert) {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            state
                .map_or(StateRevision::INITIAL, |state| {
                    current_revision(state, mutation.key())
                })
                .checked_next()
                .map_err(|_| DurableCommitRejection::StateRevisionOverflow)
        })
        .collect()
}

fn apply_memory_durable_mutations(
    state: &mut BTreeMap<Vec<u8>, StoredStateValue>,
    mutations: Vec<StateMutationEntry>,
    revisions: Vec<StateRevision>,
) -> Result<(), DurableCommitRejection> {
    for (mutation, revision) in mutations.into_iter().zip(revisions) {
        let value = match mutation.mutation {
            StateMutation::Put(value) => Some(value),
            StateMutation::Delete => None,
            StateMutation::Assert => {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
        };
        state.insert(mutation.key, StoredStateValue { revision, value });
    }
    Ok(())
}

fn read_memory_object_head(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    object_id: ObjectId,
) -> Result<DurableObjectHead, DurableReadError> {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    let head_key: MemoryDurableObjectHeadKey = (domain_bytes, object_id);
    match data.object_heads.get(&head_key) {
        None => {
            let retained_version_exists: bool = data
                .object_versions
                .range(
                    (domain_bytes, object_id, DurableObjectVersion::FIRST)
                        ..=(domain_bytes, object_id, DurableObjectVersion::MAX),
                )
                .next()
                .is_some();
            if retained_version_exists {
                return Err(DurableReadError::InvalidPersistedState);
            }
            Ok(DurableObjectHead::Absent)
        }
        Some(MemoryStoredObjectHead::Tombstoned { head_revision }) => {
            let last_object_version: DurableObjectVersion = data
                .object_versions
                .range(
                    (domain_bytes, object_id, DurableObjectVersion::FIRST)
                        ..=(domain_bytes, object_id, DurableObjectVersion::MAX),
                )
                .next_back()
                .map(|(key, _)| key.2)
                .ok_or(DurableReadError::InvalidPersistedState)?;
            Ok(DurableObjectHead::Tombstoned {
                head_revision: *head_revision,
                last_object_version,
            })
        }
        Some(MemoryStoredObjectHead::Current {
            head_revision,
            object_version,
            digest,
            owner_projection,
            routing_projection,
        }) => Ok(DurableObjectHead::Current {
            head_revision: *head_revision,
            object_version: *object_version,
            digest: *digest,
            owner_projection: owner_projection.clone(),
            routing_projection: routing_projection.clone(),
        }),
    }
}

fn read_memory_object_version(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    object_id: ObjectId,
    object_version: DurableObjectVersion,
) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
    let key: MemoryDurableObjectVersionKey = (*domain.as_bytes(), object_id, object_version);
    let record: Option<DurableObjectVersionRecord> = data.object_versions.get(&key).cloned();
    if record.as_ref().is_some_and(|record| {
        record.object_id() != object_id || record.object_version() != object_version
    }) {
        return Err(DurableReadError::InvalidPersistedState);
    }
    Ok(record)
}

fn validate_memory_object_reads(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    reads: &[DurableObjectHeadRead],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current: DurableObjectHead = read_memory_object_head(data, domain, read.object_id())
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        if &current != read.expected() {
            return Err(DurableCommitRejection::ObjectConflict {
                object_id: read.object_id(),
                current: DurableObjectHeadSummary::from(&current),
            });
        }
    }
    Ok(())
}

fn prepare_memory_object_mutations(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    changes: &DurableObjectChanges,
) -> Result<Vec<PreparedMemoryObjectMutation>, DurableCommitRejection> {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    let mut prepared: Vec<PreparedMemoryObjectMutation> =
        Vec::with_capacity(changes.mutations().len());
    for mutation in changes.mutations() {
        let read_index: usize = changes
            .reads()
            .binary_search_by_key(&mutation.object_id(), DurableObjectHeadRead::object_id)
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let expected: &DurableObjectHead = changes.reads()[read_index].expected();
        let next_head_revision: ObjectHeadRevision = match expected.head_revision() {
            Some(revision) => revision
                .checked_next()
                .ok_or(DurableCommitRejection::InvalidPersistedState)?,
            None => ObjectHeadRevision::FIRST,
        };
        let (head, version): (MemoryStoredObjectHead, Option<DurableObjectVersionRecord>) =
            match mutation.mutation() {
                DurableObjectMutation::Create {
                    version,
                    owner_projection,
                    routing_projection,
                }
                | DurableObjectMutation::Update {
                    version,
                    owner_projection,
                    routing_projection,
                } => {
                    let object_version: DurableObjectVersion = version.object_version();
                    let version_key: MemoryDurableObjectVersionKey =
                        (domain_bytes, mutation.object_id(), object_version);
                    if data.object_versions.contains_key(&version_key) {
                        return Err(DurableCommitRejection::InvalidPersistedState);
                    }
                    (
                        MemoryStoredObjectHead::Current {
                            head_revision: next_head_revision,
                            object_version,
                            digest: version.digest(),
                            owner_projection: owner_projection.clone(),
                            routing_projection: routing_projection.clone(),
                        },
                        Some(version.clone()),
                    )
                }
                DurableObjectMutation::Delete => (
                    MemoryStoredObjectHead::Tombstoned {
                        head_revision: next_head_revision,
                    },
                    None,
                ),
            };
        prepared.push(PreparedMemoryObjectMutation {
            object_id: mutation.object_id(),
            head,
            version,
        });
    }
    Ok(prepared)
}

fn apply_memory_object_mutations(
    data: &mut MemoryDurableStoreData,
    domain: AtomicityDomainId,
    prepared: Vec<PreparedMemoryObjectMutation>,
) {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    for mutation in prepared {
        if let Some(version) = mutation.version {
            let object_version: DurableObjectVersion = version.object_version();
            data.object_versions
                .insert((domain_bytes, mutation.object_id, object_version), version);
        }
        data.object_heads
            .insert((domain_bytes, mutation.object_id), mutation.head);
    }
}

impl DurableDomainStateStore for MemoryDurableStateStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        validate_state_key(key).map_err(DurableReadError::InvalidRequest)?;
        let data = self
            .inner
            .read()
            .expect("durable state store lock poisoned");
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        Ok(read_memory_versioned(
            data.state_domains.get(domain.as_bytes()),
            key,
        ))
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let mut data = self
            .inner
            .write()
            .expect("durable state store lock poisoned");
        if let Err(reason) = validate_memory_durable_commit_domain(&data, transaction.domain()) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = validate_memory_durable_commit_authority(&data, context) {
            return DurableCommitOutcome::Rejected(reason);
        }
        let domain = *transaction.domain.as_bytes();
        let state = data.state_domains.get(&domain);
        if let Err(reason) = validate_memory_durable_reads(state, transaction.reads()) {
            return DurableCommitOutcome::Rejected(reason);
        }
        let revisions = match memory_durable_revisions(state, transaction.mutations()) {
            Ok(revisions) => revisions,
            Err(reason) => return DurableCommitOutcome::Rejected(reason),
        };
        let state = data.state_domains.entry(domain).or_default();
        match apply_memory_durable_mutations(state, transaction.mutations.mutations, revisions) {
            Ok(()) => DurableCommitOutcome::Committed,
            Err(reason) => DurableCommitOutcome::Rejected(reason),
        }
    }
}

impl StructuredDurableDomainStateStore for MemoryDurableStateStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        let data = self
            .inner
            .read()
            .expect("durable state store lock poisoned");
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        read_memory_object_head(&data, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        let data = self
            .inner
            .read()
            .expect("durable state store lock poisoned");
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        read_memory_object_version(&data, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        let data = self
            .inner
            .read()
            .expect("durable state store lock poisoned");
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        Ok(data
            .receipts
            .get(&(*domain.as_bytes(), *request_id.as_bytes()))
            .cloned())
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let mut data = self
            .inner
            .write()
            .expect("durable state store lock poisoned");
        if let Err(reason) = validate_memory_durable_commit_domain(&data, transaction.domain()) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = validate_memory_durable_commit_authority(&data, context) {
            return DurableCommitOutcome::Rejected(reason);
        }

        let domain = *transaction.domain.as_bytes();
        let request_key = (domain, *transaction.receipt.request_id.as_bytes());
        if data.receipts.contains_key(&request_key) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted);
        }

        let revisions = if let Some(state_transaction) = transaction.state.as_ref() {
            let state = data.state_domains.get(&domain);
            if let Err(reason) = validate_memory_durable_reads(state, state_transaction.reads()) {
                return DurableCommitOutcome::Rejected(reason);
            }
            match memory_durable_revisions(state, state_transaction.mutations()) {
                Ok(revisions) => revisions,
                Err(reason) => return DurableCommitOutcome::Rejected(reason),
            }
        } else {
            Vec::new()
        };
        if let Err(reason) =
            validate_memory_object_reads(&data, transaction.domain, transaction.objects.reads())
        {
            return DurableCommitOutcome::Rejected(reason);
        }
        let prepared_objects: Vec<PreparedMemoryObjectMutation> =
            match prepare_memory_object_mutations(&data, transaction.domain, &transaction.objects) {
                Ok(prepared) => prepared,
                Err(reason) => return DurableCommitOutcome::Rejected(reason),
            };
        let delivery = transaction
            .outbox
            .as_ref()
            .map(|outbox| MemoryOutboxDelivery {
                next_index: 0,
                available_at_unix_millis: 0,
                active_lease: None,
                attempt_count: 0,
                completed: outbox.messages().is_empty(),
            });

        if let Some(state_transaction) = transaction.state {
            let state = data.state_domains.entry(domain).or_default();
            if let Err(reason) = apply_memory_durable_mutations(
                state,
                state_transaction.mutations.mutations,
                revisions,
            ) {
                return DurableCommitOutcome::Rejected(reason);
            }
        }
        apply_memory_object_mutations(&mut data, transaction.domain, prepared_objects);
        data.receipts.insert(request_key, transaction.receipt);
        if let Some(outbox) = transaction.outbox {
            data.outboxes.insert(request_key, outbox);
        }
        if let Some(delivery) = delivery {
            data.deliveries.insert(request_key, delivery);
        }
        DurableCommitOutcome::Committed
    }
}

fn validate_memory_outbox_claim_authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
) -> Result<(), DurableOutboxClaimRejection> {
    if context.writer_fence() != data.active_writer_fence {
        return Err(DurableOutboxClaimRejection::WriterFenced {
            active_generation: data.active_writer_fence,
        });
    }
    if context.deadline().is_expired_at(data.now_unix_millis) {
        return Err(DurableOutboxClaimRejection::DeadlineExceededBeforeCommit);
    }
    Ok(())
}

fn validate_memory_outbox_ack_authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
) -> Result<(), DurableOutboxAcknowledgementRejection> {
    if context.writer_fence() != data.active_writer_fence {
        return Err(DurableOutboxAcknowledgementRejection::WriterFenced {
            active_generation: data.active_writer_fence,
        });
    }
    if context.deadline().is_expired_at(data.now_unix_millis) {
        return Err(DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit);
    }
    Ok(())
}

fn memory_outbox_claim_from_attempt(
    data: &MemoryDurableStoreData,
    lease_id: DurableOutboxLeaseId,
    attempt: &MemoryOutboxDeliveryAttempt,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    let request_key = (*attempt.domain.as_bytes(), *attempt.request_id.as_bytes());
    let delivery = data
        .deliveries
        .get(&request_key)
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    if delivery.active_lease != Some((lease_id, attempt.lease_expires_at_unix_millis))
        || delivery.next_index != attempt.message_index
    {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    let batch = data
        .outboxes
        .get(&request_key)
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    let index = usize::try_from(attempt.message_index)
        .map_err(|_| DurableOutboxClaimRejection::ArithmeticOverflow)?;
    let message = batch
        .messages()
        .get(index)
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    DurableOutboxClaim::from_parts(
        attempt.request_id,
        attempt.message_index,
        lease_id,
        attempt.lease_expires_at_unix_millis,
        message.canonical_payload().to_vec(),
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)
}

impl IndexedOutboxRepository for MemoryDurableStateStore {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        let mut data = self
            .inner
            .write()
            .expect("durable state store lock poisoned");
        if let Err(reason) = validate_memory_outbox_claim_authority(&data, context) {
            return DurableOutboxClaimOutcome::Rejected(reason);
        }

        let lease_key = *request.lease_id().as_bytes();
        if let Some(attempt) = data.delivery_attempts.get(&lease_key).cloned() {
            if attempt.domain != request.domain() || attempt.request_id != request.request_id() {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            if attempt.status != MemoryOutboxAttemptStatus::Claimed {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            let claim = match memory_outbox_claim_from_attempt(&data, request.lease_id(), &attempt)
            {
                Ok(claim) => claim,
                Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
            };
            if attempt.lease_expires_at_unix_millis <= request.now_unix_millis() {
                if let Some(attempt) = data.delivery_attempts.get_mut(&lease_key) {
                    attempt.status = MemoryOutboxAttemptStatus::Expired;
                }
                let request_key = (*attempt.domain.as_bytes(), *attempt.request_id.as_bytes());
                if let Some(delivery) = data.deliveries.get_mut(&request_key) {
                    delivery.active_lease = None;
                    delivery.available_at_unix_millis = 0;
                }
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            return DurableOutboxClaimOutcome::Claimed(claim);
        }

        let request_key = (
            *request.domain().as_bytes(),
            *request.request_id().as_bytes(),
        );
        let Some(mut delivery) = data.deliveries.get(&request_key).cloned() else {
            return DurableOutboxClaimOutcome::NoDueWork;
        };
        if delivery.completed
            || delivery.available_at_unix_millis > request.now_unix_millis()
            || delivery
                .active_lease
                .is_some_and(|(_, expires_at)| expires_at > request.now_unix_millis())
        {
            return DurableOutboxClaimOutcome::NoDueWork;
        }
        let batch = match data.outboxes.get(&request_key) {
            Some(batch) => batch,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let index = match usize::try_from(delivery.next_index) {
            Ok(index) => index,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::ArithmeticOverflow,
                );
            }
        };
        let message = match batch.messages().get(index) {
            Some(message) => message,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let claim = match DurableOutboxClaim::from_parts(
            request.request_id(),
            delivery.next_index,
            request.lease_id(),
            request.lease_expires_at_unix_millis(),
            message.canonical_payload().to_vec(),
        ) {
            Ok(claim) => claim,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let attempt_count = match delivery.attempt_count.checked_add(1) {
            Some(attempt_count) => attempt_count,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::ArithmeticOverflow,
                );
            }
        };
        if let Some((expired_lease, expires_at)) = delivery.active_lease {
            let expired_key = *expired_lease.as_bytes();
            let Some(expired_attempt) = data.delivery_attempts.get_mut(&expired_key) else {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            };
            if expires_at > request.now_unix_millis()
                || expired_attempt.status != MemoryOutboxAttemptStatus::Claimed
                || expired_attempt.request_id != request.request_id()
                || expired_attempt.message_index != delivery.next_index
            {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
            expired_attempt.status = MemoryOutboxAttemptStatus::Expired;
        }

        delivery.active_lease = Some((request.lease_id(), request.lease_expires_at_unix_millis()));
        delivery.available_at_unix_millis = request.lease_expires_at_unix_millis();
        delivery.attempt_count = attempt_count;
        data.deliveries.insert(request_key, delivery);
        data.delivery_attempts.insert(
            lease_key,
            MemoryOutboxDeliveryAttempt {
                domain: request.domain(),
                request_id: request.request_id(),
                message_index: claim.message_index(),
                lease_expires_at_unix_millis: request.lease_expires_at_unix_millis(),
                status: MemoryOutboxAttemptStatus::Claimed,
            },
        );
        DurableOutboxClaimOutcome::Claimed(claim)
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        let mut data = self
            .inner
            .write()
            .expect("durable state store lock poisoned");
        if let Err(reason) = validate_memory_outbox_claim_authority(&data, context) {
            return DurableOutboxClaimOutcome::Rejected(reason);
        }

        let lease_key = *request.lease_id().as_bytes();
        if let Some(attempt) = data.delivery_attempts.get(&lease_key).cloned() {
            if attempt.domain != request.domain() {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            if attempt.status != MemoryOutboxAttemptStatus::Claimed {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            let claim = match memory_outbox_claim_from_attempt(&data, request.lease_id(), &attempt)
            {
                Ok(claim) => claim,
                Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
            };
            if attempt.lease_expires_at_unix_millis <= request.now_unix_millis() {
                if let Some(attempt) = data.delivery_attempts.get_mut(&lease_key) {
                    attempt.status = MemoryOutboxAttemptStatus::Expired;
                }
                let request_key = (*attempt.domain.as_bytes(), *attempt.request_id.as_bytes());
                if let Some(delivery) = data.deliveries.get_mut(&request_key) {
                    delivery.active_lease = None;
                    delivery.available_at_unix_millis = 0;
                }
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            return DurableOutboxClaimOutcome::Claimed(claim);
        }

        let domain = *request.domain().as_bytes();
        let selected = data
            .deliveries
            .iter()
            .filter(|((candidate_domain, _), delivery)| {
                *candidate_domain == domain
                    && !delivery.completed
                    && delivery.available_at_unix_millis <= request.now_unix_millis()
                    && delivery
                        .active_lease
                        .is_none_or(|(_, expires_at)| expires_at <= request.now_unix_millis())
            })
            .min_by_key(|((_, request_id), delivery)| {
                (delivery.available_at_unix_millis, *request_id)
            })
            .map(|(key, delivery)| (*key, delivery.clone()));
        let Some((request_key, mut delivery)) = selected else {
            return DurableOutboxClaimOutcome::NoDueWork;
        };
        let request_id = match OutboxRequestId::new(request_key.1) {
            Ok(request_id) => request_id,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let batch = match data.outboxes.get(&request_key) {
            Some(batch) => batch,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let index = match usize::try_from(delivery.next_index) {
            Ok(index) => index,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::ArithmeticOverflow,
                );
            }
        };
        let message = match batch.messages().get(index) {
            Some(message) => message,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let claim = match DurableOutboxClaim::from_parts(
            request_id,
            delivery.next_index,
            request.lease_id(),
            request.lease_expires_at_unix_millis(),
            message.canonical_payload().to_vec(),
        ) {
            Ok(claim) => claim,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
        };
        let attempt_count = match delivery.attempt_count.checked_add(1) {
            Some(attempt_count) => attempt_count,
            None => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::ArithmeticOverflow,
                );
            }
        };

        if let Some((expired_lease, expires_at)) = delivery.active_lease {
            let expired_key = *expired_lease.as_bytes();
            let Some(expired_attempt) = data.delivery_attempts.get_mut(&expired_key) else {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            };
            if expires_at > request.now_unix_millis()
                || expired_attempt.status != MemoryOutboxAttemptStatus::Claimed
                || expired_attempt.request_id != request_id
                || expired_attempt.message_index != delivery.next_index
            {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::InvalidPersistedState,
                );
            }
            expired_attempt.status = MemoryOutboxAttemptStatus::Expired;
        }

        delivery.active_lease = Some((request.lease_id(), request.lease_expires_at_unix_millis()));
        delivery.available_at_unix_millis = request.lease_expires_at_unix_millis();
        delivery.attempt_count = attempt_count;
        data.deliveries.insert(request_key, delivery);
        data.delivery_attempts.insert(
            lease_key,
            MemoryOutboxDeliveryAttempt {
                domain: request.domain(),
                request_id,
                message_index: claim.message_index(),
                lease_expires_at_unix_millis: request.lease_expires_at_unix_millis(),
                status: MemoryOutboxAttemptStatus::Claimed,
            },
        );
        DurableOutboxClaimOutcome::Claimed(claim)
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        let mut data = self
            .inner
            .write()
            .expect("durable state store lock poisoned");
        if let Err(reason) = validate_memory_outbox_ack_authority(&data, context) {
            return DurableOutboxAcknowledgementOutcome::Rejected(reason);
        }
        let lease_key = *acknowledgement.lease_id().as_bytes();
        let Some(attempt) = data.delivery_attempts.get(&lease_key).cloned() else {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        };
        if attempt.domain != acknowledgement.domain()
            || attempt.request_id != acknowledgement.request_id()
            || attempt.message_index != acknowledgement.message_index()
        {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        match attempt.status {
            MemoryOutboxAttemptStatus::Acknowledged => {
                return DurableOutboxAcknowledgementOutcome::Acknowledged;
            }
            MemoryOutboxAttemptStatus::Expired => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::LeaseMismatch,
                );
            }
            MemoryOutboxAttemptStatus::Claimed => {}
        }

        let request_key = (
            *acknowledgement.domain().as_bytes(),
            *acknowledgement.request_id().as_bytes(),
        );
        let Some(mut delivery) = data.deliveries.get(&request_key).cloned() else {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        };
        if delivery.next_index != acknowledgement.message_index() {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::IndexMismatch,
            );
        }
        if delivery.active_lease
            != Some((
                acknowledgement.lease_id(),
                attempt.lease_expires_at_unix_millis,
            ))
        {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        let Some(batch) = data.outboxes.get(&request_key) else {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        };
        let next_index = match delivery.next_index.checked_add(1) {
            Some(next_index) => next_index,
            None => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::ArithmeticOverflow,
                );
            }
        };
        let message_count = match u32::try_from(batch.messages().len()) {
            Ok(message_count) => message_count,
            Err(_) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::ArithmeticOverflow,
                );
            }
        };
        if next_index > message_count {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        }

        delivery.next_index = next_index;
        delivery.active_lease = None;
        delivery.completed = next_index == message_count;
        delivery.available_at_unix_millis = 0;
        data.deliveries.insert(request_key, delivery);
        if let Some(attempt) = data.delivery_attempts.get_mut(&lease_key) {
            attempt.status = MemoryOutboxAttemptStatus::Acknowledged;
        }
        DurableOutboxAcknowledgementOutcome::Acknowledged
    }
}

/// In-memory `BlobStore` implementation.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    inner: Arc<RwLock<HashMap<Digest32, Vec<u8>>>>,
}

impl BlobStore for MemoryBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let mut guard = self.inner.write().expect("blob store lock poisoned");
        guard.insert(digest, bytes);
        Ok(())
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        let guard = self.inner.read().expect("blob store lock poisoned");
        Ok(guard.get(digest).cloned())
    }
}

/// In-memory signer for runtime wiring tests.
#[derive(Clone, Debug)]
pub struct MemorySigner {
    validator_id: ValidatorId,
}

impl MemorySigner {
    /// Creates a memory signer for the validator.
    #[must_use]
    pub const fn new(validator_id: ValidatorId) -> Self {
        Self { validator_id }
    }
}

impl Signer for MemorySigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let mut signature = Vec::with_capacity(32 + payload.len());
        signature.extend_from_slice(self.validator_id.as_bytes());
        signature.extend_from_slice(payload);
        Ok(signature)
    }
}

/// In-memory queue transport.
#[derive(Clone, Debug, Default)]
pub struct MemoryTransport {
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Transport for MemoryTransport {
    fn send(&self, message: Vec<u8>) -> Result<(), RuntimeError> {
        let mut guard = self.outbound.lock().expect("transport lock poisoned");
        guard.push(message);
        Ok(())
    }

    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let mut guard = self.outbound.lock().expect("transport lock poisoned");
        Ok(std::mem::take(&mut *guard))
    }
}

/// System clock adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeError::ClockBeforeUnixEpoch)?;
        u64::try_from(duration.as_millis()).map_err(|_| RuntimeError::ClockOverflow)
    }
}

/// Manual clock for deterministic tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_unix_millis: AtomicU64,
}

impl ManualClock {
    /// Creates a manual clock with an initial timestamp.
    #[must_use]
    pub const fn new(initial_unix_millis: u64) -> Self {
        Self {
            now_unix_millis: AtomicU64::new(initial_unix_millis),
        }
    }

    /// Sets the current timestamp.
    pub fn set(&self, unix_millis: u64) {
        self.now_unix_millis.store(unix_millis, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        Ok(self.now_unix_millis.load(Ordering::Relaxed))
    }
}

/// In-memory scheduler implementation.
#[derive(Clone, Debug, Default)]
pub struct MemoryScheduler {
    queue: Arc<Mutex<Vec<ScheduledPayload>>>,
}

impl Scheduler for MemoryScheduler {
    fn schedule(&self, at_unix_millis: u64, payload: Vec<u8>) -> Result<(), RuntimeError> {
        if payload.is_empty() {
            return Err(RuntimeError::EmptyScheduledPayload);
        }

        let mut guard = self.queue.lock().expect("scheduler lock poisoned");
        let index = guard.partition_point(|item| item.at_unix_millis <= at_unix_millis);
        guard.insert(
            index,
            ScheduledPayload {
                at_unix_millis,
                payload,
            },
        );
        Ok(())
    }

    fn drain_ready(&self, now_unix_millis: u64) -> Result<Vec<ScheduledPayload>, RuntimeError> {
        let mut guard = self.queue.lock().expect("scheduler lock poisoned");
        let split_at = guard.partition_point(|item| item.at_unix_millis <= now_unix_millis);
        let ready = guard.drain(0..split_at).collect();
        Ok(ready)
    }
}

/// Explicit runtime composition from independently owned components.
///
/// This keeps storage, transport, signing, time, and scheduling policy visible
/// at the embedding boundary. Constructing this value does not certify that
/// any supplied component is durable or production-ready.
#[derive(Debug)]
pub struct ComposedRuntime<S, B, N, T, C, Q> {
    state_store: S,
    blob_store: B,
    signer: N,
    transport: T,
    clock: C,
    scheduler: Q,
}

impl<S, B, N, T, C, Q> ComposedRuntime<S, B, N, T, C, Q> {
    /// Creates a runtime without adding hidden defaults or global state.
    #[must_use]
    pub const fn new(
        state_store: S,
        blob_store: B,
        signer: N,
        transport: T,
        clock: C,
        scheduler: Q,
    ) -> Self {
        Self {
            state_store,
            blob_store,
            signer,
            transport,
            clock,
            scheduler,
        }
    }
}

impl<S, B, N, T, C, Q> Runtime for ComposedRuntime<S, B, N, T, C, Q>
where
    S: StateStore,
    B: BlobStore,
    N: Signer,
    T: Transport,
    C: Clock,
    Q: Scheduler,
{
    type State = S;
    type Blobs = B;
    type NodeSigner = N;
    type Network = T;
    type Time = C;
    type TaskScheduler = Q;

    fn state_store(&self) -> &Self::State {
        &self.state_store
    }

    fn blob_store(&self) -> &Self::Blobs {
        &self.blob_store
    }

    fn signer(&self) -> &Self::NodeSigner {
        &self.signer
    }

    fn transport(&self) -> &Self::Network {
        &self.transport
    }

    fn clock(&self) -> &Self::Time {
        &self.clock
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        &self.scheduler
    }
}

/// In-memory runtime composition.
#[derive(Debug)]
pub struct MemoryRuntime {
    state_store: MemoryStateStore,
    blob_store: MemoryBlobStore,
    signer: MemorySigner,
    transport: MemoryTransport,
    clock: ManualClock,
    scheduler: MemoryScheduler,
}

impl MemoryRuntime {
    /// Creates an in-memory runtime.
    #[must_use]
    pub fn new(validator_id: ValidatorId) -> Self {
        Self {
            state_store: MemoryStateStore::default(),
            blob_store: MemoryBlobStore::default(),
            signer: MemorySigner::new(validator_id),
            transport: MemoryTransport::default(),
            clock: ManualClock::default(),
            scheduler: MemoryScheduler::default(),
        }
    }

    /// Sets current time for the internal manual clock.
    pub fn set_time(&self, unix_millis: u64) {
        self.clock.set(unix_millis);
    }
}

impl Runtime for MemoryRuntime {
    type State = MemoryStateStore;
    type Blobs = MemoryBlobStore;
    type NodeSigner = MemorySigner;
    type Network = MemoryTransport;
    type Time = ManualClock;
    type TaskScheduler = MemoryScheduler;

    fn state_store(&self) -> &Self::State {
        &self.state_store
    }

    fn blob_store(&self) -> &Self::Blobs {
        &self.blob_store
    }

    fn signer(&self) -> &Self::NodeSigner {
        &self.signer
    }

    fn transport(&self) -> &Self::Network {
        &self.transport
    }

    fn clock(&self) -> &Self::Time {
        &self.clock
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        &self.scheduler
    }
}

/// Deterministic persistent state key layout.
#[derive(Clone, Debug)]
pub struct PersistenceLayout {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
}

impl PersistenceLayout {
    /// Creates a layout for `(chain_id, protocol_version)` namespace.
    #[must_use]
    pub fn new(chain_id: ChainId, protocol_version: ProtocolVersion) -> Self {
        Self {
            chain_id,
            protocol_version,
        }
    }

    /// Returns a protocol configuration key.
    #[must_use]
    pub fn protocol_config_key(&self) -> Vec<u8> {
        self.prefixed("protocol/config")
    }

    /// Returns an epoch metadata key.
    #[must_use]
    pub fn epoch_metadata_key(&self, epoch: Epoch) -> Vec<u8> {
        self.prefixed(&format!("epoch/{:020}/metadata", epoch.get()))
    }

    /// Returns a validator record key.
    #[must_use]
    pub fn validator_record_key(&self, validator_id: ValidatorId) -> Vec<u8> {
        self.prefixed(&format!("validators/{validator_id}/record"))
    }

    /// Returns an object-version key.
    #[must_use]
    pub fn object_version_key(&self, object_id: [u8; 32], version: u64) -> Vec<u8> {
        self.prefixed(&format!(
            "objects/{}/versions/{:020}",
            hex32(object_id),
            version
        ))
    }

    /// Returns an object latest-version key.
    #[must_use]
    pub fn object_latest_version_key(&self, object_id: [u8; 32]) -> Vec<u8> {
        self.prefixed(&format!("objects/{}/latest", hex32(object_id)))
    }

    /// Returns an execution-effects key by digest.
    #[must_use]
    pub fn effects_key(&self, effects_digest: &Digest32) -> Vec<u8> {
        let mut digest_hex = String::new();
        digest_hex.push_str(effects_digest.algorithm().label());
        digest_hex.push('-');
        for byte in effects_digest.bytes() {
            digest_hex.push_str(&format!("{byte:02x}"));
        }
        self.prefixed(&format!("effects/{digest_hex}"))
    }

    /// Returns the persisted idempotency record key for one request.
    #[must_use]
    pub fn request_dedup_key(&self, request_id: [u8; 32]) -> Vec<u8> {
        self.prefixed(&format!("requests/{}/dedup", hex32(request_id)))
    }

    /// Returns the persisted outbound batch key for one request.
    #[must_use]
    pub fn outbox_batch_key(&self, request_id: [u8; 32]) -> Vec<u8> {
        self.prefixed(&format!("outbox/{}/batch", hex32(request_id)))
    }

    /// Returns the binary prefix shared by all request outbox records.
    #[must_use]
    pub fn outbox_prefix(&self) -> Vec<u8> {
        self.prefixed("outbox/")
    }

    /// Returns the mutable outbound delivery-state key for one request.
    #[must_use]
    pub fn outbox_delivery_key(&self, request_id: [u8; 32]) -> Vec<u8> {
        self.prefixed(&format!("outbox/{}/delivery", hex32(request_id)))
    }

    /// Returns the system-module registry key.
    #[must_use]
    pub fn system_module_registry_key(&self) -> Vec<u8> {
        self.prefixed("system-modules/registry")
    }

    /// Returns a system-module version record key.
    #[must_use]
    pub fn system_module_record_key(&self, module_id: [u8; 32], version: u64) -> Vec<u8> {
        self.prefixed(&format!(
            "system-modules/{}/versions/{:020}",
            hex32(module_id),
            version
        ))
    }

    /// Returns the pending protocol-upgrade schedule key.
    #[must_use]
    pub fn protocol_upgrade_schedule_key(&self) -> Vec<u8> {
        self.prefixed("protocol/upgrades")
    }

    /// Returns the persisted shared-object consensus state key for an epoch.
    #[must_use]
    pub fn consensus_state_key(&self, epoch: Epoch) -> Vec<u8> {
        self.prefixed(&format!("consensus/{:020}/state", epoch.get()))
    }

    /// Returns a deterministic migration implementation record key.
    #[must_use]
    pub fn migration_record_key(&self, migration_hash: &Digest32) -> Vec<u8> {
        self.prefixed(&format!(
            "protocol/migrations/{}-{}",
            migration_hash.algorithm().label(),
            hex32(migration_hash.bytes())
        ))
    }

    /// Returns the binary prefix shared by every persisted sender-nonce record.
    #[must_use]
    pub fn sender_nonce_prefix(&self) -> Vec<u8> {
        self.prefixed("sender-nonces/")
    }

    /// Returns the persisted next-nonce record key for one sender in one epoch.
    #[must_use]
    pub fn sender_nonce_key(&self, sender: [u8; 32], epoch: Epoch) -> Vec<u8> {
        self.prefixed(&format!(
            "sender-nonces/{}/{:020}",
            hex32(sender),
            epoch.get()
        ))
    }

    fn prefixed(&self, suffix: &str) -> Vec<u8> {
        format!(
            "se/{}/v{}/{}",
            self.chain_id,
            self.protocol_version.get(),
            suffix
        )
        .into_bytes()
    }
}

fn ensure_non_empty_key(key: &[u8]) -> Result<(), RuntimeError> {
    if key.is_empty() {
        return Err(RuntimeError::EmptyKey);
    }
    Ok(())
}

/// Validates one runtime state key against the shared persistence bounds.
pub fn validate_state_key(key: &[u8]) -> Result<(), RuntimeError> {
    ensure_non_empty_key(key)?;
    if key.len() > MAX_STATE_KEY_BYTES {
        return Err(RuntimeError::StateKeyTooLong {
            length: key.len(),
            maximum: MAX_STATE_KEY_BYTES,
        });
    }
    Ok(())
}

/// Validates one runtime state value against the shared persistence bounds.
pub fn validate_state_value(value: &[u8]) -> Result<(), RuntimeError> {
    if value.len() > MAX_STATE_VALUE_BYTES {
        return Err(RuntimeError::StateValueTooLarge {
            length: value.len(),
            maximum: MAX_STATE_VALUE_BYTES,
        });
    }
    Ok(())
}

fn current_revision(state: &BTreeMap<Vec<u8>, StoredStateValue>, key: &[u8]) -> StateRevision {
    state
        .get(key)
        .map_or(StateRevision::INITIAL, |stored| stored.revision)
}

fn hex32(bytes: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashing::{BuiltinHashFunction, HashFunction};
    use protocol_types::{HashAlgorithmId, HashPurpose};

    fn key(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn domain(byte: u8) -> AtomicityDomainId {
        AtomicityDomainId::new([byte; 32]).unwrap()
    }

    fn read(text: &str, revision: StateRevision) -> StateReadAssertion {
        StateReadAssertion::new(key(text), revision).unwrap()
    }

    fn mutation(text: &str, mutation: StateMutation) -> StateMutationEntry {
        StateMutationEntry::new(key(text), mutation).unwrap()
    }

    fn transaction(
        domain: AtomicityDomainId,
        reads: Vec<StateReadAssertion>,
        mutations: Vec<StateMutationEntry>,
    ) -> Result<AtomicStateTransaction, RuntimeError> {
        AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(reads)?,
            AtomicStateMutationSet::new(mutations)?,
        )
    }

    fn durable_context(fence: u64, deadline: u64, correlation: u8) -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(fence).unwrap(),
            StorageDeadline::new(deadline).unwrap(),
            StorageCorrelationId::new([correlation; 16]).unwrap(),
        )
    }

    fn durable_invocation(
        domain: AtomicityDomainId,
        request_byte: u8,
        expected_revision: StateRevision,
        mutation_value: Option<u8>,
        include_outbox: bool,
    ) -> DurableInvocationTransaction {
        let request_id = DurableRequestId::new([request_byte; 32]).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 1; 32]);
        let receipt =
            DurableRequestReceipt::new(request_id, event_digest, vec![request_byte]).unwrap();
        let mutations = mutation_value
            .map(|value| vec![mutation("state", StateMutation::Put(vec![value]))])
            .unwrap_or_default();
        let state = DurableStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![read("state", expected_revision)]).unwrap(),
            mutations,
        )
        .unwrap();
        let outbox = include_outbox.then(|| {
            let message = DurableOutboxMessage::new(
                Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 2; 32]),
                vec![request_byte + 3],
            )
            .unwrap();
            DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap()
        });
        DurableInvocationTransaction::new(
            domain,
            Some(state),
            DurableObjectChanges::empty(),
            receipt,
            outbox,
        )
        .unwrap()
    }

    fn test_object_version(version: u64, byte: u8) -> DurableObjectVersionRecord {
        let object: Object = Object {
            id: ObjectId::new([byte; 32]),
            version,
            owner: Owner::Address(objects::Address::new([byte.wrapping_add(1); 32])),
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(2); 32]),
            schema_version: u32::from(byte),
            data: vec![byte.wrapping_add(3)],
        };
        let canonical: Vec<u8> = encode_object(&object).unwrap();
        let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                ProtocolVersion::new(1),
                &ChainId::new("sunrise-runtime-tests").unwrap(),
                &canonical,
            )
            .unwrap();
        DurableObjectVersionRecord::from_inline_object(object, digest, u64::from(byte)).unwrap()
    }

    fn test_create_mutation(version: u64, byte: u8) -> DurableObjectMutation {
        DurableObjectMutation::Create {
            version: test_object_version(version, byte),
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                objects::Address::new([byte.wrapping_add(1); 32]),
            ))
            .unwrap(),
            routing_projection: DurableObjectRoutingProjection::new(Some(vec![byte])).unwrap(),
        }
    }

    fn test_object_invocation(
        invocation_domain: AtomicityDomainId,
        request_byte: u8,
        objects: DurableObjectChanges,
    ) -> DurableInvocationTransaction {
        let request_id: DurableRequestId = DurableRequestId::new([request_byte; 32]).unwrap();
        let digest: Digest32 = Digest32::new(
            HashAlgorithmId::Sha2_256,
            [request_byte.wrapping_add(1); 32],
        );
        let receipt: DurableRequestReceipt =
            DurableRequestReceipt::new(request_id, digest, vec![request_byte]).unwrap();
        DurableInvocationTransaction::new(invocation_domain, None, objects, receipt, None).unwrap()
    }

    fn durable_outbox_invocation(
        domain: AtomicityDomainId,
        request_byte: u8,
        payloads: &[u8],
    ) -> DurableInvocationTransaction {
        let request_id = DurableRequestId::new([request_byte; 32]).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xD1; 32]);
        let receipt =
            DurableRequestReceipt::new(request_id, event_digest, vec![request_byte]).unwrap();
        let messages = payloads
            .iter()
            .map(|payload| {
                DurableOutboxMessage::new(
                    Digest32::new(HashAlgorithmId::Sha2_256, [*payload; 32]),
                    vec![*payload],
                )
                .unwrap()
            })
            .collect();
        let outbox = DurableOutboxBatch::new(request_id, event_digest, messages).unwrap();
        let state = DurableStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        DurableInvocationTransaction::new(
            domain,
            Some(state),
            DurableObjectChanges::empty(),
            receipt,
            Some(outbox),
        )
        .unwrap()
    }

    #[test]
    fn compare_and_swap_writes_when_expected_matches() {
        let store = MemoryStateStore::default();
        store.put(key("k"), vec![1]).unwrap();

        let result = store
            .compare_and_swap(key("k"), Some(vec![1]), vec![2])
            .unwrap();

        assert!(result.swapped);
        assert_eq!(result.current, Some(vec![1]));
        assert_eq!(store.get(b"k").unwrap(), Some(vec![2]));
    }

    #[test]
    fn compare_and_swap_rejects_when_expected_mismatch() {
        let store = MemoryStateStore::default();
        store.put(key("k"), vec![9]).unwrap();

        let result = store
            .compare_and_swap(key("k"), Some(vec![1]), vec![2])
            .unwrap();

        assert!(!result.swapped);
        assert_eq!(result.current, Some(vec![9]));
        assert_eq!(store.get(b"k").unwrap(), Some(vec![9]));
    }

    #[test]
    fn domain_transaction_envelope_is_bounded_ordered_and_complete() {
        assert_eq!(
            AtomicityDomainId::new([0; 32]),
            Err(protocol_types::TypeError::ZeroAtomicityDomainId)
        );
        assert_eq!(
            StateMutationEntry::new(key("a"), StateMutation::Assert),
            Err(RuntimeError::StateAssertionAsMutation)
        );
        assert_eq!(
            AtomicStateReadSet::new(Vec::new()),
            Err(RuntimeError::EmptyReadSet)
        );
        let duplicate_read = read("same", StateRevision::INITIAL);
        assert_eq!(
            AtomicStateReadSet::new(vec![duplicate_read.clone(), duplicate_read]),
            Err(RuntimeError::DuplicateStateReadKey)
        );
        assert_eq!(
            AtomicStateMutationSet::new(Vec::new()),
            Err(RuntimeError::EmptyWriteSet)
        );
        let duplicate_mutation = mutation("same", StateMutation::Delete);
        assert_eq!(
            AtomicStateMutationSet::new(vec![duplicate_mutation.clone(), duplicate_mutation,]),
            Err(RuntimeError::DuplicateStateWriteKey)
        );
        assert_eq!(
            transaction(
                domain(1),
                vec![read("a", StateRevision::INITIAL)],
                vec![mutation("b", StateMutation::Delete)],
            ),
            Err(RuntimeError::StateMutationWithoutRead)
        );

        let transaction = transaction(
            domain(1),
            vec![
                read("z", StateRevision::INITIAL),
                read("a", StateRevision::INITIAL),
            ],
            vec![
                mutation("z", StateMutation::Put(vec![2])),
                mutation("a", StateMutation::Put(vec![1])),
            ],
        )
        .unwrap();
        assert_eq!(transaction.reads()[0].key(), b"a");
        assert_eq!(transaction.reads()[1].key(), b"z");
        assert_eq!(transaction.mutations()[0].key(), b"a");
        assert_eq!(transaction.mutations()[1].key(), b"z");
        assert_eq!(transaction.represented_bytes(), 96);
    }

    #[test]
    fn durable_operation_context_requires_explicit_non_zero_authority_and_identity() {
        assert_eq!(WriterFenceGeneration::new(0), None);
        assert_eq!(StorageDeadline::new(0), None);
        assert_eq!(StorageCorrelationId::new([0; 16]), None);

        let fence = WriterFenceGeneration::new(7).unwrap();
        let deadline = StorageDeadline::new(1_000).unwrap();
        let correlation_id = StorageCorrelationId::new([9; 16]).unwrap();
        let context = DurableOperationContext::new(fence, deadline, correlation_id);

        assert_eq!(context.writer_fence().get(), 7);
        assert_eq!(context.writer_fence().checked_next().unwrap().get(), 8);
        assert_eq!(context.deadline().unix_millis(), 1_000);
        assert!(!context.deadline().is_expired_at(999));
        assert!(context.deadline().is_expired_at(1_000));
        assert_eq!(context.correlation_id().as_bytes(), &[9; 16]);
        assert_eq!(
            WriterFenceGeneration::new(u64::MAX).unwrap().checked_next(),
            None
        );
    }

    #[test]
    fn durable_commit_outcome_does_not_blur_conflict_and_ambiguity() {
        assert_eq!(
            DurableCommitOutcome::from(AtomicStateWriteResult::Conflict {
                key: key("dependency"),
                current_revision: StateRevision::new(4),
            }),
            DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
                key: key("dependency"),
                current_revision: StateRevision::new(4),
            })
        );
        assert_ne!(
            DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit),
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        );
        assert_ne!(
            DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure),
            DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
                key: key("dependency"),
                current_revision: StateRevision::new(4),
            })
        );
    }

    #[test]
    fn indexed_outbox_claim_contract_bounds_identity_payload_and_lease() {
        assert_eq!(
            OutboxRequestId::new([0; 32]),
            Err(IndexedOutboxContractError::ZeroRequestId)
        );
        assert_eq!(
            DurableOutboxLeaseId::new([0; 32]),
            Err(IndexedOutboxContractError::ZeroLeaseId)
        );
        let request_id = OutboxRequestId::new([3; 32]).unwrap();
        let lease_id = DurableOutboxLeaseId::new([4; 32]).unwrap();
        assert_eq!(
            DueOutboxClaimRequest::new(domain(1), 1_000, lease_id, 1_000),
            Err(IndexedOutboxContractError::InvalidLeaseWindow)
        );
        assert_eq!(
            DueOutboxClaimRequest::new(
                domain(1),
                1_000,
                lease_id,
                1_001 + MAX_DURABLE_OUTBOX_LEASE_MILLIS,
            ),
            Err(IndexedOutboxContractError::InvalidLeaseWindow)
        );
        let request = DueOutboxClaimRequest::new(domain(1), 1_000, lease_id, 2_000).unwrap();
        assert_eq!(request.domain(), domain(1));
        assert_eq!(request.now_unix_millis(), 1_000);
        assert_eq!(request.lease_id(), lease_id);
        assert_eq!(request.lease_expires_at_unix_millis(), 2_000);
        let exact =
            RequestOutboxClaimRequest::new(domain(1), request_id, 1_000, lease_id, 2_000).unwrap();
        assert_eq!(exact.domain(), domain(1));
        assert_eq!(exact.request_id(), request_id);
        assert_eq!(exact.now_unix_millis(), 1_000);
        assert_eq!(exact.lease_id(), lease_id);
        assert_eq!(exact.lease_expires_at_unix_millis(), 2_000);

        assert_eq!(
            DurableOutboxClaim::from_parts(request_id, 2, lease_id, 2_000, Vec::new()),
            Err(IndexedOutboxContractError::EmptyPayload)
        );
        let claim =
            DurableOutboxClaim::from_parts(request_id, 2, lease_id, 2_000, vec![8, 9]).unwrap();
        assert_eq!(claim.request_id(), request_id);
        assert_eq!(claim.message_index(), 2);
        assert_eq!(claim.lease_id(), lease_id);
        assert_eq!(claim.lease_expires_at_unix_millis(), 2_000);
        assert_eq!(claim.canonical_payload(), &[8, 9]);

        let acknowledgement = DurableOutboxAcknowledgement::new(domain(1), request_id, 2, lease_id);
        assert_eq!(acknowledgement.domain(), domain(1));
        assert_eq!(acknowledgement.request_id(), request_id);
        assert_eq!(acknowledgement.message_index(), 2);
        assert_eq!(acknowledgement.lease_id(), lease_id);
    }

    #[test]
    fn indexed_outbox_outcomes_keep_claim_and_ack_ambiguity_explicit() {
        assert_ne!(
            DurableOutboxClaimOutcome::Rejected(
                DurableOutboxClaimRejection::DeadlineExceededBeforeCommit
            ),
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        );
        assert_ne!(
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch
            ),
            DurableOutboxAcknowledgementOutcome::Acknowledged
        );
        assert_ne!(
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit
            ),
            DurableOutboxAcknowledgementOutcome::Indeterminate(
                IndeterminateCommitReason::DeadlineExceeded
            )
        );
    }

    #[test]
    fn structured_durable_state_section_supports_read_only_assertions() {
        let state = DurableStateTransaction::new(
            domain(1),
            AtomicStateReadSet::new(vec![read("dependency", StateRevision::new(7))]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(state.domain(), domain(1));
        assert_eq!(state.reads().len(), 1);
        assert!(state.mutations().is_empty());
        assert!(state.represented_bytes() > 0);
        assert_eq!(
            DurableStateTransaction::new(
                domain(1),
                AtomicStateReadSet::new(vec![read("dependency", StateRevision::new(7))]).unwrap(),
                vec![mutation("other", StateMutation::Delete)],
            ),
            Err(RuntimeError::StateMutationWithoutRead)
        );
    }

    #[test]
    fn durable_object_section_is_typed_canonical_contained_and_bounded() {
        assert_eq!(DurableObjectChanges::empty().represented_bytes(), 0);
        assert_eq!(DurableObjectVersion::new(0), None);
        assert_eq!(ObjectHeadRevision::new(0), None);
        assert_eq!(DurableObjectVersion::MAX.checked_next(), None);
        assert_eq!(
            ObjectHeadRevision::new(u64::MAX).unwrap().checked_next(),
            None
        );
        assert_eq!(
            DurableObjectVersionRecord::from_inline_canonical_bytes(
                vec![0; MAX_DURABLE_INLINE_OBJECT_BYTES + 1],
                Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
                1,
            ),
            Err(DurableInvocationError::ObjectBodyTooLarge {
                length: MAX_DURABLE_INLINE_OBJECT_BYTES + 1,
                maximum: MAX_DURABLE_INLINE_OBJECT_BYTES,
            })
        );
        assert_eq!(
            DurableObjectOwnerProjection::from_canonical_bytes(Some(vec![
                0;
                MAX_DURABLE_OBJECT_PROJECTION_BYTES
                    + 1
            ])),
            Err(DurableInvocationError::ObjectOwnerProjectionTooLarge {
                length: MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1,
                maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
            })
        );
        assert_eq!(
            DurableObjectRoutingProjection::new(Some(vec![
                0;
                MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1
            ])),
            Err(DurableInvocationError::ObjectRoutingProjectionTooLarge {
                length: MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1,
                maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
            })
        );

        let first_id: ObjectId = ObjectId::new([0x11; 32]);
        let second_id: ObjectId = ObjectId::new([0x22; 32]);
        let blob_record: DurableObjectVersionRecord =
            DurableObjectVersionRecord::from_blob_reference(
                first_id,
                DurableObjectVersion::FIRST,
                Digest32::new(HashAlgorithmId::Sha2_256, [0x31; 32]),
                7,
                8,
                Digest32::new(HashAlgorithmId::Sha3_256, [0x32; 32]),
            );
        assert_eq!(
            blob_record.canonical_record_type_id(),
            u32::from(OBJECT_CANONICAL_TYPE_ID)
        );
        assert_eq!(blob_record.inline_type_hash(), None);
        assert_eq!(
            blob_record.payload().blob_digest(),
            Some(Digest32::new(HashAlgorithmId::Sha3_256, [0x32; 32]))
        );
        assert!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    DurableObjectMutation::Create {
                        version: blob_record,
                        owner_projection: DurableObjectOwnerProjection::default(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            )
            .is_ok()
        );
        let changes: DurableObjectChanges = DurableObjectChanges::new(
            vec![
                DurableObjectHeadRead::new(second_id, DurableObjectHead::Absent),
                DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
            ],
            vec![
                DurableObjectMutationEntry::new(second_id, test_create_mutation(1, 0x22)),
                DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11)),
            ],
        )
        .unwrap();
        assert_eq!(changes.reads()[0].object_id(), first_id);
        assert_eq!(changes.reads()[1].object_id(), second_id);
        assert_eq!(changes.mutations()[0].object_id(), first_id);
        assert_eq!(changes.mutations()[1].object_id(), second_id);
        assert!(changes.represented_bytes() > 2 * size_of::<u32>());

        assert_eq!(
            DurableObjectChanges::new(
                vec![
                    DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
                    DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
                ],
                Vec::new(),
            ),
            Err(DurableInvocationError::DuplicateObjectReadId)
        );
        assert_eq!(
            DurableObjectChanges::new(
                Vec::new(),
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    test_create_mutation(1, 0x11),
                )],
            ),
            Err(DurableInvocationError::ObjectMutationWithoutRead {
                object_id: first_id,
            })
        );
        assert_eq!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    test_create_mutation(1, 0x22),
                )],
            ),
            Err(DurableInvocationError::InvalidObjectTransition {
                object_id: first_id,
            })
        );
        assert_eq!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    DurableObjectMutation::Create {
                        version: test_object_version(1, 0x11),
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                            .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            ),
            Err(DurableInvocationError::InvalidObjectTransition {
                object_id: first_id,
            })
        );
        assert_eq!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Absent,
                )],
                vec![
                    DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11),),
                    DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11),),
                ],
            ),
            Err(DurableInvocationError::DuplicateObjectMutationId)
        );
        assert_eq!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    test_create_mutation(2, 0x11),
                )],
            ),
            Err(DurableInvocationError::InvalidObjectTransition {
                object_id: first_id,
            })
        );

        let too_many_mutations: Vec<DurableObjectMutationEntry> = (0
            ..=MAX_DURABLE_OBJECT_MUTATIONS)
            .map(|index: usize| {
                let mut bytes: [u8; 32] = [0; 32];
                bytes[..size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
                DurableObjectMutationEntry::new(ObjectId::new(bytes), test_create_mutation(1, 0x33))
            })
            .collect();
        assert_eq!(
            DurableObjectChanges::new(Vec::new(), too_many_mutations),
            Err(DurableInvocationError::TooManyObjectMutations {
                count: MAX_DURABLE_OBJECT_MUTATIONS + 1,
                maximum: MAX_DURABLE_OBJECT_MUTATIONS,
            })
        );

        let too_many_reads: Vec<DurableObjectHeadRead> = (0_u16
            ..=u16::try_from(MAX_DURABLE_OBJECT_READS).unwrap())
            .map(|index: u16| {
                let mut bytes: [u8; 32] = [0; 32];
                bytes[..2].copy_from_slice(&index.to_be_bytes());
                DurableObjectHeadRead::new(ObjectId::new(bytes), DurableObjectHead::Absent)
            })
            .collect();
        assert_eq!(
            DurableObjectChanges::new(too_many_reads, Vec::new()),
            Err(DurableInvocationError::TooManyObjectReads {
                count: MAX_DURABLE_OBJECT_READS + 1,
                maximum: MAX_DURABLE_OBJECT_READS,
            })
        );

        let empty_object: Object = Object {
            id: first_id,
            version: 2,
            owner: Owner::Shared,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x46; 32]),
            schema_version: 1,
            data: Vec::new(),
        };
        let empty_length: usize = encode_object(&empty_object).unwrap().len();
        let mut maximum_object: Object = empty_object;
        maximum_object.data = vec![0; MAX_DURABLE_INLINE_OBJECT_BYTES - empty_length];
        let next_version: DurableObjectVersionRecord =
            DurableObjectVersionRecord::from_inline_object(
                maximum_object,
                Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
                4,
            )
            .unwrap();
        assert_eq!(
            next_version
                .payload()
                .inline()
                .unwrap()
                .canonical_bytes()
                .len(),
            MAX_DURABLE_INLINE_OBJECT_BYTES
        );
        assert!(
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    first_id,
                    DurableObjectHead::Current {
                        head_revision: ObjectHeadRevision::FIRST,
                        object_version: DurableObjectVersion::FIRST,
                        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                            .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
                vec![DurableObjectMutationEntry::new(
                    first_id,
                    DurableObjectMutation::Update {
                        version: next_version,
                        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                            .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            )
            .is_ok()
        );
    }

    #[test]
    fn memory_durable_objects_enforce_domain_fence_and_deadline() {
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(7).unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new(fence);
        store.set_time(100);
        let first_domain: AtomicityDomainId = domain(0x31);
        let second_domain: AtomicityDomainId = domain(0x32);
        let object_id: ObjectId = ObjectId::new([0x41; 32]);
        let objects: DurableObjectChanges = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                object_id,
                test_create_mutation(1, 0x41),
            )],
        )
        .unwrap();

        let stale_context: DurableOperationContext = durable_context(6, 200, 0x41);
        assert_eq!(
            store.commit_invocation(
                &stale_context,
                test_object_invocation(first_domain, 0x41, objects.clone()),
            ),
            DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
                active_generation: fence,
            })
        );
        assert_eq!(
            store.get_object_head(&stale_context, first_domain, object_id),
            Err(DurableReadError::WriterFenced {
                active_generation: fence,
            })
        );
        assert_eq!(
            store.get_object_version(
                &stale_context,
                first_domain,
                object_id,
                DurableObjectVersion::FIRST,
            ),
            Err(DurableReadError::WriterFenced {
                active_generation: fence,
            })
        );
        let expired_context: DurableOperationContext = durable_context(7, 100, 0x42);
        assert_eq!(
            store.commit_invocation(
                &expired_context,
                test_object_invocation(first_domain, 0x42, objects.clone()),
            ),
            DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
        );
        assert_eq!(
            store.get_object_head(&expired_context, first_domain, object_id),
            Err(DurableReadError::DeadlineExceeded)
        );
        assert_eq!(
            store.get_object_version(
                &expired_context,
                first_domain,
                object_id,
                DurableObjectVersion::FIRST,
            ),
            Err(DurableReadError::DeadlineExceeded)
        );

        let live_context: DurableOperationContext = durable_context(7, 200, 0x43);
        assert_eq!(
            store.commit_invocation(
                &live_context,
                test_object_invocation(first_domain, 0x43, objects),
            ),
            DurableCommitOutcome::Committed
        );
        assert!(matches!(
            store
                .get_object_head(&live_context, first_domain, object_id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
        assert_eq!(
            store
                .get_object_head(&live_context, second_domain, object_id)
                .unwrap(),
            DurableObjectHead::Absent
        );
        assert!(
            store
                .get_object_version(
                    &live_context,
                    first_domain,
                    object_id,
                    DurableObjectVersion::FIRST,
                )
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .get_object_version(
                    &live_context,
                    second_domain,
                    object_id,
                    DurableObjectVersion::FIRST,
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn structured_durable_invocation_keeps_receipt_and_outbox_typed() {
        let request_id = DurableRequestId::new([0x81; 32]).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x82; 32]);
        let message_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x83; 32]);
        let receipt =
            DurableRequestReceipt::new(request_id, event_digest, vec![0x84, 0x85]).unwrap();
        let message = DurableOutboxMessage::new(message_digest, vec![0x86, 0x87]).unwrap();
        let outbox =
            DurableOutboxBatch::new(request_id, event_digest, vec![message.clone()]).unwrap();
        let state = DurableStateTransaction::new(
            domain(1),
            AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
            vec![mutation("state", StateMutation::Put(vec![1]))],
        )
        .unwrap();
        let invocation = DurableInvocationTransaction::new(
            domain(1),
            Some(state),
            DurableObjectChanges::empty(),
            receipt.clone(),
            Some(outbox.clone()),
        )
        .unwrap();

        assert_eq!(invocation.domain(), domain(1));
        assert_eq!(invocation.state().unwrap().mutations().len(), 1);
        assert!(invocation.objects().is_empty());
        assert_eq!(invocation.receipt(), &receipt);
        assert_eq!(invocation.outbox(), Some(&outbox));
        assert!(invocation.represented_bytes() > receipt.canonical_bytes().len());
        assert_eq!(outbox.messages()[0], message);
        assert_eq!(outbox.messages()[0].payload_digest(), message_digest);
    }

    #[test]
    fn structured_durable_invocation_rejects_cross_section_identity_drift() {
        let request_id = DurableRequestId::new([0x91; 32]).unwrap();
        let other_request_id = DurableRequestId::new([0x92; 32]).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x93; 32]);
        let other_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x94; 32]);
        assert_eq!(
            DurableRequestReceipt::new(request_id, event_digest, Vec::new()),
            Err(DurableInvocationError::EmptyReceipt)
        );
        assert_eq!(
            DurableOutboxMessage::new(event_digest, Vec::new()),
            Err(DurableInvocationError::EmptyOutboxMessage)
        );
        let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
        let message = DurableOutboxMessage::new(event_digest, vec![2]).unwrap();
        let wrong_request =
            DurableOutboxBatch::new(other_request_id, event_digest, vec![message.clone()]).unwrap();
        assert_eq!(
            DurableInvocationTransaction::new(
                domain(1),
                None,
                DurableObjectChanges::empty(),
                receipt.clone(),
                Some(wrong_request),
            ),
            Err(DurableInvocationError::RequestIdentityMismatch)
        );
        let wrong_digest =
            DurableOutboxBatch::new(request_id, other_digest, vec![message]).unwrap();
        assert_eq!(
            DurableInvocationTransaction::new(
                domain(1),
                None,
                DurableObjectChanges::empty(),
                receipt.clone(),
                Some(wrong_digest),
            ),
            Err(DurableInvocationError::EventDigestMismatch)
        );
        let state = DurableStateTransaction::new(
            domain(2),
            AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            DurableInvocationTransaction::new(
                domain(1),
                Some(state),
                DurableObjectChanges::empty(),
                receipt,
                None,
            ),
            Err(DurableInvocationError::StateDomainMismatch)
        );
    }

    #[test]
    fn memory_durable_store_commits_state_receipt_and_outbox_atomically() {
        let fence = WriterFenceGeneration::new(7).unwrap();
        let store = MemoryDurableStateStore::new(fence);
        store.set_time(100);
        let context = durable_context(7, 1_000, 1);
        let invocation = durable_invocation(domain(3), 0xA1, StateRevision::INITIAL, Some(9), true);
        let request_id = invocation.receipt().request_id();
        let receipt = invocation.receipt().clone();

        assert_eq!(
            store.commit_invocation(&context, invocation),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            store
                .get_versioned_durable(&context, domain(3), b"state")
                .unwrap(),
            VersionedStateValue::from_persisted_parts(StateRevision::new(1), Some(vec![9]))
                .unwrap()
        );
        assert_eq!(
            store
                .get_request_receipt(&context, domain(3), request_id)
                .unwrap(),
            Some(receipt)
        );
        let data = store.inner.read().unwrap();
        assert_eq!(data.receipts.len(), 1);
        assert_eq!(data.outboxes.len(), 1);
    }

    #[test]
    fn memory_durable_store_conflict_publishes_no_partial_invocation() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let context = durable_context(1, 1_000, 2);
        let initialize = AtomicStateTransaction::new(
            domain(4),
            AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
            AtomicStateMutationSet::new(vec![mutation("state", StateMutation::Put(vec![7]))])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, initialize),
            DurableCommitOutcome::Committed
        );
        let invocation = durable_invocation(domain(4), 0xB1, StateRevision::INITIAL, Some(8), true);
        let request_id = invocation.receipt().request_id();

        assert_eq!(
            store.commit_invocation(&context, invocation),
            DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
                key: key("state"),
                current_revision: StateRevision::new(1),
            })
        );
        assert_eq!(
            store
                .get_versioned_durable(&context, domain(4), b"state")
                .unwrap()
                .value(),
            Some([7].as_slice())
        );
        assert_eq!(
            store
                .get_request_receipt(&context, domain(4), request_id)
                .unwrap(),
            None
        );
        assert!(store.inner.read().unwrap().outboxes.is_empty());
    }

    #[test]
    fn memory_durable_store_preserves_read_only_revision_and_fails_closed_on_authority() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(5).unwrap());
        store.set_time(100);
        let context = durable_context(5, 1_000, 3);
        let read_only = durable_invocation(domain(5), 0xC1, StateRevision::INITIAL, None, false);
        assert_eq!(
            store.commit_invocation(&context, read_only),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            store
                .get_versioned_durable(&context, domain(5), b"state")
                .unwrap()
                .revision(),
            StateRevision::INITIAL
        );

        store.set_active_writer_fence(WriterFenceGeneration::new(6).unwrap());
        assert_eq!(
            store.get_versioned_durable(&context, domain(5), b"state"),
            Err(DurableReadError::WriterFenced {
                active_generation: WriterFenceGeneration::new(6).unwrap(),
            })
        );
        assert_eq!(
            store.commit_invocation(
                &context,
                durable_invocation(domain(5), 0xC2, StateRevision::INITIAL, None, false,),
            ),
            DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
                active_generation: WriterFenceGeneration::new(6).unwrap(),
            })
        );

        let current_context = durable_context(6, 100, 4);
        assert_eq!(
            store.get_versioned_durable(&current_context, domain(5), b"state"),
            Err(DurableReadError::DeadlineExceeded)
        );
        assert_eq!(
            store.commit_invocation(
                &current_context,
                durable_invocation(domain(5), 0xC3, StateRevision::INITIAL, None, false,),
            ),
            DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
        );
    }

    #[test]
    fn memory_indexed_outbox_claims_stable_order_and_reconciles_same_lease() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let context = durable_context(1, 1_000, 5);
        let selected_domain = domain(6);
        assert_eq!(
            store.commit_invocation(
                &context,
                durable_outbox_invocation(selected_domain, 0xB2, &[0x22]),
            ),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            store.commit_invocation(
                &context,
                durable_outbox_invocation(selected_domain, 0xA2, &[0x11]),
            ),
            DurableCommitOutcome::Committed
        );

        let lease = DurableOutboxLeaseId::new([0x31; 32]).unwrap();
        let request = DueOutboxClaimRequest::new(selected_domain, 0, lease, 10).unwrap();
        let first = store.claim_due_outbox(&context, request);
        let replay = store.claim_due_outbox(&context, request);
        assert_eq!(first, replay);
        assert_eq!(
            store.claim_due_outbox(
                &context,
                DueOutboxClaimRequest::new(domain(8), 0, lease, 10).unwrap(),
            ),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
        );
        let DurableOutboxClaimOutcome::Claimed(claim) = first else {
            panic!("expected a claimed outbox");
        };
        assert_eq!(
            claim.request_id(),
            OutboxRequestId::new([0xA2; 32]).unwrap()
        );
        assert_eq!(claim.canonical_payload(), &[0x11]);
        assert_eq!(
            store.acknowledge_outbox(
                &context,
                DurableOutboxAcknowledgement::new(
                    selected_domain,
                    claim.request_id(),
                    claim.message_index(),
                    lease,
                ),
            ),
            DurableOutboxAcknowledgementOutcome::Acknowledged
        );

        let next_lease = DurableOutboxLeaseId::new([0x32; 32]).unwrap();
        let next = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 0, next_lease, 10).unwrap(),
        );
        let DurableOutboxClaimOutcome::Claimed(next) = next else {
            panic!("expected the next ordered outbox");
        };
        assert_eq!(next.request_id(), OutboxRequestId::new([0xB2; 32]).unwrap());
    }

    #[test]
    fn memory_exact_request_claim_does_not_take_an_older_domain_row() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(3).unwrap());
        let context = durable_context(3, 1_000, 7);
        let selected_domain = domain(9);
        for request_byte in [0xA3, 0xB3] {
            assert_eq!(
                store.commit_invocation(
                    &context,
                    durable_outbox_invocation(selected_domain, request_byte, &[request_byte]),
                ),
                DurableCommitOutcome::Committed
            );
        }

        let exact_request_id = OutboxRequestId::new([0xB3; 32]).unwrap();
        let exact_lease = DurableOutboxLeaseId::new([0x51; 32]).unwrap();
        let exact_request =
            RequestOutboxClaimRequest::new(selected_domain, exact_request_id, 0, exact_lease, 10)
                .unwrap();
        let exact = store.claim_request_outbox(&context, exact_request);
        let DurableOutboxClaimOutcome::Claimed(exact) = exact else {
            panic!("expected exact request claim");
        };
        assert_eq!(exact.request_id(), exact_request_id);
        assert_eq!(exact.canonical_payload(), &[0xB3]);
        assert_eq!(
            store.claim_request_outbox(
                &context,
                RequestOutboxClaimRequest::new(
                    selected_domain,
                    OutboxRequestId::new([0xA3; 32]).unwrap(),
                    0,
                    exact_lease,
                    10,
                )
                .unwrap(),
            ),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
        );

        let due_lease = DurableOutboxLeaseId::new([0x52; 32]).unwrap();
        let due = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 0, due_lease, 10).unwrap(),
        );
        let DurableOutboxClaimOutcome::Claimed(due) = due else {
            panic!("expected remaining due claim");
        };
        assert_eq!(due.request_id(), OutboxRequestId::new([0xA3; 32]).unwrap());
    }

    #[test]
    fn memory_indexed_outbox_retains_attempt_history_for_delayed_ack() {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(2).unwrap());
        let context = durable_context(2, 1_000, 6);
        let selected_domain = domain(7);
        assert_eq!(
            store.commit_invocation(
                &context,
                durable_outbox_invocation(selected_domain, 0xD2, &[0x41, 0x42]),
            ),
            DurableCommitOutcome::Committed
        );
        let request_id = OutboxRequestId::new([0xD2; 32]).unwrap();
        let expired_lease = DurableOutboxLeaseId::new([0x41; 32]).unwrap();
        assert!(matches!(
            store.claim_due_outbox(
                &context,
                DueOutboxClaimRequest::new(selected_domain, 0, expired_lease, 10).unwrap(),
            ),
            DurableOutboxClaimOutcome::Claimed(_)
        ));
        assert_eq!(
            store.claim_due_outbox(
                &context,
                DueOutboxClaimRequest::new(selected_domain, 10, expired_lease, 20).unwrap(),
            ),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
        );

        let first_acknowledged_lease = DurableOutboxLeaseId::new([0x42; 32]).unwrap();
        let redelivery = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 10, first_acknowledged_lease, 20).unwrap(),
        );
        let DurableOutboxClaimOutcome::Claimed(redelivery) = redelivery else {
            panic!("expected expired lease redelivery");
        };
        assert_eq!(redelivery.message_index(), 0);
        let first_ack = DurableOutboxAcknowledgement::new(
            selected_domain,
            request_id,
            0,
            first_acknowledged_lease,
        );
        assert_eq!(
            store.acknowledge_outbox(&context, first_ack),
            DurableOutboxAcknowledgementOutcome::Acknowledged
        );

        let second_lease = DurableOutboxLeaseId::new([0x43; 32]).unwrap();
        let second = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 10, second_lease, 20).unwrap(),
        );
        let DurableOutboxClaimOutcome::Claimed(second) = second else {
            panic!("expected second message");
        };
        assert_eq!(second.message_index(), 1);
        assert_eq!(
            store.acknowledge_outbox(
                &context,
                DurableOutboxAcknowledgement::new(selected_domain, request_id, 1, second_lease),
            ),
            DurableOutboxAcknowledgementOutcome::Acknowledged
        );

        assert_eq!(
            store.acknowledge_outbox(&context, first_ack),
            DurableOutboxAcknowledgementOutcome::Acknowledged
        );
        assert_eq!(
            store.claim_due_outbox(
                &context,
                DueOutboxClaimRequest::new(selected_domain, 10, expired_lease, 20).unwrap(),
            ),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
        );
        let data = store.inner.read().unwrap();
        assert_eq!(data.delivery_attempts.len(), 3);
        assert!(data.deliveries.values().all(|delivery| delivery.completed));
    }

    #[test]
    fn memory_domain_transactions_isolate_domains_and_assert_every_read() {
        let store = MemoryStateStore::default();
        let first_domain = domain(1);
        let second_domain = domain(2);

        let initialize_dependency = transaction(
            first_domain,
            vec![read("dependency", StateRevision::INITIAL)],
            vec![mutation("dependency", StateMutation::Put(vec![9]))],
        )
        .unwrap();
        assert_eq!(
            store.commit_transaction(initialize_dependency).unwrap(),
            AtomicStateWriteResult::Committed
        );

        let stale = transaction(
            first_domain,
            vec![
                read("dependency", StateRevision::INITIAL),
                read("result", StateRevision::INITIAL),
            ],
            vec![mutation("result", StateMutation::Put(vec![1]))],
        )
        .unwrap();
        assert_eq!(
            store.commit_transaction(stale).unwrap(),
            AtomicStateWriteResult::Conflict {
                key: key("dependency"),
                current_revision: StateRevision::new(1),
            }
        );
        assert_eq!(
            store
                .get_versioned_in_domain(first_domain, b"result")
                .unwrap()
                .value(),
            None
        );
        assert_eq!(
            store
                .get_versioned_in_domain(first_domain, b"dependency")
                .unwrap()
                .value(),
            Some([9].as_slice())
        );
        assert_eq!(
            store
                .get_versioned_in_domain(second_domain, b"dependency")
                .unwrap(),
            VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
        );
    }

    #[test]
    fn state_key_scan_is_prefix_bounded_and_cursor_paginated() {
        let store = MemoryStateStore::default();
        for name in ["outbox/c", "other/a", "outbox/a", "outbox/b"] {
            store.put(key(name), vec![1]).unwrap();
        }
        let first_scan =
            StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(2).unwrap()).unwrap();
        let first = store.scan_keys(&first_scan).unwrap();
        assert_eq!(first.keys(), &[key("outbox/a"), key("outbox/b")]);
        assert_eq!(first.continuation_cursor(), Some(b"outbox/b".as_slice()));

        let second_scan = StateKeyScan::new(
            key("outbox/"),
            first.continuation_cursor().map(<[u8]>::to_vec),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let second = store.scan_keys(&second_scan).unwrap();
        assert_eq!(second.keys(), &[key("outbox/c")]);
        assert_eq!(second.continuation_cursor(), None);
    }

    #[test]
    fn state_key_scan_rejects_unbounded_or_invalid_pages() {
        assert_eq!(
            StateKeyScan::new(
                key("outbox/"),
                Some(key("other/a")),
                NonZeroUsize::new(1).unwrap(),
            ),
            Err(RuntimeError::StateScanCursorOutsidePrefix)
        );
        assert_eq!(
            StateKeyScan::new(
                key("outbox/"),
                None,
                NonZeroUsize::new(MAX_STATE_SCAN_KEYS + 1).unwrap(),
            ),
            Err(RuntimeError::StateScanLimitTooLarge {
                requested: MAX_STATE_SCAN_KEYS + 1,
                maximum: MAX_STATE_SCAN_KEYS,
            })
        );

        let scan = StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(2).unwrap()).unwrap();
        assert_eq!(
            StateKeyPage::from_ordered_candidates(&scan, vec![key("outbox/b"), key("outbox/a")],),
            Err(RuntimeError::InvalidStateScanPage)
        );
        assert_eq!(
            StateKeyPage::from_ordered_candidates(&scan, vec![key("other/a")]),
            Err(RuntimeError::InvalidStateScanPage)
        );
    }

    #[test]
    fn atomic_write_set_commits_multiple_keys_in_canonical_order() {
        let store = MemoryStateStore::default();
        let writes = AtomicStateWriteSet::new(vec![
            StateWrite::new(
                key("z"),
                StateRevision::INITIAL,
                StateMutation::Put(vec![2]),
            )
            .unwrap(),
            StateWrite::new(
                key("a"),
                StateRevision::INITIAL,
                StateMutation::Put(vec![1]),
            )
            .unwrap(),
        ])
        .unwrap();

        assert_eq!(writes.writes()[0].key(), b"a");
        assert_eq!(writes.writes()[1].key(), b"z");
        assert_eq!(
            store.commit_atomic(writes).unwrap(),
            AtomicStateWriteResult::Committed
        );
        assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
        assert_eq!(store.get(b"z").unwrap(), Some(vec![2]));
        assert_eq!(
            store.get_versioned(b"a").unwrap().revision(),
            StateRevision::new(1)
        );
    }

    #[test]
    fn atomic_conflict_applies_none_of_the_write_set() {
        let store = MemoryStateStore::default();
        store.put(key("a"), vec![1]).unwrap();
        let observed_a = store.get_versioned(b"a").unwrap();
        let observed_b = store.get_versioned(b"b").unwrap();

        store.put(key("a"), vec![9]).unwrap();
        let writes = AtomicStateWriteSet::new(vec![
            StateWrite::new(key("a"), observed_a.revision(), StateMutation::Put(vec![2])).unwrap(),
            StateWrite::new(key("b"), observed_b.revision(), StateMutation::Put(vec![3])).unwrap(),
        ])
        .unwrap();

        assert_eq!(
            store.commit_atomic(writes).unwrap(),
            AtomicStateWriteResult::Conflict {
                key: key("a"),
                current_revision: StateRevision::new(2),
            }
        );
        assert_eq!(store.get(b"a").unwrap(), Some(vec![9]));
        assert_eq!(store.get(b"b").unwrap(), None);
    }

    #[test]
    fn tombstone_revision_prevents_delete_recreate_aba() {
        let store = MemoryStateStore::default();
        store.put(key("k"), vec![1]).unwrap();
        let stale = store.get_versioned(b"k").unwrap();

        let delete = AtomicStateWriteSet::new(vec![
            StateWrite::new(key("k"), stale.revision(), StateMutation::Delete).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            store.commit_atomic(delete).unwrap(),
            AtomicStateWriteResult::Committed
        );
        let deleted = store.get_versioned(b"k").unwrap();
        assert_eq!(deleted.value(), None);
        assert_eq!(deleted.revision(), StateRevision::new(2));

        let recreate = AtomicStateWriteSet::new(vec![
            StateWrite::new(key("k"), deleted.revision(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            store.commit_atomic(recreate).unwrap(),
            AtomicStateWriteResult::Committed
        );

        let stale_write = AtomicStateWriteSet::new(vec![
            StateWrite::new(key("k"), stale.revision(), StateMutation::Put(vec![7])).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            store.commit_atomic(stale_write).unwrap(),
            AtomicStateWriteResult::Conflict {
                key: key("k"),
                current_revision: StateRevision::new(3),
            }
        );
        assert_eq!(store.get(b"k").unwrap(), Some(vec![1]));
    }

    #[test]
    fn atomic_write_set_rejects_duplicates_and_resource_excess() {
        let duplicate =
            StateWrite::new(key("same"), StateRevision::INITIAL, StateMutation::Delete).unwrap();
        assert_eq!(
            AtomicStateWriteSet::new(vec![duplicate.clone(), duplicate]),
            Err(RuntimeError::DuplicateStateWriteKey)
        );
        assert_eq!(
            AtomicStateWriteSet::new(Vec::new()),
            Err(RuntimeError::EmptyWriteSet)
        );
        assert!(matches!(
            StateWrite::new(
                vec![0; MAX_STATE_KEY_BYTES + 1],
                StateRevision::INITIAL,
                StateMutation::Delete,
            ),
            Err(RuntimeError::StateKeyTooLong { .. })
        ));
        assert!(matches!(
            StateWrite::new(
                key("large"),
                StateRevision::INITIAL,
                StateMutation::Put(vec![0; MAX_STATE_VALUE_BYTES + 1]),
            ),
            Err(RuntimeError::StateValueTooLarge { .. })
        ));
    }

    #[test]
    fn revision_overflow_aborts_before_any_atomic_mutation() {
        let store = MemoryStateStore::default();
        {
            let mut domains = store.inner.write().unwrap();
            domains.entry(LEGACY_MEMORY_DOMAIN).or_default().insert(
                key("a"),
                StoredStateValue {
                    revision: StateRevision::new(u64::MAX),
                    value: Some(vec![1]),
                },
            );
        }
        let writes = AtomicStateWriteSet::new(vec![
            StateWrite::new(
                key("a"),
                StateRevision::new(u64::MAX),
                StateMutation::Put(vec![2]),
            )
            .unwrap(),
            StateWrite::new(
                key("b"),
                StateRevision::INITIAL,
                StateMutation::Put(vec![3]),
            )
            .unwrap(),
        ])
        .unwrap();

        assert_eq!(
            store.commit_atomic(writes),
            Err(RuntimeError::StateRevisionOverflow)
        );
        assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
        assert_eq!(store.get(b"b").unwrap(), None);
    }

    #[test]
    fn atomic_assert_checks_revision_without_incrementing_it() {
        let store = MemoryStateStore::default();
        store.put(key("a"), vec![1]).unwrap();
        let observed = store.get_versioned(b"a").unwrap();
        let write_set = AtomicStateWriteSet::new(vec![
            StateWrite::new(key("a"), observed.revision(), StateMutation::Assert).unwrap(),
        ])
        .unwrap();

        assert_eq!(
            store.commit_atomic(write_set).unwrap(),
            AtomicStateWriteResult::Committed
        );
        assert_eq!(store.get_versioned(b"a").unwrap(), observed);
    }

    #[test]
    fn scheduler_returns_only_ready_payloads() {
        let scheduler = MemoryScheduler::default();
        scheduler.schedule(20, vec![2]).unwrap();
        scheduler.schedule(10, vec![1]).unwrap();
        scheduler.schedule(30, vec![3]).unwrap();

        let first = scheduler.drain_ready(20).unwrap();
        let second = scheduler.drain_ready(25).unwrap();
        let third = scheduler.drain_ready(30).unwrap();

        assert_eq!(first.len(), 2);
        assert_eq!(first[0].payload, vec![1]);
        assert_eq!(first[1].payload, vec![2]);
        assert!(second.is_empty());
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].payload, vec![3]);
    }

    #[test]
    fn persistence_layout_is_deterministic_and_namespaced() {
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let layout = PersistenceLayout::new(chain_id.clone(), ProtocolVersion::new(3));

        let key1 = layout.epoch_metadata_key(Epoch::new(7));
        let key2 = layout.epoch_metadata_key(Epoch::new(7));
        assert_eq!(key1, key2);

        let key3 = layout.object_version_key([0x11; 32], 5);
        let key4 = layout.object_version_key([0x11; 32], 6);
        assert_ne!(key3, key4);

        let key5 = layout.system_module_record_key([0xAA; 32], 1);
        let key6 = layout.system_module_record_key([0xAA; 32], 2);
        assert_ne!(key5, key6);

        let other_layout = PersistenceLayout::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
        );
        assert_ne!(
            layout.protocol_config_key(),
            other_layout.protocol_config_key()
        );

        let key1_text = String::from_utf8(key1).unwrap();
        assert!(key1_text.starts_with("se/sunrise-devnet/v3/epoch/"));
        let key5_text = String::from_utf8(key5).unwrap();
        assert!(key5_text.contains("system-modules/"));

        let migration = Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0xBB; 32]);
        let migration_key = layout.migration_record_key(&migration);
        assert_ne!(migration_key, layout.protocol_upgrade_schedule_key());
        assert_ne!(
            layout.consensus_state_key(Epoch::new(7)),
            layout.consensus_state_key(Epoch::new(8))
        );
        assert_ne!(
            layout.request_dedup_key([0xCC; 32]),
            layout.outbox_batch_key([0xCC; 32])
        );
        assert_ne!(
            layout.outbox_batch_key([0xCC; 32]),
            layout.outbox_delivery_key([0xCC; 32])
        );
        assert_ne!(
            layout.request_dedup_key([0xCC; 32]),
            layout.request_dedup_key([0xCD; 32])
        );
        assert!(
            String::from_utf8(migration_key)
                .unwrap()
                .contains("protocol/migrations/sha2-256-")
        );
    }

    #[test]
    fn sender_nonce_key_matches_exact_stable_vector() {
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let layout = PersistenceLayout::new(chain_id, ProtocolVersion::new(3));

        let key = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
        let expected = b"se/sunrise-devnet/v3/sender-nonces/\
1111111111111111111111111111111111111111111111111111111111111111\
/00000000000000000007"
            .to_vec();
        assert_eq!(key, expected);

        let prefix = layout.sender_nonce_prefix();
        assert_eq!(prefix, b"se/sunrise-devnet/v3/sender-nonces/".to_vec());
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn sender_nonce_key_is_deterministic_and_namespaced_per_sender_epoch_chain() {
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let layout = PersistenceLayout::new(chain_id, ProtocolVersion::new(3));

        let key1 = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
        let key2 = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
        assert_eq!(key1, key2);

        let different_sender = layout.sender_nonce_key([0x22; 32], Epoch::new(7));
        assert_ne!(key1, different_sender);

        let different_epoch = layout.sender_nonce_key([0x11; 32], Epoch::new(8));
        assert_ne!(key1, different_epoch);

        let other_layout = PersistenceLayout::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
        );
        assert_ne!(
            key1,
            other_layout.sender_nonce_key([0x11; 32], Epoch::new(7))
        );

        assert!(key1.starts_with(&layout.sender_nonce_prefix()));
        assert!(!different_sender.starts_with(&other_layout.sender_nonce_prefix()));
    }

    #[test]
    fn memory_runtime_wires_components() {
        let runtime = MemoryRuntime::new(ValidatorId::new([0xAA; 32]));
        runtime.set_time(123);

        assert_eq!(runtime.clock().now_unix_millis().unwrap(), 123);
        assert_eq!(
            runtime.signer().validator_id(),
            ValidatorId::new([0xAA; 32])
        );

        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]);
        runtime.blob_store().put_blob(digest, vec![7, 8]).unwrap();
        assert_eq!(
            runtime.blob_store().get_blob(&digest).unwrap(),
            Some(vec![7, 8])
        );

        runtime.transport().send(vec![1, 2, 3]).unwrap();
        assert_eq!(
            runtime.transport().drain_outbound().unwrap(),
            vec![vec![1, 2, 3]]
        );
    }
}
