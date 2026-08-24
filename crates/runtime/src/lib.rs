#![forbid(unsafe_code)]

//! Runtime abstraction and in-memory adapters for serverless-safe node execution.

use core::fmt;
pub use protocol_types::ValidatorId;
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
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
    /// A state revision could not be incremented without wrapping.
    StateRevisionOverflow,
    /// The system clock appears to be before unix epoch.
    ClockBeforeUnixEpoch,
    /// The system clock value exceeds supported range.
    ClockOverflow,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => write!(f, "state keys must not be empty"),
            Self::EmptyScheduledPayload => write!(f, "scheduled payloads must not be empty"),
            Self::EmptyWriteSet => write!(f, "atomic state write set must not be empty"),
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
            Self::StateRevisionOverflow => write!(f, "state revision overflow"),
            Self::ClockBeforeUnixEpoch => write!(f, "clock is before unix epoch"),
            Self::ClockOverflow => write!(f, "clock value exceeds u64 milliseconds range"),
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

    fn checked_next(self) -> Result<Self, RuntimeError> {
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
#[derive(Clone, Debug, Default)]
pub struct MemoryStateStore {
    inner: Arc<RwLock<BTreeMap<Vec<u8>, StoredStateValue>>>,
}

#[derive(Clone, Debug)]
struct StoredStateValue {
    revision: StateRevision,
    value: Option<Vec<u8>>,
}

impl StateStore for MemoryStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        ensure_non_empty_key(key)?;
        let guard = self.inner.read().expect("state store lock poisoned");
        Ok(guard.get(key).and_then(|stored| stored.value.clone()))
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
        ensure_non_empty_key(&key)?;
        validate_state_key(&key)?;
        validate_state_value(&value)?;
        let mut guard = self.inner.write().expect("state store lock poisoned");
        let revision = current_revision(&guard, &key).checked_next()?;
        guard.insert(
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

        let mut guard = self.inner.write().expect("state store lock poisoned");
        let current = guard.get(&key).and_then(|stored| stored.value.clone());
        if current == expected {
            let revision = current_revision(&guard, &key).checked_next()?;
            guard.insert(
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

impl TransactionalStateStore for MemoryStateStore {
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
        validate_state_key(key)?;
        let guard = self.inner.read().expect("state store lock poisoned");
        Ok(match guard.get(key) {
            Some(stored) => VersionedStateValue {
                revision: stored.revision,
                value: stored.value.clone(),
            },
            None => VersionedStateValue {
                revision: StateRevision::INITIAL,
                value: None,
            },
        })
    }

    fn commit_atomic(
        &self,
        write_set: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        let mut guard = self.inner.write().expect("state store lock poisoned");

        for write in write_set.writes() {
            let current = current_revision(&guard, write.key());
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
            .map(|write| current_revision(&guard, write.key()).checked_next())
            .collect::<Result<Vec<_>, _>>()?;

        for (write, revision) in write_set.writes.into_iter().zip(revisions) {
            let value = match write.mutation {
                StateMutation::Put(value) => Some(value),
                StateMutation::Delete => None,
            };
            guard.insert(write.key, StoredStateValue { revision, value });
        }
        Ok(AtomicStateWriteResult::Committed)
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

fn validate_state_key(key: &[u8]) -> Result<(), RuntimeError> {
    ensure_non_empty_key(key)?;
    if key.len() > MAX_STATE_KEY_BYTES {
        return Err(RuntimeError::StateKeyTooLong {
            length: key.len(),
            maximum: MAX_STATE_KEY_BYTES,
        });
    }
    Ok(())
}

fn validate_state_value(value: &[u8]) -> Result<(), RuntimeError> {
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
    use protocol_types::HashAlgorithmId;

    fn key(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
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
            let mut guard = store.inner.write().unwrap();
            guard.insert(
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
        assert!(
            String::from_utf8(migration_key)
                .unwrap()
                .contains("protocol/migrations/sha2-256-")
        );
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
