#![forbid(unsafe_code)]

//! Durable SQLite implementation of the runtime state-store contracts.
//!
//! The store uses a local SQLite database in WAL mode with synchronous FULL.
//! Each atomic write set runs in a BEGIN IMMEDIATE transaction, validates every
//! expected revision in canonical key order, and then commits all mutations or
//! none. Deleted keys retain revision-bearing tombstones.
//!
//! Recovery adapters can discover keys through bounded, exclusive-cursor BLOB
//! prefix pages. A multi-page scan is not a database snapshot; callers must
//! periodically restart from the prefix to observe concurrent earlier inserts.
//!
//! SQLite WAL requires local storage with working shared-memory semantics. This
//! crate does not make network filesystems or serverless ephemeral disks durable.

mod structured;

pub use structured::{
    SQLITE_STRUCTURED_SCHEMA_IDENTITY, SqliteDurableStore, SqliteDurableStoreError, SqliteNamespace,
};

use runtime::{
    AtomicStateWriteResult, AtomicStateWriteSet, CompareAndSwapResult, RuntimeError, StateKeyPage,
    StateKeyScan, StateKeyScanner, StateMutation, StateRevision, StateStore,
    TransactionalStateStore, VersionedStateValue, validate_state_key, validate_state_value,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

/// Encodes a `u64` as an order-preserving 8-byte big-endian value.
///
/// Shared by the legacy opaque store and the structured store so both use the
/// same lexicographically ordered on-disk revision/generation encoding.
pub(crate) fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Decodes an order-preserving 8-byte big-endian `u64`, if the length matches.
pub(crate) fn decode_u64(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x5352_4544;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors produced while opening or inspecting a durable SQLite store.
#[derive(Debug)]
pub enum SqliteStateStoreError {
    /// SQLite rejected an operation.
    Database(rusqlite::Error),
    /// Shared runtime bounds or revision invariants were violated.
    Runtime(RuntimeError),
    /// The database could not enter WAL mode.
    UnsupportedJournalMode(String),
    /// The database belongs to another application.
    ApplicationId(i64),
    /// An unclaimed database already contained unrelated schema objects.
    UnclaimedDatabase,
    /// The database schema version is not supported by this binary.
    SchemaVersion(i64),
    /// A stored revision was not exactly one big-endian `u64`.
    InvalidRevisionEncoding,
    /// Another thread panicked while holding the connection.
    ConnectionPoisoned,
}

impl fmt::Display for SqliteStateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "SQLite operation failed: {error}"),
            Self::Runtime(error) => write!(f, "runtime state validation failed: {error}"),
            Self::UnsupportedJournalMode(mode) => {
                write!(f, "SQLite journal mode is {mode}, expected wal")
            }
            Self::ApplicationId(id) => write!(
                f,
                "SQLite application id is {id:#x}, expected {APPLICATION_ID:#x}"
            ),
            Self::UnclaimedDatabase => {
                f.write_str("unclaimed SQLite database already contains schema objects")
            }
            Self::SchemaVersion(version) => write!(
                f,
                "SQLite schema version is {version}, expected {SCHEMA_VERSION}"
            ),
            Self::InvalidRevisionEncoding => {
                f.write_str("SQLite state revision is not an 8-byte big-endian integer")
            }
            Self::ConnectionPoisoned => f.write_str("SQLite connection lock is poisoned"),
        }
    }
}

impl Error for SqliteStateStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteStateStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

impl From<RuntimeError> for SqliteStateStoreError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// A blocking, durable transactional state store backed by one SQLite file.
///
/// Callers must run this synchronous interface behind bounded blocking
/// isolation when used from an asynchronous request runtime.
#[derive(Debug)]
pub struct SqliteStateStore {
    connection: Mutex<Connection>,
}

impl SqliteStateStore {
    /// Opens or initializes a Sunrise Edge state database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteStateStoreError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;

        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        initialize_schema(&mut connection)?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteStateStoreError::UnsupportedJournalMode(journal_mode));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, SqliteStateStoreError> {
        self.connection
            .lock()
            .map_err(|_| SqliteStateStoreError::ConnectionPoisoned)
    }
}

impl StateStore for SqliteStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        validate_state_key(key)?;
        let connection = self.connection().map_err(runtime_failure)?;
        read_versioned(&connection, key)
            .map(|value| value.value().map(<[u8]>::to_vec))
            .map_err(runtime_failure)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
        validate_state_key(&key)?;
        validate_state_value(&value)?;
        let mut connection = self.connection().map_err(runtime_failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_failure)?;
        let current = read_versioned(&transaction, &key).map_err(runtime_failure)?;
        let next = current.revision().checked_next()?;
        upsert(&transaction, &key, next, Some(&value)).map_err(database_failure)?;
        transaction.commit().map_err(database_failure)
    }

    fn compare_and_swap(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError> {
        validate_state_key(&key)?;
        if let Some(expected) = expected.as_deref() {
            validate_state_value(expected)?;
        }
        validate_state_value(&new_value)?;

        let mut connection = self.connection().map_err(runtime_failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_failure)?;
        let current = read_versioned(&transaction, &key).map_err(runtime_failure)?;
        let current_value = current.value().map(<[u8]>::to_vec);
        let swapped = current_value == expected;
        if swapped {
            let next = current.revision().checked_next()?;
            upsert(&transaction, &key, next, Some(&new_value)).map_err(database_failure)?;
        }
        transaction.commit().map_err(database_failure)?;
        Ok(CompareAndSwapResult {
            swapped,
            current: current_value,
        })
    }
}

impl StateKeyScanner for SqliteStateStore {
    fn scan_keys(&self, scan: &StateKeyScan) -> Result<StateKeyPage, RuntimeError> {
        let connection = self.connection().map_err(runtime_failure)?;
        let upper_bound = prefix_upper_bound(scan.prefix());
        let candidate_limit = i64::try_from(scan.limit().get() + 1)
            .map_err(|_| RuntimeError::InvalidStateScanPage)?;
        let mut statement = connection
            .prepare(
                "SELECT key FROM sunrise_state
                 WHERE key >= ?1
                   AND (?2 IS NULL OR key > ?2)
                   AND (?3 IS NULL OR key < ?3)
                 ORDER BY key
                 LIMIT ?4",
            )
            .map_err(database_failure)?;
        let rows = statement
            .query_map(
                params![
                    scan.prefix(),
                    scan.after(),
                    upper_bound.as_deref(),
                    candidate_limit
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(database_failure)?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(database_failure)?);
        }
        StateKeyPage::from_ordered_candidates(scan, keys)
    }
}

impl TransactionalStateStore for SqliteStateStore {
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
        validate_state_key(key)?;
        let connection = self.connection().map_err(runtime_failure)?;
        read_versioned(&connection, key).map_err(runtime_failure)
    }

    fn commit_atomic(
        &self,
        write_set: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        let mut connection = self.connection().map_err(runtime_failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_failure)?;

        let mut next_revisions = Vec::with_capacity(write_set.writes().len());
        for write in write_set.writes() {
            let current = read_versioned(&transaction, write.key()).map_err(runtime_failure)?;
            if current.revision() != write.expected_revision() {
                let result = AtomicStateWriteResult::Conflict {
                    key: write.key().to_vec(),
                    current_revision: current.revision(),
                };
                transaction.rollback().map_err(database_failure)?;
                return Ok(result);
            }
            next_revisions.push(match write.mutation() {
                StateMutation::Assert => None,
                StateMutation::Put(_) | StateMutation::Delete => {
                    Some(current.revision().checked_next()?)
                }
            });
        }

        for (write, next_revision) in write_set.writes().iter().zip(next_revisions) {
            let Some(next_revision) = next_revision else {
                continue;
            };
            match write.mutation() {
                StateMutation::Assert => {}
                StateMutation::Put(value) => {
                    upsert(&transaction, write.key(), next_revision, Some(value))
                        .map_err(database_failure)?;
                }
                StateMutation::Delete => {
                    upsert(&transaction, write.key(), next_revision, None)
                        .map_err(database_failure)?;
                }
            }
        }
        transaction.commit().map_err(database_failure)?;
        Ok(AtomicStateWriteResult::Committed)
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<(), SqliteStateStoreError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 && application_id != APPLICATION_ID {
        return Err(SqliteStateStoreError::ApplicationId(application_id));
    }
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != 0 && schema_version != SCHEMA_VERSION {
        return Err(SqliteStateStoreError::SchemaVersion(schema_version));
    }

    if application_id == APPLICATION_ID && schema_version == SCHEMA_VERSION {
        connection.prepare("SELECT key, revision, value FROM sunrise_state LIMIT 0")?;
        return Ok(());
    }
    if application_id != 0 {
        return Err(SqliteStateStoreError::SchemaVersion(schema_version));
    }
    if schema_version != 0 {
        return Err(SqliteStateStoreError::ApplicationId(application_id));
    }
    let schema_objects: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if schema_objects != 0 {
        return Err(SqliteStateStoreError::UnclaimedDatabase);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS sunrise_state (
            key BLOB PRIMARY KEY NOT NULL,
            revision BLOB NOT NULL CHECK(length(revision) = 8),
            value BLOB NULL
         ) WITHOUT ROWID;
         PRAGMA application_id = 1397900612;
         PRAGMA user_version = 1;",
    )?;
    transaction.commit()?;

    connection.prepare("SELECT key, revision, value FROM sunrise_state LIMIT 0")?;
    Ok(())
}

fn read_versioned(
    connection: &Connection,
    key: &[u8],
) -> Result<VersionedStateValue, SqliteStateStoreError> {
    let row: Option<(Vec<u8>, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT revision, value FROM sunrise_state WHERE key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(VersionedStateValue::from_persisted_parts(
            StateRevision::INITIAL,
            None,
        )?),
        Some((revision, value)) => {
            let revision = decode_revision(&revision)?;
            if revision == StateRevision::INITIAL {
                return Err(SqliteStateStoreError::Runtime(
                    RuntimeError::InvalidPersistedState,
                ));
            }
            Ok(VersionedStateValue::from_persisted_parts(revision, value)?)
        }
    }
}

fn upsert(
    transaction: &Transaction<'_>,
    key: &[u8],
    revision: StateRevision,
    value: Option<&[u8]>,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO sunrise_state (key, revision, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET
           revision = excluded.revision,
           value = excluded.value",
        params![key, revision.get().to_be_bytes().as_slice(), value],
    )?;
    Ok(())
}

fn decode_revision(bytes: &[u8]) -> Result<StateRevision, SqliteStateStoreError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SqliteStateStoreError::InvalidRevisionEncoding)?;
    Ok(StateRevision::new(u64::from_be_bytes(bytes)))
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    let index = upper.iter().rposition(|byte| *byte != u8::MAX)?;
    upper[index] += 1;
    upper.truncate(index + 1);
    Some(upper)
}

fn database_failure(_error: rusqlite::Error) -> RuntimeError {
    RuntimeError::DurableStoreUnavailable
}

fn runtime_failure(error: SqliteStateStoreError) -> RuntimeError {
    match error {
        SqliteStateStoreError::Runtime(error) => error,
        SqliteStateStoreError::InvalidRevisionEncoding => RuntimeError::InvalidPersistedState,
        _ => RuntimeError::DurableStoreUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{StateKeyScan, StateKeyScanner, StateMutation, StateWrite};
    use std::{
        fs,
        num::NonZeroUsize,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let nonce = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-sqlite-{}-{nanos}-{nonce}.db",
                std::process::id()
            ));
            Self { path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = self.path.as_os_str().to_owned();
                path.push(suffix);
                let path = PathBuf::from(path);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
        }
    }

    fn write(key: &[u8], revision: u64, mutation: StateMutation) -> StateWrite {
        StateWrite::new(key.to_vec(), StateRevision::new(revision), mutation).unwrap()
    }

    #[test]
    fn atomic_values_and_tombstones_survive_reopen() {
        let database = TestDatabase::new();
        {
            let store = SqliteStateStore::open(&database.path).unwrap();
            let result = store
                .commit_atomic(
                    AtomicStateWriteSet::new(vec![
                        write(b"a", 0, StateMutation::Put(vec![1])),
                        write(b"b", 0, StateMutation::Put(vec![2])),
                    ])
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(result, AtomicStateWriteResult::Committed);
        }

        {
            let store = SqliteStateStore::open(&database.path).unwrap();
            let a = store.get_versioned(b"a").unwrap();
            assert_eq!(a.revision(), StateRevision::new(1));
            assert_eq!(a.value(), Some([1].as_slice()));
            let result = store
                .commit_atomic(
                    AtomicStateWriteSet::new(vec![write(b"a", 1, StateMutation::Delete)]).unwrap(),
                )
                .unwrap();
            assert_eq!(result, AtomicStateWriteResult::Committed);
        }

        let store = SqliteStateStore::open(&database.path).unwrap();
        let deleted = store.get_versioned(b"a").unwrap();
        assert_eq!(deleted.revision(), StateRevision::new(2));
        assert_eq!(deleted.value(), None);
        assert_eq!(store.get(b"b").unwrap(), Some(vec![2]));
    }

    #[test]
    fn conflict_aborts_every_mutation_in_key_order() {
        let database = TestDatabase::new();
        let store = SqliteStateStore::open(&database.path).unwrap();
        store.put(b"a".to_vec(), vec![1]).unwrap();

        let result = store
            .commit_atomic(
                AtomicStateWriteSet::new(vec![
                    write(b"b", 0, StateMutation::Put(vec![2])),
                    write(b"a", 0, StateMutation::Put(vec![9])),
                ])
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            result,
            AtomicStateWriteResult::Conflict {
                key: b"a".to_vec(),
                current_revision: StateRevision::new(1),
            }
        );
        assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
        assert_eq!(store.get(b"b").unwrap(), None);
    }

    #[test]
    fn compare_and_swap_is_durable_and_reports_observed_value() {
        let database = TestDatabase::new();
        let store = SqliteStateStore::open(&database.path).unwrap();
        let first = store
            .compare_and_swap(b"key".to_vec(), None, vec![1])
            .unwrap();
        assert!(first.swapped);
        assert_eq!(first.current, None);
        let conflict = store
            .compare_and_swap(b"key".to_vec(), None, vec![2])
            .unwrap();
        assert!(!conflict.swapped);
        assert_eq!(conflict.current, Some(vec![1]));
        drop(store);

        let reopened = SqliteStateStore::open(&database.path).unwrap();
        assert_eq!(reopened.get(b"key").unwrap(), Some(vec![1]));
    }

    #[test]
    fn ordered_prefix_scan_paginates_tombstones_and_survives_reopen() {
        let database = TestDatabase::new();
        let store = SqliteStateStore::open(&database.path).unwrap();
        for key in [b"outbox/c".as_slice(), b"other/a", b"outbox/a", b"outbox/b"] {
            store.put(key.to_vec(), vec![1]).unwrap();
        }
        let observed = store.get_versioned(b"outbox/b").unwrap();
        store
            .commit_atomic(
                AtomicStateWriteSet::new(vec![
                    StateWrite::new(
                        b"outbox/b".to_vec(),
                        observed.revision(),
                        StateMutation::Delete,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();

        let first_scan =
            StateKeyScan::new(b"outbox/".to_vec(), None, NonZeroUsize::new(2).unwrap()).unwrap();
        let first = store.scan_keys(&first_scan).unwrap();
        assert_eq!(first.keys(), &[b"outbox/a".to_vec(), b"outbox/b".to_vec()]);
        assert_eq!(first.continuation_cursor(), Some(b"outbox/b".as_slice()));
        drop(store);

        let reopened = SqliteStateStore::open(&database.path).unwrap();
        let second_scan = StateKeyScan::new(
            b"outbox/".to_vec(),
            first.continuation_cursor().map(<[u8]>::to_vec),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let second = reopened.scan_keys(&second_scan).unwrap();
        assert_eq!(second.keys(), &[b"outbox/c".to_vec()]);
        assert_eq!(second.continuation_cursor(), None);
    }

    #[test]
    fn binary_prefix_scan_handles_prefix_without_finite_upper_bound() {
        let database = TestDatabase::new();
        let store = SqliteStateStore::open(&database.path).unwrap();
        for key in [vec![0xFE, 0xFF], vec![0xFF], vec![0xFF, 0x00]] {
            store.put(key, vec![1]).unwrap();
        }
        let scan = StateKeyScan::new(vec![0xFF], None, NonZeroUsize::new(4).unwrap()).unwrap();
        let page = store.scan_keys(&scan).unwrap();
        assert_eq!(page.keys(), &[vec![0xFF], vec![0xFF, 0x00]]);
        assert_eq!(page.continuation_cursor(), None);
    }

    #[test]
    fn revision_overflow_rolls_back_the_complete_transaction() {
        let database = TestDatabase::new();
        let store = SqliteStateStore::open(&database.path).unwrap();
        store.put(b"a".to_vec(), vec![1]).unwrap();
        drop(store);

        let connection = Connection::open(&database.path).unwrap();
        connection
            .execute(
                "UPDATE sunrise_state SET revision = ?1 WHERE key = ?2",
                params![u64::MAX.to_be_bytes().as_slice(), b"a".as_slice()],
            )
            .unwrap();
        drop(connection);

        let store = SqliteStateStore::open(&database.path).unwrap();
        let error = store
            .commit_atomic(
                AtomicStateWriteSet::new(vec![
                    write(b"a", u64::MAX, StateMutation::Put(vec![9])),
                    write(b"b", 0, StateMutation::Put(vec![2])),
                ])
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(error, RuntimeError::StateRevisionOverflow);
        assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
        assert_eq!(store.get(b"b").unwrap(), None);
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .pragma_update(None, "user_version", 99_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteStateStore::open(&database.path),
            Err(SqliteStateStoreError::SchemaVersion(99))
        ));
    }

    #[test]
    fn unclaimed_database_with_existing_schema_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .execute("CREATE TABLE foreign_data (id INTEGER)", [])
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteStateStore::open(&database.path),
            Err(SqliteStateStoreError::UnclaimedDatabase)
        ));
    }
}
