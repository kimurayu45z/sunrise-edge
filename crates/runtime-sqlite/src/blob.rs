//! Local-only, file-backed content-addressed [`BlobStore`] implementation.
//!
//! [`SqliteBlobStore`] uses its own SQLite `PRAGMA application_id`, schema,
//! and file, separate from both [`crate::SqliteStateStore`] (the opaque
//! legacy store) and [`crate::SqliteDurableStore`] (the structured store):
//! `application_id`/`user_version` are whole-file SQLite properties, so this
//! store cannot share a database file with either of them, and this module
//! never creates, reads, or migrates their tables. A blob is identified only
//! by its self-describing digest, never by a chain/validator/domain
//! namespace, so unlike [`crate::SqliteDurableStore`] this store binds no
//! namespace at open time.
//!
//! `put_blob` is atomic insert-if-absent: storing byte-identical content
//! under an already-present digest is an idempotent no-op success, storing
//! different content under an already-present digest fails closed with
//! [`RuntimeError::BlobDigestConflict`], and each `put_blob` call runs inside
//! its own `BEGIN IMMEDIATE` transaction. `get_blob` is a single bounded
//! point query against the connection, not wrapped in a transaction. This
//! module defines no delete or garbage-collection operation; GC/checkpoint
//! manifest work that would reclaim unreferenced blobs remains deferred.

use protocol_types::Digest32;
use runtime::{BlobStore, RuntimeError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

const BLOB_APPLICATION_ID: i64 = 0x5352_4245;
const BLOB_SCHEMA_VERSION: i64 = 1;
const BLOB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Stable identity of the local-only content-addressed blob SQLite schema,
/// generation one.
///
/// A future additive migration bumps [`BLOB_SCHEMA_VERSION`] and this
/// identity together; a database claimed by an unsupported identity or
/// version fails closed rather than being silently reinterpreted.
pub const SQLITE_BLOB_SCHEMA_IDENTITY: &[u8] = b"sunrise-edge/sqlite/blob/schema/v1";

/// Fail-closed errors opening or bootstrapping a blob SQLite database, distinct
/// from the [`RuntimeError`] surface [`BlobStore`] methods return.
#[derive(Debug)]
pub enum SqliteBlobStoreError {
    /// SQLite rejected an operation.
    Database(rusqlite::Error),
    /// The database could not enter WAL mode.
    UnsupportedJournalMode(String),
    /// The database belongs to another application.
    ApplicationId(i64),
    /// An unclaimed database already contained unrelated schema objects.
    UnclaimedDatabase,
    /// The database schema version is not supported by this binary.
    SchemaVersion(i64),
    /// The persisted schema identity does not match this binary.
    SchemaIdentityMismatch,
    /// The metadata row is missing or malformed.
    InvalidPersistedMetadata,
    /// Another thread panicked while holding the connection.
    ConnectionPoisoned,
}

impl fmt::Display for SqliteBlobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "SQLite operation failed: {error}"),
            Self::UnsupportedJournalMode(mode) => {
                write!(f, "SQLite journal mode is {mode}, expected wal")
            }
            Self::ApplicationId(id) => write!(
                f,
                "SQLite application id is {id:#x}, expected {BLOB_APPLICATION_ID:#x}"
            ),
            Self::UnclaimedDatabase => {
                f.write_str("unclaimed SQLite database already contains schema objects")
            }
            Self::SchemaVersion(version) => write!(
                f,
                "SQLite blob schema version is {version}, expected {BLOB_SCHEMA_VERSION}"
            ),
            Self::SchemaIdentityMismatch => {
                f.write_str("SQLite blob schema identity is unsupported")
            }
            Self::InvalidPersistedMetadata => {
                f.write_str("SQLite blob metadata row is missing or malformed")
            }
            Self::ConnectionPoisoned => f.write_str("SQLite connection lock is poisoned"),
        }
    }
}

impl Error for SqliteBlobStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteBlobStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

/// A blocking, durable, content-addressed [`BlobStore`] backed by one SQLite
/// file.
///
/// Callers must run this synchronous interface behind bounded blocking
/// isolation when used from an asynchronous request runtime. See the module
/// documentation for its exact scope and limits.
#[derive(Debug)]
pub struct SqliteBlobStore {
    connection: Mutex<Connection>,
}

impl SqliteBlobStore {
    /// Opens or bootstraps a local content-addressed blob database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteBlobStoreError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BLOB_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteBlobStoreError::UnsupportedJournalMode(journal_mode));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;

        initialize_blob_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, SqliteBlobStoreError> {
        self.connection
            .lock()
            .map_err(|_| SqliteBlobStoreError::ConnectionPoisoned)
    }
}

impl BlobStore for SqliteBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let mut connection = self.connection().map_err(runtime_failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_failure)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT content FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_failure)?;
        match existing {
            Some(content) if content == bytes => {
                transaction.rollback().map_err(database_failure)?;
                Ok(())
            }
            Some(_) => {
                transaction.rollback().map_err(database_failure)?;
                Err(RuntimeError::BlobDigestConflict { digest })
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO blobs (digest_algorithm, digest_bytes, content)
                         VALUES (?1, ?2, ?3)",
                        params![
                            i64::from(digest.algorithm().as_u16()),
                            digest.bytes().as_slice(),
                            bytes,
                        ],
                    )
                    .map_err(database_failure)?;
                transaction.commit().map_err(database_failure)
            }
        }
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        let connection = self.connection().map_err(runtime_failure)?;
        connection
            .query_row(
                "SELECT content FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_failure)
    }
}

fn blob_schema_ddl() -> String {
    format!(
        "CREATE TABLE blob_metadata (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             schema_identity BLOB NOT NULL
         );

         CREATE TABLE blobs (
             digest_algorithm INTEGER NOT NULL,
             digest_bytes BLOB NOT NULL CHECK(length(digest_bytes) = 32),
             content BLOB NOT NULL,
             PRIMARY KEY (digest_algorithm, digest_bytes)
         ) WITHOUT ROWID;

         PRAGMA application_id = {BLOB_APPLICATION_ID};
         PRAGMA user_version = {BLOB_SCHEMA_VERSION};"
    )
}

fn initialize_blob_schema(connection: &mut Connection) -> Result<(), SqliteBlobStoreError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 && application_id != BLOB_APPLICATION_ID {
        return Err(SqliteBlobStoreError::ApplicationId(application_id));
    }
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != 0 && schema_version != BLOB_SCHEMA_VERSION {
        return Err(SqliteBlobStoreError::SchemaVersion(schema_version));
    }

    if application_id == BLOB_APPLICATION_ID && schema_version == BLOB_SCHEMA_VERSION {
        return verify_schema_identity(connection);
    }
    if application_id != 0 {
        return Err(SqliteBlobStoreError::SchemaVersion(schema_version));
    }
    if schema_version != 0 {
        return Err(SqliteBlobStoreError::ApplicationId(application_id));
    }
    let schema_objects: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if schema_objects != 0 {
        return Err(SqliteBlobStoreError::UnclaimedDatabase);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(&blob_schema_ddl())?;
    transaction.execute(
        "INSERT INTO blob_metadata (id, schema_identity) VALUES (1, ?1)",
        params![SQLITE_BLOB_SCHEMA_IDENTITY],
    )?;
    transaction.commit()?;
    verify_schema_identity(connection)
}

fn verify_schema_identity(connection: &Connection) -> Result<(), SqliteBlobStoreError> {
    let schema_identity: Option<Vec<u8>> = connection
        .query_row(
            "SELECT schema_identity FROM blob_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(schema_identity) = schema_identity else {
        return Err(SqliteBlobStoreError::InvalidPersistedMetadata);
    };
    if schema_identity != SQLITE_BLOB_SCHEMA_IDENTITY {
        return Err(SqliteBlobStoreError::SchemaIdentityMismatch);
    }
    Ok(())
}

fn database_failure(_error: rusqlite::Error) -> RuntimeError {
    RuntimeError::DurableStoreUnavailable
}

fn runtime_failure(_error: SqliteBlobStoreError) -> RuntimeError {
    RuntimeError::DurableStoreUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;
    use std::{
        fs,
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
                "sunrise-edge-sqlite-blob-{}-{nanos}-{nonce}.db",
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

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    #[test]
    fn put_and_get_survive_reopen() {
        let database = TestDatabase::new();
        let content_digest = digest(0x01);
        {
            let store = SqliteBlobStore::open(&database.path).unwrap();
            store.put_blob(content_digest, vec![1, 2, 3]).unwrap();
            assert_eq!(
                store.get_blob(&content_digest).unwrap(),
                Some(vec![1, 2, 3])
            );
        }

        let reopened = SqliteBlobStore::open(&database.path).unwrap();
        assert_eq!(
            reopened.get_blob(&content_digest).unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn get_missing_digest_is_none() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        assert_eq!(store.get_blob(&digest(0x02)).unwrap(), None);
    }

    #[test]
    fn put_is_idempotent_for_identical_content() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let content_digest = digest(0x03);
        store.put_blob(content_digest, vec![9, 9]).unwrap();
        store.put_blob(content_digest, vec![9, 9]).unwrap();
        assert_eq!(store.get_blob(&content_digest).unwrap(), Some(vec![9, 9]));
    }

    #[test]
    fn put_rejects_conflicting_content_and_retains_original() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let content_digest = digest(0x04);
        store.put_blob(content_digest, vec![1, 1]).unwrap();
        let error = store.put_blob(content_digest, vec![2, 2]).unwrap_err();
        assert_eq!(
            error,
            RuntimeError::BlobDigestConflict {
                digest: content_digest
            }
        );
        assert_eq!(store.get_blob(&content_digest).unwrap(), Some(vec![1, 1]));
    }

    #[test]
    fn distinct_algorithms_over_the_same_bytes_are_distinct_keys() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let sha2 = Digest32::new(HashAlgorithmId::Sha2_256, [0x05; 32]);
        let sha3 = Digest32::new(HashAlgorithmId::Sha3_256, [0x05; 32]);
        store.put_blob(sha2, vec![1]).unwrap();
        store.put_blob(sha3, vec![2]).unwrap();
        assert_eq!(store.get_blob(&sha2).unwrap(), Some(vec![1]));
        assert_eq!(store.get_blob(&sha3).unwrap(), Some(vec![2]));
    }

    #[test]
    fn journal_mode_is_wal_and_synchronous_is_full() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let connection = store.connection().unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        // SQLite reports synchronous=FULL as 2.
        assert_eq!(synchronous, 2);
    }

    #[test]
    fn unknown_application_id_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .pragma_update(None, "application_id", 0x1234_5678_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::ApplicationId(0x1234_5678))
        ));
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .pragma_update(None, "application_id", BLOB_APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 99_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::SchemaVersion(99))
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
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::UnclaimedDatabase)
        ));
    }

    #[test]
    fn cannot_share_a_file_with_the_structured_store() {
        use crate::{SqliteDurableStore, SqliteNamespace};
        use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
        use runtime::WriterFenceGeneration;

        let database = TestDatabase::new();
        let namespace = SqliteNamespace::new(
            ChainId::new("sunrise-test").unwrap(),
            ValidatorId::new([0x01; 32]),
            AtomicityDomainId::new([0x02; 32]).unwrap(),
        );
        SqliteDurableStore::open(
            &database.path,
            namespace,
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::ApplicationId(_))
        ));
    }
}
