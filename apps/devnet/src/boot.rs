//! Persisted writer-fence startup for the local devnet.

use crate::{config::DevnetConfig, genesis::DEVNET_DOMAIN_BYTES};
use protocol_types::{AtomicityDomainId, ValidatorId};
use runtime::WriterFenceGeneration;
use runtime_sqlite::{
    SqliteBlobStore, SqliteBlobStoreError, SqliteDurableStore, SqliteDurableStoreError,
    SqliteNamespace,
};
use std::{error::Error, fmt, fs, io, path::PathBuf};

/// Structured SQLite file used by the local devnet.
pub const DEVNET_DATABASE_FILE: &str = "structured.sqlite3";
/// Content-addressed blob SQLite file used by the local devnet.
///
/// Deliberately a separate file from [`DEVNET_DATABASE_FILE`]:
/// `application_id`/`user_version` are whole-file SQLite properties, so the
/// structured store and the blob store cannot share one database file.
pub const DEVNET_BLOB_DATABASE_FILE: &str = "blobs.sqlite3";
const INITIAL_WRITER_FENCE_VALUE: u64 = 1;
const DEVNET_VALIDATOR_BYTES: [u8; 32] = [0x56; 32];

/// One successfully fenced local devnet boot.
#[derive(Debug)]
pub struct DevnetBoot {
    store: SqliteDurableStore,
    blob_store: SqliteBlobStore,
    boot_generation: WriterFenceGeneration,
    database_path: PathBuf,
    blob_database_path: PathBuf,
}

impl DevnetBoot {
    /// Returns the opened structured store.
    #[must_use]
    pub const fn store(&self) -> &SqliteDurableStore {
        &self.store
    }

    /// Returns the opened content-addressed blob store.
    #[must_use]
    pub const fn blob_store(&self) -> &SqliteBlobStore {
        &self.blob_store
    }

    /// Consumes the boot and returns its structured store and blob store.
    #[must_use]
    pub fn into_parts(self) -> (SqliteDurableStore, SqliteBlobStore) {
        (self.store, self.blob_store)
    }

    /// Returns this process boot's persisted writer generation.
    #[must_use]
    pub const fn boot_generation(&self) -> WriterFenceGeneration {
        self.boot_generation
    }

    /// Returns the exact structured SQLite path opened for this boot.
    #[must_use]
    pub fn database_path(&self) -> &std::path::Path {
        &self.database_path
    }

    /// Returns the exact blob SQLite path opened for this boot.
    #[must_use]
    pub fn blob_database_path(&self) -> &std::path::Path {
        &self.blob_database_path
    }
}

/// Opens the local structured database and blob database, and atomically
/// claims a fresh writer generation for this process boot.
///
/// The blob database has no writer-fence concept of its own: it is
/// content-addressed and every write is insert-if-absent, so a stale writer
/// cannot overwrite content or mutate a structured head/reference; a digest
/// conflict fails closed. It can still leave unreachable content and consume
/// storage, so multi-writer operation and GC/capacity controls remain outside
/// this local profile rather than being claimed safe here.
pub fn boot_local_store(config: &DevnetConfig) -> Result<DevnetBoot, DevnetBootError> {
    fs::create_dir_all(config.data_dir()).map_err(DevnetBootError::CreateDataDirectory)?;
    let database_path: PathBuf = config.data_dir().join(DEVNET_DATABASE_FILE);
    let blob_database_path: PathBuf = config.data_dir().join(DEVNET_BLOB_DATABASE_FILE);
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetBootError::InvalidStaticDomain)?;
    let namespace: SqliteNamespace = SqliteNamespace::new(
        config.chain_id().clone(),
        ValidatorId::new(DEVNET_VALIDATOR_BYTES),
        domain,
    );
    let initial_writer_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(INITIAL_WRITER_FENCE_VALUE)
            .ok_or(DevnetBootError::InvalidInitialWriterFence)?;
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database_path, namespace, initial_writer_fence)
            .map_err(DevnetBootError::Store)?;
    // Open and validate the independent blob database before promoting the
    // structured writer fence. A blob-schema failure therefore aborts this
    // boot without consuming a structured generation.
    let blob_store: SqliteBlobStore =
        SqliteBlobStore::open(&blob_database_path).map_err(DevnetBootError::BlobStore)?;
    let persisted: WriterFenceGeneration = store.writer_fence().map_err(DevnetBootError::Store)?;
    let boot_generation: WriterFenceGeneration = persisted
        .checked_next()
        .ok_or(DevnetBootError::WriterFenceExhausted(persisted))?;
    store
        .advance_writer_fence(persisted, boot_generation)
        .map_err(DevnetBootError::Store)?;
    Ok(DevnetBoot {
        store,
        blob_store,
        boot_generation,
        database_path,
        blob_database_path,
    })
}

/// Failures while claiming one local devnet boot generation.
#[derive(Debug)]
pub enum DevnetBootError {
    /// The process could not create its explicit data directory.
    CreateDataDirectory(io::Error),
    /// A hard-coded non-zero domain invariant was violated.
    InvalidStaticDomain,
    /// A hard-coded non-zero initial fence invariant was violated.
    InvalidInitialWriterFence,
    /// The persisted boot generation reached the representation limit.
    WriterFenceExhausted(WriterFenceGeneration),
    /// The structured SQLite adapter rejected startup or fence advancement.
    Store(SqliteDurableStoreError),
    /// The blob SQLite adapter rejected startup.
    BlobStore(SqliteBlobStoreError),
}

impl fmt::Display for DevnetBootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDataDirectory(error) => {
                write!(f, "failed to create devnet data directory: {error}")
            }
            Self::InvalidStaticDomain => f.write_str("devnet's static atomicity domain is invalid"),
            Self::InvalidInitialWriterFence => {
                f.write_str("devnet's initial writer fence is invalid")
            }
            Self::WriterFenceExhausted(generation) => write!(
                f,
                "devnet writer fence is exhausted at generation {}",
                generation.get()
            ),
            Self::Store(error) => write!(f, "devnet structured store startup failed: {error}"),
            Self::BlobStore(error) => write!(f, "devnet blob store startup failed: {error}"),
        }
    }
}

impl Error for DevnetBootError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CreateDataDirectory(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::BlobStore(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_account::ASSET_ACCOUNT_WASM,
        catalog::build_asset_module,
        config::DevOwner,
        genesis::build_devnet_protocol_context,
        seed::{SeedAssetAccountsOutcome, seed_asset_accounts},
    };
    use ed25519_zebra::{SigningKey, VerificationKey};
    use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline};
    use std::{
        ffi::OsString,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    fn owner_hex(seed: u8) -> String {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let verification_key: VerificationKey = VerificationKey::from(&signing_key);
        verification_key
            .as_ref()
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect()
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-devnet-{}-{sequence}",
                std::process::id()
            ));
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn config(directory: &std::path::Path, chain: &str) -> DevnetConfig {
        DevnetConfig::parse_from(vec![
            OsString::from("--data-dir"),
            directory.as_os_str().to_owned(),
            OsString::from("--listen"),
            OsString::from("[::1]:7400"),
            OsString::from("--chain-id"),
            OsString::from(chain),
            OsString::from("--epoch"),
            OsString::from("0"),
            OsString::from("--dev-owner"),
            OsString::from(owner_hex(0x22)),
            OsString::from("--max-concurrent"),
            OsString::from("4"),
            OsString::from("--fee-treasury-owner"),
            OsString::from(owner_hex(0x33)),
        ])
        .unwrap()
    }

    #[test]
    fn boot_advances_and_persists_writer_generation() {
        let directory = TestDirectory::new();
        let config = config(&directory.0, "devnet-boot-test");
        let first = boot_local_store(&config).unwrap();
        assert_eq!(first.boot_generation().get(), 2);
        assert_eq!(first.store().writer_fence().unwrap().get(), 2);
        drop(first);

        let second = boot_local_store(&config).unwrap();
        assert_eq!(second.boot_generation().get(), 3);
        assert_eq!(second.store().writer_fence().unwrap().get(), 3);
        assert_eq!(
            second.database_path(),
            directory.0.join(DEVNET_DATABASE_FILE)
        );
    }

    #[test]
    fn blob_open_failure_does_not_consume_a_structured_writer_generation() {
        let directory = TestDirectory::new();
        let config = config(&directory.0, "devnet-blob-boot-failure");
        let first = boot_local_store(&config).unwrap();
        assert_eq!(first.boot_generation().get(), 2);
        drop(first);

        let blob_path = directory.0.join(DEVNET_BLOB_DATABASE_FILE);
        fs::remove_file(&blob_path).unwrap();
        fs::create_dir(&blob_path).unwrap();
        assert!(matches!(
            boot_local_store(&config),
            Err(DevnetBootError::BlobStore(_))
        ));

        fs::remove_dir(&blob_path).unwrap();
        let recovered = boot_local_store(&config).unwrap();
        assert_eq!(
            recovered.boot_generation().get(),
            3,
            "the failed blob-store open must not have consumed generation 3"
        );
    }

    #[test]
    fn reopening_same_file_under_another_chain_fails_closed() {
        let directory = TestDirectory::new();
        let first_config = config(&directory.0, "devnet-chain-a");
        let first = boot_local_store(&first_config).unwrap();
        drop(first);

        let second_config = config(&directory.0, "devnet-chain-b");
        assert!(matches!(
            boot_local_store(&second_config),
            Err(DevnetBootError::Store(
                SqliteDurableStoreError::NamespaceMismatch
            ))
        ));
    }

    #[test]
    fn sqlite_reopen_verifies_the_same_seeded_account_refs() {
        let directory = TestDirectory::new();
        let config = config(&directory.0, "devnet-seed-reopen-test");
        let owner: DevOwner = config.dev_owners()[0];

        let first = boot_local_store(&config).unwrap();
        let first_generation = first.boot_generation();
        let first_context = DurableOperationContext::new(
            first_generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([0x31; 16]).unwrap(),
        );
        let first_protocol =
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
        let first_module = build_asset_module(first_protocol, ASSET_ACCOUNT_WASM.to_vec()).unwrap();
        let created = seed_asset_accounts(
            first.store(),
            first.blob_store(),
            first_module.resolver(),
            config.epoch(),
            owner,
            first_generation,
            &first_context,
        )
        .unwrap();
        assert!(matches!(created, SeedAssetAccountsOutcome::Created(_)));
        drop(first);

        let second = boot_local_store(&config).unwrap();
        let second_generation = second.boot_generation();
        let second_context = DurableOperationContext::new(
            second_generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([0x32; 16]).unwrap(),
        );
        let second_protocol =
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
        let second_module =
            build_asset_module(second_protocol, ASSET_ACCOUNT_WASM.to_vec()).unwrap();
        let existing = seed_asset_accounts(
            second.store(),
            second.blob_store(),
            second_module.resolver(),
            config.epoch(),
            owner,
            second_generation,
            &second_context,
        )
        .unwrap();

        assert!(matches!(existing, SeedAssetAccountsOutcome::Existing(_)));
        assert_eq!(created.accounts(), existing.accounts());
    }
}
