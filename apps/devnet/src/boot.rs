//! Persisted writer-fence startup for the local devnet.

use crate::{config::DevnetConfig, genesis::DEVNET_DOMAIN_BYTES};
use protocol_types::{AtomicityDomainId, ValidatorId};
use runtime::WriterFenceGeneration;
use runtime_sqlite::{SqliteDurableStore, SqliteDurableStoreError, SqliteNamespace};
use std::{error::Error, fmt, fs, io, path::PathBuf};

/// Structured SQLite file used by the local devnet.
pub const DEVNET_DATABASE_FILE: &str = "structured.sqlite3";
const INITIAL_WRITER_FENCE_VALUE: u64 = 1;
const DEVNET_VALIDATOR_BYTES: [u8; 32] = [0x56; 32];

/// One successfully fenced local devnet boot.
#[derive(Debug)]
pub struct DevnetBoot {
    store: SqliteDurableStore,
    boot_generation: WriterFenceGeneration,
    database_path: PathBuf,
}

impl DevnetBoot {
    /// Returns the opened structured store.
    #[must_use]
    pub const fn store(&self) -> &SqliteDurableStore {
        &self.store
    }

    /// Consumes the boot and returns its structured store.
    #[must_use]
    pub fn into_store(self) -> SqliteDurableStore {
        self.store
    }

    /// Returns this process boot's persisted writer generation.
    #[must_use]
    pub const fn boot_generation(&self) -> WriterFenceGeneration {
        self.boot_generation
    }

    /// Returns the exact SQLite path opened for this boot.
    #[must_use]
    pub fn database_path(&self) -> &std::path::Path {
        &self.database_path
    }
}

/// Opens the local structured database and atomically claims a fresh writer
/// generation for this process boot.
pub fn boot_local_store(config: &DevnetConfig) -> Result<DevnetBoot, DevnetBootError> {
    fs::create_dir_all(config.data_dir()).map_err(DevnetBootError::CreateDataDirectory)?;
    let database_path: PathBuf = config.data_dir().join(DEVNET_DATABASE_FILE);
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
    let persisted: WriterFenceGeneration = store.writer_fence().map_err(DevnetBootError::Store)?;
    let boot_generation: WriterFenceGeneration = persisted
        .checked_next()
        .ok_or(DevnetBootError::WriterFenceExhausted(persisted))?;
    store
        .advance_writer_fence(persisted, boot_generation)
        .map_err(DevnetBootError::Store)?;
    Ok(DevnetBoot {
        store,
        boot_generation,
        database_path,
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
        }
    }
}

impl Error for DevnetBootError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CreateDataDirectory(error) => Some(error),
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

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
            OsString::from("2222222222222222222222222222222222222222222222222222222222222222"),
            OsString::from("--max-concurrent"),
            OsString::from("4"),
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
}
