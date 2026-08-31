//! Trusted native-router composition for the local developer network.

use crate::{
    catalog::DevnetAssetModule,
    identities::DevnetOutboxIdentitySource,
    machine::{DEVNET_GENERIC_STATE_KEY, DevnetMachine},
    transport::DevnetTransport,
};
use axum::Router;
use native_http::{
    IndexedOutboxRecoveryAuthorityError, NativeBlockingPolicy, PreinstalledWasmComposition,
    StructuredDurableNativeComponents, StructuredDurableRequestAuthority,
    StructuredDurableRouterError, preinstalled_wasm_structured_durable_router,
};
use node_core::{NodeConfig, NodeCoreError};
use runtime::{SystemClock, WriterFenceGeneration};
use runtime_sqlite::SqliteDurableStore;
use std::{error::Error, fmt, num::NonZeroUsize, sync::Arc};

const REQUEST_OPERATION_TIMEOUT_MILLIS: u64 = 5_000;
const OUTBOX_LEASE_MILLIS: u64 = 30_000;

/// Builds the exact bounded native router used by the devnet binary.
///
/// `reserved_correlation_sequences` is the number of seed operations already
/// assigned operational correlation IDs in this boot. Outbox identities begin
/// strictly after that range.
pub fn compose_devnet_router(
    store: Arc<SqliteDurableStore>,
    asset_module: DevnetAssetModule,
    boot_generation: WriterFenceGeneration,
    max_concurrent: usize,
    reserved_correlation_sequences: usize,
) -> Result<Router, DevnetCompositionError> {
    let admission: NonZeroUsize =
        NonZeroUsize::new(max_concurrent).ok_or(DevnetCompositionError::InvalidConcurrency)?;
    let reserved_sequences: u64 = u64::try_from(reserved_correlation_sequences)
        .map_err(|_| DevnetCompositionError::ReservedSequenceOverflow)?;
    let (chain_id, epoch, _domain, protocol_config, resolver, catalog, _module_ref) =
        asset_module.into_parts();
    let node_config: NodeConfig = NodeConfig::new(
        chain_id,
        protocol_config.protocol_version,
        epoch,
        DEVNET_GENERIC_STATE_KEY.to_vec(),
    )
    .map_err(DevnetCompositionError::NodeCore)?;
    let components = StructuredDurableNativeComponents::new(
        store,
        Arc::new(DevnetTransport::new(admission)),
        Arc::new(SystemClock),
        Arc::new(DevnetOutboxIdentitySource::new_after(
            boot_generation,
            reserved_sequences,
        )),
    );
    let preinstalled_wasm = PreinstalledWasmComposition::new(
        Arc::new(catalog),
        execution::WasmExecutionEngine,
        boot_generation.get(),
    );
    let authority = StructuredDurableRequestAuthority::new(
        boot_generation,
        REQUEST_OPERATION_TIMEOUT_MILLIS,
        OUTBOX_LEASE_MILLIS,
    )
    .map_err(DevnetCompositionError::Authority)?;
    preinstalled_wasm_structured_durable_router(
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        node_config,
        resolver,
        Arc::new(DevnetMachine),
        NativeBlockingPolicy::new(admission),
    )
    .map_err(DevnetCompositionError::Router)
}

/// Fail-closed errors while composing the local native router.
#[derive(Debug)]
pub enum DevnetCompositionError {
    /// The synchronous admission bound was zero.
    InvalidConcurrency,
    /// The platform could not represent the reserved seed sequence count.
    ReservedSequenceOverflow,
    /// Trusted node configuration was internally inconsistent.
    NodeCore(NodeCoreError),
    /// Durable request/lease budgets were invalid.
    Authority(IndexedOutboxRecoveryAuthorityError),
    /// Protocol and node authorities disagreed at router construction.
    Router(StructuredDurableRouterError),
}

impl fmt::Display for DevnetCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConcurrency => formatter.write_str("devnet concurrency must be non-zero"),
            Self::ReservedSequenceOverflow => {
                formatter.write_str("devnet seed correlation count does not fit in u64")
            }
            Self::NodeCore(error) => write!(formatter, "devnet node configuration failed: {error}"),
            Self::Authority(error) => write!(formatter, "devnet request authority failed: {error}"),
            Self::Router(error) => write!(formatter, "devnet router composition failed: {error}"),
        }
    }
}

impl Error for DevnetCompositionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NodeCore(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Router(error) => Some(error),
            Self::InvalidConcurrency | Self::ReservedSequenceOverflow => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_account::ASSET_ACCOUNT_WASM, boot::boot_local_store, catalog::build_asset_module,
        config::DevnetConfig, genesis::build_devnet_protocol_context,
    };
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence: u64 = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "sunrise-edge-devnet-composition-{}-{sequence}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn committed_devnet_authorities_compose_the_native_router() {
        let directory = TestDirectory::new();
        let config = DevnetConfig::parse_from(vec![
            OsString::from("--data-dir"),
            directory.0.as_os_str().to_owned(),
            OsString::from("--listen"),
            OsString::from("127.0.0.1:7400"),
            OsString::from("--chain-id"),
            OsString::from("devnet-composition-test"),
            OsString::from("--epoch"),
            OsString::from("0"),
            OsString::from("--dev-owner"),
            OsString::from("2222222222222222222222222222222222222222222222222222222222222222"),
            OsString::from("--max-concurrent"),
            OsString::from("4"),
        ])
        .unwrap();
        let boot = boot_local_store(&config).unwrap();
        let generation = boot.boot_generation();
        let context =
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
        let module = build_asset_module(context, ASSET_ACCOUNT_WASM.to_vec()).unwrap();

        let router = compose_devnet_router(
            Arc::new(boot.into_store()),
            module,
            generation,
            config.max_concurrent(),
            config.dev_owners().len(),
        )
        .unwrap();

        drop(router);
    }
}
