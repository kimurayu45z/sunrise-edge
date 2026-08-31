#![forbid(unsafe_code)]

use native_http::{
    NativeBlockingPolicy, PreinstalledWasmComposition, StructuredDurableNativeComponents,
    StructuredDurableRequestAuthority, preinstalled_wasm_structured_durable_router, serve,
};
use node_core::NodeConfig;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use std::{error::Error, num::NonZeroUsize, process::ExitCode, sync::Arc};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, DEVNET_DATABASE_FILE, DevnetConfig, DevnetMachine,
    DevnetOutboxIdentitySource, DevnetTransport, SeedAssetAccountsOutcome, boot_local_store,
    build_asset_module, build_devnet_protocol_context, seed_asset_accounts,
};

const REQUEST_OPERATION_TIMEOUT_MILLIS: u64 = 5_000;
const OUTBOX_LEASE_MILLIS: u64 = 30_000;
const SEED_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;
const DEVNET_STATE_KEY: &[u8] = b"devnet/generic-events/v1";

async fn run() -> Result<(), Box<dyn Error>> {
    let config: DevnetConfig = DevnetConfig::parse_from(std::env::args_os().skip(1))?;
    let boot = boot_local_store(&config)?;
    let boot_generation = boot.boot_generation();
    let database_path = boot.database_path().to_path_buf();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch())?;
    let asset_module = build_asset_module(protocol_context, ASSET_ACCOUNT_WASM.to_vec())?;
    for (index, owner) in config.dev_owners().iter().copied().enumerate() {
        let now_unix_millis: u64 = SystemClock.now_unix_millis()?;
        let seed_deadline_unix_millis: u64 = now_unix_millis
            .checked_add(SEED_OPERATION_TIMEOUT_MILLIS)
            .ok_or("seed deadline overflow")?;
        let seed_deadline =
            StorageDeadline::new(seed_deadline_unix_millis).ok_or("invalid seed deadline")?;
        let sequence: u64 = u64::try_from(index)?
            .checked_add(1)
            .ok_or("seed correlation sequence overflow")?;
        let mut correlation_bytes: [u8; 16] = [0; 16];
        correlation_bytes[..8].copy_from_slice(&boot_generation.get().to_be_bytes());
        correlation_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        let correlation_id = StorageCorrelationId::new(correlation_bytes)
            .ok_or("invalid seed correlation identity")?;
        let operation_context =
            DurableOperationContext::new(boot_generation, seed_deadline, correlation_id);
        let outcome = seed_asset_accounts(
            boot.store(),
            asset_module.resolver(),
            config.epoch(),
            owner,
            boot_generation,
            &operation_context,
        )?;
        let seed_status: &str = match &outcome {
            SeedAssetAccountsOutcome::Created(_) => "created",
            SeedAssetAccountsOutcome::Existing(_) => "verified-existing",
        };
        println!(
            "owner={} seed_status={} source={} destination={}",
            owner,
            seed_status,
            outcome.accounts().source().id,
            outcome.accounts().destination().id
        );
    }

    let (chain_id, epoch, _domain, protocol_config, resolver, catalog, _module_ref) =
        asset_module.into_parts();
    let node_config = NodeConfig::new(
        chain_id,
        protocol_config.protocol_version,
        epoch,
        DEVNET_STATE_KEY.to_vec(),
    )?;
    let admission = NonZeroUsize::new(config.max_concurrent())
        .ok_or("validated concurrency unexpectedly became zero")?;
    let store = Arc::new(boot.into_store());
    let transport = Arc::new(DevnetTransport::new(admission));
    let identities = Arc::new(DevnetOutboxIdentitySource::new(boot_generation));
    let components = StructuredDurableNativeComponents::new(
        Arc::clone(&store),
        transport,
        Arc::new(SystemClock),
        identities,
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
    )?;
    let router = preinstalled_wasm_structured_durable_router(
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        node_config,
        resolver,
        Arc::new(DevnetMachine),
        NativeBlockingPolicy::new(admission),
    )?;
    let listener = tokio::net::TcpListener::bind(config.listen()).await?;

    println!("Sunrise Edge local devnet initialized.");
    println!("chain_id={}", config.chain_id());
    println!("epoch={}", config.epoch().get());
    println!("listen={}", listener.local_addr()?);
    println!("database={}", database_path.display());
    println!("database_file={DEVNET_DATABASE_FILE}");
    println!("boot_generation={}", boot_generation.get());
    println!("dev_owners={}", config.dev_owners().len());
    println!("max_concurrent={}", config.max_concurrent());
    println!(
        "limitations=single-validator,same-sender-owned-objects,fee-free,local-sqlite,non-production"
    );
    println!("Press Ctrl-C to stop.");

    serve(listener, router, async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to install Ctrl-C handler: {error}");
        }
    })
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sunrise-edge-devnet failed: {error}");
            ExitCode::FAILURE
        }
    }
}
