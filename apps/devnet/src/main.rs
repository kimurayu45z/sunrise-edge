#![forbid(unsafe_code)]

use native_http::serve;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use std::{error::Error, process::ExitCode, sync::Arc};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, DEVNET_ASSET_ID, DEVNET_DATABASE_FILE, DevnetConfig,
    SeedAssetAccountsOutcome, asset_account_type_hash, boot_local_store, build_asset_module,
    build_devnet_protocol_context, compose_devnet_router, seed_asset_accounts,
};

const SEED_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;

async fn run() -> Result<(), Box<dyn Error>> {
    let config: DevnetConfig = DevnetConfig::parse_from(std::env::args_os().skip(1))?;
    let boot = boot_local_store(&config)?;
    let boot_generation = boot.boot_generation();
    let database_path = boot.database_path().to_path_buf();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch())?;
    let asset_module = build_asset_module(protocol_context, ASSET_ACCOUNT_WASM.to_vec())?;
    let module_ref = asset_module.module_ref().clone();
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

    let store = Arc::new(boot.into_store());
    let router = compose_devnet_router(
        store,
        asset_module,
        boot_generation,
        config.max_concurrent(),
        config.dev_owners().len(),
    )?;
    let listener = tokio::net::TcpListener::bind(config.listen()).await?;

    println!("Sunrise Edge local devnet initialized.");
    println!("chain_id={}", config.chain_id());
    println!("epoch={}", config.epoch().get());
    println!("listen={}", listener.local_addr()?);
    println!("database={}", database_path.display());
    println!("database_file={DEVNET_DATABASE_FILE}");
    println!("boot_generation={}", boot_generation.get());
    println!(
        "asset_id={} asset_account_type={} module_id={} module_version={} module_digest={}",
        DEVNET_ASSET_ID,
        asset_account_type_hash(),
        module_ref.id,
        module_ref.version,
        module_ref.digest
    );
    println!("dev_owners={}", config.dev_owners().len());
    println!("max_concurrent={}", config.max_concurrent());
    println!(
        "limitations=single-validator,owned-objects-only,cross-owner-transfer-fail-closed,fee-free,local-sqlite,non-production"
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
