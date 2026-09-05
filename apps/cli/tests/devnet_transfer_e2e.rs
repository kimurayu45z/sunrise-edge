//! Real loopback TCP E2E: the `transfer` subcommand against a real,
//! seeded, composed local devnet router, exactly as a user would invoke the
//! `sunrise-edge-cli` binary.
//!
//! This does not just check that the CLI command and a follow-up query
//! return success: it independently queries both asset accounts afterward
//! through `sunrise-edge-client` directly, decodes their canonical bodies,
//! and asserts the exact expected balance/sequence change and conservation.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use sunrise_edge_client::{Client, LoopbackHttpTransport, ObjectId, decode_object};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, AssetAccount, DEVNET_ASSET_ID, DevOwner, DevnetConfig, boot_local_store,
    build_asset_module, build_devnet_protocol_context, compose_devnet_router, decode_asset_account,
    genesis::{DEVNET_DOMAIN_BYTES, DEVNET_PROTOCOL_VERSION},
    seed_asset_accounts, verify_seeded_asset_supply,
};

const INITIAL_SOURCE_BALANCE: u64 = 1_000_000;
const TRANSFER_AMOUNT: u64 = 250;
const EXPECTED_CHAIN_ID: &str = "cli-transfer-e2e-devnet";
const EXPECTED_EPOCH: &str = "11";
const EXPECTED_HASH_SUITE_ID: &str = "1";

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-{label}-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

struct TempSeedFile(PathBuf);

impl TempSeedFile {
    fn new(seed: [u8; 32]) -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sunrise-edge-cli-transfer-seed-{}-{sequence}",
            std::process::id()
        ));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(hex.as_bytes()).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(path)
    }
}

impl Drop for TempSeedFile {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.0);
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Queries `object_id` directly through `sunrise-edge-client` (independent
/// of anything the CLI itself printed) and decodes its canonical body as a
/// devnet asset account. Asset-account bodies remain below DR-0096's fixed
/// blob-publication threshold, so seeing a blob reference here would be a
/// product-surface regression for the current CLI.
fn query_asset_account(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (sunrise_edge_client::ObjectRef, AssetAccount) {
    let result = client
        .query_object(object_id)
        .expect("object query should succeed");
    match result {
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => {
            let object =
                decode_object(&canonical_object_bytes).expect("canonical object should decode");
            let account = decode_asset_account(&object.data)
                .expect("object body should decode as an asset account");
            (
                sunrise_edge_client::ObjectRef {
                    id: object_id,
                    version: object_version.get(),
                    digest,
                },
                account,
            )
        }
        other => panic!("expected object {object_id} to be CurrentInline, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_transfer_command_moves_balance_through_the_real_devnet_router_over_tcp() {
    let owner_signer = sunrise_edge_client::LocalSigner::from_seed([0x5A; 32]);
    let owner_address = owner_signer.address();
    let seed_file = TempSeedFile::new([0x5A; 32]);

    let directory = TestDirectory::new("transfer-e2e");
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-transfer-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("11"),
        OsString::from("--dev-owner"),
        OsString::from(owner_address.to_string()),
        OsString::from("--fee-treasury-owner"),
        OsString::from("6b".repeat(32)),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();

    let boot = boot_local_store(&config).unwrap();
    let boot_generation = boot.boot_generation();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let module = build_asset_module(protocol_context, ASSET_ACCOUNT_WASM.to_vec()).unwrap();

    let dev_owner = DevOwner::new(*owner_address.as_bytes());
    let now_unix_millis = SystemClock.now_unix_millis().unwrap();
    let seed_deadline = StorageDeadline::new(now_unix_millis + 30_000).unwrap();
    let seed_correlation = StorageCorrelationId::new([0x77; 16]).unwrap();
    let seed_context =
        DurableOperationContext::new(boot_generation, seed_deadline, seed_correlation);
    let seed_outcome = seed_asset_accounts(
        boot.store(),
        boot.blob_store(),
        module.resolver(),
        config.epoch(),
        dev_owner,
        boot_generation,
        &seed_context,
    )
    .unwrap();
    let treasury_context = DurableOperationContext::new(
        boot_generation,
        seed_deadline,
        StorageCorrelationId::new([0x78; 16]).unwrap(),
    );
    let treasury_outcome = seed_asset_accounts(
        boot.store(),
        boot.blob_store(),
        module.resolver(),
        config.epoch(),
        config.fee_treasury_owner(),
        boot_generation,
        &treasury_context,
    )
    .unwrap();
    verify_seeded_asset_supply(&[seed_outcome.clone(), treasury_outcome.clone()]).unwrap();
    let accounts = seed_outcome.accounts();
    let source_id = accounts.source().id;
    let destination_id = accounts.destination().id;
    let treasury_id = treasury_outcome.accounts().destination().id;
    let module_ref = module.module_ref().clone();

    let (structured_store, blob_store) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(structured_store),
        Arc::new(blob_store),
        module,
        boot_generation,
        config.max_concurrent(),
        2,
        treasury_id,
    )
    .unwrap();

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(native_http::serve(
        listener,
        router,
        std::future::pending::<()>(),
    ));

    let endpoint = address.to_string();
    let seed_path = seed_file.0.clone();
    tokio::task::spawn_blocking(move || {
        // Baseline: query both accounts before the transfer, independent of
        // the seeding code above, so the assertions below are anchored to
        // what the running server itself reports.
        let verify_transport = LoopbackHttpTransport::new(
            address,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(1024 * 1024).unwrap(),
        )
        .unwrap();
        let verify_client = Client::new(verify_transport);

        let (source_ref_before, source_before) = query_asset_account(&verify_client, source_id);
        let (destination_ref_before, destination_before) =
            query_asset_account(&verify_client, destination_id);
        let (treasury_ref_before, treasury_before) =
            query_asset_account(&verify_client, treasury_id);
        assert_eq!(source_before.balance, INITIAL_SOURCE_BALANCE);
        assert_eq!(destination_before.balance, 0);
        assert_eq!(source_before.sequence, 0);
        assert_eq!(destination_before.sequence, 0);
        assert_eq!(treasury_before.balance, 0);
        assert_eq!(treasury_before.sequence, 0);

        sunrise_edge_cli::run(vec![
            OsString::from("transfer"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--seed-file"),
            OsString::from(seed_path.as_os_str()),
            OsString::from("--module-id"),
            OsString::from(module_ref.id.to_string()),
            OsString::from("--module-version"),
            OsString::from(module_ref.version.to_string()),
            OsString::from("--module-digest-algorithm"),
            OsString::from(module_ref.digest.algorithm().as_u16().to_string()),
            OsString::from("--module-digest"),
            OsString::from(hex32(&module_ref.digest.bytes())),
            OsString::from("--source-object"),
            OsString::from(source_id.to_string()),
            OsString::from("--destination-object"),
            OsString::from(destination_id.to_string()),
            OsString::from("--destination-owner"),
            OsString::from(owner_address.to_string()),
            OsString::from("--amount"),
            OsString::from(TRANSFER_AMOUNT.to_string()),
            OsString::from("--gas-limit"),
            OsString::from("1000000"),
            OsString::from("--fee-asset-id"),
            OsString::from(hex32(DEVNET_ASSET_ID.as_bytes())),
            OsString::from("--max-fee"),
            OsString::from("1000001"),
            OsString::from("--fee-treasury-object"),
            OsString::from(treasury_id.to_string()),
            OsString::from("--request-id"),
            OsString::from("50".repeat(32)),
            OsString::from("--expected-chain-id"),
            OsString::from(EXPECTED_CHAIN_ID),
            OsString::from("--expected-protocol-version"),
            OsString::from(DEVNET_PROTOCOL_VERSION.get().to_string()),
            OsString::from("--expected-epoch"),
            OsString::from(EXPECTED_EPOCH),
            OsString::from("--expected-hash-suite-id"),
            OsString::from(EXPECTED_HASH_SUITE_ID),
            OsString::from("--expected-domain"),
            OsString::from(hex32(&DEVNET_DOMAIN_BYTES)),
            OsString::from("--wait"),
            OsString::from("--wait-max-attempts"),
            OsString::from("20"),
            OsString::from("--wait-initial-backoff-ms"),
            OsString::from("10"),
            OsString::from("--wait-max-backoff-ms"),
            OsString::from("50"),
            OsString::from("--wait-max-elapsed-ms"),
            OsString::from("5000"),
        ])
        .expect("transfer command should succeed against the real seeded devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("object"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--object-id"),
            OsString::from(destination_id.to_string()),
        ])
        .expect("post-transfer object query should succeed");

        // The real assertion: independently query and decode both accounts
        // after the transfer and prove the exact expected balance movement,
        // sequence advancement, and conservation — not merely that the
        // commands above returned success.
        let (source_ref_after, source_after) = query_asset_account(&verify_client, source_id);
        let (destination_ref_after, destination_after) =
            query_asset_account(&verify_client, destination_id);
        let (treasury_ref_after, treasury_after) = query_asset_account(&verify_client, treasury_id);
        let charged_fee = treasury_after.balance - treasury_before.balance;

        assert_eq!(source_after.asset_id, source_before.asset_id);
        assert_eq!(destination_after.asset_id, destination_before.asset_id);
        assert_eq!(
            source_after.balance,
            source_before.balance - TRANSFER_AMOUNT - charged_fee,
            "source balance should decrease by the transfer and actual fee"
        );
        assert_eq!(
            destination_after.balance,
            destination_before.balance + TRANSFER_AMOUNT,
            "destination balance should increase by exactly the transferred amount"
        );
        assert_eq!(
            source_after.sequence,
            source_before.sequence + 2,
            "application transfer and fee composition each advance the source body sequence"
        );
        assert_eq!(
            destination_after.sequence,
            destination_before.sequence + 1,
            "destination sequence should advance by exactly one"
        );
        assert_eq!(
            treasury_after.sequence,
            treasury_before.sequence + 1,
            "treasury sequence should advance by exactly one"
        );
        assert_eq!(source_ref_after.version, source_ref_before.version + 1);
        assert_eq!(
            destination_ref_after.version,
            destination_ref_before.version + 1
        );
        assert_eq!(treasury_ref_after.version, treasury_ref_before.version + 1);
        assert!(charged_fee > 1, "execution must add a non-zero metered fee");
        assert!(
            charged_fee < 1_000_001,
            "successful execution must charge actual gas, not the gas limit"
        );
        assert_eq!(
            source_after.balance + destination_after.balance + treasury_after.balance,
            source_before.balance + destination_before.balance + treasury_before.balance,
            "the ordinary asset must be conserved across transfer and fee settlement"
        );
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;
}
