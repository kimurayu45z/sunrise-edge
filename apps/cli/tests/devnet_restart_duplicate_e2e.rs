//! Real loopback TCP restart/duplicate E2E for the CLI Developer MVP Gate's
//! S0 slice (see `TODO.md#cli-developer-mvp-gate`).
//!
//! This uses a real file-backed `SqliteDurableStore`, the real composed
//! devnet router, real loopback TCP, `sunrise_edge_cli::run` for the
//! user-facing transfer leg, and `sunrise-edge-client` directly for
//! independent verification and for building/replaying one raw
//! `SubmitTransactionRequest`. It proves exactly:
//!
//! 1. A CLI transfer of amount 250 against a freshly seeded devnet, verified
//!    independently through the client.
//! 2. An orderly stop (graceful HTTP shutdown, awaited server task, every
//!    `Arc<SqliteDurableStore>` reference dropped so the SQLite file is
//!    genuinely closed) followed by a real reopen through `boot_local_store`
//!    that advances the writer generation, a reseed that verifies the exact
//!    same account identities, and a fresh router composed on a new
//!    ephemeral port.
//! 3. State (balances, sequences, receipts, next nonce) observed immediately
//!    before the restart is observed byte-identically after it.
//! 4. One signed `SubmitTransactionRequest`, built once, replayed
//!    byte-identically both before and after restart: the canonical response
//!    bytes are identical and neither duplicate re-applies its effects.
//! 5. Reusing an already-committed request id for a different transaction is
//!    a typed, nonzero, fail-closed HTTP conflict with no state change.
//! 6. The pre-restart writer generation is fenced on the reopened store.
//!
//! This intentionally proves only orderly stop/reopen: it says nothing about
//! `kill -9`, power loss, torn writes, load, concurrency, or SQLite's
//! suitability for production use (see `ARCHITECTURE.md` "Local devnet
//! architecture" and `TODO.md`'s persistence notes).

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use runtime::{
    Clock, DurableOperationContext, DurableReadError, DurableRequestId, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, SystemClock,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, AtomicityDomainId, Client, ClientError,
    HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult, LocalSigner,
    LoopbackHttpTransport, NodeResponseStatus, ObjectId, ObjectRef, RequestId, SignatureSchemeId,
    SubmitTransactionRequest, TransactionRequest, build_signed_transaction,
    decode_execution_effects, decode_object,
};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, AssetAccount, DevOwner, DevnetConfig, SeedAssetAccountsOutcome,
    SeededAssetAccounts, TransferArgs, boot_local_store, build_asset_module,
    build_devnet_protocol_context, compose_devnet_router, decode_asset_account,
    encode_transfer_args,
    genesis::{DEVNET_DOMAIN_BYTES, DEVNET_PROTOCOL_VERSION},
    seed_asset_accounts,
};

const INITIAL_SOURCE_BALANCE: u64 = 1_000_000;
const CLI_TRANSFER_AMOUNT: u64 = 250;
const SECOND_TRANSFER_AMOUNT: u64 = 25;
const TRANSFER_ENTRYPOINT: &str = "transfer";
const GAS_LIMIT: u64 = 1_000_000;
const REQUEST_ID_R1_BYTE: u8 = 0x51;
const REQUEST_ID_R2_BYTE: u8 = 0x52;
const EXPECTED_CHAIN_ID: &str = "cli-restart-duplicate-e2e-devnet";
const EXPECTED_EPOCH: &str = "13";
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
            "sunrise-edge-cli-restart-seed-{}-{sequence}",
            std::process::id()
        ));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        fs::write(&path, hex.as_bytes()).unwrap();
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

fn make_client(address: SocketAddr) -> Client<LoopbackHttpTransport> {
    let transport = LoopbackHttpTransport::new(
        address,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(1024 * 1024).unwrap(),
    )
    .unwrap();
    Client::new(transport)
}

/// Independently queries and decodes `object_id`'s current inline body,
/// returning a fresh [`ObjectRef`] (for building a follow-up transaction's
/// access manifest), the decoded asset-account state, and the result's exact
/// canonical bytes for restart comparisons.
fn query_current_account(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (ObjectRef, AssetAccount, Vec<u8>) {
    let result = client
        .query_object(object_id)
        .expect("object query should succeed");
    let canonical_result_bytes = result
        .encode()
        .expect("object query result should encode canonically");
    match result {
        HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ref canonical_object_bytes,
            ..
        } => {
            let object =
                decode_object(canonical_object_bytes).expect("canonical object should decode");
            let account = decode_asset_account(&object.data)
                .expect("object body should decode as an asset account");
            let object_ref = ObjectRef {
                id: object_id,
                version: object_version.get(),
                digest,
            };
            (object_ref, account, canonical_result_bytes)
        }
        other => panic!("expected object {object_id} to be CurrentInline, got {other:?}"),
    }
}

/// Everything captured immediately before the server stops, so the
/// post-restart phase can assert byte-identical continuity.
struct PreRestartState {
    source_account: AssetAccount,
    destination_account: AssetAccount,
    source_ref: ObjectRef,
    destination_ref: ObjectRef,
    source_query_bytes: Vec<u8>,
    destination_query_bytes: Vec<u8>,
    cli_receipt: HttpReceiptQueryResult,
    cli_receipt_bytes: Vec<u8>,
    second_transfer_receipt: HttpReceiptQueryResult,
    second_transfer_receipt_bytes: Vec<u8>,
    next_nonce: u64,
    next_nonce_query_bytes: Vec<u8>,
    request_id_r2: RequestId,
    signed_transaction_bytes_r2: Vec<u8>,
    submit_result_r2: HttpNodeResult,
    submit_result_r2_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devnet_survives_orderly_restart_and_rejects_duplicate_and_reused_requests() {
    let owner_signer = LocalSigner::from_seed([0x5B; 32]);
    let owner_address = owner_signer.address();
    let seed_file = TempSeedFile::new([0x5B; 32]);
    let dev_owner = DevOwner::new(*owner_address.as_bytes());

    let directory = TestDirectory::new("restart-duplicate-e2e");
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-restart-duplicate-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("13"),
        OsString::from("--dev-owner"),
        OsString::from(owner_address.to_string()),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();

    // --- Boot generation N, seed accounts. ---
    let first_boot = boot_local_store(&config).unwrap();
    let first_generation = first_boot.boot_generation();
    let first_protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let first_module =
        build_asset_module(first_protocol_context, ASSET_ACCOUNT_WASM.to_vec()).unwrap();

    let now_unix_millis = SystemClock.now_unix_millis().unwrap();
    let seed_deadline = StorageDeadline::new(now_unix_millis + 30_000).unwrap();
    let seed_context = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    );
    let seed_outcome = seed_asset_accounts(
        first_boot.store(),
        first_module.resolver(),
        config.epoch(),
        dev_owner,
        first_generation,
        &seed_context,
    )
    .unwrap();
    assert!(matches!(seed_outcome, SeedAssetAccountsOutcome::Created(_)));
    let first_accounts: SeededAssetAccounts = seed_outcome.accounts().clone();
    let source_id = first_accounts.source().id;
    let destination_id = first_accounts.destination().id;
    let module_ref = first_module.module_ref().clone();

    // --- Serve on an ephemeral loopback port. ---
    let first_store = Arc::new(first_boot.into_store());
    let first_router = compose_devnet_router(
        Arc::clone(&first_store),
        first_module,
        first_generation,
        config.max_concurrent(),
        config.dev_owners().len(),
    )
    .unwrap();
    let first_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let (first_shutdown_tx, first_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let first_server = tokio::spawn(native_http::serve(first_listener, first_router, async {
        let _ = first_shutdown_rx.await;
    }));

    let request_id_r1 = RequestId::new([REQUEST_ID_R1_BYTE; 32]).unwrap();
    let request_id_r2 = RequestId::new([REQUEST_ID_R2_BYTE; 32]).unwrap();
    let endpoint = first_address.to_string();
    let seed_path = seed_file.0.clone();
    let module_ref_for_blocking = module_ref.clone();
    let pre_restart: PreRestartState = tokio::task::spawn_blocking(move || {
        let module_ref = module_ref_for_blocking;
        let verify_client = make_client(first_address);

        // Baseline, independent of the seeding code above.
        let (_, source_baseline, _) = query_current_account(&verify_client, source_id);
        let (_, destination_baseline, _) = query_current_account(&verify_client, destination_id);
        assert_eq!(source_baseline.balance, INITIAL_SOURCE_BALANCE);
        assert_eq!(destination_baseline.balance, 0);

        // Property 1: user-facing transfer leg through the real CLI binary
        // entrypoint, amount 250, with a bounded wait for the receipt.
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
            OsString::from("--amount"),
            OsString::from(CLI_TRANSFER_AMOUNT.to_string()),
            OsString::from("--gas-limit"),
            OsString::from(GAS_LIMIT.to_string()),
            OsString::from("--request-id"),
            OsString::from(hex32(&[REQUEST_ID_R1_BYTE; 32])),
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
        .expect("CLI transfer should succeed against the real seeded devnet router");

        // Independently capture both decoded account states, the present
        // receipt, and the next nonce after the CLI transfer.
        let (source_ref_after_cli, source_after_cli, _) =
            query_current_account(&verify_client, source_id);
        let (destination_ref_after_cli, destination_after_cli, _) =
            query_current_account(&verify_client, destination_id);
        assert_eq!(
            source_after_cli.balance,
            source_baseline.balance - CLI_TRANSFER_AMOUNT
        );
        assert_eq!(
            destination_after_cli.balance,
            destination_baseline.balance + CLI_TRANSFER_AMOUNT
        );

        let cli_receipt = verify_client
            .query_receipt(request_id_r1)
            .expect("CLI transfer receipt query should succeed");
        assert!(matches!(
            cli_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));

        let context = verify_client
            .query_context()
            .expect("context query should succeed");
        let nonce_after_cli = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce query should succeed");
        assert_eq!(nonce_after_cli.epoch(), context.epoch());

        // Property 4 setup: build one signed `SubmitTransactionRequest`
        // directly through `sunrise-edge-client` (not the CLI), independent
        // of the CLI transfer above, and submit it once now. It is replayed
        // byte-identically once in this boot and once after restart.
        let mut access_manifest = AccessManifest::new();
        access_manifest.push(AccessEntry {
            object_ref: source_ref_after_cli,
            mode: AccessMode::Write,
        });
        access_manifest.push(AccessEntry {
            object_ref: destination_ref_after_cli,
            mode: AccessMode::Write,
        });
        let args =
            encode_transfer_args(TransferArgs::new(SECOND_TRANSFER_AMOUNT).unwrap()).unwrap();
        let transaction_request = TransactionRequest {
            chain_id: context.chain_id().clone(),
            protocol_version: context.protocol_version(),
            epoch: context.epoch(),
            nonce: nonce_after_cli.next_nonce(),
            access_manifest,
            module_ref: module_ref.clone(),
            entrypoint: TRANSFER_ENTRYPOINT.to_string(),
            args,
            gas_limit: GAS_LIMIT,
            fee_payment: None,
        };
        let signed_transaction_bytes_r2 = build_signed_transaction(
            &owner_signer,
            SignatureSchemeId::Ed25519,
            transaction_request,
        )
        .unwrap();

        let submit_result_r2 = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r2,
                signed_transaction_bytes: signed_transaction_bytes_r2.clone(),
            })
            .expect("the second, directly built transfer should be accepted");
        let submit_result_r2_bytes = submit_result_r2
            .encode()
            .expect("submit result should encode canonically");
        assert_eq!(submit_result_r2.responses().len(), 1);
        assert_eq!(
            submit_result_r2.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let payload = submit_result_r2.responses()[0]
            .payload()
            .expect("accepted transfer should carry execution effects");
        let effects = decode_execution_effects(payload).unwrap();
        assert!(matches!(
            effects.status,
            sunrise_edge_client::ExecutionStatus::Success
        ));

        let (source_ref_after_r2, source_after_r2, source_query_bytes) =
            query_current_account(&verify_client, source_id);
        let (destination_ref_after_r2, destination_after_r2, destination_query_bytes) =
            query_current_account(&verify_client, destination_id);
        assert_eq!(
            source_after_r2.balance,
            source_after_cli.balance - SECOND_TRANSFER_AMOUNT
        );
        assert_eq!(
            destination_after_r2.balance,
            destination_after_cli.balance + SECOND_TRANSFER_AMOUNT
        );

        let second_transfer_receipt = verify_client
            .query_receipt(request_id_r2)
            .expect("second transfer receipt query should succeed");
        assert!(matches!(
            second_transfer_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let cli_receipt_bytes = cli_receipt
            .encode()
            .expect("CLI receipt result should encode canonically");
        let second_transfer_receipt_bytes = second_transfer_receipt
            .encode()
            .expect("second receipt result should encode canonically");
        let next_nonce_result = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce query should succeed");
        let next_nonce_final = next_nonce_result.next_nonce();
        let next_nonce_query_bytes = next_nonce_result
            .encode()
            .expect("next-nonce result should encode canonically");

        // Same-boot duplicate evidence: replay the exact request before the
        // restart and prove both the canonical response and every persisted
        // observation remain byte-identical.
        let duplicate_before_restart = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r2,
                signed_transaction_bytes: signed_transaction_bytes_r2.clone(),
            })
            .expect("the exact same-boot duplicate should reconcile");
        assert_eq!(
            duplicate_before_restart
                .encode()
                .expect("duplicate submit result should encode canonically"),
            submit_result_r2_bytes
        );

        let (
            source_ref_after_same_boot_duplicate,
            source_after_same_boot_duplicate,
            source_bytes_after_same_boot_duplicate,
        ) = query_current_account(&verify_client, source_id);
        let (
            destination_ref_after_same_boot_duplicate,
            destination_after_same_boot_duplicate,
            destination_bytes_after_same_boot_duplicate,
        ) = query_current_account(&verify_client, destination_id);
        assert_eq!(source_ref_after_same_boot_duplicate, source_ref_after_r2);
        assert_eq!(
            destination_ref_after_same_boot_duplicate,
            destination_ref_after_r2
        );
        assert_eq!(source_after_same_boot_duplicate, source_after_r2);
        assert_eq!(destination_after_same_boot_duplicate, destination_after_r2);
        assert_eq!(source_bytes_after_same_boot_duplicate, source_query_bytes);
        assert_eq!(
            destination_bytes_after_same_boot_duplicate,
            destination_query_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(request_id_r2)
                .expect("duplicate receipt query should succeed")
                .encode()
                .expect("duplicate receipt result should encode canonically"),
            second_transfer_receipt_bytes
        );
        assert_eq!(
            verify_client
                .query_next_nonce(owner_address)
                .expect("next-nonce query after duplicate should succeed")
                .encode()
                .expect("next-nonce result should encode canonically"),
            next_nonce_query_bytes
        );

        PreRestartState {
            source_account: source_after_r2,
            destination_account: destination_after_r2,
            source_ref: source_ref_after_r2,
            destination_ref: destination_ref_after_r2,
            source_query_bytes,
            destination_query_bytes,
            cli_receipt,
            cli_receipt_bytes,
            second_transfer_receipt,
            second_transfer_receipt_bytes,
            next_nonce: next_nonce_final,
            next_nonce_query_bytes,
            request_id_r2,
            signed_transaction_bytes_r2,
            submit_result_r2,
            submit_result_r2_bytes,
        }
    })
    .await
    .unwrap();

    // --- Stop and await the server; drop every store/router reference. ---
    first_shutdown_tx
        .send(())
        .expect("shutdown signal should reach the still-running server task");
    first_server
        .await
        .expect("server task should not panic")
        .expect("graceful shutdown should complete without error");
    let closed_store = Arc::try_unwrap(first_store)
        .expect("no other durable-store reference should remain after orderly shutdown");
    drop(closed_store);

    // --- Reopen through boot_local_store; assert generation N+1. ---
    let second_boot = boot_local_store(&config).unwrap();
    let second_generation = second_boot.boot_generation();
    assert_eq!(second_generation.get(), first_generation.get() + 1);

    // Property 6: the pre-restart writer generation is fenced on the
    // reopened store. This is a read attempt scoped to this store's own
    // trusted (chain, validator, domain) namespace and bound to the stale
    // generation's `DurableOperationContext`; it must fail closed rather
    // than silently succeed against or alongside the new generation.
    let domain = AtomicityDomainId::new(sunrise_edge_devnet::genesis::DEVNET_DOMAIN_BYTES).unwrap();
    let stale_generation_context = DurableOperationContext::new(
        first_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x62; 16]).unwrap(),
    );
    let durable_request_id_r1 = DurableRequestId::new(*request_id_r1.as_bytes()).unwrap();
    let fencing_result = second_boot.store().get_request_receipt(
        &stale_generation_context,
        domain,
        durable_request_id_r1,
    );
    assert_eq!(
        fencing_result,
        Err(DurableReadError::WriterFenced {
            active_generation: second_generation
        })
    );

    // Reseed and require Existing with identical account refs.
    let second_protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let second_module =
        build_asset_module(second_protocol_context, ASSET_ACCOUNT_WASM.to_vec()).unwrap();
    let reseed_context = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x63; 16]).unwrap(),
    );
    let reseed_outcome = seed_asset_accounts(
        second_boot.store(),
        second_module.resolver(),
        config.epoch(),
        dev_owner,
        second_generation,
        &reseed_context,
    )
    .unwrap();
    assert!(matches!(
        reseed_outcome,
        SeedAssetAccountsOutcome::Existing(_)
    ));
    // `seed_asset_accounts` reports the *current* head reference on the
    // `Existing` path (not the version-one creation snapshot the `Created`
    // path in `first_accounts` captured), so the account identities (owner,
    // object ids) are compared against `first_accounts`, while the exact
    // current `ObjectRef` (version/digest, advanced by the two real
    // transfers above) is compared against the state independently observed
    // immediately before restart.
    assert_eq!(reseed_outcome.accounts().owner(), first_accounts.owner());
    assert_eq!(
        reseed_outcome.accounts().source().id,
        first_accounts.source().id
    );
    assert_eq!(
        reseed_outcome.accounts().destination().id,
        first_accounts.destination().id
    );
    assert_eq!(reseed_outcome.accounts().source(), &pre_restart.source_ref);
    assert_eq!(
        reseed_outcome.accounts().destination(),
        &pre_restart.destination_ref
    );
    assert_eq!(second_module.module_ref(), &module_ref);

    // --- Recompose on a fresh ephemeral port. ---
    let second_store = Arc::new(second_boot.into_store());
    let second_router = compose_devnet_router(
        Arc::clone(&second_store),
        second_module,
        second_generation,
        config.max_concurrent(),
        config.dev_owners().len(),
    )
    .unwrap();
    let second_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let second_address = second_listener.local_addr().unwrap();
    let (second_shutdown_tx, second_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let second_server = tokio::spawn(native_http::serve(second_listener, second_router, async {
        let _ = second_shutdown_rx.await;
    }));

    tokio::task::spawn_blocking(move || {
        let verify_client = make_client(second_address);

        // Property 3: balances, sequences, receipts, and next nonce are
        // byte-identical to the values captured immediately before restart.
        let (_, source_after_restart, source_query_bytes_after_restart) =
            query_current_account(&verify_client, source_id);
        let (_, destination_after_restart, destination_query_bytes_after_restart) =
            query_current_account(&verify_client, destination_id);
        assert_eq!(source_after_restart, pre_restart.source_account);
        assert_eq!(destination_after_restart, pre_restart.destination_account);
        assert_eq!(
            source_query_bytes_after_restart,
            pre_restart.source_query_bytes
        );
        assert_eq!(
            destination_query_bytes_after_restart,
            pre_restart.destination_query_bytes
        );

        let cli_receipt_after_restart = verify_client
            .query_receipt(request_id_r1)
            .expect("CLI transfer receipt query should succeed after restart");
        assert_eq!(cli_receipt_after_restart, pre_restart.cli_receipt);
        assert_eq!(
            cli_receipt_after_restart
                .encode()
                .expect("CLI receipt result should encode canonically after restart"),
            pre_restart.cli_receipt_bytes
        );

        let second_transfer_receipt_after_restart = verify_client
            .query_receipt(pre_restart.request_id_r2)
            .expect("second transfer receipt query should succeed after restart");
        assert_eq!(
            second_transfer_receipt_after_restart,
            pre_restart.second_transfer_receipt
        );
        assert_eq!(
            second_transfer_receipt_after_restart
                .encode()
                .expect("second receipt result should encode canonically after restart"),
            pre_restart.second_transfer_receipt_bytes
        );

        let next_nonce_result_after_restart = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce query should succeed after restart");
        let next_nonce_after_restart = next_nonce_result_after_restart.next_nonce();
        assert_eq!(next_nonce_after_restart, pre_restart.next_nonce);
        assert_eq!(
            next_nonce_result_after_restart
                .encode()
                .expect("next-nonce result should encode canonically after restart"),
            pre_restart.next_nonce_query_bytes
        );

        // Property 4: submit the exact same signed transaction byte-for-byte
        // with the same request id, across restart. It must return the same
        // response and must not change state further.
        let context = verify_client
            .query_context()
            .expect("context query should succeed after restart");
        let duplicate_result = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: pre_restart.request_id_r2,
                signed_transaction_bytes: pre_restart.signed_transaction_bytes_r2.clone(),
            })
            .expect("the exact duplicate submission should still be accepted as a replay");
        assert_eq!(duplicate_result, pre_restart.submit_result_r2);
        assert_eq!(
            duplicate_result
                .encode()
                .expect("duplicate result should encode canonically after restart"),
            pre_restart.submit_result_r2_bytes
        );

        let (_, source_after_duplicate, source_query_bytes_after_duplicate) =
            query_current_account(&verify_client, source_id);
        let (_, destination_after_duplicate, destination_query_bytes_after_duplicate) =
            query_current_account(&verify_client, destination_id);
        assert_eq!(source_after_duplicate, pre_restart.source_account);
        assert_eq!(destination_after_duplicate, pre_restart.destination_account);
        assert_eq!(
            source_query_bytes_after_duplicate,
            pre_restart.source_query_bytes
        );
        assert_eq!(
            destination_query_bytes_after_duplicate,
            pre_restart.destination_query_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(pre_restart.request_id_r2)
                .expect("receipt query after duplicate should succeed")
                .encode()
                .expect("receipt result after duplicate should encode canonically"),
            pre_restart.second_transfer_receipt_bytes
        );
        let next_nonce_result_after_duplicate = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce query should succeed after the duplicate submission");
        let next_nonce_after_duplicate = next_nonce_result_after_duplicate.next_nonce();
        assert_eq!(next_nonce_after_duplicate, pre_restart.next_nonce);
        assert_eq!(
            next_nonce_result_after_duplicate
                .encode()
                .expect("next-nonce result after duplicate should encode canonically"),
            pre_restart.next_nonce_query_bytes
        );

        // Property 5: reusing an already-committed request id for a
        // different transaction/event is a typed, nonzero, fail-closed
        // result, with no state change. `request_id_r1` was already
        // committed by the CLI transfer above; resubmitting it with the
        // second transaction's different signed bytes must be rejected.
        let reused_id_error = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r1,
                signed_transaction_bytes: pre_restart.signed_transaction_bytes_r2.clone(),
            })
            .expect_err("reusing a committed request id for a different transaction must fail");
        match reused_id_error {
            ClientError::UnexpectedStatus { status, .. } => {
                assert_ne!(status, 0);
                assert_eq!(status, 409);
            }
            other => panic!("expected a typed fail-closed HTTP conflict, got {other:?}"),
        }

        let (_, source_after_reuse_attempt, source_query_bytes_after_reuse_attempt) =
            query_current_account(&verify_client, source_id);
        let (_, destination_after_reuse_attempt, destination_query_bytes_after_reuse_attempt) =
            query_current_account(&verify_client, destination_id);
        assert_eq!(source_after_reuse_attempt, pre_restart.source_account);
        assert_eq!(
            destination_after_reuse_attempt,
            pre_restart.destination_account
        );
        assert_eq!(
            source_query_bytes_after_reuse_attempt,
            pre_restart.source_query_bytes
        );
        assert_eq!(
            destination_query_bytes_after_reuse_attempt,
            pre_restart.destination_query_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(request_id_r1)
                .expect("CLI receipt query should succeed after the rejected reuse attempt")
                .encode()
                .expect("CLI receipt should encode canonically after rejected reuse"),
            pre_restart.cli_receipt_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(pre_restart.request_id_r2)
                .expect("second receipt query should succeed after the rejected reuse attempt")
                .encode()
                .expect("second receipt should encode canonically after rejected reuse"),
            pre_restart.second_transfer_receipt_bytes
        );
        let next_nonce_result_after_reuse_attempt = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce query should succeed after the rejected reuse attempt");
        let next_nonce_after_reuse_attempt = next_nonce_result_after_reuse_attempt.next_nonce();
        assert_eq!(next_nonce_after_reuse_attempt, pre_restart.next_nonce);
        assert_eq!(
            next_nonce_result_after_reuse_attempt
                .encode()
                .expect("next-nonce result after reuse should encode canonically"),
            pre_restart.next_nonce_query_bytes
        );
    })
    .await
    .unwrap();

    second_shutdown_tx
        .send(())
        .expect("shutdown signal should reach the still-running server task");
    second_server
        .await
        .expect("server task should not panic")
        .expect("graceful shutdown should complete without error");
    let closed_second_store = Arc::try_unwrap(second_store)
        .expect("no other durable-store reference should remain after the final shutdown");
    drop(closed_second_store);
}
