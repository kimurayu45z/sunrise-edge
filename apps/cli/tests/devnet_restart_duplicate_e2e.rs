//! Real loopback TCP restart/duplicate E2E for the CLI Developer MVP Gate's
//! S3 uniform-fee slice (see `TODO.md#cli-developer-mvp-gate`).
//!
//! This uses a real file-backed `SqliteDurableStore`, the real composed
//! devnet router, real loopback TCP, `sunrise_edge_cli::run` for the
//! user-facing transfer leg, and `sunrise-edge-client` directly for
//! independent verification and for building/replaying one raw
//! `SubmitTransactionRequest`. It proves exactly:
//!
//! 1. A fee-enabled CLI transfer of amount 250 from a sender-owned source into an
//!    independently seeded recipient-owned destination, verified
//!    independently through the client with the recipient owner unchanged and
//!    the distinct ordinary treasury credited by the actual committed gas.
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
//! 5. A trapped invocation discards its application transfer but charges the
//!    normalized actual gas through fee-only source/treasury writes.
//! 6. Reusing an already-committed request id for a different transaction is
//!    a typed, nonzero, fail-closed HTTP conflict with no state change.
//! 7. The pre-restart writer generation is fenced on the reopened store.
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
    AccessEntry, AccessManifest, AccessMode, Amount, AtomicityDomainId, Client, ClientError,
    ExecutionStatus, FeePayment, HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    LocalSigner, LoopbackHttpTransport, NodeResponseStatus, ObjectId, ObjectRef, Owner, RequestId,
    SignatureSchemeId, SubmitTransactionRequest, TransactionRequest, build_signed_transaction,
    decode_execution_effects, decode_object,
};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, AssetAccount, DEVNET_ASSET_ID, DevOwner, DevnetConfig,
    SeedAssetAccountsOutcome, SeededAssetAccounts, TransferArgs, boot_local_store,
    build_asset_module, build_devnet_protocol_context, compose_devnet_router, decode_asset_account,
    decode_transfer_event, encode_transfer_args,
    genesis::{DEVNET_DOMAIN_BYTES, DEVNET_PROTOCOL_VERSION},
    seed_asset_accounts, verify_seeded_asset_supply,
};

const INITIAL_SOURCE_BALANCE: u64 = 1_000_000;
const CLI_TRANSFER_AMOUNT: u64 = 250;
const SECOND_TRANSFER_AMOUNT: u64 = 25;
const TRANSFER_ENTRYPOINT: &str = "transfer";
const GAS_LIMIT: u64 = 1_000_000;
const REQUEST_ID_R1_BYTE: u8 = 0x51;
const REQUEST_ID_R2_BYTE: u8 = 0x52;
const REQUEST_ID_R3_BYTE: u8 = 0x53;
const TRAP_GAS_LIMIT: u64 = 10_000;
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
) -> (ObjectRef, AssetAccount, Owner, Vec<u8>) {
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
            let owner: Owner = object.owner;
            let object_ref = ObjectRef {
                id: object_id,
                version: object_version.get(),
                digest,
            };
            (object_ref, account, owner, canonical_result_bytes)
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
    treasury_account: AssetAccount,
    treasury_ref: ObjectRef,
    source_query_bytes: Vec<u8>,
    destination_query_bytes: Vec<u8>,
    treasury_query_bytes: Vec<u8>,
    cli_receipt: HttpReceiptQueryResult,
    cli_receipt_bytes: Vec<u8>,
    second_transfer_receipt: HttpReceiptQueryResult,
    second_transfer_receipt_bytes: Vec<u8>,
    trapped_receipt: HttpReceiptQueryResult,
    trapped_receipt_bytes: Vec<u8>,
    next_nonce: u64,
    next_nonce_query_bytes: Vec<u8>,
    request_id_r2: RequestId,
    signed_transaction_bytes_r2: Vec<u8>,
    submit_result_r2: HttpNodeResult,
    submit_result_r2_bytes: Vec<u8>,
    request_id_r3: RequestId,
    signed_transaction_bytes_r3: Vec<u8>,
    submit_result_r3: HttpNodeResult,
    submit_result_r3_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devnet_survives_orderly_restart_and_rejects_duplicate_and_reused_requests() {
    let owner_signer = LocalSigner::from_seed([0x5B; 32]);
    let owner_address = owner_signer.address();
    let recipient_signer = LocalSigner::from_seed([0x6B; 32]);
    let recipient_address = recipient_signer.address();
    let seed_file = TempSeedFile::new([0x5B; 32]);
    let dev_owner = DevOwner::new(*owner_address.as_bytes());
    let recipient_dev_owner = DevOwner::new(*recipient_address.as_bytes());
    let treasury_dev_owner = DevOwner::new([0x7B; 32]);

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
        OsString::from("--dev-owner"),
        OsString::from(recipient_address.to_string()),
        OsString::from("--fee-treasury-owner"),
        OsString::from("7b".repeat(32)),
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
    let recipient_seed_context = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x64; 16]).unwrap(),
    );
    let recipient_seed_outcome = seed_asset_accounts(
        first_boot.store(),
        first_module.resolver(),
        config.epoch(),
        recipient_dev_owner,
        first_generation,
        &recipient_seed_context,
    )
    .unwrap();
    assert!(matches!(
        recipient_seed_outcome,
        SeedAssetAccountsOutcome::Created(_)
    ));
    let treasury_seed_context = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x66; 16]).unwrap(),
    );
    let treasury_seed_outcome = seed_asset_accounts(
        first_boot.store(),
        first_module.resolver(),
        config.epoch(),
        treasury_dev_owner,
        first_generation,
        &treasury_seed_context,
    )
    .unwrap();
    assert!(matches!(
        treasury_seed_outcome,
        SeedAssetAccountsOutcome::Created(_)
    ));
    verify_seeded_asset_supply(&[
        seed_outcome.clone(),
        recipient_seed_outcome.clone(),
        treasury_seed_outcome.clone(),
    ])
    .unwrap();
    let recipient_accounts: SeededAssetAccounts = recipient_seed_outcome.accounts().clone();
    let source_id = first_accounts.source().id;
    let destination_id = recipient_accounts.destination().id;
    let treasury_accounts: SeededAssetAccounts = treasury_seed_outcome.accounts().clone();
    let treasury_id = treasury_accounts.destination().id;
    let module_ref = first_module.module_ref().clone();

    // --- Serve on an ephemeral loopback port. ---
    let first_store = Arc::new(first_boot.into_store());
    let first_router = compose_devnet_router(
        Arc::clone(&first_store),
        first_module,
        first_generation,
        config.max_concurrent(),
        3,
        treasury_id,
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
        let (_, source_baseline, source_owner_baseline, _) =
            query_current_account(&verify_client, source_id);
        let (_, destination_baseline, destination_owner_baseline, _) =
            query_current_account(&verify_client, destination_id);
        let (_, treasury_baseline, treasury_owner_baseline, _) =
            query_current_account(&verify_client, treasury_id);
        assert_eq!(source_baseline.balance, INITIAL_SOURCE_BALANCE);
        assert_eq!(destination_baseline.balance, 0);
        assert_eq!(source_owner_baseline, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_baseline,
            Owner::Address(recipient_address)
        );
        assert_eq!(treasury_baseline.balance, 0);
        assert_eq!(
            treasury_owner_baseline,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );

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
            OsString::from("--destination-owner"),
            OsString::from(recipient_address.to_string()),
            OsString::from("--amount"),
            OsString::from(CLI_TRANSFER_AMOUNT.to_string()),
            OsString::from("--gas-limit"),
            OsString::from(GAS_LIMIT.to_string()),
            OsString::from("--fee-asset-id"),
            OsString::from(hex32(DEVNET_ASSET_ID.as_bytes())),
            OsString::from("--max-fee"),
            OsString::from((GAS_LIMIT + 1).to_string()),
            OsString::from("--fee-treasury-object"),
            OsString::from(treasury_id.to_string()),
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
        let (source_ref_after_cli, source_after_cli, source_owner_after_cli, _) =
            query_current_account(&verify_client, source_id);
        let (destination_ref_after_cli, destination_after_cli, destination_owner_after_cli, _) =
            query_current_account(&verify_client, destination_id);
        let (treasury_ref_after_cli, treasury_after_cli, treasury_owner_after_cli, _) =
            query_current_account(&verify_client, treasury_id);
        let cli_fee: u64 = treasury_after_cli.balance - treasury_baseline.balance;
        assert_eq!(
            source_after_cli.balance,
            source_baseline.balance - CLI_TRANSFER_AMOUNT - cli_fee
        );
        assert_eq!(
            destination_after_cli.balance,
            destination_baseline.balance + CLI_TRANSFER_AMOUNT
        );
        assert_eq!(source_owner_after_cli, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_after_cli,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_cli,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
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
            object_ref: source_ref_after_cli.clone(),
            mode: AccessMode::Write,
        });
        access_manifest.push(AccessEntry {
            object_ref: destination_ref_after_cli.clone(),
            mode: AccessMode::Write,
        });
        access_manifest.push(AccessEntry {
            object_ref: treasury_ref_after_cli.clone(),
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
            fee_payment: Some(FeePayment {
                asset_id: DEVNET_ASSET_ID,
                max_fee: Amount::new(GAS_LIMIT + 1),
                fee_object: source_ref_after_cli.clone(),
            }),
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
        assert!(matches!(effects.status, ExecutionStatus::Success));
        assert_eq!(effects.events.len(), 1);
        let transfer_event = decode_transfer_event(&effects.events[0].data).unwrap();
        assert_eq!(transfer_event.amount, SECOND_TRANSFER_AMOUNT);
        assert_eq!(
            transfer_event.source_balance,
            source_after_cli.balance - SECOND_TRANSFER_AMOUNT
        );

        let (source_ref_after_r2, source_after_r2, source_owner_after_r2, _) =
            query_current_account(&verify_client, source_id);
        let (destination_ref_after_r2, destination_after_r2, destination_owner_after_r2, _) =
            query_current_account(&verify_client, destination_id);
        let (treasury_ref_after_r2, treasury_after_r2, treasury_owner_after_r2, _) =
            query_current_account(&verify_client, treasury_id);
        let r2_fee: u64 = treasury_after_r2.balance - treasury_after_cli.balance;
        assert_eq!(r2_fee, 1 + effects.gas_used);
        assert_eq!(
            source_after_r2.balance,
            source_after_cli.balance - SECOND_TRANSFER_AMOUNT - r2_fee
        );
        assert_eq!(
            source_after_r2.balance,
            transfer_event.source_balance - r2_fee
        );
        assert_eq!(
            destination_after_r2.balance,
            destination_after_cli.balance + SECOND_TRANSFER_AMOUNT
        );
        assert_eq!(source_owner_after_r2, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_after_r2,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_r2,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );
        assert_eq!(source_after_r2.sequence, source_after_cli.sequence + 2);
        assert_eq!(
            source_ref_after_r2.version,
            source_ref_after_cli.version + 1
        );
        assert_eq!(
            destination_ref_after_r2.version,
            destination_ref_after_cli.version + 1
        );
        assert_eq!(
            treasury_ref_after_r2.version,
            treasury_ref_after_cli.version + 1
        );

        // Property 5: malformed module arguments deterministically trap.
        // Application effects are discarded, while the normalized
        // `gas_used == gas_limit` charge commits only source/treasury writes.
        let nonce_before_trap = verify_client
            .query_next_nonce(owner_address)
            .expect("next-nonce before trapped invocation should succeed");
        let mut trap_manifest = AccessManifest::new();
        trap_manifest.push(AccessEntry {
            object_ref: source_ref_after_r2.clone(),
            mode: AccessMode::Write,
        });
        trap_manifest.push(AccessEntry {
            object_ref: destination_ref_after_r2.clone(),
            mode: AccessMode::Write,
        });
        trap_manifest.push(AccessEntry {
            object_ref: treasury_ref_after_r2,
            mode: AccessMode::Write,
        });
        let trapped_signed_bytes = build_signed_transaction(
            &owner_signer,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: nonce_before_trap.next_nonce(),
                access_manifest: trap_manifest,
                module_ref: module_ref.clone(),
                entrypoint: TRANSFER_ENTRYPOINT.to_string(),
                args: vec![0],
                gas_limit: TRAP_GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id: DEVNET_ASSET_ID,
                    max_fee: Amount::new(TRAP_GAS_LIMIT + 1),
                    fee_object: source_ref_after_r2.clone(),
                }),
            },
        )
        .unwrap();
        let request_id_r3 = RequestId::new([REQUEST_ID_R3_BYTE; 32]).unwrap();
        let trapped_result = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r3,
                signed_transaction_bytes: trapped_signed_bytes.clone(),
            })
            .expect("trapped execution should commit its rejected receipt and fee effects");
        assert_eq!(trapped_result.responses().len(), 1);
        assert_eq!(
            trapped_result.responses()[0].status(),
            NodeResponseStatus::Rejected
        );
        let trapped_effects = decode_execution_effects(
            trapped_result.responses()[0]
                .payload()
                .expect("trapped execution should carry normalized effects"),
        )
        .unwrap();
        assert!(matches!(
            trapped_effects.status,
            ExecutionStatus::Failure { .. }
        ));
        assert_eq!(trapped_effects.gas_used, TRAP_GAS_LIMIT);
        assert!(trapped_effects.object_effects.is_empty());
        let trapped_result_bytes = trapped_result
            .encode()
            .expect("trapped submit result should encode canonically");

        let source_before_trap: AssetAccount = source_after_r2;
        let destination_before_trap: AssetAccount = destination_after_r2;
        let treasury_before_trap: AssetAccount = treasury_after_r2;
        let (source_ref_after_r2, source_after_r2, source_owner_after_r2, source_query_bytes) =
            query_current_account(&verify_client, source_id);
        let (
            destination_ref_after_r2,
            destination_after_r2,
            destination_owner_after_r2,
            destination_query_bytes,
        ) = query_current_account(&verify_client, destination_id);
        let (
            treasury_ref_after_r2,
            treasury_after_r2,
            treasury_owner_after_r2,
            treasury_query_bytes,
        ) = query_current_account(&verify_client, treasury_id);
        assert_eq!(
            source_after_r2.balance,
            source_before_trap.balance - TRAP_GAS_LIMIT - 1
        );
        assert_eq!(destination_after_r2, destination_before_trap);
        assert_eq!(
            treasury_after_r2.balance,
            treasury_before_trap.balance + TRAP_GAS_LIMIT + 1
        );
        assert_eq!(source_after_r2.sequence, source_before_trap.sequence + 1);
        assert_eq!(
            treasury_after_r2.sequence,
            treasury_before_trap.sequence + 1
        );
        assert_eq!(source_owner_after_r2, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_after_r2,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_r2,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );

        let second_transfer_receipt = verify_client
            .query_receipt(request_id_r2)
            .expect("second transfer receipt query should succeed");
        assert!(matches!(
            second_transfer_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let trapped_receipt = verify_client
            .query_receipt(request_id_r3)
            .expect("trapped invocation receipt query should succeed");
        assert!(matches!(
            trapped_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let cli_receipt_bytes = cli_receipt
            .encode()
            .expect("CLI receipt result should encode canonically");
        let second_transfer_receipt_bytes = second_transfer_receipt
            .encode()
            .expect("second receipt result should encode canonically");
        let trapped_receipt_bytes = trapped_receipt
            .encode()
            .expect("trapped receipt result should encode canonically");
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
            source_owner_after_same_boot_duplicate,
            source_bytes_after_same_boot_duplicate,
        ) = query_current_account(&verify_client, source_id);
        let (
            destination_ref_after_same_boot_duplicate,
            destination_after_same_boot_duplicate,
            destination_owner_after_same_boot_duplicate,
            destination_bytes_after_same_boot_duplicate,
        ) = query_current_account(&verify_client, destination_id);
        let (
            treasury_ref_after_same_boot_duplicate,
            treasury_after_same_boot_duplicate,
            treasury_owner_after_same_boot_duplicate,
            treasury_bytes_after_same_boot_duplicate,
        ) = query_current_account(&verify_client, treasury_id);
        assert_eq!(source_ref_after_same_boot_duplicate, source_ref_after_r2);
        assert_eq!(
            destination_ref_after_same_boot_duplicate,
            destination_ref_after_r2
        );
        assert_eq!(source_after_same_boot_duplicate, source_after_r2);
        assert_eq!(destination_after_same_boot_duplicate, destination_after_r2);
        assert_eq!(
            treasury_ref_after_same_boot_duplicate,
            treasury_ref_after_r2
        );
        assert_eq!(treasury_after_same_boot_duplicate, treasury_after_r2);
        assert_eq!(
            source_owner_after_same_boot_duplicate,
            Owner::Address(owner_address)
        );
        assert_eq!(
            destination_owner_after_same_boot_duplicate,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_same_boot_duplicate,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );
        assert_eq!(source_bytes_after_same_boot_duplicate, source_query_bytes);
        assert_eq!(
            destination_bytes_after_same_boot_duplicate,
            destination_query_bytes
        );
        assert_eq!(
            treasury_bytes_after_same_boot_duplicate,
            treasury_query_bytes
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
                .query_receipt(request_id_r3)
                .expect("trapped receipt query after duplicate should succeed")
                .encode()
                .expect("trapped receipt result should encode canonically"),
            trapped_receipt_bytes
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
            treasury_account: treasury_after_r2,
            treasury_ref: treasury_ref_after_r2,
            source_query_bytes,
            destination_query_bytes,
            treasury_query_bytes,
            cli_receipt,
            cli_receipt_bytes,
            second_transfer_receipt,
            second_transfer_receipt_bytes,
            trapped_receipt,
            trapped_receipt_bytes,
            next_nonce: next_nonce_final,
            next_nonce_query_bytes,
            request_id_r2,
            signed_transaction_bytes_r2,
            submit_result_r2,
            submit_result_r2_bytes,
            request_id_r3,
            signed_transaction_bytes_r3: trapped_signed_bytes,
            submit_result_r3: trapped_result,
            submit_result_r3_bytes: trapped_result_bytes,
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

    // Reseed both transfer owners and the distinct treasury owner, requiring
    // Existing with identical identities and current references.
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
    let recipient_reseed_context = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x65; 16]).unwrap(),
    );
    let recipient_reseed_outcome = seed_asset_accounts(
        second_boot.store(),
        second_module.resolver(),
        config.epoch(),
        recipient_dev_owner,
        second_generation,
        &recipient_reseed_context,
    )
    .unwrap();
    assert!(matches!(
        recipient_reseed_outcome,
        SeedAssetAccountsOutcome::Existing(_)
    ));
    let treasury_reseed_context = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x67; 16]).unwrap(),
    );
    let treasury_reseed_outcome = seed_asset_accounts(
        second_boot.store(),
        second_module.resolver(),
        config.epoch(),
        treasury_dev_owner,
        second_generation,
        &treasury_reseed_context,
    )
    .unwrap();
    assert!(matches!(
        treasury_reseed_outcome,
        SeedAssetAccountsOutcome::Existing(_)
    ));
    verify_seeded_asset_supply(&[
        reseed_outcome.clone(),
        recipient_reseed_outcome.clone(),
        treasury_reseed_outcome.clone(),
    ])
    .unwrap();
    // `seed_asset_accounts` reports the *current* head reference on the
    // `Existing` path (not the version-one creation snapshot the `Created`
    // path in `first_accounts` captured), so the account identities (owner,
    // object ids) are compared against `first_accounts`, while the exact
    // current `ObjectRef` (version/digest, advanced on the sender source and
    // recipient destination by the two real cross-owner transfers above) is
    // compared against state independently observed immediately before
    // restart. The two unused companion accounts remain at their seeded refs.
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
        first_accounts.destination()
    );
    assert_eq!(
        recipient_reseed_outcome.accounts().owner(),
        recipient_accounts.owner()
    );
    assert_eq!(
        recipient_reseed_outcome.accounts().source(),
        recipient_accounts.source()
    );
    assert_eq!(
        recipient_reseed_outcome.accounts().destination(),
        &pre_restart.destination_ref
    );
    assert_eq!(
        treasury_reseed_outcome.accounts().owner(),
        treasury_accounts.owner()
    );
    assert_eq!(
        treasury_reseed_outcome.accounts().source(),
        treasury_accounts.source()
    );
    assert_eq!(
        treasury_reseed_outcome.accounts().destination(),
        &pre_restart.treasury_ref
    );
    assert_eq!(second_module.module_ref(), &module_ref);

    // --- Recompose on a fresh ephemeral port. ---
    let second_store = Arc::new(second_boot.into_store());
    let second_router = compose_devnet_router(
        Arc::clone(&second_store),
        second_module,
        second_generation,
        config.max_concurrent(),
        3,
        treasury_id,
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
        let request_id_r3 = RequestId::new([REQUEST_ID_R3_BYTE; 32]).unwrap();

        // Property 3: balances, sequences, receipts, and next nonce are
        // byte-identical to the values captured immediately before restart.
        let (_, source_after_restart, source_owner_after_restart, source_query_bytes_after_restart) =
            query_current_account(&verify_client, source_id);
        let (
            _,
            destination_after_restart,
            destination_owner_after_restart,
            destination_query_bytes_after_restart,
        ) = query_current_account(&verify_client, destination_id);
        let (
            treasury_ref_after_restart,
            treasury_after_restart,
            treasury_owner_after_restart,
            treasury_query_bytes_after_restart,
        ) = query_current_account(&verify_client, treasury_id);
        assert_eq!(source_after_restart, pre_restart.source_account);
        assert_eq!(destination_after_restart, pre_restart.destination_account);
        assert_eq!(treasury_after_restart, pre_restart.treasury_account);
        assert_eq!(treasury_ref_after_restart, pre_restart.treasury_ref);
        assert_eq!(source_owner_after_restart, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_after_restart,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_restart,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );
        assert_eq!(
            source_query_bytes_after_restart,
            pre_restart.source_query_bytes
        );
        assert_eq!(
            destination_query_bytes_after_restart,
            pre_restart.destination_query_bytes
        );
        assert_eq!(
            treasury_query_bytes_after_restart,
            pre_restart.treasury_query_bytes
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

        let trapped_receipt_after_restart = verify_client
            .query_receipt(request_id_r3)
            .expect("trapped receipt query should succeed after restart");
        assert_eq!(trapped_receipt_after_restart, pre_restart.trapped_receipt);
        assert_eq!(
            trapped_receipt_after_restart
                .encode()
                .expect("trapped receipt should encode canonically after restart"),
            pre_restart.trapped_receipt_bytes
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

        let trapped_duplicate_result = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: pre_restart.request_id_r3,
                signed_transaction_bytes: pre_restart.signed_transaction_bytes_r3.clone(),
            })
            .expect("the trapped invocation must reconcile without a second fee debit");
        assert_eq!(trapped_duplicate_result, pre_restart.submit_result_r3);
        assert_eq!(
            trapped_duplicate_result
                .encode()
                .expect("trapped duplicate should encode canonically after restart"),
            pre_restart.submit_result_r3_bytes
        );

        let (_, source_after_duplicate, source_owner_after_duplicate, source_query_bytes_after_duplicate) =
            query_current_account(&verify_client, source_id);
        let (
            _,
            destination_after_duplicate,
            destination_owner_after_duplicate,
            destination_query_bytes_after_duplicate,
        ) = query_current_account(&verify_client, destination_id);
        let (
            _,
            treasury_after_duplicate,
            treasury_owner_after_duplicate,
            treasury_query_bytes_after_duplicate,
        ) = query_current_account(&verify_client, treasury_id);
        assert_eq!(source_after_duplicate, pre_restart.source_account);
        assert_eq!(destination_after_duplicate, pre_restart.destination_account);
        assert_eq!(treasury_after_duplicate, pre_restart.treasury_account);
        assert_eq!(source_owner_after_duplicate, Owner::Address(owner_address));
        assert_eq!(
            destination_owner_after_duplicate,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_duplicate,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
        );
        assert_eq!(
            source_query_bytes_after_duplicate,
            pre_restart.source_query_bytes
        );
        assert_eq!(
            destination_query_bytes_after_duplicate,
            pre_restart.destination_query_bytes
        );
        assert_eq!(
            treasury_query_bytes_after_duplicate,
            pre_restart.treasury_query_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(pre_restart.request_id_r2)
                .expect("receipt query after duplicate should succeed")
                .encode()
                .expect("receipt result after duplicate should encode canonically"),
            pre_restart.second_transfer_receipt_bytes
        );
        assert_eq!(
            verify_client
                .query_receipt(request_id_r3)
                .expect("trapped receipt query after duplicate should succeed")
                .encode()
                .expect("trapped receipt after duplicate should encode canonically"),
            pre_restart.trapped_receipt_bytes
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

        let (_, source_after_reuse_attempt, source_owner_after_reuse_attempt, source_query_bytes_after_reuse_attempt) =
            query_current_account(&verify_client, source_id);
        let (
            _,
            destination_after_reuse_attempt,
            destination_owner_after_reuse_attempt,
            destination_query_bytes_after_reuse_attempt,
        ) = query_current_account(&verify_client, destination_id);
        let (
            _,
            treasury_after_reuse_attempt,
            treasury_owner_after_reuse_attempt,
            treasury_query_bytes_after_reuse_attempt,
        ) = query_current_account(&verify_client, treasury_id);
        assert_eq!(source_after_reuse_attempt, pre_restart.source_account);
        assert_eq!(
            destination_after_reuse_attempt,
            pre_restart.destination_account
        );
        assert_eq!(treasury_after_reuse_attempt, pre_restart.treasury_account);
        assert_eq!(
            source_owner_after_reuse_attempt,
            Owner::Address(owner_address)
        );
        assert_eq!(
            destination_owner_after_reuse_attempt,
            Owner::Address(recipient_address)
        );
        assert_eq!(
            treasury_owner_after_reuse_attempt,
            Owner::Address(sunrise_edge_client::Address::new([0x7B; 32]))
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
            treasury_query_bytes_after_reuse_attempt,
            pre_restart.treasury_query_bytes
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
        assert_eq!(
            verify_client
                .query_receipt(request_id_r3)
                .expect("trapped receipt query should succeed after rejected reuse")
                .encode()
                .expect("trapped receipt should encode after rejected reuse"),
            pre_restart.trapped_receipt_bytes
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
