//! Real loopback TCP E2E: `sunrise_edge_cli::run` against the composed
//! local devnet router, exactly as a user would invoke the `sunrise-edge-cli`
//! binary.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use objects::ObjectId;
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, DevnetConfig, boot_local_store, build_asset_module,
    build_devnet_protocol_context, compose_devnet_router,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-e2e-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_context_and_next_nonce_commands_reach_the_real_devnet_router_over_tcp() {
    let dev_owner = sunrise_edge_client::LocalSigner::from_seed([0x33; 32]).address();
    let treasury_owner = sunrise_edge_client::LocalSigner::from_seed([0x44; 32]).address();
    let directory = TestDirectory::new();
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("9"),
        OsString::from("--dev-owner"),
        OsString::from(dev_owner.to_string()),
        OsString::from("--fee-treasury-owner"),
        OsString::from(treasury_owner.to_string()),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();
    let boot = boot_local_store(&config).unwrap();
    let generation = boot.boot_generation();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let module = build_asset_module(protocol_context, ASSET_ACCOUNT_WASM.to_vec()).unwrap();
    let (structured_store, blob_store) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(structured_store),
        Arc::new(blob_store),
        module,
        generation,
        config.max_concurrent(),
        config.dev_owners().len(),
        ObjectId::new([0xFE; 32]),
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
    tokio::task::spawn_blocking(move || {
        sunrise_edge_cli::run(vec![
            OsString::from("context"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
        ])
        .expect("context command should succeed against the real devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("next-nonce"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--sender"),
            OsString::from("44".repeat(32)),
        ])
        .expect("next-nonce command should succeed against the real devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("object"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--object-id"),
            OsString::from("45".repeat(32)),
        ])
        .expect("object command should succeed against the real devnet router");
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;
}
