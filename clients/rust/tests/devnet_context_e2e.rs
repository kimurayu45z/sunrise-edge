//! Real TCP E2E from `sunrise-edge-client` through the native HTTP adapter
//! into the composed local devnet query surface.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sunrise_edge_client::{
    Address, Client, HttpObjectQueryResult, HttpReceiptQueryResult, LoopbackHttpTransport,
    ObjectId, RequestId,
};
use sunrise_edge_devnet::{
    ASSET_ACCOUNT_WASM, DevnetConfig, boot_local_store, build_asset_module,
    build_devnet_protocol_context, compose_devnet_router,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence: u64 = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-client-e2e-{}-{sequence}",
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
async fn client_queries_all_four_routes_from_the_real_devnet_router_over_tcp() {
    let directory = TestDirectory::new();
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("client-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("7"),
        OsString::from("--dev-owner"),
        OsString::from("2222222222222222222222222222222222222222222222222222222222222222"),
        OsString::from("--fee-treasury-owner"),
        OsString::from("3333333333333333333333333333333333333333333333333333333333333333"),
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

    let result = tokio::task::spawn_blocking(move || {
        let transport = LoopbackHttpTransport::new(
            address,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(1024 * 1024).unwrap(),
        )
        .unwrap();
        let client = Client::new(transport);
        let context = client.query_context().unwrap();

        let object_id = ObjectId::new([0x41; 32]);
        assert_eq!(
            client.query_object(object_id).unwrap(),
            HttpObjectQueryResult::Absent { object_id }
        );

        let request_id = RequestId::new([0x42; 32]).unwrap();
        assert_eq!(
            client.query_receipt(request_id).unwrap(),
            HttpReceiptQueryResult::Absent { request_id }
        );

        let sender = Address::new([0x43; 32]);
        let nonce = client.query_next_nonce(sender).unwrap();
        assert_eq!(nonce.sender(), sender);
        assert_eq!(nonce.epoch().get(), 7);
        assert_eq!(nonce.next_nonce(), 0);
        context
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;

    assert_eq!(result.chain_id().as_str(), "client-e2e-devnet");
    assert_eq!(result.epoch().get(), 7);
    assert!(!result.protocol_config_bytes().is_empty());
}
