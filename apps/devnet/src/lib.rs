#![forbid(unsafe_code)]

//! Local-only Developer MVP devnet foundations.
//!
//! This crate owns strict process configuration, fenced SQLite startup,
//! restart-safe outbox attempt identities, the preinstalled asset-account
//! module/catalog, and idempotent development-account seeding. Its binary
//! composes these pieces into the bounded native HTTP router.

pub mod asset_account;
pub mod boot;
pub mod catalog;
pub mod composition;
pub mod config;
pub mod genesis;
pub mod identities;
pub mod machine;
pub mod seed;
pub mod transport;

pub use asset_account::{
    ASSET_ACCOUNT_WASM, AssetAccount, DEVNET_ASSET_ID, TransferArgs, TransferEvent,
    asset_account_type_hash, decode_asset_account, decode_transfer_args, decode_transfer_event,
    encode_asset_account, encode_transfer_args, encode_transfer_event,
};
pub use boot::{DEVNET_DATABASE_FILE, DevnetBoot, DevnetBootError, boot_local_store};
pub use catalog::{DevnetAssetModule, DevnetCatalogError, build_asset_module};
pub use composition::{DevnetCompositionError, compose_devnet_router};
pub use config::{
    DEVNET_STARTUP_LIMITATIONS_BANNER, DevOwner, DevnetConfig, DevnetConfigError,
    MAX_DEVNET_CONCURRENCY, MAX_DEVNET_OWNERS,
};
pub use genesis::{DevnetGenesisError, DevnetProtocolContext, build_devnet_protocol_context};
pub use identities::DevnetOutboxIdentitySource;
pub use machine::DevnetMachine;
pub use seed::{
    DevnetSeedError, SeedAssetAccountsOutcome, SeededAssetAccounts, seed_asset_accounts,
    verify_seeded_asset_supply,
};
pub use transport::DevnetTransport;
