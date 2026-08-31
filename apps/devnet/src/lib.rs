#![forbid(unsafe_code)]

//! Local-only Developer MVP devnet foundations.
//!
//! This crate currently owns strict process configuration, fenced SQLite
//! startup, and restart-safe outbox attempt identities. The native request
//! composition is intentionally not wired yet.

pub mod boot;
pub mod config;
pub mod identities;

pub use boot::{DEVNET_DATABASE_FILE, DevnetBoot, DevnetBootError, boot_local_store};
pub use config::{DevOwner, DevnetConfig, DevnetConfigError, MAX_DEVNET_CONCURRENCY};
pub use identities::DevnetOutboxIdentitySource;
