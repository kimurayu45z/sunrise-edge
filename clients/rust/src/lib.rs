#![forbid(unsafe_code)]

//! Sunrise Edge Developer MVP Rust client (ARCHITECTURE.md §44, DR-0083).
//!
//! This is a runtime-neutral library: seed-based Ed25519 key/address
//! handling, canonical Transaction v1 construction and signing, submission
//! with a caller-supplied request id, bounded receipt waiting, and the four
//! bounded query operations (`/v1/context`, `/v1/objects/{object_id}`,
//! `/v1/receipts/{request_id}`, `/v1/senders/{sender}/next-nonce`).
//!
//! It depends on `node-core` and `node-wire` for the canonical wire
//! contract and never on Axum or `native-http`. The provided
//! [`transport::LoopbackHttpTransport`] is a strict, synchronous,
//! loopback-only HTTP/1.1 implementation for local development; the
//! [`transport::Transport`] trait exists so tests and other embedders can
//! supply a deterministic fake instead.
//!
//! This client keeps `ProtocolConfig` bytes opaque, requires the caller to
//! supply module/object references and the active signature scheme, never
//! derives a request id, never recomputes a hash-suite or execution-effects
//! digest, and adds no asset-specific helpers or CLI policy. Those
//! capabilities, production remote transport, keystores, and blob fetch
//! remain deferred (see `ARCHITECTURE.md` §44 / DR-0083).

pub mod client;
pub mod error;
pub mod key;
pub mod transaction;
pub mod transport;

pub use client::{Client, ReceiptPollBounds, SubmitTransactionRequest};
pub use error::ClientError;
pub use key::LocalSigner;
pub use transaction::{TransactionRequest, build_signed_transaction};
pub use transport::{
    LoopbackHttpTransport, Method, Transport, TransportError, WireRequest, WireResponse,
};

// Re-exported for convenience: every `Client` query method returns one of
// these node-wire types, and callers need `RequestId`/`ObjectId`/`Address`
// to call them in the first place.
pub use execution::{
    EventRecord, ExecutionEffects, ExecutionStatus, decode_event_record, decode_execution_effects,
    decode_object_effect,
};
pub use node_core::{NodeCoreError, NodeResponse, NodeResponseStatus, RequestId};
pub use node_wire::{
    HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult,
    HttpReceiptQueryResult, NEXT_NONCE_QUERY_RESULT_TYPE_ID, ObjectQueryStatus, QUERY_CONTEXT_PATH,
    QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH, QUERY_RESULT_MEDIA_TYPE,
    QueryResultError, ReceiptQueryStatus,
};
pub use objects::{Address, ObjectId, ObjectRef};
