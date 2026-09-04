#![forbid(unsafe_code)]

//! Sunrise Edge Developer MVP Rust client (ARCHITECTURE.md §44, DR-0083,
//! DR-0084).
//!
//! This is a runtime-neutral library: seed-based Ed25519 key/address
//! handling, canonical Transaction v1 construction and signing through a
//! safe two-stage external-signer API
//! ([`transaction::PreparedTransaction`]), submission with a
//! caller-supplied request id, bounded receipt waiting, and the four bounded
//! query operations (`/v1/context`, `/v1/objects/{object_id}`,
//! `/v1/receipts/{request_id}`, `/v1/senders/{sender}/next-nonce`).
//!
//! It depends on `node-core` and `node-wire` for the canonical wire
//! contract and never on Axum or `native-http`. The provided
//! [`transport::LoopbackHttpTransport`] is a strict, synchronous,
//! loopback-only plaintext HTTP/1.1 implementation for local development;
//! [`transport::RemoteTlsHttpTransport`] is this crate's `CLI-First Node
//! Production Gate` S1 remote transport slice (see `ARCHITECTURE.md`
//! DR-0085): a strict, synchronous HTTP/1.1-over-TLS implementation that
//! shares the identical request/response framing but requires an explicit
//! DNS server name and CA trust anchor and performs normal TLS
//! server-identity and hostname validation instead of trusting loopback. The
//! [`transport::Transport`] trait exists so tests and other embedders can
//! supply a deterministic fake instead.
//!
//! [`context::ExpectedProtocolContext`] implements that same S1 slice's
//! other, separate concern: a mandatory, locally trusted expected-
//! protocol-context check ([`Client::query_verified_context`]) that a
//! caller must perform before any nonce/object query or signing, since a
//! successful transport connection — including the implemented remote TLS one — proves
//! only that the client reached some server holding a trusted key for that
//! hostname, never that it is the caller's intended chain/protocol.
//!
//! This client keeps `ProtocolConfig` bytes opaque, requires the caller to
//! supply module/object references and the active signature scheme, never
//! derives a request id, never recomputes a hash-suite or execution-effects
//! digest, and adds no asset-specific helpers or CLI policy. Those
//! capabilities, general-purpose DNS/root-store/mTLS transport expansion, and
//! blob fetch remain deferred (see `ARCHITECTURE.md` §44 / DR-0083).
//! [`key::LocalSigner`] is
//! an explicit development-only, in-memory key, never a keystore; real
//! external/hardware signing remains outside this vendor-neutral crate.
//! S4c Phase 1's dedicated Ledger host adapter now lives downstream in
//! `clients/ledger` (see `ARCHITECTURE.md` DR-0092), depending on this crate
//! rather than reversing the dependency. [`transaction::PreparedTransaction`]
//! exposes exactly the bytes such an external signer needs and independently
//! verifies whatever signature comes back before producing output, preserving
//! the local signing path and this crate's vendor independence.

pub mod client;
pub mod context;
pub mod error;
pub mod key;
pub mod support;
pub mod transaction;
pub mod transport;

pub use client::{Client, ReceiptPollBounds, SubmitTransactionRequest};
pub use context::{ExpectedProtocolContext, ExpectedProtocolContextError, ProtocolContextMismatch};
pub use error::ClientError;
pub use key::LocalSigner;
pub use signing_view::{
    ClearSigningPolicy, ClearSigningPolicyError, ClearSigningView, DEVNET_ASSET_TRANSFER_POLICY,
    DeviceSigningProfile, SigningViewError,
};
pub use support::{
    ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID, ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
    current_inline_object_ref,
};
pub use transaction::{
    ExternalSigner, PreparedTransaction, TransactionRequest, build_signed_transaction,
};
pub use transport::{
    LoopbackHttpTransport, MAX_CA_CERTIFICATE_DER_BYTES, Method, RemoteTlsHttpTransport, Transport,
    TransportError, WireRequest, WireResponse,
};

// Re-exported for convenience: every `Client` query method returns one of
// these node-wire types, and callers need `RequestId`/`ObjectId`/`Address`
// to call them in the first place.
pub use execution::{
    EventRecord, ExecutionEffects, ExecutionStatus, ObjectEffect, decode_event_record,
    decode_execution_effects, decode_object_effect,
};
pub use node_core::{NodeCoreError, NodeResponse, NodeResponseStatus, RequestId};
pub use node_wire::{
    HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult,
    HttpReceiptQueryResult, NEXT_NONCE_QUERY_RESULT_TYPE_ID, NODE_RESULT_MEDIA_TYPE,
    ObjectQueryStatus, QUERY_CONTEXT_PATH, QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH,
    QUERY_RECEIPT_PATH, QUERY_RESULT_MEDIA_TYPE, QueryResultError, ReceiptQueryStatus,
};
pub use objects::{
    AccessMode, Address, Object, ObjectError, ObjectId, ObjectRef, Owner, decode_object,
};

// Re-exported so `apps/cli` (and other application-specific consumers) can
// build a `TransactionRequest`'s access manifest and canonical argument
// frames without a direct dependency on any lower protocol crate. `abi` and
// `canonical-encoding` are foundational, dependency-light crates this client
// already depends on for its own construction/signing path; re-exporting a
// handful of their generic types here is the "smallest generic client
// surface" carve-out from `ARCHITECTURE.md` §44 / DR-0083 and DR-0084 — it
// adds no devnet or other application-specific semantics.
pub use abi::{AccessEntry, AccessManifest};
pub use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
pub use fees::{Amount, AssetId, FeePayment};
pub use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, HashSuiteId, ProtocolVersion,
    SignatureSchemeId, TypeError,
};
