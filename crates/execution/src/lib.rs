#![forbid(unsafe_code)]

//! Execution layer: transaction types, execution effects, and the
//! `ExecutionEngine` trait for deterministic contract execution.
//!
//! # Crate overview
//!
//! | Type / Trait                | Purpose                                                  |
//! |-----------------------------|----------------------------------------------------------|
//! | [`Transaction`]             | A canonically encoded, signed execution request.         |
//! | [`ResolvedObject`]          | An object fetched from state for use as execution input. |
//! | [`ExecutionEffects`]        | The deterministic output produced by running a tx.       |
//! | [`ObjectEffect`]            | A single created / mutated / deleted object change.      |
//! | [`EventRecord`]             | An event emitted by a contract.                          |
//! | [`ExecutionStatus`]         | Whether execution succeeded or trapped.                  |
//! | [`ExecutionEngine`]         | Trait implemented by execution back-ends.                |
//! | [`NullExecutionEngine`]     | No-op back-end useful for wiring tests.                  |
//!
//! # Canonical encoding
//!
//! Every protocol-critical type exposes an `encode_*` function that uses the
//! same `CanonicalStruct` framing used throughout the workspace.  Type-id
//! constants in this crate live in the `0x6xxx` namespace.

use abi::{AbiError, AccessManifest, encode_access_manifest};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32};
use core::fmt;
use fees::{FeeError, FeePayment, encode_fee_payment};
use hashing::{BuiltinHashFunction, HashFunction, HashingError};
use objects::{
    AccessMode, Address, Object, ObjectId, ObjectRef, encode_object, encode_object_id,
    encode_object_ref,
};
use protocol_types::{ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion};
use std::error::Error;

// ── type-id constants ──────────────────────────────────────────────────────

const TRANSACTION_TYPE_ID: u16 = 0x6001;
const EVENT_RECORD_TYPE_ID: u16 = 0x6002;
const OBJECT_EFFECT_TYPE_ID: u16 = 0x6003;
const EXECUTION_EFFECTS_TYPE_ID: u16 = 0x6004;
const OBJECT_EFFECTS_LIST_TYPE_ID: u16 = 0x6005;
const EVENT_RECORDS_LIST_TYPE_ID: u16 = 0x6006;
const ENCODING_VERSION: u16 = 1;

// ── error type ────────────────────────────────────────────────────────────

/// Errors produced by the execution crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// ABI encoding failed.
    Abi(AbiError),
    /// Object encoding failed.
    Object(objects::ObjectError),
    /// Hashing failed.
    Hashing(HashingError),
    /// Fee payment encoding failed.
    Fee(FeeError),
    /// The transaction entrypoint name must not be empty.
    EmptyEntrypoint,
    /// The transaction must carry a non-empty signature.
    EmptySignature,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::Abi(e) => write!(f, "abi error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
            Self::Hashing(e) => write!(f, "hashing error: {e}"),
            Self::Fee(e) => write!(f, "fee error: {e}"),
            Self::EmptyEntrypoint => write!(f, "transaction entrypoint must not be empty"),
            Self::EmptySignature => write!(f, "transaction signature must not be empty"),
        }
    }
}

impl Error for ExecutionError {}

impl From<CanonicalEncodingError> for ExecutionError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<AbiError> for ExecutionError {
    fn from(value: AbiError) -> Self {
        Self::Abi(value)
    }
}

impl From<objects::ObjectError> for ExecutionError {
    fn from(value: objects::ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<HashingError> for ExecutionError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<FeeError> for ExecutionError {
    fn from(value: FeeError) -> Self {
        Self::Fee(value)
    }
}

// ── Transaction ───────────────────────────────────────────────────────────

/// A signed, canonically encodable execution request.
///
/// Before execution the validator verifies:
///
/// 1. `chain_id`, `protocol_version`, and `epoch` match the active context.
/// 2. The sender `signature` over the canonical transaction encoding is valid.
/// 3. The `access_manifest` covers every object the contract will touch.
/// 4. The `module_ref` points to a known WASM module object.
/// 5. `gas_limit` does not exceed the per-transaction protocol maximum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Chain replay protection identifier.
    pub chain_id: ChainId,
    /// Protocol version replay protection.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay protection.
    pub epoch: Epoch,
    /// Address of the transaction sender.
    pub sender: Address,
    /// Sender nonce for intra-epoch replay protection.
    pub nonce: u64,
    /// All objects the transaction may access, with their access modes.
    pub access_manifest: AccessManifest,
    /// Reference to the WASM module object that will be executed.
    pub module_ref: ObjectRef,
    /// Entry-point function to invoke inside the module.
    pub entrypoint: String,
    /// Canonically encoded arguments passed to the entry-point.
    pub args: Vec<u8>,
    /// Maximum gas units the sender is willing to spend.
    pub gas_limit: u64,
    /// Stablecoin-denominated fee payment authorization.
    pub fee_payment: Option<FeePayment>,
    /// Sender signature over the canonical transaction payload (fields 1-10 plus fee payment).
    pub signature: Vec<u8>,
}

/// Encodes a [`Transaction`] in the canonical wire format.
///
/// The signature field is included so that the full signed payload
/// is preserved in storage and transmitted over the network.
pub fn encode_transaction(tx: &Transaction) -> Result<Vec<u8>, ExecutionError> {
    if tx.entrypoint.is_empty() {
        return Err(ExecutionError::EmptyEntrypoint);
    }
    if tx.signature.is_empty() {
        return Err(ExecutionError::EmptySignature);
    }

    let mut canonical = CanonicalStruct::new(TRANSACTION_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, tx.chain_id.as_str())?;
    canonical.field_u32(2, tx.protocol_version.get())?;
    canonical.field_u64(3, tx.epoch.get())?;
    canonical.field_bytes(4, tx.sender.as_bytes())?;
    canonical.field_u64(5, tx.nonce)?;
    canonical.field_bytes(6, encode_access_manifest(&tx.access_manifest)?)?;
    canonical.field_bytes(7, encode_object_ref(&tx.module_ref)?)?;
    canonical.field_str(8, &tx.entrypoint)?;
    canonical.field_bytes(9, tx.args.as_slice())?;
    canonical.field_u64(10, tx.gas_limit)?;
    if let Some(fee_payment) = &tx.fee_payment {
        canonical.field_bytes(11, encode_fee_payment(fee_payment)?)?;
    }
    canonical.field_bytes(12, tx.signature.as_slice())?;
    Ok(canonical.finish()?)
}

/// Encodes the *signable* portion of a transaction (everything except the
/// signature field) and returns it as a canonical byte vector.
///
/// Validators and clients must sign and verify this payload, not the full
/// encoded transaction.
pub fn encode_transaction_signable(tx: &Transaction) -> Result<Vec<u8>, ExecutionError> {
    if tx.entrypoint.is_empty() {
        return Err(ExecutionError::EmptyEntrypoint);
    }

    let mut canonical = CanonicalStruct::new(TRANSACTION_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, tx.chain_id.as_str())?;
    canonical.field_u32(2, tx.protocol_version.get())?;
    canonical.field_u64(3, tx.epoch.get())?;
    canonical.field_bytes(4, tx.sender.as_bytes())?;
    canonical.field_u64(5, tx.nonce)?;
    canonical.field_bytes(6, encode_access_manifest(&tx.access_manifest)?)?;
    canonical.field_bytes(7, encode_object_ref(&tx.module_ref)?)?;
    canonical.field_str(8, &tx.entrypoint)?;
    canonical.field_bytes(9, tx.args.as_slice())?;
    canonical.field_u64(10, tx.gas_limit)?;
    if let Some(fee_payment) = &tx.fee_payment {
        canonical.field_bytes(11, encode_fee_payment(fee_payment)?)?;
    }
    Ok(canonical.finish()?)
}

/// Hashes the *signable* transaction payload using the supplied hash suite
/// algorithm for the `Transaction` purpose.
///
/// The resulting digest can be used as the authoritative transaction hash
/// (`tx_hash`) included in votes and certificates.
pub fn hash_transaction(
    tx: &Transaction,
    algorithm: protocol_types::HashAlgorithmId,
) -> Result<Digest32, ExecutionError> {
    let signable = encode_transaction_signable(tx)?;
    let hasher = BuiltinHashFunction::new(algorithm);
    Ok(hasher.hash(
        HashPurpose::Transaction,
        tx.protocol_version,
        &tx.chain_id,
        &signable,
    )?)
}

// ── ResolvedObject ────────────────────────────────────────────────────────

/// An object fetched from state for use as an execution input.
///
/// The execution engine receives a slice of `ResolvedObject`s that correspond
/// 1-to-1 with the entries in the transaction's [`AccessManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedObject {
    /// The full object loaded from persistent state.
    pub object: Object,
    /// The access mode declared in the manifest for this object.
    pub mode: AccessMode,
}

// ── EventRecord ────────────────────────────────────────────────────────────

/// An event emitted by a contract during execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    /// A type tag identifying the event schema.
    pub type_tag: Vec<u8>,
    /// Canonically encoded event data.
    pub data: Vec<u8>,
}

/// Encodes an [`EventRecord`] in the canonical wire format.
pub fn encode_event_record(event: &EventRecord) -> Result<Vec<u8>, ExecutionError> {
    let mut canonical = CanonicalStruct::new(EVENT_RECORD_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, event.type_tag.as_slice())?;
    canonical.field_bytes(2, event.data.as_slice())?;
    Ok(canonical.finish()?)
}

// ── ObjectEffect ──────────────────────────────────────────────────────────

/// A single object-level change produced by execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectEffect {
    /// The execution created a new object.
    Created(Object),
    /// The execution mutated an existing object.
    Mutated {
        /// The version of the object before this mutation.
        previous_version: u64,
        /// The new state of the object after mutation.
        new_object: Object,
    },
    /// The execution deleted / consumed an object.
    Deleted {
        /// The identifier of the deleted object.
        id: ObjectId,
        /// The version that was deleted.
        version: u64,
    },
}

impl ObjectEffect {
    const fn tag(&self) -> u8 {
        match self {
            Self::Created(_) => 1,
            Self::Mutated { .. } => 2,
            Self::Deleted { .. } => 3,
        }
    }
}

/// Encodes an [`ObjectEffect`] in the canonical wire format.
pub fn encode_object_effect(effect: &ObjectEffect) -> Result<Vec<u8>, ExecutionError> {
    let mut canonical = CanonicalStruct::new(OBJECT_EFFECT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, [effect.tag()])?;
    match effect {
        ObjectEffect::Created(object) => {
            canonical.field_bytes(2, encode_object(object)?)?;
        }
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        } => {
            canonical.field_u64(2, *previous_version)?;
            canonical.field_bytes(3, encode_object(new_object)?)?;
        }
        ObjectEffect::Deleted { id, version } => {
            canonical.field_bytes(2, encode_object_id(id)?)?;
            canonical.field_u64(3, *version)?;
        }
    }
    Ok(canonical.finish()?)
}

// ── ExecutionStatus ───────────────────────────────────────────────────────

/// The outcome of an execution attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Execution completed without trapping.
    Success,
    /// Execution trapped with the provided reason string.
    Failure {
        /// Human-readable trap reason for debugging.
        reason: String,
    },
}

impl ExecutionStatus {
    const fn tag(&self) -> u8 {
        match self {
            Self::Success => 1,
            Self::Failure { .. } => 2,
        }
    }
}

// ── ExecutionEffects ──────────────────────────────────────────────────────

/// The complete, deterministic output produced by executing one transaction.
///
/// This is the artifact that validators sign and include in fast-path votes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionEffects {
    /// Hash of the transaction that produced these effects.
    pub tx_hash: Digest32,
    /// Whether execution succeeded or trapped.
    pub status: ExecutionStatus,
    /// All object-level changes (in deterministic order).
    pub object_effects: Vec<ObjectEffect>,
    /// All events emitted by the contract (in emission order).
    pub events: Vec<EventRecord>,
    /// Actual gas consumed by execution.
    pub gas_used: u64,
}

/// Encodes [`ExecutionEffects`] in the canonical wire format.
///
/// Object effects are gathered into a nested list struct (type `0x6005`) and
/// events into a separate nested list struct (type `0x6006`), both stored as
/// fixed fields in the outer struct.  This ensures the field-id space is
/// unambiguous regardless of how many effects or events are present.
pub fn encode_execution_effects(effects: &ExecutionEffects) -> Result<Vec<u8>, ExecutionError> {
    const MAX_ITEMS: usize = u16::MAX as usize - 1;

    if effects.object_effects.len() > MAX_ITEMS {
        return Err(ExecutionError::CanonicalEncoding(
            CanonicalEncodingError::TooManyFields(effects.object_effects.len()),
        ));
    }
    if effects.events.len() > MAX_ITEMS {
        return Err(ExecutionError::CanonicalEncoding(
            CanonicalEncodingError::TooManyFields(effects.events.len()),
        ));
    }

    // Encode the object-effects collection as a self-contained nested struct.
    let mut effects_list = CanonicalStruct::new(OBJECT_EFFECTS_LIST_TYPE_ID, ENCODING_VERSION);
    effects_list.field_u32(1, effects.object_effects.len() as u32)?;
    for (index, effect) in effects.object_effects.iter().enumerate() {
        let field_id = (2 + index) as u16;
        effects_list.field_bytes(field_id, encode_object_effect(effect)?)?;
    }
    let effects_list_bytes = effects_list.finish()?;

    // Encode the events collection as a self-contained nested struct.
    let mut events_list = CanonicalStruct::new(EVENT_RECORDS_LIST_TYPE_ID, ENCODING_VERSION);
    events_list.field_u32(1, effects.events.len() as u32)?;
    for (index, event) in effects.events.iter().enumerate() {
        let field_id = (2 + index) as u16;
        events_list.field_bytes(field_id, encode_event_record(event)?)?;
    }
    let events_list_bytes = events_list.finish()?;

    let mut canonical = CanonicalStruct::new(EXECUTION_EFFECTS_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_digest32(&effects.tx_hash)?)?;
    canonical.field_bytes(2, [effects.status.tag()])?;
    if let ExecutionStatus::Failure { reason } = &effects.status {
        canonical.field_str(3, reason.as_str())?;
    }
    canonical.field_u64(4, effects.gas_used)?;
    canonical.field_bytes(5, effects_list_bytes)?;
    canonical.field_bytes(6, events_list_bytes)?;
    Ok(canonical.finish()?)
}

/// Hashes the canonical encoding of [`ExecutionEffects`] for the
/// `ExecutionEffects` purpose.
///
/// Validators include this digest in their votes.
pub fn hash_execution_effects(
    effects: &ExecutionEffects,
    algorithm: protocol_types::HashAlgorithmId,
    protocol_version: ProtocolVersion,
    chain_id: &ChainId,
) -> Result<Digest32, ExecutionError> {
    let encoded = encode_execution_effects(effects)?;
    let hasher = BuiltinHashFunction::new(algorithm);
    Ok(hasher.hash(
        HashPurpose::ExecutionEffects,
        protocol_version,
        chain_id,
        &encoded,
    )?)
}

// ── ExecutionEngine ───────────────────────────────────────────────────────

/// A deterministic execution back-end.
///
/// Implementations must be deterministic: given the same inputs they must
/// always produce the same [`ExecutionEffects`].  The `tx_hash` inside the
/// effects must match the hash of the submitted transaction.
pub trait ExecutionEngine {
    /// Executes a module entry-point with the provided resolved inputs.
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        protocol_version: ProtocolVersion,
        tx_hash: Digest32,
        module: &[u8],
        entrypoint: &str,
        inputs: &[ResolvedObject],
        args: &[u8],
        gas_limit: u64,
    ) -> Result<ExecutionEffects, ExecutionError>;
}

// ── NullExecutionEngine ───────────────────────────────────────────────────

/// A no-op [`ExecutionEngine`] that always returns an empty success.
///
/// Useful for wiring tests where actual WASM execution is not needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullExecutionEngine;

impl ExecutionEngine for NullExecutionEngine {
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        _protocol_version: ProtocolVersion,
        tx_hash: Digest32,
        _module: &[u8],
        _entrypoint: &str,
        _inputs: &[ResolvedObject],
        _args: &[u8],
        _gas_limit: u64,
    ) -> Result<ExecutionEffects, ExecutionError> {
        Ok(ExecutionEffects {
            tx_hash,
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 0,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{AccessEntry, AccessManifest};
    use fees::{Amount, AssetId, FeePayment};
    use objects::{AccessMode, Address, ObjectId, ObjectRef, Owner};
    use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion};

    fn sample_chain_id() -> ChainId {
        ChainId::new("sunrise-devnet").unwrap()
    }

    fn sample_protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(1)
    }

    fn sample_digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn sample_object_ref(id_byte: u8, version: u64) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version,
            digest: sample_digest(id_byte),
        }
    }

    fn sample_fee_payment() -> FeePayment {
        FeePayment {
            asset_id: AssetId::new([0xEE; 32]),
            max_fee: Amount::new(250),
            fee_object: sample_object_ref(0xEF, 3),
        }
    }

    fn sample_object(id_byte: u8, version: u64) -> Object {
        Object {
            id: ObjectId::new([id_byte; 32]),
            version,
            owner: Owner::Shared,
            type_hash: sample_digest(0xAA),
            schema_version: 1,
            data: vec![id_byte; 8],
        }
    }

    fn sample_transaction() -> Transaction {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x11, 1),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x22, 2),
            mode: AccessMode::Write,
        });

        Transaction {
            chain_id: sample_chain_id(),
            protocol_version: sample_protocol_version(),
            epoch: Epoch::new(5),
            sender: Address::new([0xCC; 32]),
            nonce: 42,
            access_manifest: manifest,
            module_ref: sample_object_ref(0xDD, 7),
            entrypoint: "transfer".to_string(),
            args: vec![1, 2, 3, 4],
            gas_limit: 100_000,
            fee_payment: Some(sample_fee_payment()),
            signature: vec![0xFF; 64],
        }
    }

    // ── transaction encoding ──────────────────────────────────────────────

    #[test]
    fn transaction_encodes_deterministically() {
        let tx = sample_transaction();
        let left = encode_transaction(&tx).unwrap();
        let right = encode_transaction(&tx).unwrap();
        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn signable_payload_differs_from_full_transaction() {
        let tx = sample_transaction();
        let full = encode_transaction(&tx).unwrap();
        let signable = encode_transaction_signable(&tx).unwrap();
        assert_ne!(full, signable);
    }

    #[test]
    fn fee_payment_affects_transaction_encoding() {
        let mut with_fee = sample_transaction();
        let mut without_fee = sample_transaction();
        without_fee.fee_payment = None;

        assert_ne!(
            encode_transaction(&with_fee).unwrap(),
            encode_transaction(&without_fee).unwrap()
        );
        with_fee.fee_payment = None;
        assert_eq!(
            encode_transaction_signable(&with_fee).unwrap(),
            encode_transaction_signable(&without_fee).unwrap()
        );
    }

    #[test]
    fn empty_entrypoint_is_rejected() {
        let mut tx = sample_transaction();
        tx.entrypoint = String::new();
        assert_eq!(
            encode_transaction(&tx),
            Err(ExecutionError::EmptyEntrypoint)
        );
    }

    #[test]
    fn empty_signature_is_rejected() {
        let mut tx = sample_transaction();
        tx.signature = vec![];
        assert_eq!(encode_transaction(&tx), Err(ExecutionError::EmptySignature));
    }

    #[test]
    fn different_transactions_produce_different_encodings() {
        let tx1 = sample_transaction();
        let mut tx2 = sample_transaction();
        tx2.nonce = 43;
        assert_ne!(
            encode_transaction(&tx1).unwrap(),
            encode_transaction(&tx2).unwrap()
        );
    }

    // ── transaction hashing ───────────────────────────────────────────────

    #[test]
    fn transaction_hash_is_deterministic() {
        let tx = sample_transaction();
        let h1 = hash_transaction(&tx, HashAlgorithmId::Sha2_256).unwrap();
        let h2 = hash_transaction(&tx, HashAlgorithmId::Sha2_256).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_algorithm_produces_different_hash() {
        let tx = sample_transaction();
        let sha2 = hash_transaction(&tx, HashAlgorithmId::Sha2_256).unwrap();
        let sha3 = hash_transaction(&tx, HashAlgorithmId::Sha3_256).unwrap();
        assert_ne!(sha2, sha3);
        assert_eq!(sha2.algorithm(), HashAlgorithmId::Sha2_256);
        assert_eq!(sha3.algorithm(), HashAlgorithmId::Sha3_256);
    }

    #[test]
    fn modified_transaction_produces_different_hash() {
        let tx1 = sample_transaction();
        let mut tx2 = sample_transaction();
        tx2.nonce = 99;
        let h1 = hash_transaction(&tx1, HashAlgorithmId::Sha2_256).unwrap();
        let h2 = hash_transaction(&tx2, HashAlgorithmId::Sha2_256).unwrap();
        assert_ne!(h1, h2);
    }

    // ── event record ─────────────────────────────────────────────────────

    #[test]
    fn event_record_encodes_deterministically() {
        let event = EventRecord {
            type_tag: b"transfer".to_vec(),
            data: vec![1, 2, 3],
        };
        let left = encode_event_record(&event).unwrap();
        let right = encode_event_record(&event).unwrap();
        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn different_events_produce_different_encodings() {
        let e1 = EventRecord {
            type_tag: b"mint".to_vec(),
            data: vec![1],
        };
        let e2 = EventRecord {
            type_tag: b"burn".to_vec(),
            data: vec![1],
        };
        assert_ne!(
            encode_event_record(&e1).unwrap(),
            encode_event_record(&e2).unwrap()
        );
    }

    // ── object effect ─────────────────────────────────────────────────────

    #[test]
    fn object_effect_created_encodes_deterministically() {
        let effect = ObjectEffect::Created(sample_object(0x01, 1));
        let left = encode_object_effect(&effect).unwrap();
        let right = encode_object_effect(&effect).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn object_effect_mutated_encodes_deterministically() {
        let effect = ObjectEffect::Mutated {
            previous_version: 1,
            new_object: sample_object(0x02, 2),
        };
        let left = encode_object_effect(&effect).unwrap();
        let right = encode_object_effect(&effect).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn object_effect_deleted_encodes_deterministically() {
        let effect = ObjectEffect::Deleted {
            id: ObjectId::new([0x03; 32]),
            version: 5,
        };
        let left = encode_object_effect(&effect).unwrap();
        let right = encode_object_effect(&effect).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn object_effect_variants_produce_different_encodings() {
        let created = ObjectEffect::Created(sample_object(0x01, 1));
        let mutated = ObjectEffect::Mutated {
            previous_version: 1,
            new_object: sample_object(0x01, 2),
        };
        let deleted = ObjectEffect::Deleted {
            id: ObjectId::new([0x01; 32]),
            version: 1,
        };
        let c = encode_object_effect(&created).unwrap();
        let m = encode_object_effect(&mutated).unwrap();
        let d = encode_object_effect(&deleted).unwrap();
        assert_ne!(c, m);
        assert_ne!(m, d);
        assert_ne!(c, d);
    }

    // ── execution effects ────────────────────────────────────────────────

    fn sample_effects(tx_hash: Digest32) -> ExecutionEffects {
        ExecutionEffects {
            tx_hash,
            status: ExecutionStatus::Success,
            object_effects: vec![
                ObjectEffect::Mutated {
                    previous_version: 1,
                    new_object: sample_object(0x11, 2),
                },
                ObjectEffect::Created(sample_object(0x33, 1)),
            ],
            events: vec![EventRecord {
                type_tag: b"transfer".to_vec(),
                data: vec![0xDE, 0xAD],
            }],
            gas_used: 5_000,
        }
    }

    #[test]
    fn execution_effects_encode_deterministically() {
        let tx = sample_transaction();
        let tx_hash = hash_transaction(&tx, HashAlgorithmId::Sha2_256).unwrap();
        let effects = sample_effects(tx_hash);

        let left = encode_execution_effects(&effects).unwrap();
        let right = encode_execution_effects(&effects).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn failed_effects_encode_differently_than_success() {
        let tx_hash = sample_digest(0xAB);
        let success = ExecutionEffects {
            tx_hash,
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 0,
        };
        let failure = ExecutionEffects {
            tx_hash,
            status: ExecutionStatus::Failure {
                reason: "out of gas".to_string(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 100_000,
        };
        assert_ne!(
            encode_execution_effects(&success).unwrap(),
            encode_execution_effects(&failure).unwrap()
        );
    }

    #[test]
    fn execution_effects_hash_is_deterministic() {
        let tx_hash = sample_digest(0x01);
        let effects = sample_effects(tx_hash);

        let h1 = hash_execution_effects(
            &effects,
            HashAlgorithmId::Sha2_256,
            sample_protocol_version(),
            &sample_chain_id(),
        )
        .unwrap();
        let h2 = hash_execution_effects(
            &effects,
            HashAlgorithmId::Sha2_256,
            sample_protocol_version(),
            &sample_chain_id(),
        )
        .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.algorithm(), HashAlgorithmId::Sha2_256);
    }

    // ── NullExecutionEngine ───────────────────────────────────────────────

    #[test]
    fn null_engine_returns_success_with_no_effects() {
        let engine = NullExecutionEngine;
        let tx_hash = sample_digest(0xFF);
        let effects = engine
            .execute(
                sample_protocol_version(),
                tx_hash,
                b"fake-wasm",
                "entry",
                &[],
                &[],
                50_000,
            )
            .unwrap();
        assert_eq!(effects.tx_hash, tx_hash);
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert!(effects.object_effects.is_empty());
        assert!(effects.events.is_empty());
        assert_eq!(effects.gas_used, 0);
    }

    #[test]
    fn null_engine_is_deterministic() {
        let engine = NullExecutionEngine;
        let tx_hash = sample_digest(0x10);
        let e1 = engine
            .execute(sample_protocol_version(), tx_hash, b"", "noop", &[], &[], 0)
            .unwrap();
        let e2 = engine
            .execute(sample_protocol_version(), tx_hash, b"", "noop", &[], &[], 0)
            .unwrap();
        assert_eq!(e1, e2);
    }

    // ── stable encoding vector ────────────────────────────────────────────

    /// Regression guard: the canonical encoding of a minimal transaction must
    /// not change across versions.
    #[test]
    fn transaction_stable_encoding_vector() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x11, 1),
            mode: AccessMode::Read,
        });

        let tx = Transaction {
            chain_id: ChainId::new("test-chain").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            sender: Address::new([0xAA; 32]),
            nonce: 1,
            access_manifest: manifest,
            module_ref: sample_object_ref(0xBB, 1),
            entrypoint: "run".to_string(),
            args: vec![],
            gas_limit: 1_000,
            fee_payment: Some(FeePayment {
                asset_id: AssetId::new([0xCC; 32]),
                max_fee: Amount::new(9),
                fee_object: sample_object_ref(0xDD, 2),
            }),
            signature: vec![0x01; 32],
        };

        let encoded = encode_transaction(&tx).unwrap();
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();

        // Snapshot – must not change between releases.
        assert_eq!(
            hex,
            "534e5245016001000c0001000a000000746573742d636861696e020004000000010000000300080000000000000000000000040020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05000800000001000000000000000600cd000000534e5245025001000200010004000000010000000200b3000000534e524501500100020001008c000000534e5245044001000300010030000000534e524501400100010001002000000011111111111111111111111111111111111111111111111111111111111111110200080000000100000000000000030038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111020011000000534e52450640010001000100010000000107008c000000534e5245044001000300010030000000534e5245014001000100010020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb08000300000072756e0900000000000a0008000000e8030000000000000b00e0000000534e5245027001000300010030000000534e5245017001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc020008000000090000000000000003008c000000534e5245044001000300010030000000534e5245014001000100010020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd0c00200000000101010101010101010101010101010101010101010101010101010101010101"
        );
    }
}
