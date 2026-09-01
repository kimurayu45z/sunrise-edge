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
//! | [`WasmExecutionEngine`]     | Deterministic WASM back-end built on `wasmi`.            |
//! | [`ExecutionProof`]          | Self-describing proof envelope for execution results.    |
//!
//! # Canonical encoding
//!
//! Every protocol-critical type exposes an `encode_*` function that uses the
//! same `CanonicalStruct` framing used throughout the workspace.  Type-id
//! constants in this crate live in the `0x6xxx` namespace.

use abi::{AbiError, AccessManifest, decode_access_manifest, encode_access_manifest};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32,
};
use core::fmt;
use fees::{FeeError, FeePayment, decode_fee_payment, encode_fee_payment};
use hashing::{HashSuiteResolver, HashingError};
use objects::{
    AccessMode, Address, Object, ObjectId, ObjectRef, decode_object, decode_object_id,
    decode_object_ref, encode_object, encode_object_id, encode_object_ref,
};
use protocol_types::{ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion, TypeError};
use std::error::Error;

// ── type-id constants ──────────────────────────────────────────────────────

const TRANSACTION_TYPE_ID: u16 = 0x6001;
const EVENT_RECORD_TYPE_ID: u16 = 0x6002;
const OBJECT_EFFECT_TYPE_ID: u16 = 0x6003;
const EXECUTION_EFFECTS_TYPE_ID: u16 = 0x6004;
const OBJECT_EFFECTS_LIST_TYPE_ID: u16 = 0x6005;
const EVENT_RECORDS_LIST_TYPE_ID: u16 = 0x6006;
const ENCODING_VERSION: u16 = 1;

// ── transaction decode resource bounds ──────────────────────────────────────
//
// A [`Transaction`] is decoded directly from untrusted sender input, before
// any fee or gas check runs. These bounds are deliberately tighter than the
// shared 32 MiB canonical frame bound
// (`canonical_encoding::MAX_CANONICAL_FRAME_BYTES`), which they reuse for
// every nested frame rather than duplicate.

/// Maximum byte length of a decoded transaction's `chain_id` string.
///
/// Matches the conservative bound `node-core` already applies to a
/// `NodeEvent`'s chain identifier.
pub const MAX_TRANSACTION_CHAIN_ID_BYTES: usize = 128;
/// Maximum byte length of a decoded transaction's `entrypoint` name.
///
/// WASM export names are short identifiers, not attacker-sized payloads.
pub const MAX_TRANSACTION_ENTRYPOINT_BYTES: usize = 256;
/// Maximum byte length of a decoded transaction's `args` payload.
///
/// Matches the bound the WASM engine already enforces on argument bytes
/// (`wasm_engine::MAX_ARGS_BYTES`), so a transaction that would be rejected
/// at execution time is also rejected at decode time.
pub const MAX_TRANSACTION_ARGS_BYTES: usize = 1024 * 1024;
/// Maximum byte length of a decoded transaction's `signature` field.
///
/// No implemented signature scheme in this workspace produces anything
/// close to this size; it exists to bound an attacker-supplied length
/// before the bytes are copied.
pub const MAX_TRANSACTION_SIGNATURE_BYTES: usize = 4_096;
/// Maximum number of [`abi::AccessEntry`] entries a decoded transaction's
/// [`AccessManifest`] may declare.
///
/// Matches the object-list bounds already used elsewhere in the workspace
/// for a single transaction/invocation (for example
/// `wasm_engine::MAX_INPUT_OBJECTS` and `runtime::MAX_ATOMIC_STATE_READS`).
pub const MAX_TRANSACTION_MANIFEST_ENTRIES: usize = 4_096;

// ── error type ────────────────────────────────────────────────────────────

/// Errors produced by the execution crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// ABI encoding or decoding failed.
    Abi(AbiError),
    /// Object encoding or decoding failed.
    Object(objects::ObjectError),
    /// Hashing failed.
    Hashing(HashingError),
    /// Fee payment encoding or decoding failed.
    Fee(FeeError),
    /// A decoded protocol identifier failed validation.
    ProtocolType(TypeError),
    /// The transaction entrypoint name must not be empty.
    EmptyEntrypoint,
    /// The transaction must carry a non-empty signature.
    EmptySignature,
    /// A decoded transaction's field exceeded its deterministic resource
    /// bound.
    TransactionFieldTooLarge {
        /// Name of the oversized field.
        field: &'static str,
        /// Actual byte or item length.
        actual: usize,
        /// Maximum permitted byte or item length.
        maximum: usize,
    },
    /// Re-encoding a decoded transaction did not reproduce its input bytes,
    /// meaning the input was not the unique canonical encoding of its value.
    NonCanonicalTransactionEncoding,
    /// The WASM engine raised an error (module parse, instantiation, or trap).
    WasmEngine(String),
    /// The requested entry-point function was not found in the WASM module.
    MissingEntrypoint(String),
    /// An object at the maximum version cannot be mutated again.
    ObjectVersionOverflow(ObjectId),
    /// A transaction's chain does not match the selected hash-suite resolver.
    HashChainMismatch,
    /// A transaction's protocol version does not match the selected resolver.
    HashProtocolVersionMismatch {
        /// Version carried by the transaction.
        transaction: ProtocolVersion,
        /// Version bound to the resolver.
        resolver: ProtocolVersion,
    },
    /// A deterministic execution resource limit was exceeded.
    ResourceLimitExceeded(&'static str),
    /// A decoded `ExecutionStatus` tag was not `1` (success) or `2` (failure).
    UnknownExecutionStatusTag(u8),
    /// A decoded `ObjectEffect` tag was not `1` (created), `2` (mutated), or
    /// `3` (deleted).
    UnknownObjectEffectTag(u8),
    /// A decoded object-effects list declared more entries than the encoder
    /// permits.
    TooManyObjectEffects(usize),
    /// A decoded event-records list declared more entries than the encoder
    /// permits.
    TooManyEvents(usize),
    /// Re-encoding a decoded `ExecutionEffects` did not reproduce its input
    /// bytes, meaning the input was not the unique canonical encoding of its
    /// value.
    NonCanonicalExecutionEffectsEncoding,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::CanonicalDecoding(e) => write!(f, "canonical decoding error: {e}"),
            Self::Abi(e) => write!(f, "abi error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
            Self::Hashing(e) => write!(f, "hashing error: {e}"),
            Self::Fee(e) => write!(f, "fee error: {e}"),
            Self::ProtocolType(e) => write!(f, "protocol type error: {e}"),
            Self::EmptyEntrypoint => write!(f, "transaction entrypoint must not be empty"),
            Self::EmptySignature => write!(f, "transaction signature must not be empty"),
            Self::TransactionFieldTooLarge {
                field,
                actual,
                maximum,
            } => write!(
                f,
                "transaction field {field} is {actual} bytes/items, maximum is {maximum}"
            ),
            Self::NonCanonicalTransactionEncoding => write!(
                f,
                "decoded transaction does not re-encode to its input bytes"
            ),
            Self::WasmEngine(msg) => write!(f, "wasm engine error: {msg}"),
            Self::MissingEntrypoint(name) => {
                write!(f, "entry-point not found in wasm module: {name}")
            }
            Self::ObjectVersionOverflow(id) => {
                write!(f, "object version overflow while mutating {id}")
            }
            Self::HashChainMismatch => {
                write!(f, "transaction chain does not match hash-suite resolver")
            }
            Self::HashProtocolVersionMismatch {
                transaction,
                resolver,
            } => write!(
                f,
                "transaction protocol version {} does not match resolver version {}",
                transaction.get(),
                resolver.get()
            ),
            Self::ResourceLimitExceeded(resource) => {
                write!(f, "execution resource limit exceeded: {resource}")
            }
            Self::UnknownExecutionStatusTag(tag) => {
                write!(f, "unknown execution status tag: {tag}")
            }
            Self::UnknownObjectEffectTag(tag) => {
                write!(f, "unknown object effect tag: {tag}")
            }
            Self::TooManyObjectEffects(count) => {
                write!(f, "execution effects declare {count} object effects")
            }
            Self::TooManyEvents(count) => {
                write!(f, "execution effects declare {count} events")
            }
            Self::NonCanonicalExecutionEffectsEncoding => write!(
                f,
                "decoded execution effects do not re-encode to their input bytes"
            ),
        }
    }
}

impl Error for ExecutionError {}

impl From<CanonicalEncodingError> for ExecutionError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for ExecutionError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<TypeError> for ExecutionError {
    fn from(value: TypeError) -> Self {
        Self::ProtocolType(value)
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
/// 4. `module_ref` identifies the code to execute; this crate does not fix
///    how. A caller may interpret it as a stored `Object` reference or,
///    as `node-core`'s current preinstalled-module MVP composition does,
///    reinterpret its `ObjectId`/version/digest fields as a direct
///    `(module_id, version, canonical_code_hash)` lookup into a
///    governance-managed system-module registry with no backing `Object` at
///    all.
/// 5. `gas_limit` is bounded by whatever ceiling the calling composition
///    enforces. This crate does not itself fix or enforce a protocol-wide
///    maximum; `node-core`'s preinstalled-module MVP composition currently
///    enforces its own conservative pre-activation ceiling before running the
///    engine.
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
    /// Reference interpreted by the calling composition to select executable
    /// code. The preinstalled-module MVP maps its id/version/digest directly
    /// to a governed module record rather than a stored object.
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

/// Decodes a [`Transaction`] from its strict canonical wire format.
///
/// This is the single strict decoder for transaction bytes accepted from an
/// untrusted sender. Beyond the shared [`decode_canonical_frame`] guarantees
/// (correct magic, no truncation/trailing bytes, strictly increasing field
/// order, no duplicate fields), this function additionally:
///
/// * requires the transaction type id (`0x6001`) and encoding version 1;
/// * requires exactly fields 1-10 and 12, with field 11 (`fee_payment`)
///   optional, and rejects any other field id;
/// * recursively decodes and validates every nested frame (`access_manifest`,
///   `module_ref`, `fee_payment`) with the same strict rules, reusing the
///   shared 32 MiB canonical frame bound
///   ([`canonical_encoding::MAX_CANONICAL_FRAME_BYTES`]) at every nesting
///   level;
/// * applies the tighter transaction-specific bounds
///   ([`MAX_TRANSACTION_CHAIN_ID_BYTES`], [`MAX_TRANSACTION_ENTRYPOINT_BYTES`],
///   [`MAX_TRANSACTION_ARGS_BYTES`], [`MAX_TRANSACTION_SIGNATURE_BYTES`],
///   [`MAX_TRANSACTION_MANIFEST_ENTRIES`]) *before* copying the corresponding
///   attacker-controlled bytes/entries out of the borrowed frame;
/// * rejects an empty `entrypoint` or `signature`, matching
///   [`encode_transaction`];
/// * rejects a non-canonical `access_manifest` count/field layout and any
///   duplicate `ObjectId` entry within it (see [`abi::decode_access_manifest`]);
/// * finally re-encodes the decoded value with [`encode_transaction`] and
///   requires the result to be byte-for-byte identical to `input`, so no
///   alternate representation of the same logical transaction is accepted.
pub fn decode_transaction(input: &[u8]) -> Result<Transaction, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(TRANSACTION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;

    let chain_id_str = frame.required_str(1)?;
    if chain_id_str.len() > MAX_TRANSACTION_CHAIN_ID_BYTES {
        return Err(ExecutionError::TransactionFieldTooLarge {
            field: "chain_id",
            actual: chain_id_str.len(),
            maximum: MAX_TRANSACTION_CHAIN_ID_BYTES,
        });
    }
    let chain_id = ChainId::new(chain_id_str)?;

    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let sender = Address::try_from_slice(frame.required_field(4)?)?;
    let nonce = frame.required_u64(5)?;

    let access_manifest =
        decode_access_manifest(frame.required_field(6)?, MAX_TRANSACTION_MANIFEST_ENTRIES)?;

    let module_ref = decode_object_ref(frame.required_field(7)?)?;

    let entrypoint = frame.required_str(8)?;
    if entrypoint.is_empty() {
        return Err(ExecutionError::EmptyEntrypoint);
    }
    if entrypoint.len() > MAX_TRANSACTION_ENTRYPOINT_BYTES {
        return Err(ExecutionError::TransactionFieldTooLarge {
            field: "entrypoint",
            actual: entrypoint.len(),
            maximum: MAX_TRANSACTION_ENTRYPOINT_BYTES,
        });
    }
    let entrypoint = entrypoint.to_string();

    let args_bytes = frame.required_field(9)?;
    if args_bytes.len() > MAX_TRANSACTION_ARGS_BYTES {
        return Err(ExecutionError::TransactionFieldTooLarge {
            field: "args",
            actual: args_bytes.len(),
            maximum: MAX_TRANSACTION_ARGS_BYTES,
        });
    }
    let args = args_bytes.to_vec();

    let gas_limit = frame.required_u64(10)?;

    let fee_payment = frame.field(11).map(decode_fee_payment).transpose()?;

    let signature_bytes = frame.required_field(12)?;
    if signature_bytes.is_empty() {
        return Err(ExecutionError::EmptySignature);
    }
    if signature_bytes.len() > MAX_TRANSACTION_SIGNATURE_BYTES {
        return Err(ExecutionError::TransactionFieldTooLarge {
            field: "signature",
            actual: signature_bytes.len(),
            maximum: MAX_TRANSACTION_SIGNATURE_BYTES,
        });
    }
    let signature = signature_bytes.to_vec();

    let transaction = Transaction {
        chain_id,
        protocol_version,
        epoch,
        sender,
        nonce,
        access_manifest,
        module_ref,
        entrypoint,
        args,
        gas_limit,
        fee_payment,
        signature,
    };

    if encode_transaction(&transaction)?.as_slice() != input {
        return Err(ExecutionError::NonCanonicalTransactionEncoding);
    }

    Ok(transaction)
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

/// Hashes the signable transaction payload using the suite selected from the
/// transaction's `(chain_id, protocol_version, epoch)` context.
///
/// The resulting digest can be used as the authoritative transaction hash
/// (`tx_hash`) included in votes and certificates.
pub fn hash_transaction(
    tx: &Transaction,
    resolver: &HashSuiteResolver,
) -> Result<Digest32, ExecutionError> {
    if &tx.chain_id != resolver.chain_id() {
        return Err(ExecutionError::HashChainMismatch);
    }
    if tx.protocol_version != resolver.protocol_version() {
        return Err(ExecutionError::HashProtocolVersionMismatch {
            transaction: tx.protocol_version,
            resolver: resolver.protocol_version(),
        });
    }
    let signable = encode_transaction_signable(tx)?;
    Ok(resolver.hash_for_purpose(tx.epoch, HashPurpose::Transaction, &signable)?)
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

/// Decodes one canonical [`EventRecord`], rejecting any field other than the
/// exact `type_tag`/`data` pair produced by [`encode_event_record`].
pub fn decode_event_record(input: &[u8]) -> Result<EventRecord, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(EVENT_RECORD_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    Ok(EventRecord {
        type_tag: frame.required_field(1)?.to_vec(),
        data: frame.required_field(2)?.to_vec(),
    })
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

/// Decodes one canonical [`ObjectEffect`], rejecting an unknown tag or any
/// field the encoded variant does not itself carry.
pub fn decode_object_effect(input: &[u8]) -> Result<ObjectEffect, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_EFFECT_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let tag_bytes = frame.required_field(1)?;
    let tag: [u8; 1] =
        tag_bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 1,
                expected: 1,
                actual: tag_bytes.len(),
            })?;
    match tag[0] {
        1 => {
            frame.require_only_fields(&[1, 2])?;
            Ok(ObjectEffect::Created(decode_object(
                frame.required_field(2)?,
            )?))
        }
        2 => {
            frame.require_only_fields(&[1, 2, 3])?;
            Ok(ObjectEffect::Mutated {
                previous_version: frame.required_u64(2)?,
                new_object: decode_object(frame.required_field(3)?)?,
            })
        }
        3 => {
            frame.require_only_fields(&[1, 2, 3])?;
            Ok(ObjectEffect::Deleted {
                id: decode_object_id(frame.required_field(2)?)?,
                version: frame.required_u64(3)?,
            })
        }
        other => Err(ExecutionError::UnknownObjectEffectTag(other)),
    }
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

/// Maximum object effects or events one nested list frame may carry.
///
/// Matches the field-id ceiling [`encode_execution_effects`] itself relies
/// on: each entry after the leading count field claims one `u16` field id
/// starting at `2`, so `u16::MAX - 1` entries is the most the wire format can
/// address.
const MAX_EXECUTION_EFFECTS_LIST_ITEMS: usize = u16::MAX as usize - 1;

fn decode_object_effects_list(bytes: &[u8]) -> Result<Vec<ObjectEffect>, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(OBJECT_EFFECTS_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let count = usize::try_from(frame.required_u32(1)?)
        .map_err(|_| ExecutionError::TooManyObjectEffects(usize::MAX))?;
    if count > MAX_EXECUTION_EFFECTS_LIST_ITEMS {
        return Err(ExecutionError::TooManyObjectEffects(count));
    }

    let mut allowed_fields: Vec<u16> = Vec::with_capacity(count + 1);
    allowed_fields.push(1);
    let mut effects = Vec::with_capacity(count);
    for index in 0..count {
        let field_id =
            u16::try_from(2 + index).map_err(|_| ExecutionError::TooManyObjectEffects(count))?;
        allowed_fields.push(field_id);
        effects.push(decode_object_effect(frame.required_field(field_id)?)?);
    }
    frame.require_only_fields(&allowed_fields)?;
    Ok(effects)
}

fn decode_event_records_list(bytes: &[u8]) -> Result<Vec<EventRecord>, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(EVENT_RECORDS_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let count = usize::try_from(frame.required_u32(1)?)
        .map_err(|_| ExecutionError::TooManyEvents(usize::MAX))?;
    if count > MAX_EXECUTION_EFFECTS_LIST_ITEMS {
        return Err(ExecutionError::TooManyEvents(count));
    }

    let mut allowed_fields: Vec<u16> = Vec::with_capacity(count + 1);
    allowed_fields.push(1);
    let mut events = Vec::with_capacity(count);
    for index in 0..count {
        let field_id =
            u16::try_from(2 + index).map_err(|_| ExecutionError::TooManyEvents(count))?;
        allowed_fields.push(field_id);
        events.push(decode_event_record(frame.required_field(field_id)?)?);
    }
    frame.require_only_fields(&allowed_fields)?;
    Ok(events)
}

/// Decodes [`ExecutionEffects`] from its strict canonical wire format.
///
/// Beyond the shared [`decode_canonical_frame`] guarantees, this additionally:
///
/// * requires the execution-effects type id (`0x6004`) and encoding version 1;
/// * requires exactly fields 1, 2, 4, 5, 6, with field 3 (`reason`) present if
///   and only if the decoded status tag is `2` (failure), and rejects any
///   other field id or an unknown status tag;
/// * recursively decodes the nested object-effects (`0x6005`) and
///   event-records (`0x6006`) list frames, each bounded to the same
///   `u16::MAX - 1` item ceiling [`encode_execution_effects`] enforces, and
///   each nested [`ObjectEffect`]/[`EventRecord`] frame with
///   [`decode_object_effect`]/[`decode_event_record`];
/// * finally re-encodes the decoded value with [`encode_execution_effects`]
///   and requires the result to be byte-for-byte identical to `input`, so no
///   alternate representation of the same logical effects is accepted.
pub fn decode_execution_effects(input: &[u8]) -> Result<ExecutionEffects, ExecutionError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(EXECUTION_EFFECTS_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let tx_hash = decode_digest32(frame.required_field(1)?)?;

    let status_tag_bytes = frame.required_field(2)?;
    let status_tag: [u8; 1] =
        status_tag_bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 1,
                actual: status_tag_bytes.len(),
            })?;
    let status = match status_tag[0] {
        1 => {
            frame.require_only_fields(&[1, 2, 4, 5, 6])?;
            ExecutionStatus::Success
        }
        2 => {
            frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
            ExecutionStatus::Failure {
                reason: frame.required_str(3)?.to_string(),
            }
        }
        other => return Err(ExecutionError::UnknownExecutionStatusTag(other)),
    };

    let gas_used = frame.required_u64(4)?;
    let object_effects = decode_object_effects_list(frame.required_field(5)?)?;
    let events = decode_event_records_list(frame.required_field(6)?)?;

    let effects = ExecutionEffects {
        tx_hash,
        status,
        object_effects,
        events,
        gas_used,
    };
    if encode_execution_effects(&effects)?.as_slice() != input {
        return Err(ExecutionError::NonCanonicalExecutionEffectsEncoding);
    }
    Ok(effects)
}

/// Hashes the canonical encoding of [`ExecutionEffects`] for the
/// `ExecutionEffects` purpose.
///
/// Validators include this digest in their votes.
pub fn hash_execution_effects(
    effects: &ExecutionEffects,
    epoch: Epoch,
    resolver: &HashSuiteResolver,
) -> Result<Digest32, ExecutionError> {
    let encoded = encode_execution_effects(effects)?;
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &encoded)?)
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

// ── WASM engine ───────────────────────────────────────────────────────────

mod wasm_engine;
pub use wasm_engine::WasmExecutionEngine;

mod execution_proof;
pub use execution_proof::{
    ExecutionProof, ExecutionProofError, ExecutionProofStatement, ExecutionProofVerifier,
    MAX_EXECUTION_PROOF_BYTES, ProofSystemId, ProofVerificationError, encode_execution_proof,
    encode_execution_proof_statement, encode_proof_system_id, validate_execution_proof,
    verify_execution_proof,
};

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{AccessEntry, AccessManifest};
    use fees::{Amount, AssetId, FeePayment};
    use objects::{AccessMode, Address, ObjectId, ObjectRef, Owner};
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule,
        ProtocolVersion,
    };

    fn sample_chain_id() -> ChainId {
        ChainId::new("sunrise-devnet").unwrap()
    }

    fn sample_protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(1)
    }

    fn sample_resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            sample_chain_id(),
            sample_protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
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
        let with_fee = sample_transaction();
        let mut without_fee = sample_transaction();
        without_fee.fee_payment = None;

        assert_ne!(
            encode_transaction(&with_fee).unwrap(),
            encode_transaction(&without_fee).unwrap()
        );
        assert_ne!(
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

    // ── transaction decoding ────────────────────────────────────────────────

    const ALL_TRANSACTION_FIELDS: [u16; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn indexed_object_ref(index: u32) -> ObjectRef {
        let mut id = [0u8; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        ObjectRef {
            id: ObjectId::new(id),
            version: 1,
            digest: sample_digest(0x01),
        }
    }

    /// Hand-builds a transaction frame field-by-field, so adversarial tests
    /// can omit required fields, add unknown ones, or splice in raw bytes
    /// that the safe [`encode_transaction`] wrapper could never produce.
    fn manual_transaction_frame(
        tx: &Transaction,
        fields: &[u16],
        overrides: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut canonical = CanonicalStruct::new(TRANSACTION_TYPE_ID, ENCODING_VERSION);
        for &field in fields {
            if let Some((_, bytes)) = overrides.iter().find(|(id, _)| *id == field) {
                canonical.field_bytes(field, bytes.clone()).unwrap();
                continue;
            }
            match field {
                1 => canonical.field_str(1, tx.chain_id.as_str()).unwrap(),
                2 => canonical.field_u32(2, tx.protocol_version.get()).unwrap(),
                3 => canonical.field_u64(3, tx.epoch.get()).unwrap(),
                4 => canonical.field_bytes(4, tx.sender.as_bytes()).unwrap(),
                5 => canonical.field_u64(5, tx.nonce).unwrap(),
                6 => canonical
                    .field_bytes(6, encode_access_manifest(&tx.access_manifest).unwrap())
                    .unwrap(),
                7 => canonical
                    .field_bytes(7, encode_object_ref(&tx.module_ref).unwrap())
                    .unwrap(),
                8 => canonical.field_str(8, &tx.entrypoint).unwrap(),
                9 => canonical.field_bytes(9, tx.args.as_slice()).unwrap(),
                10 => canonical.field_u64(10, tx.gas_limit).unwrap(),
                11 => canonical
                    .field_bytes(
                        11,
                        encode_fee_payment(tx.fee_payment.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap(),
                12 => canonical.field_bytes(12, tx.signature.as_slice()).unwrap(),
                other => canonical.field_bytes(other, Vec::<u8>::new()).unwrap(),
            }
        }
        canonical.finish().unwrap()
    }

    /// Scans a valid canonical frame's field headers (10-byte frame header,
    /// then 2-byte field id + 4-byte length + payload per field) and returns
    /// the byte offset of the requested field's 2-byte id header, so
    /// adversarial tests can splice a specific field id without hand-computing
    /// every preceding field's payload length.
    fn field_id_offset(encoded: &[u8], field_id: u16) -> usize {
        const FRAME_HEADER_BYTES: usize = 10;
        const FIELD_HEADER_BYTES: usize = 6;
        let mut offset: usize = FRAME_HEADER_BYTES;
        loop {
            let current_id_bytes: [u8; 2] = [encoded[offset], encoded[offset + 1]];
            let current_id = u16::from_le_bytes(current_id_bytes);
            if current_id == field_id {
                return offset;
            }
            let length_bytes: [u8; 4] = [
                encoded[offset + 2],
                encoded[offset + 3],
                encoded[offset + 4],
                encoded[offset + 5],
            ];
            let length = u32::from_le_bytes(length_bytes) as usize;
            offset += FIELD_HEADER_BYTES + length;
        }
    }

    #[test]
    fn transaction_decoder_round_trips_with_fee() {
        let tx = sample_transaction();
        let encoded = encode_transaction(&tx).unwrap();
        assert_eq!(decode_transaction(&encoded), Ok(tx));
    }

    #[test]
    fn transaction_decoder_round_trips_without_fee() {
        let mut tx = sample_transaction();
        tx.fee_payment = None;
        let encoded = encode_transaction(&tx).unwrap();
        assert_eq!(decode_transaction(&encoded), Ok(tx));
    }

    #[test]
    fn transaction_decoder_round_trips_stable_vector_transaction() {
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
        assert_eq!(decode_transaction(&encoded), Ok(tx));
    }

    #[test]
    fn transaction_decoder_rejects_wrong_type_id() {
        let tx = sample_transaction();
        let mut encoded = encode_transaction(&tx).unwrap();
        encoded[4..6].copy_from_slice(&0x6999_u16.to_le_bytes());
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: TRANSACTION_TYPE_ID,
                    actual: 0x6999,
                }
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_wrong_version() {
        let tx = sample_transaction();
        let mut encoded = encode_transaction(&tx).unwrap();
        encoded[6..8].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: ENCODING_VERSION,
                    actual: 2,
                }
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_duplicate_field_id() {
        let tx: Transaction = sample_transaction();
        let mut encoded: Vec<u8> = encode_transaction(&tx).unwrap();
        // Overwrite field 2's (`protocol_version`) 2-byte id header so it
        // duplicates field 1's (`chain_id`) id, without touching field 2's
        // declared length or payload bytes.
        let field_2_id_offset: usize = field_id_offset(&encoded, 2);
        let duplicate_id_bytes: [u8; 2] = 1_u16.to_le_bytes();
        encoded[field_2_id_offset..field_2_id_offset + 2].copy_from_slice(&duplicate_id_bytes);
        let expected_error: CanonicalDecodingError =
            CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 1,
                current: 1,
            };
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(expected_error))
        );
    }

    #[test]
    fn transaction_decoder_rejects_out_of_order_field_id() {
        let tx: Transaction = sample_transaction();
        let mut encoded: Vec<u8> = encode_transaction(&tx).unwrap();
        // Overwrite field 7's (`module_ref`) 2-byte id header so it becomes
        // field 3 (`epoch`)'s id, which is strictly less than the preceding
        // field 6 (`access_manifest`) but not equal to it, without touching
        // field 7's declared length or payload bytes.
        let field_7_id_offset: usize = field_id_offset(&encoded, 7);
        let out_of_order_id_bytes: [u8; 2] = 3_u16.to_le_bytes();
        encoded[field_7_id_offset..field_7_id_offset + 2].copy_from_slice(&out_of_order_id_bytes);
        let expected_error: CanonicalDecodingError =
            CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 6,
                current: 3,
            };
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(expected_error))
        );
    }

    #[test]
    fn transaction_decoder_rejects_wrong_length_numeric_field() {
        let tx: Transaction = sample_transaction();
        // `protocol_version` (field 2) must be a 4-byte little-endian `u32`;
        // supply 3 bytes instead so the frame parses structurally but the
        // typed accessor rejects the wrong length.
        let wrong_length_protocol_version: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
        let overrides: [(u16, Vec<u8>); 1] = [(2, wrong_length_protocol_version)];
        let encoded: Vec<u8> = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &overrides);
        let expected_error: CanonicalDecodingError = CanonicalDecodingError::InvalidFieldLength {
            field_id: 2,
            expected: 4,
            actual: 3,
        };
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(expected_error))
        );
    }

    #[test]
    fn transaction_decoder_rejects_missing_required_field() {
        let tx = sample_transaction();
        let encoded = manual_transaction_frame(&tx, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12], &[]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(10)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_unknown_field() {
        let tx = sample_transaction();
        let mut fields = ALL_TRANSACTION_FIELDS.to_vec();
        fields.push(13);
        let encoded = manual_transaction_frame(&tx, &fields, &[]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(13)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_trailing_bytes() {
        let tx = sample_transaction();
        let mut encoded = encode_transaction(&tx).unwrap();
        encoded.push(0x00);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_every_truncated_prefix() {
        let tx = sample_transaction();
        let encoded = encode_transaction(&tx).unwrap();
        for end in 0..encoded.len() {
            assert!(matches!(
                decode_transaction(&encoded[..end]),
                Err(ExecutionError::CanonicalDecoding(
                    CanonicalDecodingError::Truncated { .. }
                ))
            ));
        }
        assert!(decode_transaction(&encoded).is_ok());
    }

    #[test]
    fn transaction_decoder_rejects_invalid_utf8_chain_id() {
        let tx = sample_transaction();
        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(1, vec![0xFF, 0xFE])]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::InvalidUtf8(1)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_invalid_utf8_entrypoint() {
        let tx = sample_transaction();
        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(8, vec![0xFF, 0xFE])]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::InvalidUtf8(8)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_wrong_sender_length() {
        let tx = sample_transaction();
        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(4, vec![0xCC; 31])]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::Object(
                objects::ObjectError::InvalidAddressLength(31)
            ))
        );
    }

    #[test]
    fn transaction_decoder_rejects_unknown_module_ref_digest_algorithm() {
        let tx = sample_transaction();

        // Digest32 (0x0103), ObjectId (0x4001), and ObjectRef (0x4004) are the
        // stable, already-committed type ids used by `objects`; an unknown
        // hash-algorithm tag cannot be produced through the public encoders,
        // so it is hand-built here the same way `canonical-encoding`'s own
        // adversarial tests build it.
        let mut digest_frame = CanonicalStruct::new(0x0103, 1);
        digest_frame.field_u16(1, 0xFFFF).unwrap();
        digest_frame.field_bytes(2, [0x11; 32]).unwrap();
        let digest_bytes = digest_frame.finish().unwrap();

        let mut object_id_frame = CanonicalStruct::new(0x4001, 1);
        object_id_frame
            .field_bytes(1, tx.module_ref.id.as_bytes())
            .unwrap();
        let object_id_bytes = object_id_frame.finish().unwrap();

        let mut object_ref_frame = CanonicalStruct::new(0x4004, 1);
        object_ref_frame.field_bytes(1, object_id_bytes).unwrap();
        object_ref_frame
            .field_u64(2, tx.module_ref.version)
            .unwrap();
        object_ref_frame.field_bytes(3, digest_bytes).unwrap();
        let object_ref_bytes = object_ref_frame.finish().unwrap();

        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(7, object_ref_bytes)]);

        let inner_error = CanonicalDecodingError::UnknownHashAlgorithmId(0xFFFF);
        let expected_error = objects::ObjectError::CanonicalDecoding(inner_error);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::Object(expected_error))
        );
    }

    #[test]
    fn transaction_decoder_rejects_empty_entrypoint() {
        let tx = sample_transaction();
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(8, Vec::new())]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::EmptyEntrypoint)
        );
    }

    #[test]
    fn transaction_decoder_rejects_empty_signature() {
        let tx = sample_transaction();
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(12, Vec::new())]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::EmptySignature)
        );
    }

    #[test]
    fn transaction_decoder_rejects_oversized_chain_id() {
        let tx = sample_transaction();
        let oversized = vec![b'x'; MAX_TRANSACTION_CHAIN_ID_BYTES + 1];
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(1, oversized)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::TransactionFieldTooLarge {
                field: "chain_id",
                actual: MAX_TRANSACTION_CHAIN_ID_BYTES + 1,
                maximum: MAX_TRANSACTION_CHAIN_ID_BYTES,
            })
        );
    }

    #[test]
    fn transaction_decoder_rejects_oversized_entrypoint() {
        let tx = sample_transaction();
        let oversized = vec![b'a'; MAX_TRANSACTION_ENTRYPOINT_BYTES + 1];
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(8, oversized)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::TransactionFieldTooLarge {
                field: "entrypoint",
                actual: MAX_TRANSACTION_ENTRYPOINT_BYTES + 1,
                maximum: MAX_TRANSACTION_ENTRYPOINT_BYTES,
            })
        );
    }

    #[test]
    fn transaction_decoder_rejects_oversized_args() {
        let tx = sample_transaction();
        let oversized = vec![0u8; MAX_TRANSACTION_ARGS_BYTES + 1];
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(9, oversized)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::TransactionFieldTooLarge {
                field: "args",
                actual: MAX_TRANSACTION_ARGS_BYTES + 1,
                maximum: MAX_TRANSACTION_ARGS_BYTES,
            })
        );
    }

    #[test]
    fn transaction_decoder_rejects_oversized_signature() {
        let tx = sample_transaction();
        let oversized = vec![0u8; MAX_TRANSACTION_SIGNATURE_BYTES + 1];
        let encoded = manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(12, oversized)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::TransactionFieldTooLarge {
                field: "signature",
                actual: MAX_TRANSACTION_SIGNATURE_BYTES + 1,
                maximum: MAX_TRANSACTION_SIGNATURE_BYTES,
            })
        );
    }

    #[test]
    fn transaction_decoder_rejects_manifest_count_above_bound_before_copying_entries() {
        let tx = sample_transaction();

        // AccessManifest (0x5002) declares an entry count above the
        // transaction-specific bound without any of the (expensive to
        // construct) matching entries, proving the bound is enforced before
        // entries are decoded/copied.
        let mut manifest_frame = CanonicalStruct::new(0x5002, 1);
        manifest_frame
            .field_u32(1, (MAX_TRANSACTION_MANIFEST_ENTRIES + 1) as u32)
            .unwrap();
        let manifest_bytes = manifest_frame.finish().unwrap();

        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(6, manifest_bytes)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::Abi(AbiError::ManifestTooLarge(
                MAX_TRANSACTION_MANIFEST_ENTRIES + 1
            )))
        );
    }

    #[test]
    fn transaction_decoder_rejects_manifest_count_field_layout_mismatch() {
        let tx = sample_transaction();
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: indexed_object_ref(1),
            mode: AccessMode::Read,
        });
        let mut encoded_manifest = encode_access_manifest(&manifest).unwrap();
        // Field 1 (`declared_count`) is a fixed-width little-endian `u32`
        // located right after the 10-byte frame header and 6-byte field
        // header.
        encoded_manifest[16..20].copy_from_slice(&2_u32.to_le_bytes());

        let encoded =
            manual_transaction_frame(&tx, &ALL_TRANSACTION_FIELDS, &[(6, encoded_manifest)]);
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::Abi(AbiError::NonCanonicalManifestLayout {
                declared_count: 2,
                field_count: 2,
            }))
        );
    }

    #[test]
    fn transaction_decoder_rejects_duplicate_manifest_objects() {
        let mut tx = sample_transaction();
        let shared_ref = indexed_object_ref(7);
        tx.access_manifest = AccessManifest::new();
        tx.access_manifest.push(AccessEntry {
            object_ref: shared_ref.clone(),
            mode: AccessMode::Read,
        });
        tx.access_manifest.push(AccessEntry {
            object_ref: shared_ref.clone(),
            mode: AccessMode::Write,
        });

        let encoded = encode_transaction(&tx).unwrap();
        assert_eq!(
            decode_transaction(&encoded),
            Err(ExecutionError::Abi(AbiError::DuplicateObjectId(
                shared_ref.id
            )))
        );
    }

    #[test]
    fn transaction_decoder_rejects_malformed_fee_payment() {
        let tx = sample_transaction();
        // FeePayment (0x7002) missing its required fields entirely.
        let mut bogus_fee = CanonicalStruct::new(0x7002, 1);
        bogus_fee.field_u64(1, 5).unwrap();
        let encoded = manual_transaction_frame(
            &tx,
            &ALL_TRANSACTION_FIELDS,
            &[(11, bogus_fee.finish().unwrap())],
        );
        assert!(matches!(
            decode_transaction(&encoded),
            Err(ExecutionError::Fee(_))
        ));
    }

    // ── transaction hashing ───────────────────────────────────────────────

    #[test]
    fn transaction_hash_is_deterministic() {
        let tx = sample_transaction();
        let resolver = sample_resolver();
        let h1 = hash_transaction(&tx, &resolver).unwrap();
        let h2 = hash_transaction(&tx, &resolver).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_algorithm_is_selected_by_epoch_schedule() {
        let resolver = HashSuiteResolver::new(
            sample_chain_id(),
            sample_protocol_version(),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(6),
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap();
        let sha2 = hash_transaction(&sample_transaction(), &resolver).unwrap();
        let mut upgraded = sample_transaction();
        upgraded.epoch = Epoch::new(6);
        let sha3 = hash_transaction(&upgraded, &resolver).unwrap();
        assert_ne!(sha2, sha3);
        assert_eq!(sha2.algorithm(), HashAlgorithmId::Sha2_256);
        assert_eq!(sha3.algorithm(), HashAlgorithmId::Sha3_256);
    }

    #[test]
    fn modified_transaction_produces_different_hash() {
        let tx1 = sample_transaction();
        let mut tx2 = sample_transaction();
        tx2.nonce = 99;
        let resolver = sample_resolver();
        let h1 = hash_transaction(&tx1, &resolver).unwrap();
        let h2 = hash_transaction(&tx2, &resolver).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn transaction_hash_rejects_mismatched_resolver_context() {
        let resolver = HashSuiteResolver::new(
            ChainId::new("other-chain").unwrap(),
            sample_protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        assert_eq!(
            hash_transaction(&sample_transaction(), &resolver),
            Err(ExecutionError::HashChainMismatch)
        );
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
        let tx_hash = hash_transaction(&tx, &sample_resolver()).unwrap();
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

        let h1 = hash_execution_effects(&effects, Epoch::new(5), &sample_resolver()).unwrap();
        let h2 = hash_execution_effects(&effects, Epoch::new(5), &sample_resolver()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.algorithm(), HashAlgorithmId::Sha2_256);
    }

    // ── decode_event_record / decode_object_effect / decode_execution_effects ──

    #[test]
    fn event_record_round_trips() {
        let event = EventRecord {
            type_tag: b"transfer".to_vec(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = encode_event_record(&event).unwrap();
        assert_eq!(decode_event_record(&encoded).unwrap(), event);
    }

    #[test]
    fn event_record_rejects_wrong_type_id() {
        let object_effect =
            encode_object_effect(&ObjectEffect::Created(sample_object(0x01, 1))).unwrap();
        assert!(matches!(
            decode_event_record(&object_effect),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    #[test]
    fn event_record_rejects_trailing_bytes() {
        let event = EventRecord {
            type_tag: b"tag".to_vec(),
            data: vec![0x01],
        };
        let mut encoded = encode_event_record(&event).unwrap();
        encoded.push(0x00);
        assert!(matches!(
            decode_event_record(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn object_effect_round_trips_every_variant() {
        let created = ObjectEffect::Created(sample_object(0x21, 1));
        let mutated = ObjectEffect::Mutated {
            previous_version: 3,
            new_object: sample_object(0x22, 4),
        };
        let deleted = ObjectEffect::Deleted {
            id: ObjectId::new([0x23; 32]),
            version: 7,
        };
        for effect in [created, mutated, deleted] {
            let encoded = encode_object_effect(&effect).unwrap();
            assert_eq!(decode_object_effect(&encoded).unwrap(), effect);
        }
    }

    #[test]
    fn object_effect_rejects_unknown_tag() {
        let mut frame = CanonicalStruct::new(OBJECT_EFFECT_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, [9u8]).unwrap();
        let bytes = frame.finish().unwrap();

        assert_eq!(
            decode_object_effect(&bytes),
            Err(ExecutionError::UnknownObjectEffectTag(9))
        );
    }

    #[test]
    fn object_effect_created_rejects_a_trailing_field() {
        let object_bytes = encode_object(&sample_object(0x24, 1)).unwrap();
        let mut frame = CanonicalStruct::new(OBJECT_EFFECT_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, [1u8]).unwrap();
        frame.field_bytes(2, object_bytes).unwrap();
        frame.field_u64(3, 99).unwrap();
        let bytes = frame.finish().unwrap();

        assert!(matches!(
            decode_object_effect(&bytes),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    #[test]
    fn execution_effects_round_trip_success_and_failure() {
        let tx_hash = sample_digest(0x40);
        let success = sample_effects(tx_hash);
        let encoded_success = encode_execution_effects(&success).unwrap();
        assert_eq!(decode_execution_effects(&encoded_success).unwrap(), success);

        let failure = ExecutionEffects {
            tx_hash,
            status: ExecutionStatus::Failure {
                reason: "trap".to_string(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 42,
        };
        let encoded_failure = encode_execution_effects(&failure).unwrap();
        assert_eq!(decode_execution_effects(&encoded_failure).unwrap(), failure);
    }

    #[test]
    fn execution_effects_decode_rejects_unknown_status_tag() {
        let mut frame = CanonicalStruct::new(EXECUTION_EFFECTS_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_digest32(&sample_digest(0x41)).unwrap())
            .unwrap();
        frame.field_bytes(2, [9u8]).unwrap();
        frame.field_u64(4, 0).unwrap();
        let empty_effects_list = {
            let mut list = CanonicalStruct::new(OBJECT_EFFECTS_LIST_TYPE_ID, ENCODING_VERSION);
            list.field_u32(1, 0).unwrap();
            list.finish().unwrap()
        };
        let empty_events_list = {
            let mut list = CanonicalStruct::new(EVENT_RECORDS_LIST_TYPE_ID, ENCODING_VERSION);
            list.field_u32(1, 0).unwrap();
            list.finish().unwrap()
        };
        frame.field_bytes(5, empty_effects_list).unwrap();
        frame.field_bytes(6, empty_events_list).unwrap();
        let bytes = frame.finish().unwrap();

        assert_eq!(
            decode_execution_effects(&bytes),
            Err(ExecutionError::UnknownExecutionStatusTag(9))
        );
    }

    #[test]
    fn execution_effects_success_rejects_a_present_reason_field() {
        let tx_hash = sample_digest(0x42);
        let mut success = sample_effects(tx_hash);
        success.object_effects.clear();
        success.events.clear();
        let encoded = encode_execution_effects(&success).unwrap();

        // Re-encode by hand with an extra field-3 `reason` string even though
        // the status tag stays `1` (success), simulating a tampered/malformed
        // peer rather than anything `encode_execution_effects` itself emits.
        let mut frame = CanonicalStruct::new(EXECUTION_EFFECTS_TYPE_ID, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_digest32(&tx_hash).unwrap())
            .unwrap();
        frame.field_bytes(2, [1u8]).unwrap();
        frame.field_str(3, "unexpected").unwrap();
        frame.field_u64(4, success.gas_used).unwrap();
        let empty_effects_list = {
            let mut list = CanonicalStruct::new(OBJECT_EFFECTS_LIST_TYPE_ID, ENCODING_VERSION);
            list.field_u32(1, 0).unwrap();
            list.finish().unwrap()
        };
        let empty_events_list = {
            let mut list = CanonicalStruct::new(EVENT_RECORDS_LIST_TYPE_ID, ENCODING_VERSION);
            list.field_u32(1, 0).unwrap();
            list.finish().unwrap()
        };
        frame.field_bytes(5, empty_effects_list).unwrap();
        frame.field_bytes(6, empty_events_list).unwrap();
        let tampered = frame.finish().unwrap();
        assert_ne!(tampered, encoded);

        assert!(matches!(
            decode_execution_effects(&tampered),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    #[test]
    fn execution_effects_decode_rejects_trailing_bytes() {
        let tx_hash = sample_digest(0x43);
        let effects = sample_effects(tx_hash);
        let mut encoded = encode_execution_effects(&effects).unwrap();
        encoded.push(0xAB);

        assert!(matches!(
            decode_execution_effects(&encoded),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn object_effects_list_decode_rejects_a_count_exceeding_the_item_ceiling() {
        let mut list = CanonicalStruct::new(OBJECT_EFFECTS_LIST_TYPE_ID, ENCODING_VERSION);
        list.field_u32(1, u32::from(u16::MAX)).unwrap();
        let bytes = list.finish().unwrap();

        assert_eq!(
            decode_object_effects_list(&bytes),
            Err(ExecutionError::TooManyObjectEffects(usize::from(u16::MAX)))
        );
    }

    #[test]
    fn object_effects_list_decode_rejects_a_missing_declared_entry() {
        let mut list = CanonicalStruct::new(OBJECT_EFFECTS_LIST_TYPE_ID, ENCODING_VERSION);
        list.field_u32(1, 1).unwrap();
        let bytes = list.finish().unwrap();

        assert_eq!(
            decode_object_effects_list(&bytes),
            Err(ExecutionError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(2)
            ))
        );
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
