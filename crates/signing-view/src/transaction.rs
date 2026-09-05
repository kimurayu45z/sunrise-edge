//! Standalone strict decoder for the signed `TransactionSignable` (`0x6001`
//! v1, fields 1-10 plus optional field 11) shape.

use crate::{SigningViewError, profile::DeviceSigningProfile};
use abi::{AccessManifest, decode_access_manifest, encode_access_manifest};
use canonical_encoding::{CanonicalFrame, CanonicalStruct, decode_canonical_frame};
use fees::{FeePayment, decode_fee_payment, encode_fee_payment};
use objects::{Address, ObjectRef, decode_object_ref, encode_object_ref};
use protocol_types::{ChainId, Epoch, ProtocolVersion};

/// Stable canonical type identifier for a Transaction v1 frame
/// (`execution::encode_transaction`/`decode_transaction`'s `0x6001`).
///
/// Duplicated here as data, not imported: this crate must not depend on
/// `execution` (see the crate-level documentation and `docs/architecture/README.md` S4a
/// / DR-0088), since that crate pulls in the full deterministic WASM
/// execution engine. This constant, [`ENCODING_VERSION`], and every field
/// layout this module decodes are compatibility constraints inherited from
/// `execution`, not a design choice this crate is free to change; the
/// differential test in `tests/execution_differential.rs` proves this
/// module's independent encode/decode agrees byte-for-byte with
/// `execution`'s for the same logical transaction.
pub const TRANSACTION_TYPE_ID: u16 = 0x6001;
/// Stable canonical encoding version for [`TRANSACTION_TYPE_ID`].
pub const ENCODING_VERSION: u16 = 1;

const ALLOWED_FIELDS: [u16; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/// The exact signable fields of a canonical Transaction v1: fields 1-10 and
/// optional field 11 (the fee payment). Field 12 (the signature) is never
/// part of this shape — a `TransactionSignable` is, by construction, exactly
/// the bytes a signer signs, never the signed transaction itself.
///
/// This is the same shape `execution::encode_transaction_signable` produces,
/// decoded independently (see [`TRANSACTION_TYPE_ID`]'s doc comment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSignable {
    /// Chain replay-protection identifier.
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
    /// Reference to the module/entrypoint the transaction will execute.
    pub module_ref: ObjectRef,
    /// Entry-point function to invoke inside the module.
    pub entrypoint: String,
    /// Canonically encoded arguments passed to the entry-point.
    pub args: Vec<u8>,
    /// Maximum gas units the sender is willing to spend.
    pub gas_limit: u64,
    /// Stablecoin-denominated fee payment authorization, if any.
    pub fee_payment: Option<FeePayment>,
}

/// Encodes the signable fields of a [`TransactionSignable`] in the exact
/// canonical wire format `execution::encode_transaction_signable` produces.
pub fn encode_transaction_signable(
    value: &TransactionSignable,
) -> Result<Vec<u8>, SigningViewError> {
    if value.entrypoint.is_empty() {
        return Err(SigningViewError::EmptyEntrypoint);
    }

    let mut canonical = CanonicalStruct::new(TRANSACTION_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, value.chain_id.as_str())?;
    canonical.field_u32(2, value.protocol_version.get())?;
    canonical.field_u64(3, value.epoch.get())?;
    canonical.field_bytes(4, value.sender.as_bytes())?;
    canonical.field_u64(5, value.nonce)?;
    canonical.field_bytes(6, encode_access_manifest(&value.access_manifest)?)?;
    canonical.field_bytes(7, encode_object_ref(&value.module_ref)?)?;
    canonical.field_str(8, &value.entrypoint)?;
    canonical.field_bytes(9, value.args.as_slice())?;
    canonical.field_u64(10, value.gas_limit)?;
    if let Some(fee_payment) = &value.fee_payment {
        canonical.field_bytes(11, encode_fee_payment(fee_payment)?)?;
    }
    Ok(canonical.finish()?)
}

/// Strictly decodes a `TransactionSignable` payload — the exact bytes
/// `crypto::frame_signature_message`'s field 6 carries for a Transaction v1
/// signature.
///
/// Beyond the shared [`decode_canonical_frame`] guarantees (correct magic,
/// no truncation/trailing bytes, strictly increasing field order, no
/// duplicate fields), this function additionally:
///
/// * requires the transaction type id ([`TRANSACTION_TYPE_ID`]) and
///   [`ENCODING_VERSION`];
/// * requires exactly fields 1-10, with field 11 (`fee_payment`) optional,
///   and rejects any other field id — in particular, field 12 (the
///   signature) is always rejected, since a `TransactionSignable` never
///   carries one;
/// * recursively decodes and validates every nested frame (`access_manifest`,
///   `module_ref`, `fee_payment`) with the same strict rules;
/// * applies `profile`'s bounds to `chain_id`, `entrypoint`, `args`, and the
///   access-manifest entry count *before* copying the corresponding
///   attacker-controlled bytes/entries out of the borrowed frame;
/// * rejects an empty `entrypoint`;
/// * finally re-encodes the decoded value with [`encode_transaction_signable`]
///   and requires the result to be byte-for-byte identical to `input`, so no
///   alternate representation of the same logical value is accepted.
pub fn decode_transaction_signable(
    input: &[u8],
    profile: &DeviceSigningProfile,
) -> Result<TransactionSignable, SigningViewError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(TRANSACTION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&ALLOWED_FIELDS)?;

    let chain_id_str = frame.required_str(1)?;
    if chain_id_str.len() > profile.max_chain_id_bytes() {
        return Err(SigningViewError::FieldTooLarge {
            field: "chain_id",
            actual: chain_id_str.len(),
            maximum: profile.max_chain_id_bytes(),
        });
    }
    let chain_id = ChainId::new(chain_id_str)?;

    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let sender = Address::try_from_slice(frame.required_field(4)?)?;
    let nonce = frame.required_u64(5)?;

    let access_manifest = decode_access_manifest(
        frame.required_field(6)?,
        profile.max_manifest_entries(),
    )
    .map_err(|error| match error {
        abi::AbiError::ManifestTooLarge(actual) => SigningViewError::TooManyManifestEntries {
            actual,
            maximum: profile.max_manifest_entries(),
        },
        other => SigningViewError::Abi(other),
    })?;

    let module_ref = decode_object_ref(frame.required_field(7)?)?;

    let entrypoint = frame.required_str(8)?;
    if entrypoint.is_empty() {
        return Err(SigningViewError::EmptyEntrypoint);
    }
    if entrypoint.len() > profile.max_entrypoint_bytes() {
        return Err(SigningViewError::FieldTooLarge {
            field: "entrypoint",
            actual: entrypoint.len(),
            maximum: profile.max_entrypoint_bytes(),
        });
    }
    let entrypoint = entrypoint.to_string();

    let args_bytes = frame.required_field(9)?;
    if args_bytes.len() > profile.max_args_bytes() {
        return Err(SigningViewError::FieldTooLarge {
            field: "args",
            actual: args_bytes.len(),
            maximum: profile.max_args_bytes(),
        });
    }
    let args = args_bytes.to_vec();

    let gas_limit = frame.required_u64(10)?;
    let fee_payment = frame.field(11).map(decode_fee_payment).transpose()?;

    let value = TransactionSignable {
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
    };

    if encode_transaction_signable(&value)?.as_slice() != input {
        return Err(SigningViewError::NonCanonicalTransactionSignableEncoding);
    }

    Ok(value)
}
