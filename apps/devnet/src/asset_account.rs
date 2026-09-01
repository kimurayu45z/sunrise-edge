//! Canonical local-devnet fungible asset accounts and transfer module.
//!
//! Every fungible asset uses this one account/body/transfer shape. The fixed
//! asset and type identifiers below are development-profile identifiers, not
//! production metadata claims. The current WASM host ABI exposes object bodies
//! but not their type hash, schema version, ID, or owner. Consequently the WASM
//! module validates the complete self-describing body frame while node-core
//! separately authenticates the sender-owned source, enforces the committed
//! destination policy, and freezes metadata including both owners.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use fees::AssetId;
use protocol_types::{Digest32, HashAlgorithmId};
use std::{error::Error, fmt};

/// Canonical type ID for an asset-account body.
pub const ASSET_ACCOUNT_TYPE_ID: u16 = 0xF001;
/// Canonical type ID for transfer arguments.
pub const TRANSFER_ARGS_TYPE_ID: u16 = 0xF002;
/// Canonical type ID for a successful transfer event.
pub const TRANSFER_EVENT_TYPE_ID: u16 = 0xF003;
/// Encoding version shared by all local-devnet asset-account frames.
pub const ENCODING_VERSION: u16 = 1;

/// Exact encoded length of an asset-account body.
pub const ASSET_ACCOUNT_ENCODED_LEN: usize = 76;
/// Exact encoded length of transfer arguments.
pub const TRANSFER_ARGS_ENCODED_LEN: usize = 24;
/// Exact encoded length of a transfer event.
pub const TRANSFER_EVENT_ENCODED_LEN: usize = 90;

/// Preinstalled module name used by the local devnet catalog.
pub const MODULE_NAME: &str = "sunrise.devnet.asset_account.v1";
/// Only entrypoint exposed by the local devnet asset-account module.
pub const TRANSFER_ENTRYPOINT: &str = "transfer";
/// Canonical event type tag emitted after a successful transfer.
pub const TRANSFER_EVENT_TYPE_TAG: &[u8] = b"sunrise.devnet.asset_account.transferred.v1";

/// SHA-256 of `sunrise.devnet.asset.v1`, fixed as an opaque dev-profile ID.
pub const DEVNET_ASSET_ID_BYTES: [u8; 32] = [
    0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47, 0xBC, 0x11,
    0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B, 0x43, 0x3E, 0xA8,
];
/// Fixed non-zero asset ID shared by the seeded source and destination.
pub const DEVNET_ASSET_ID: AssetId = AssetId::new(DEVNET_ASSET_ID_BYTES);

/// SHA-256 of `sunrise.devnet.asset_account.v1`, fixed as a local type ID.
pub const ASSET_ACCOUNT_TYPE_HASH_BYTES: [u8; 32] = [
    0xD7, 0x4A, 0x09, 0x2B, 0x09, 0xFF, 0x86, 0xE0, 0x2C, 0xB8, 0x2C, 0xCD, 0x10, 0x58, 0xB1, 0xE9,
    0x9E, 0x74, 0x96, 0xBB, 0x03, 0x66, 0x69, 0x16, 0x49, 0xBD, 0x3E, 0xC1, 0x55, 0x36, 0x9A, 0x7F,
];

/// Returns the fixed self-describing local asset-account type hash.
///
/// This deliberately does not allocate a new protocol `HashPurpose`.
#[must_use]
pub const fn asset_account_type_hash() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, ASSET_ACCOUNT_TYPE_HASH_BYTES)
}

/// Exact committed WASM artifact generated from [`ASSET_ACCOUNT_WAT`].
pub const ASSET_ACCOUNT_WASM: &[u8] = include_bytes!("../modules/asset_account.wasm");
/// Auditable WAT source for [`ASSET_ACCOUNT_WASM`].
pub const ASSET_ACCOUNT_WAT: &str = include_str!("../modules/asset_account.wat");

/// One ordinary account for one fungible asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetAccount {
    /// Fungible asset represented by this account.
    pub asset_id: AssetId,
    /// Balance in the asset's canonical integer unit.
    pub balance: u64,
    /// Monotonic mutation sequence maintained by the module.
    pub sequence: u64,
}

impl AssetAccount {
    /// Creates an asset-account value.
    #[must_use]
    pub const fn new(asset_id: AssetId, balance: u64, sequence: u64) -> Self {
        Self {
            asset_id,
            balance,
            sequence,
        }
    }
}

/// Canonical arguments for one transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferArgs {
    /// Non-zero amount debited from source and credited to destination.
    pub amount: u64,
}

impl TransferArgs {
    /// Creates transfer arguments, rejecting the semantically invalid zero.
    pub const fn new(amount: u64) -> Result<Self, AssetAccountCodecError> {
        if amount == 0 {
            return Err(AssetAccountCodecError::ZeroTransferAmount);
        }
        Ok(Self { amount })
    }
}

/// Canonical data emitted by a successful transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferEvent {
    /// Asset moved by the transfer.
    pub asset_id: AssetId,
    /// Amount debited and credited.
    pub amount: u64,
    /// Source balance after the transfer.
    pub source_balance: u64,
    /// Destination balance after the transfer.
    pub destination_balance: u64,
}

/// Errors returned by strict local asset-account codecs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetAccountCodecError {
    /// Shared canonical framing failed while encoding.
    CanonicalEncoding(CanonicalEncodingError),
    /// Shared canonical framing or schema validation failed while decoding.
    CanonicalDecoding(CanonicalDecodingError),
    /// A transfer amount must be non-zero.
    ZeroTransferAmount,
}

impl fmt::Display for AssetAccountCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => error.fmt(formatter),
            Self::CanonicalDecoding(error) => error.fmt(formatter),
            Self::ZeroTransferAmount => formatter.write_str("transfer amount must be non-zero"),
        }
    }
}

impl Error for AssetAccountCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::ZeroTransferAmount => None,
        }
    }
}

impl From<CanonicalEncodingError> for AssetAccountCodecError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(error)
    }
}

impl From<CanonicalDecodingError> for AssetAccountCodecError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(error)
    }
}

/// Encodes an asset-account body with the shared canonical implementation.
pub fn encode_asset_account(account: &AssetAccount) -> Result<Vec<u8>, AssetAccountCodecError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(ASSET_ACCOUNT_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, *account.asset_id.as_bytes())?;
    frame.field_u64(2, account.balance)?;
    frame.field_u64(3, account.sequence)?;
    Ok(frame.finish()?)
}

/// Strictly decodes one complete asset-account body.
pub fn decode_asset_account(input: &[u8]) -> Result<AssetAccount, AssetAccountCodecError> {
    let frame: CanonicalFrame<'_> = decode_schema(input, ASSET_ACCOUNT_TYPE_ID, &[1, 2, 3])?;
    let asset_id: AssetId = decode_asset_id(&frame, 1)?;
    let balance: u64 = frame.required_u64(2)?;
    let sequence: u64 = frame.required_u64(3)?;
    Ok(AssetAccount::new(asset_id, balance, sequence))
}

/// Encodes non-zero transfer arguments.
pub fn encode_transfer_args(args: TransferArgs) -> Result<Vec<u8>, AssetAccountCodecError> {
    if args.amount == 0 {
        return Err(AssetAccountCodecError::ZeroTransferAmount);
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(TRANSFER_ARGS_TYPE_ID, ENCODING_VERSION);
    frame.field_u64(1, args.amount)?;
    Ok(frame.finish()?)
}

/// Strictly decodes non-zero transfer arguments.
pub fn decode_transfer_args(input: &[u8]) -> Result<TransferArgs, AssetAccountCodecError> {
    let frame: CanonicalFrame<'_> = decode_schema(input, TRANSFER_ARGS_TYPE_ID, &[1])?;
    TransferArgs::new(frame.required_u64(1)?)
}

/// Encodes one successful transfer event.
pub fn encode_transfer_event(event: &TransferEvent) -> Result<Vec<u8>, AssetAccountCodecError> {
    if event.amount == 0 {
        return Err(AssetAccountCodecError::ZeroTransferAmount);
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(TRANSFER_EVENT_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, *event.asset_id.as_bytes())?;
    frame.field_u64(2, event.amount)?;
    frame.field_u64(3, event.source_balance)?;
    frame.field_u64(4, event.destination_balance)?;
    Ok(frame.finish()?)
}

/// Strictly decodes one successful transfer event.
pub fn decode_transfer_event(input: &[u8]) -> Result<TransferEvent, AssetAccountCodecError> {
    let frame: CanonicalFrame<'_> = decode_schema(input, TRANSFER_EVENT_TYPE_ID, &[1, 2, 3, 4])?;
    let asset_id: AssetId = decode_asset_id(&frame, 1)?;
    let amount: u64 = frame.required_u64(2)?;
    if amount == 0 {
        return Err(AssetAccountCodecError::ZeroTransferAmount);
    }
    Ok(TransferEvent {
        asset_id,
        amount,
        source_balance: frame.required_u64(3)?,
        destination_balance: frame.required_u64(4)?,
    })
}

fn decode_schema<'a>(
    input: &'a [u8],
    type_id: u16,
    fields: &[u16],
) -> Result<CanonicalFrame<'a>, AssetAccountCodecError> {
    let frame: CanonicalFrame<'a> = decode_canonical_frame(input)?;
    frame.require_type(type_id)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(fields)?;
    Ok(frame)
}

fn decode_asset_id(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<AssetId, AssetAccountCodecError> {
    let bytes: &[u8] = frame.required_field(field_id)?;
    let fixed: [u8; 32] =
        bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id,
                expected: 32,
                actual: bytes.len(),
            })?;
    Ok(AssetId::new(fixed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution::{
        ExecutionEffects, ExecutionEngine, ExecutionStatus, ObjectEffect, ResolvedObject,
        WasmExecutionEngine,
    };
    use objects::{AccessMode, Address, Object, ObjectId, Owner};
    use protocol_types::ProtocolVersion;

    const ACCOUNT_VECTOR: [u8; ASSET_ACCOUNT_ENCODED_LEN] = [
        0x53, 0x4E, 0x52, 0x45, 0x01, 0xF0, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00,
        0x00, 0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47,
        0xBC, 0x11, 0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B,
        0x43, 0x3E, 0xA8, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x40, 0x42, 0x0F, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    const ARGS_VECTOR: [u8; TRANSFER_ARGS_ENCODED_LEN] = [
        0x53, 0x4E, 0x52, 0x45, 0x02, 0xF0, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
        0x00, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const EVENT_VECTOR: [u8; TRANSFER_EVENT_ENCODED_LEN] = [
        0x53, 0x4E, 0x52, 0x45, 0x03, 0xF0, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00,
        0x00, 0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47,
        0xBC, 0x11, 0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B,
        0x43, 0x3E, 0xA8, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x46, 0x41, 0x0F, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn canonical_stable_vectors_and_round_trips_are_fixed() {
        let account: AssetAccount = AssetAccount::new(DEVNET_ASSET_ID, 1_000_000, 7);
        let args: TransferArgs = TransferArgs::new(250).expect("non-zero stable amount");
        let event: TransferEvent = TransferEvent {
            asset_id: DEVNET_ASSET_ID,
            amount: 250,
            source_balance: 999_750,
            destination_balance: 250,
        };

        assert_eq!(encode_asset_account(&account).unwrap(), ACCOUNT_VECTOR);
        assert_eq!(encode_transfer_args(args).unwrap(), ARGS_VECTOR);
        assert_eq!(encode_transfer_event(&event).unwrap(), EVENT_VECTOR);
        assert_eq!(decode_asset_account(&ACCOUNT_VECTOR).unwrap(), account);
        assert_eq!(decode_transfer_args(&ARGS_VECTOR).unwrap(), args);
        assert_eq!(decode_transfer_event(&EVENT_VECTOR).unwrap(), event);
    }

    #[test]
    fn strict_decoders_reject_unknown_fields_and_zero_amount() {
        let mut unknown: CanonicalStruct =
            CanonicalStruct::new(ASSET_ACCOUNT_TYPE_ID, ENCODING_VERSION);
        unknown.field_bytes(1, DEVNET_ASSET_ID_BYTES).unwrap();
        unknown.field_u64(2, 1).unwrap();
        unknown.field_u64(3, 0).unwrap();
        unknown.field_u64(4, 0).unwrap();
        assert!(matches!(
            decode_asset_account(&unknown.finish().unwrap()),
            Err(AssetAccountCodecError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(4)
            ))
        ));

        let mut zero: CanonicalStruct =
            CanonicalStruct::new(TRANSFER_ARGS_TYPE_ID, ENCODING_VERSION);
        zero.field_u64(1, 0).unwrap();
        assert_eq!(
            decode_transfer_args(&zero.finish().unwrap()),
            Err(AssetAccountCodecError::ZeroTransferAmount)
        );

        let mut trailing: Vec<u8> = ACCOUNT_VECTOR.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_asset_account(&trailing),
            Err(AssetAccountCodecError::CanonicalDecoding(_))
        ));
    }

    #[test]
    fn committed_wasm_exactly_matches_a_fresh_wat_parse() {
        let rebuilt: Vec<u8> = wat::parse_str(ASSET_ACCOUNT_WAT).expect("valid committed WAT");
        assert_eq!(rebuilt, ASSET_ACCOUNT_WASM);
    }

    fn resolved_account(id_byte: u8, account: AssetAccount) -> ResolvedObject {
        ResolvedObject {
            object: Object {
                id: ObjectId::new([id_byte; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0xA1; 32])),
                type_hash: asset_account_type_hash(),
                schema_version: 1,
                data: encode_asset_account(&account).expect("valid test account"),
            },
            mode: AccessMode::Write,
        }
    }

    fn execute_committed_module(inputs: &[ResolvedObject], args: &[u8]) -> ExecutionEffects {
        WasmExecutionEngine
            .execute(
                ProtocolVersion::new(3),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x57; 32]),
                ASSET_ACCOUNT_WASM,
                TRANSFER_ENTRYPOINT,
                inputs,
                args,
                1_000_000,
            )
            .expect("module traps are deterministic execution outcomes")
    }

    fn assert_effect_free_rejection(effects: &ExecutionEffects) {
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
        assert!(effects.object_effects.is_empty());
        assert!(effects.events.is_empty());
    }

    #[test]
    fn committed_wasm_moves_one_asset_through_two_ordinary_accounts() {
        let source: ResolvedObject =
            resolved_account(0x11, AssetAccount::new(DEVNET_ASSET_ID, 1_000_000, 0));
        let destination: ResolvedObject =
            resolved_account(0x22, AssetAccount::new(DEVNET_ASSET_ID, 0, 0));
        let args: Vec<u8> =
            encode_transfer_args(TransferArgs::new(250).expect("non-zero transfer amount"))
                .expect("valid canonical arguments");
        let tx_hash: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]);

        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(3),
                tx_hash,
                ASSET_ACCOUNT_WASM,
                TRANSFER_ENTRYPOINT,
                &[source, destination],
                &args,
                1_000_000,
            )
            .expect("committed module executes");

        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 2);
        let expected_accounts: [AssetAccount; 2] = [
            AssetAccount::new(DEVNET_ASSET_ID, 999_750, 1),
            AssetAccount::new(DEVNET_ASSET_ID, 250, 1),
        ];
        for (effect, expected) in effects.object_effects.iter().zip(expected_accounts) {
            match effect {
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                } => {
                    assert_eq!(*previous_version, 1);
                    assert_eq!(new_object.version, 2);
                    assert_eq!(new_object.owner, Owner::Address(Address::new([0xA1; 32])));
                    assert_eq!(new_object.type_hash, asset_account_type_hash());
                    assert_eq!(new_object.schema_version, 1);
                    assert_eq!(decode_asset_account(&new_object.data).unwrap(), expected);
                }
                other => panic!("expected mutated asset account, got {other:?}"),
            }
        }
        assert_eq!(effects.events.len(), 1);
        assert_eq!(effects.events[0].type_tag, TRANSFER_EVENT_TYPE_TAG);
        assert_eq!(
            decode_transfer_event(&effects.events[0].data).unwrap(),
            TransferEvent {
                asset_id: DEVNET_ASSET_ID,
                amount: 250,
                source_balance: 999_750,
                destination_balance: 250,
            }
        );
    }

    #[test]
    fn committed_wasm_rejects_mixed_asset_ids_without_effects() {
        let source: ResolvedObject =
            resolved_account(0x11, AssetAccount::new(DEVNET_ASSET_ID, 1_000_000, 0));
        let other_asset: AssetId = AssetId::new([0x99; 32]);
        let destination: ResolvedObject =
            resolved_account(0x22, AssetAccount::new(other_asset, 0, 0));
        let args: Vec<u8> =
            encode_transfer_args(TransferArgs::new(250).expect("non-zero transfer amount"))
                .expect("valid canonical arguments");

        let effects: ExecutionEffects = execute_committed_module(&[source, destination], &args);

        assert_effect_free_rejection(&effects);
    }

    #[test]
    fn committed_wasm_rejects_every_conservation_boundary_without_effects() {
        let valid_args: Vec<u8> =
            encode_transfer_args(TransferArgs::new(1).expect("non-zero transfer amount")).unwrap();

        let mut zero_args: CanonicalStruct =
            CanonicalStruct::new(TRANSFER_ARGS_TYPE_ID, ENCODING_VERSION);
        zero_args.field_u64(1, 0).unwrap();
        let zero_args: Vec<u8> = zero_args.finish().unwrap();
        let source = resolved_account(0x11, AssetAccount::new(DEVNET_ASSET_ID, 1, 0));
        let destination = resolved_account(0x22, AssetAccount::new(DEVNET_ASSET_ID, 0, 0));
        assert_effect_free_rejection(&execute_committed_module(
            &[source.clone(), destination.clone()],
            &zero_args,
        ));

        let empty_source = resolved_account(0x11, AssetAccount::new(DEVNET_ASSET_ID, 0, 0));
        assert_effect_free_rejection(&execute_committed_module(
            &[empty_source, destination.clone()],
            &valid_args,
        ));

        let full_destination =
            resolved_account(0x22, AssetAccount::new(DEVNET_ASSET_ID, u64::MAX, 0));
        assert_effect_free_rejection(&execute_committed_module(
            &[source.clone(), full_destination],
            &valid_args,
        ));

        let exhausted_sequence =
            resolved_account(0x11, AssetAccount::new(DEVNET_ASSET_ID, 1, u64::MAX));
        assert_effect_free_rejection(&execute_committed_module(
            &[exhausted_sequence, destination.clone()],
            &valid_args,
        ));

        let mut malformed_body = source.clone();
        malformed_body.object.data[0] ^= 0xFF;
        assert_effect_free_rejection(&execute_committed_module(
            &[malformed_body, destination.clone()],
            &valid_args,
        ));
        assert_effect_free_rejection(&execute_committed_module(
            &[source.clone(), destination],
            &[0; TRANSFER_ARGS_ENCODED_LEN],
        ));
        assert_effect_free_rejection(&execute_committed_module(&[source], &valid_args));
    }
}
