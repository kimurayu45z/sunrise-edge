//! Adversarial coverage for the strict `TransactionSignable` decoder, the
//! exact-match `ClearSigningPolicy`, and the end-to-end
//! `build_clear_signing_view` boundary.

use abi::{AccessEntry, AccessManifest, encode_access_manifest};
use canonical_encoding::{CanonicalDecodingError, CanonicalStruct};
use crypto::{CryptoError, SignatureDomain, SignatureMessageType, frame_signature_message};
use fees::{Amount, AssetId, FeePayment, encode_fee_payment};
use objects::{AccessMode, Address, ObjectId, ObjectRef, encode_object_ref};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion, SignatureSchemeId,
};
use signing_view::{
    ClearSigningPolicyError, DEVNET_ASSET_TRANSFER_POLICY, DeviceSigningProfile, SigningViewError,
    TransactionSignable, build_clear_signing_view, decode_transaction_signable,
    encode_transaction_signable,
};

const TRANSACTION_TYPE_ID: u16 = 0x6001;
const ENCODING_VERSION: u16 = 1;
const PROFILE: DeviceSigningProfile = DeviceSigningProfile::V1;

fn sample_object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
    }
}

fn recognized_args(amount: u64) -> Vec<u8> {
    let mut canonical = CanonicalStruct::new(
        DEVNET_ASSET_TRANSFER_POLICY.args_type_id(),
        DEVNET_ASSET_TRANSFER_POLICY.args_version(),
    );
    canonical
        .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), amount)
        .unwrap();
    canonical.finish().unwrap()
}

fn recognized_module_ref() -> ObjectRef {
    ObjectRef {
        id: ObjectId::new(DEVNET_ASSET_TRANSFER_POLICY.module_id()),
        version: DEVNET_ASSET_TRANSFER_POLICY.module_version(),
        digest: Digest32::new(
            DEVNET_ASSET_TRANSFER_POLICY.code_digest_algorithm(),
            DEVNET_ASSET_TRANSFER_POLICY.code_digest_bytes(),
        ),
    }
}

fn sample_tx() -> TransactionSignable {
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x11, 1, 0x12),
        mode: AccessMode::Write,
    });
    manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x21, 2, 0x22),
        mode: AccessMode::Write,
    });
    manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x31, 3, 0x32),
        mode: AccessMode::Write,
    });

    let source_ref: ObjectRef = manifest.entries[0].object_ref.clone();

    TransactionSignable {
        chain_id: ChainId::new("sunrise-local-devnet").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(0),
        sender: Address::new([0x01; 32]),
        nonce: 1,
        access_manifest: manifest,
        module_ref: recognized_module_ref(),
        entrypoint: DEVNET_ASSET_TRANSFER_POLICY.entrypoint().to_string(),
        args: recognized_args(1_000_000),
        gas_limit: 1_000,
        fee_payment: Some(FeePayment {
            asset_id: AssetId::new(DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id()),
            max_fee: Amount::new(1_001),
            fee_object: source_ref,
        }),
    }
}

fn wrap_signed(payload: &[u8]) -> Vec<u8> {
    let domain = SignatureDomain {
        chain_id: ChainId::new("sunrise-local-devnet").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(0),
        message_type: SignatureMessageType::new("transaction-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    frame_signature_message(&domain, payload).unwrap()
}

/// Hand-builds a `TransactionSignable` frame field by field, so adversarial
/// tests can omit required fields, add unknown ones (including field 12,
/// which a `TransactionSignable` never carries), or splice in raw bytes the
/// safe [`encode_transaction_signable`] wrapper could never produce.
fn manual_signable_frame(
    tx: &TransactionSignable,
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
            12 => canonical.field_bytes(12, vec![0xAB; 64]).unwrap(),
            other => canonical.field_bytes(other, Vec::<u8>::new()).unwrap(),
        }
    }
    canonical.finish().unwrap()
}

/// Scans a valid canonical frame's field headers and returns the byte
/// offset of the requested field's 2-byte id header, mirroring
/// `execution`'s own adversarial-test helper.
fn field_id_offset(encoded: &[u8], field_id: u16) -> usize {
    const FRAME_HEADER_BYTES: usize = 10;
    const FIELD_HEADER_BYTES: usize = 6;
    let mut offset: usize = FRAME_HEADER_BYTES;
    loop {
        let current_id = u16::from_le_bytes([encoded[offset], encoded[offset + 1]]);
        if current_id == field_id {
            return offset;
        }
        let length = u32::from_le_bytes([
            encoded[offset + 2],
            encoded[offset + 3],
            encoded[offset + 4],
            encoded[offset + 5],
        ]) as usize;
        offset += FIELD_HEADER_BYTES + length;
    }
}

const ALL_FIELDS: [u16; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

// ── struct-shape adversarial cases ──────────────────────────────────────

#[test]
fn rejects_wrong_struct_type_id() {
    let tx = sample_tx();
    let mut wrong = CanonicalStruct::new(0x9999, ENCODING_VERSION);
    wrong.field_str(1, tx.chain_id.as_str()).unwrap();
    wrong.field_u32(2, tx.protocol_version.get()).unwrap();
    wrong.field_u64(3, tx.epoch.get()).unwrap();
    wrong.field_bytes(4, tx.sender.as_bytes()).unwrap();
    wrong.field_u64(5, tx.nonce).unwrap();
    wrong
        .field_bytes(6, encode_access_manifest(&tx.access_manifest).unwrap())
        .unwrap();
    wrong
        .field_bytes(7, encode_object_ref(&tx.module_ref).unwrap())
        .unwrap();
    wrong.field_str(8, &tx.entrypoint).unwrap();
    wrong.field_bytes(9, tx.args.as_slice()).unwrap();
    wrong.field_u64(10, tx.gas_limit).unwrap();
    let encoded = wrong.finish().unwrap();

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId {
                expected: TRANSACTION_TYPE_ID,
                actual: 0x9999,
            }
        ))
    );
}

#[test]
fn rejects_wrong_encoding_version() {
    let tx = sample_tx();
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);
    // Encoding version lives right after the type id in the frame header.
    let mut wrong_version = encoded.clone();
    wrong_version[6..8].copy_from_slice(&2_u16.to_le_bytes());

    assert_eq!(
        decode_transaction_signable(&wrong_version, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: ENCODING_VERSION,
                actual: 2,
            }
        ))
    );
}

#[test]
fn rejects_a_missing_required_field() {
    let tx = sample_tx();
    let fields: Vec<u16> = ALL_FIELDS.iter().copied().filter(|&f| f != 5).collect();
    let encoded = manual_signable_frame(&tx, &fields, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::MissingField(5)
        ))
    );
}

#[test]
fn rejects_an_unknown_field() {
    let tx = sample_tx();
    let mut fields = ALL_FIELDS.to_vec();
    fields.push(13);
    let encoded = manual_signable_frame(&tx, &fields, &[(13, b"unexpected".to_vec())]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(13)
        ))
    );
}

#[test]
fn rejects_field_12_the_signature_field() {
    let tx = sample_tx();
    let mut fields = ALL_FIELDS.to_vec();
    fields.push(12);
    let encoded = manual_signable_frame(&tx, &fields, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(12)
        ))
    );
}

#[test]
fn rejects_a_duplicate_field_id() {
    let tx = sample_tx();
    let mut encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);
    let field_2_offset = field_id_offset(&encoded, 2);
    encoded[field_2_offset..field_2_offset + 2].copy_from_slice(&1_u16.to_le_bytes());

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 1,
                current: 1,
            }
        ))
    );
}

#[test]
fn rejects_an_out_of_order_field_id() {
    let tx = sample_tx();
    let mut encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);
    let field_7_offset = field_id_offset(&encoded, 7);
    encoded[field_7_offset..field_7_offset + 2].copy_from_slice(&3_u16.to_le_bytes());

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 6,
                current: 3,
            }
        ))
    );
}

#[test]
fn rejects_trailing_bytes() {
    let tx = sample_tx();
    let mut encoded = encode_transaction_signable(&tx).unwrap();
    encoded.push(0xFF);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::CanonicalDecoding(
            CanonicalDecodingError::TrailingBytes(1)
        ))
    );
}

// ── device-profile bounds ───────────────────────────────────────────────

#[test]
fn rejects_a_complete_frame_over_the_device_bound_before_decoding() {
    let framed = vec![0_u8; PROFILE.max_framed_message_bytes() + 1];
    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::FramedMessageTooLarge {
            actual: PROFILE.max_framed_message_bytes() + 1,
            maximum: PROFILE.max_framed_message_bytes(),
        })
    );
}

#[test]
fn rejects_an_inner_payload_over_the_device_bound_before_transaction_decoding() {
    let payload = vec![0_u8; PROFILE.max_transaction_payload_bytes() + 1];
    let framed = wrap_signed(&payload);
    assert!(framed.len() <= PROFILE.max_framed_message_bytes());
    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::TransactionPayloadTooLarge {
            actual: PROFILE.max_transaction_payload_bytes() + 1,
            maximum: PROFILE.max_transaction_payload_bytes(),
        })
    );
}

#[test]
fn rejects_a_chain_id_over_the_device_bound() {
    let mut tx = sample_tx();
    tx.chain_id = ChainId::new("x".repeat(PROFILE.max_chain_id_bytes() + 1)).unwrap();
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::FieldTooLarge {
            field: "chain_id",
            actual: PROFILE.max_chain_id_bytes() + 1,
            maximum: PROFILE.max_chain_id_bytes(),
        })
    );
}

#[test]
fn rejects_an_entrypoint_over_the_device_bound() {
    let mut tx = sample_tx();
    tx.entrypoint = "e".repeat(PROFILE.max_entrypoint_bytes() + 1);
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::FieldTooLarge {
            field: "entrypoint",
            actual: PROFILE.max_entrypoint_bytes() + 1,
            maximum: PROFILE.max_entrypoint_bytes(),
        })
    );
}

#[test]
fn rejects_an_empty_entrypoint() {
    let mut tx = sample_tx();
    tx.entrypoint = String::new();
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::EmptyEntrypoint)
    );
}

#[test]
fn rejects_args_over_the_device_bound() {
    let mut tx = sample_tx();
    tx.args = vec![0u8; PROFILE.max_args_bytes() + 1];
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::FieldTooLarge {
            field: "args",
            actual: PROFILE.max_args_bytes() + 1,
            maximum: PROFILE.max_args_bytes(),
        })
    );
}

#[test]
fn rejects_more_manifest_entries_than_the_device_bound() {
    let mut tx = sample_tx();
    tx.access_manifest = AccessManifest::new();
    for index in 0..=PROFILE.max_manifest_entries() {
        tx.access_manifest.push(AccessEntry {
            object_ref: sample_object_ref(index as u8 + 1, 1, index as u8 + 1),
            mode: AccessMode::Write,
        });
    }
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::TooManyManifestEntries {
            actual: PROFILE.max_manifest_entries() + 1,
            maximum: PROFILE.max_manifest_entries(),
        })
    );
}

#[test]
fn rejects_duplicate_manifest_objects() {
    let mut tx = sample_tx();
    tx.access_manifest = AccessManifest::new();
    tx.access_manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x77, 1, 0x78),
        mode: AccessMode::Write,
    });
    tx.access_manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x77, 2, 0x79),
        mode: AccessMode::Read,
    });
    let encoded = manual_signable_frame(&tx, &ALL_FIELDS, &[]);

    assert_eq!(
        decode_transaction_signable(&encoded, &PROFILE),
        Err(SigningViewError::Abi(abi::AbiError::DuplicateObjectId(
            ObjectId::new([0x77; 32])
        )))
    );
}

// ── outer signature-frame checks ────────────────────────────────────────

#[test]
fn rejects_an_unsupported_message_type() {
    let tx = sample_tx();
    let payload = encode_transaction_signable(&tx).unwrap();
    let domain = SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        message_type: SignatureMessageType::new("vote").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    let framed = frame_signature_message(&domain, &payload).unwrap();

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::UnsupportedMessageType("vote".to_string()))
    );
}

#[test]
fn rejects_an_unsupported_signature_scheme() {
    let tx = sample_tx();
    let payload = encode_transaction_signable(&tx).unwrap();
    let domain = SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        message_type: SignatureMessageType::new("transaction-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Secp256k1,
    };
    let framed = frame_signature_message(&domain, &payload).unwrap();

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::UnsupportedSignatureScheme(
            SignatureSchemeId::Secp256k1
        ))
    );
}

#[test]
fn rejects_a_transaction_payload_chain_id_that_disagrees_with_the_outer_frame() {
    let mut tx = sample_tx();
    tx.chain_id = ChainId::new("some-other-chain").unwrap();
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::SignedContextMismatch { field: "chain_id" })
    );
}

#[test]
fn rejects_a_transaction_payload_protocol_version_that_disagrees_with_the_outer_frame() {
    let mut tx = sample_tx();
    tx.protocol_version = ProtocolVersion::new(4);
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::SignedContextMismatch {
            field: "protocol_version"
        })
    );
}

#[test]
fn rejects_a_transaction_payload_epoch_that_disagrees_with_the_outer_frame() {
    let mut tx = sample_tx();
    tx.epoch = Epoch::new(6);
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::SignedContextMismatch { field: "epoch" })
    );
}

#[test]
fn propagates_outer_frame_decode_failures_typed() {
    // A signature frame is itself just a canonical struct; corrupting its
    // magic must surface as this crate's own typed error, not a panic.
    let tx = sample_tx();
    let payload = encode_transaction_signable(&tx).unwrap();
    let mut framed = wrap_signed(&payload);
    framed[0] ^= 0xFF;

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::Crypto(CryptoError::CanonicalDecoding(
            CanonicalDecodingError::InvalidMagic
        )))
    );
}

// ── recognized-module policy adversarial cases ──────────────────────────

#[test]
fn recognizes_the_exact_devnet_transfer_shape() {
    let tx = sample_tx();
    assert_eq!(DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx), Ok(1_000_000));
}

#[test]
fn rejects_a_different_chain_even_when_both_signed_context_copies_match() {
    let mut tx = sample_tx();
    tx.chain_id = ChainId::new("another-chain").unwrap();
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ChainId)
    );
}

#[test]
fn rejects_a_different_protocol_version_under_the_reference_policy() {
    let mut tx = sample_tx();
    tx.protocol_version = ProtocolVersion::new(4);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ProtocolVersion)
    );
}

#[test]
fn rejects_a_different_epoch_under_the_reference_policy() {
    let mut tx = sample_tx();
    tx.epoch = Epoch::new(1);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::Epoch)
    );
}

#[test]
fn does_not_recognize_a_wrong_module_id() {
    let mut tx = sample_tx();
    tx.module_ref.id = ObjectId::new([0xEE; 32]);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ModuleId)
    );
}

#[test]
fn does_not_recognize_a_wrong_module_version() {
    let mut tx = sample_tx();
    tx.module_ref.version += 1;
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ModuleVersion)
    );
}

#[test]
fn does_not_recognize_a_wrong_digest_algorithm() {
    let mut tx = sample_tx();
    tx.module_ref.digest = Digest32::new(HashAlgorithmId::Sha3_256, tx.module_ref.digest.bytes());
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ModuleDigestAlgorithm)
    );
}

#[test]
fn does_not_recognize_wrong_digest_bytes() {
    let mut tx = sample_tx();
    let mut bytes = tx.module_ref.digest.bytes();
    bytes[0] ^= 0xFF;
    tx.module_ref.digest = Digest32::new(tx.module_ref.digest.algorithm(), bytes);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ModuleDigest)
    );
}

#[test]
fn does_not_recognize_a_wrong_entrypoint() {
    let mut tx = sample_tx();
    tx.entrypoint = "not_transfer".to_string();
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::Entrypoint)
    );
}

#[test]
fn rejects_a_non_transfer_access_shape() {
    let mut tx = sample_tx();
    tx.access_manifest.entries[1].mode = AccessMode::Read;
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::AccessShape)
    );
}

#[test]
fn rejects_a_transfer_without_fee_authorization() {
    let mut tx = sample_tx();
    tx.fee_payment = None;
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::FeeRequired)
    );
}

#[test]
fn rejects_a_fee_object_other_than_the_source() {
    let mut tx = sample_tx();
    tx.fee_payment.as_mut().unwrap().fee_object = tx.access_manifest.entries[1].object_ref.clone();
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::FeeObjectMismatch)
    );
}

#[test]
fn rejects_an_unrecognized_fee_asset() {
    let mut tx = sample_tx();
    tx.fee_payment.as_mut().unwrap().asset_id = AssetId::new([0xFE; 32]);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::FeeAsset)
    );
}

#[test]
fn does_not_recognize_a_wrong_args_type_id() {
    let mut tx = sample_tx();
    let mut wrong = CanonicalStruct::new(0xF003, DEVNET_ASSET_TRANSFER_POLICY.args_version());
    wrong
        .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), 5)
        .unwrap();
    tx.args = wrong.finish().unwrap();
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ArgumentsTypeId(0xF003))
    );
}

#[test]
fn does_not_recognize_a_wrong_args_version() {
    let mut tx = sample_tx();
    let mut wrong = CanonicalStruct::new(DEVNET_ASSET_TRANSFER_POLICY.args_type_id(), 2);
    wrong
        .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), 5)
        .unwrap();
    tx.args = wrong.finish().unwrap();
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ArgumentsVersion(2))
    );
}

#[test]
fn does_not_recognize_a_wrong_args_field_shape() {
    let mut tx = sample_tx();
    // Correct type/version, but the value lives under field 2, not field 1.
    let mut wrong = CanonicalStruct::new(
        DEVNET_ASSET_TRANSFER_POLICY.args_type_id(),
        DEVNET_ASSET_TRANSFER_POLICY.args_version(),
    );
    wrong.field_u64(2, 5).unwrap();
    tx.args = wrong.finish().unwrap();
    assert!(matches!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ArgumentsShape(_))
    ));
}

#[test]
fn does_not_recognize_an_extra_args_field() {
    let mut tx = sample_tx();
    let mut wrong = CanonicalStruct::new(
        DEVNET_ASSET_TRANSFER_POLICY.args_type_id(),
        DEVNET_ASSET_TRANSFER_POLICY.args_version(),
    );
    wrong
        .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), 5)
        .unwrap();
    wrong.field_u64(2, 1).unwrap();
    tx.args = wrong.finish().unwrap();
    assert!(matches!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ArgumentsShape(_))
    ));
}

#[test]
fn does_not_recognize_a_malformed_zero_amount() {
    let mut tx = sample_tx();
    tx.args = recognized_args(0);
    assert_eq!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ZeroAmount)
    );
}

#[test]
fn does_not_recognize_opaque_non_canonical_args() {
    let mut tx = sample_tx();
    tx.args = b"not-a-frame".to_vec();
    assert!(matches!(
        DEVNET_ASSET_TRANSFER_POLICY.recognize(&tx),
        Err(ClearSigningPolicyError::ArgumentsEncoding(_))
    ));
}

#[test]
fn unrecognized_args_are_rejected_without_a_raw_fallback() {
    let mut tx = sample_tx();
    tx.args = recognized_args(0);
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());

    assert_eq!(
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY),
        Err(SigningViewError::Policy(
            ClearSigningPolicyError::ZeroAmount
        ))
    );
}

// ── mutation and host-metadata isolation ────────────────────────────────

#[test]
fn every_single_byte_mutation_changes_or_rejects_the_view() {
    let tx = sample_tx();
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());
    let original =
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY).unwrap();

    for index in 0..framed.len() {
        let mut mutated = framed.clone();
        mutated[index] ^= 0xFF;
        if let Ok(view) =
            build_clear_signing_view(&mutated, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY)
        {
            assert_ne!(
                view, original,
                "byte {index} mutation produced an unchanged view"
            );
        }
    }
}

#[test]
fn view_contains_no_unsigned_host_metadata_tokens() {
    let tx = sample_tx();
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());
    let view = build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY).unwrap();

    let forbidden = [
        "request_id",
        "destination_owner",
        "owner=",
        "symbol",
        "sunrise.devnet.asset_account",
        "module_name",
    ];
    for token in forbidden {
        assert!(
            !view.lines().iter().any(|line| line.contains(token)),
            "unexpected unsigned-metadata token `{token}` in view"
        );
    }
}

#[test]
fn identical_signed_bytes_render_identically_regardless_of_unrelated_call_context() {
    let tx = sample_tx();
    let framed = wrap_signed(&encode_transaction_signable(&tx).unwrap());

    let first = build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY).unwrap();

    // `build_clear_signing_view` accepts no request id, owner, or symbol
    // parameter at all — there is no host channel through which unrelated
    // per-call context like the values below could reach the rendered view.
    let _unrelated_request_id: u64 = 0xFFFF_FFFF;
    let _unrelated_destination_owner = Address::new([0xEE; 32]);

    let second =
        build_clear_signing_view(&framed, &PROFILE, &DEVNET_ASSET_TRANSFER_POLICY).unwrap();

    assert_eq!(first, second);
}
