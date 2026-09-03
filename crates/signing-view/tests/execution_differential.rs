//! Differential tests against `execution`, the crate that owns the
//! authoritative Transaction v1 wire format.
//!
//! `signing-view` intentionally does not depend on `execution` (see the
//! crate-level documentation): it independently reimplements the strict
//! `TransactionSignable` decode/encode. These tests are the proof that the
//! reimplementation agrees byte-for-byte with `execution`'s own
//! `encode_transaction_signable` for the same logical transaction, and that
//! `signing_view::decode_transaction_signable` recovers the exact same
//! field values `execution::decode_transaction` would. `execution` is a
//! `[dev-dependencies]`-only dependency of this crate (see `Cargo.toml`):
//! nothing in `src/` depends on it.

use abi::{AccessEntry, AccessManifest};
use execution::{Transaction, encode_transaction_signable as execution_encode_signable};
use fees::{Amount, AssetId, FeePayment};
use objects::{AccessMode, Address, ObjectId, ObjectRef};
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion};
use signing_view::{
    DeviceSigningProfile, TransactionSignable, decode_transaction_signable,
    encode_transaction_signable,
};

fn sample_object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
    }
}

fn to_signable(tx: &Transaction) -> TransactionSignable {
    TransactionSignable {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        sender: tx.sender,
        nonce: tx.nonce,
        access_manifest: tx.access_manifest.clone(),
        module_ref: tx.module_ref.clone(),
        entrypoint: tx.entrypoint.clone(),
        args: tx.args.clone(),
        gas_limit: tx.gas_limit,
        fee_payment: tx.fee_payment.clone(),
    }
}

fn base_transaction() -> Transaction {
    Transaction {
        chain_id: ChainId::new("sunrise-local-devnet").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(5),
        sender: Address::new([0x01; 32]),
        nonce: 1,
        access_manifest: AccessManifest::new(),
        module_ref: sample_object_ref(0x02, 1, 0x03),
        entrypoint: "noop".to_string(),
        args: vec![1, 2, 3],
        gas_limit: 1_000,
        fee_payment: None,
        signature: Vec::new(),
    }
}

fn sample_transactions() -> Vec<Transaction> {
    let mut with_manifest = base_transaction();
    with_manifest.access_manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x11, 4, 0x12),
        mode: AccessMode::Write,
    });
    with_manifest.access_manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x21, 9, 0x22),
        mode: AccessMode::Read,
    });

    let mut with_fee = base_transaction();
    with_fee.fee_payment = Some(FeePayment {
        asset_id: AssetId::new([0x33; 32]),
        max_fee: Amount::new(7),
        fee_object: sample_object_ref(0x44, 2, 0x45),
    });

    let mut empty_args = base_transaction();
    empty_args.args = Vec::new();

    let mut consume_entry = base_transaction();
    consume_entry.access_manifest.push(AccessEntry {
        object_ref: sample_object_ref(0x55, 1, 0x56),
        mode: AccessMode::Consume,
    });

    vec![
        base_transaction(),
        with_manifest,
        with_fee,
        empty_args,
        consume_entry,
    ]
}

#[test]
fn signable_encoding_matches_execution_crate_byte_for_byte() {
    for tx in sample_transactions() {
        let execution_bytes = execution_encode_signable(&tx).unwrap();
        let signing_view_bytes = encode_transaction_signable(&to_signable(&tx)).unwrap();

        assert_eq!(
            execution_bytes, signing_view_bytes,
            "diverged for entrypoint {:?}",
            tx.entrypoint
        );
    }
}

#[test]
fn decode_transaction_signable_recovers_the_exact_execution_crate_fields() {
    for tx in sample_transactions() {
        let execution_bytes = execution_encode_signable(&tx).unwrap();

        let decoded = decode_transaction_signable(&execution_bytes, &DeviceSigningProfile::V1)
            .unwrap_or_else(|error| {
                panic!("decode failed for entrypoint {:?}: {error}", tx.entrypoint)
            });

        assert_eq!(decoded, to_signable(&tx));
    }
}
