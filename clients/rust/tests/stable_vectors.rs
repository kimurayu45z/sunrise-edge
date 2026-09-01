//! Stable vectors shared with `node_core::transaction_auth`.
//!
//! `STABLE_VECTOR_SIGNED_TX_HEX` is copied verbatim from
//! `crates/node-core/src/transaction_auth.rs`'s own
//! `stable_vector_signed_transaction_authenticates_from_pinned_bytes` test.
//! That test proves node-core accepts these exact bytes; this test proves
//! `sunrise_edge_client::build_signed_transaction` *produces* those exact
//! bytes from the same seed and transaction shape, and additionally proves
//! acceptance directly by calling `node_core::authenticate_transaction_bytes`
//! itself. Together they pin one canonical contract from both sides without
//! either crate depending on the other's test code.

use abi::AccessManifest;
use ed25519_zebra::SigningKey;
use objects::{Address, ObjectId, ObjectRef};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, TransactionAuthProfile};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion,
    SignatureSchemeId,
};
use sunrise_edge_client::{LocalSigner, TransactionRequest, build_signed_transaction};

const STABLE_VECTOR_SEED: u8 = 0xAB;

/// Exact canonical-encoded, signed stable-vector transaction bytes, pinned
/// verbatim from `node_core::transaction_auth`'s own
/// `STABLE_VECTOR_SIGNED_TX_HEX`.
const STABLE_VECTOR_SIGNED_TX_HEX: &str = "534e5245016001000b0001000e00000073756e726973652d6465766e6574020004000000030000000300080000000500000000000000040020000000248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd9300500080000000100000000000000060014000000534e52450250010001000100040000000000000007008c000000534e5245044001000300010030000000534e524501400100010001002000000000000000000000000000000000000000000000000000000000000000000000000200080000000100000000000000030038000000534e5245030101000200010002000000010002002000000000000000000000000000000000000000000000000000000000000000000000000800040000006e6f6f700900030000000102030a0008000000e8030000000000000c0040000000480cbb90e331345d311713e86e5b1fc3087e6bd800f3efac6cf47e3486f00f935bd13b5ae5cccc4a00af614a24c7fc045b6754316ea9bbbea65546ad80ad320b";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex literal must have an even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn stable_vector_sender() -> Address {
    let signing_key = SigningKey::from([STABLE_VECTOR_SEED; 32]);
    let verification_key = ed25519_zebra::VerificationKey::from(&signing_key);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(verification_key.as_ref());
    Address::new(bytes)
}

fn stable_vector_request() -> TransactionRequest {
    TransactionRequest {
        chain_id: ChainId::new("sunrise-devnet").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(5),
        nonce: 1,
        access_manifest: AccessManifest::new(),
        module_ref: ObjectRef {
            id: ObjectId::new([0_u8; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0_u8; 32]),
        },
        entrypoint: "noop".to_string(),
        args: vec![1, 2, 3],
        gas_limit: 1_000,
        fee_payment: None,
    }
}

fn active_protocol_config() -> ProtocolConfig {
    let mut config = ProtocolConfig::genesis();
    config.protocol_version = ProtocolVersion::new(3);
    config.domain_placement = Some(
        DomainPlacementManifest::single_domain(
            1,
            AtomicityDomainId::new([0x22; 32]).unwrap(),
            Epoch::new(0),
        )
        .unwrap(),
    );
    config.transaction_auth_profile = Some(TransactionAuthProfile::ed25519_address_is_public_key());
    config
}

#[test]
fn client_produces_the_exact_node_core_stable_vector_bytes() {
    let signer = LocalSigner::from_seed([STABLE_VECTOR_SEED; 32]);
    assert_eq!(signer.address(), stable_vector_sender());

    let bytes =
        build_signed_transaction(&signer, SignatureSchemeId::Ed25519, stable_vector_request())
            .unwrap();

    assert_eq!(bytes_to_hex(&bytes), STABLE_VECTOR_SIGNED_TX_HEX);
}

#[test]
fn client_produced_bytes_authenticate_against_node_core_directly() {
    let signer = LocalSigner::from_seed([STABLE_VECTOR_SEED; 32]);
    let bytes =
        build_signed_transaction(&signer, SignatureSchemeId::Ed25519, stable_vector_request())
            .unwrap();

    let config = active_protocol_config();
    let context = node_core::TrustedTransactionContext::new(
        ChainId::new("sunrise-devnet").unwrap(),
        Epoch::new(5),
        &config,
    );

    let authenticated = node_core::authenticate_transaction_bytes(&bytes, &context).unwrap();
    assert_eq!(authenticated.transaction().sender, stable_vector_sender());
    assert_eq!(authenticated.transaction().nonce, 1);
    assert_eq!(authenticated.transaction().entrypoint, "noop");
}

#[test]
fn pinned_hex_vector_decodes_to_bytes_matching_the_freshly_signed_ones() {
    let signer = LocalSigner::from_seed([STABLE_VECTOR_SEED; 32]);
    let fresh =
        build_signed_transaction(&signer, SignatureSchemeId::Ed25519, stable_vector_request())
            .unwrap();
    assert_eq!(fresh, hex_to_bytes(STABLE_VECTOR_SIGNED_TX_HEX));
}
