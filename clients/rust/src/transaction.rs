//! Canonical Transaction v1 construction and signing.

use crypto::{SignatureDomain, SignatureMessageType, SignatureSigner};
use execution::{Transaction, encode_transaction, encode_transaction_signable};
use node_core::TRANSACTION_V1_MESSAGE_TYPE;
use objects::ObjectRef;
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId};

use crate::error::ClientError;
use crate::key::LocalSigner;

/// Explicit, caller-supplied inputs for one canonical Transaction v1.
///
/// Every reference here — the access manifest and the module reference — is
/// exactly what the caller supplies. This builder invents no object
/// discovery, module lookup, or asset-specific defaults; that is deliberate
/// (see `ARCHITECTURE.md` §44 / DR-0083).
pub struct TransactionRequest {
    /// Chain replay-protection identifier. Must match the trusted
    /// `/v1/context` chain id.
    pub chain_id: ChainId,
    /// Protocol version replay protection. Must match the committed
    /// `ProtocolConfig` version reported by `/v1/context`.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay protection. Must match the trusted current epoch.
    pub epoch: Epoch,
    /// Sender nonce for intra-epoch replay protection. Callers should read
    /// this from `/v1/senders/{sender}/next-nonce` immediately before
    /// building the transaction.
    pub nonce: u64,
    /// All objects the transaction may access, with their access modes.
    pub access_manifest: abi::AccessManifest,
    /// Caller-supplied reference to the module/entrypoint to execute.
    pub module_ref: ObjectRef,
    /// Entry-point function to invoke inside the module.
    pub entrypoint: String,
    /// Canonically encoded arguments passed to the entry-point.
    pub args: Vec<u8>,
    /// Maximum gas units the sender is willing to spend.
    pub gas_limit: u64,
    /// Stablecoin-denominated fee payment authorization, if any. The
    /// Developer MVP devnet's fee registry is empty and every transaction
    /// commits with `fee_payment: None`.
    pub fee_payment: Option<fees::FeePayment>,
}

/// Builds and signs one canonical Transaction v1 under the exact stable
/// `"transaction-v1"` message family
/// ([`node_core::TRANSACTION_V1_MESSAGE_TYPE`]) and returns its exact
/// canonical wire bytes, ready to submit as a `SubmitTransaction` event.
///
/// `signature_scheme_id` must come from a trusted `/v1/context` query
/// result; this function never guesses or defaults the active scheme, and
/// [`crypto::SignatureSigner::sign_canonical`] rejects a scheme mismatch
/// between `signer` and `signature_scheme_id` before any framing or signing
/// work runs.
pub fn build_signed_transaction(
    signer: &LocalSigner,
    signature_scheme_id: SignatureSchemeId,
    request: TransactionRequest,
) -> Result<Vec<u8>, ClientError> {
    let TransactionRequest {
        chain_id,
        protocol_version,
        epoch,
        nonce,
        access_manifest,
        module_ref,
        entrypoint,
        args,
        gas_limit,
        fee_payment,
    } = request;

    let unsigned = Transaction {
        chain_id: chain_id.clone(),
        protocol_version,
        epoch,
        sender: signer.address(),
        nonce,
        access_manifest,
        module_ref,
        entrypoint,
        args,
        gas_limit,
        fee_payment,
        signature: Vec::new(),
    };

    let signable = encode_transaction_signable(&unsigned)?;
    let domain = SignatureDomain {
        chain_id,
        protocol_version,
        epoch,
        message_type: SignatureMessageType::new(TRANSACTION_V1_MESSAGE_TYPE)?,
        signature_scheme_id,
    };
    let signature = signer.sign_canonical(&domain, &signable)?;

    let mut signed = unsigned;
    signed.signature = signature;
    Ok(encode_transaction(&signed)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::AccessManifest;
    use execution::decode_transaction;
    use objects::ObjectId;
    use protocol_types::{Digest32, HashAlgorithmId};

    fn sample_module_ref() -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([0x02; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
        }
    }

    fn base_request() -> TransactionRequest {
        TransactionRequest {
            chain_id: ChainId::new("sunrise-devnet").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(5),
            nonce: 1,
            access_manifest: AccessManifest::new(),
            module_ref: sample_module_ref(),
            entrypoint: "noop".to_string(),
            args: vec![1, 2, 3],
            gas_limit: 1_000,
            fee_payment: None,
        }
    }

    #[test]
    fn builds_a_decodable_self_consistent_transaction() {
        let signer = LocalSigner::from_seed([0xAB; 32]);
        let bytes =
            build_signed_transaction(&signer, SignatureSchemeId::Ed25519, base_request()).unwrap();

        let decoded = decode_transaction(&bytes).unwrap();
        assert_eq!(decoded.sender, signer.address());
        assert_eq!(decoded.nonce, 1);
        assert_eq!(decoded.entrypoint, "noop");
        assert_eq!(decoded.args, vec![1, 2, 3]);
        assert!(!decoded.signature.is_empty());
    }

    #[test]
    fn same_inputs_produce_deterministic_bytes() {
        let signer = LocalSigner::from_seed([0xAC; 32]);
        let left =
            build_signed_transaction(&signer, SignatureSchemeId::Ed25519, base_request()).unwrap();
        let right =
            build_signed_transaction(&signer, SignatureSchemeId::Ed25519, base_request()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn changing_the_nonce_changes_the_signature() {
        let signer = LocalSigner::from_seed([0xAD; 32]);
        let mut second_request = base_request();
        second_request.nonce = 2;

        let first =
            build_signed_transaction(&signer, SignatureSchemeId::Ed25519, base_request()).unwrap();
        let second =
            build_signed_transaction(&signer, SignatureSchemeId::Ed25519, second_request).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn scheme_mismatch_is_rejected_before_signing() {
        let signer = LocalSigner::from_seed([0xAE; 32]);
        let result =
            build_signed_transaction(&signer, SignatureSchemeId::Secp256k1, base_request());
        assert!(matches!(
            result,
            Err(ClientError::Crypto(
                crypto::CryptoError::SignatureSchemeMismatch { .. }
            ))
        ));
    }
}
