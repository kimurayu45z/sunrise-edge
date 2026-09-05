//! Canonical Transaction v1 construction and signing.
//!
//! Construction is a safe two-stage external-signer API
//! ([`PreparedTransaction::prepare`] /
//! [`PreparedTransaction::finalize`]/[`PreparedTransaction::sign_and_finalize_with`]):
//! a caller first prepares an immutable transaction from an explicit
//! sender, the active signature scheme, and a [`TransactionRequest`], then
//! either signs it in-process with a [`SignatureSigner`] (for example
//! [`LocalSigner`]) or exports the exact bytes an out-of-process signer
//! (see `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0084's Ledger-ready external signing boundary)
//! must sign. [`build_signed_transaction`] is the original
//! single-call convenience entrypoint and is now implemented through this
//! same path, so its stable output is unchanged.

use crypto::{
    Ed25519Verifier, SignatureDomain, SignatureMessageType, SignatureSigner, SignatureVerifier,
    frame_signature_message,
};
use execution::{Transaction, encode_transaction, encode_transaction_signable};
use node_core::TRANSACTION_V1_MESSAGE_TYPE;
use objects::{Address, ObjectRef};
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId};
use signing_view::{
    ClearSigningPolicy, ClearSigningView, DeviceSigningProfile, build_clear_signing_view,
};
use std::error::Error;

use crate::error::ClientError;
use crate::key::LocalSigner;

/// Explicit, caller-supplied inputs for one canonical Transaction v1.
///
/// Every reference here — the access manifest and the module reference — is
/// exactly what the caller supplies. This builder invents no object
/// discovery, module lookup, or asset-specific defaults; that is deliberate
/// (see `docs/architecture/product-surfaces.md` §44 /
/// `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0083).
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

/// An immutable, fully framed Transaction v1 awaiting a signature.
///
/// Built by [`PreparedTransaction::prepare`] from an explicit sender, the
/// active signature scheme, and a [`TransactionRequest`]. Every field the
/// signature covers is fixed the moment this value exists; nothing about it
/// can be mutated before signing, so a signer (in-process or external) is
/// always shown the exact bytes it is about to authenticate.
///
/// Only `Ed25519` with the `AddressIsPublicKey` address binding is
/// implemented anywhere in this workspace today (see
/// `docs/architecture/decisions/0081-0087-cli-first-roadmap.md`
/// DR-0084): [`PreparedTransaction::prepare`] rejects every other signature
/// scheme before any framing happens, and
/// [`PreparedTransaction::finalize`] verifies a returned signature directly
/// against the sender's 32 bytes as an Ed25519 verification key. A future
/// scheme requires an explicit new arm in both places, not a silent
/// fallback.
pub struct PreparedTransaction {
    unsigned: Transaction,
    domain: SignatureDomain,
    signable: Vec<u8>,
}

/// A bounded external signing boundary.
///
/// Implementations report the exact device/account identity before signing
/// and receive only the exact canonical signature frame. A hardware
/// implementation must independently parse and confirm that frame; it must
/// not trust a host-rendered view as authorization.
pub trait ExternalSigner {
    /// Typed implementation-specific failure.
    type Error: Error + Send + Sync + 'static;

    /// Signature scheme implemented by this signer.
    fn signature_scheme_id(&self) -> SignatureSchemeId;

    /// Address bound to the selected signer account.
    fn address(&self) -> Address;

    /// Signs one already-framed canonical message.
    fn sign_frame(&self, framed_message: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

impl PreparedTransaction {
    /// Prepares an immutable transaction, rejecting an unsupported signature
    /// scheme before any framing or allocation beyond the signable payload
    /// itself.
    pub fn prepare(
        sender: Address,
        signature_scheme_id: SignatureSchemeId,
        request: TransactionRequest,
    ) -> Result<Self, ClientError> {
        reject_unsupported_scheme(signature_scheme_id)?;

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
            sender,
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

        Ok(Self {
            unsigned,
            domain,
            signable,
        })
    }

    /// Returns the sender this transaction will be authenticated as.
    #[must_use]
    pub const fn sender(&self) -> Address {
        self.unsigned.sender
    }

    /// Returns the declared signature scheme.
    #[must_use]
    pub const fn signature_scheme_id(&self) -> SignatureSchemeId {
        self.domain.signature_scheme_id
    }

    /// Returns the exact framed bytes an external signer must produce a raw
    /// signature over.
    ///
    /// This is the same centralized domain frame every in-process signer and
    /// verifier in this workspace uses
    /// ([`crypto::frame_signature_message`]); it exists so an out-of-process
    /// signer — for example a future dedicated hardware-wallet application
    /// (see `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0084) — can be shown the exact bytes it is
    /// asked to sign without this client duplicating or re-deriving that
    /// framing.
    pub fn signable_frame(&self) -> Result<Vec<u8>, ClientError> {
        Ok(frame_signature_message(&self.domain, &self.signable)?)
    }

    /// Derives the bounded, fail-closed hardware display exclusively from
    /// [`Self::signable_frame`].
    pub fn clear_signing_view(
        &self,
        profile: &DeviceSigningProfile,
        policy: &ClearSigningPolicy,
    ) -> Result<ClearSigningView, ClientError> {
        let framed: Vec<u8> = self.signable_frame()?;
        Ok(build_clear_signing_view(&framed, profile, policy)?)
    }

    /// Checks an external signer's scheme and address, proves the exact frame
    /// fits an approved clear-signing policy, invokes the signer, then applies
    /// [`Self::finalize`]'s independent signature verification.
    ///
    /// The host-side view is a preflight and conformance check, not a source
    /// of device trust. A dedicated device app must parse and display the same
    /// `framed` bytes independently before approving the signature.
    pub fn sign_and_finalize_external<S>(
        self,
        signer: &S,
        profile: &DeviceSigningProfile,
        policy: &ClearSigningPolicy,
    ) -> Result<Vec<u8>, ClientError>
    where
        S: ExternalSigner,
    {
        let expected_scheme: SignatureSchemeId = self.signature_scheme_id();
        let actual_scheme: SignatureSchemeId = signer.signature_scheme_id();
        if actual_scheme != expected_scheme {
            return Err(ClientError::ExternalSignerSchemeMismatch {
                expected: expected_scheme,
                actual: actual_scheme,
            });
        }

        let expected_address: Address = self.sender();
        let actual_address: Address = signer.address();
        if actual_address != expected_address {
            return Err(ClientError::ExternalSignerAddressMismatch {
                expected: expected_address,
                actual: actual_address,
            });
        }

        let framed: Vec<u8> = self.signable_frame()?;
        let _view: ClearSigningView = build_clear_signing_view(&framed, profile, policy)?;
        let signature: Vec<u8> = signer
            .sign_frame(&framed)
            .map_err(|error| ClientError::ExternalSigner(Box::new(error)))?;
        self.finalize(signature)
    }

    /// Finalizes this transaction with a signature produced by an external
    /// signer, returning the exact canonical signed wire bytes.
    ///
    /// Fails closed, in order: an unsupported declared scheme (defense in
    /// depth; [`PreparedTransaction::prepare`] already rejects this), a
    /// signature whose length is not exactly the scheme's supported length,
    /// and a well-formed signature that does not cryptographically verify
    /// against this transaction's sender treated as an `AddressIsPublicKey`
    /// Ed25519 verification key under the declared scheme. Only a `true`
    /// verification result produces output.
    pub fn finalize(mut self, signature: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        match self.domain.signature_scheme_id {
            SignatureSchemeId::Ed25519 => {
                let verifier =
                    Ed25519Verifier::from_verifying_key_bytes(self.unsigned.sender.as_bytes())?;
                let framed = self.signable_frame()?;
                if !verifier.verify_framed(&framed, &signature)? {
                    return Err(ClientError::ExternalSignatureInvalid {
                        sender: self.unsigned.sender,
                    });
                }
                self.unsigned.signature = signature;
                Ok(encode_transaction(&self.unsigned)?)
            }
            SignatureSchemeId::Secp256k1 => Err(ClientError::UnsupportedSignatureScheme(
                self.domain.signature_scheme_id,
            )),
        }
    }

    /// Signs this transaction in-process with `signer` and finalizes it in
    /// one call.
    ///
    /// Uses [`SignatureSigner::sign_canonical`], so a `signer` whose own
    /// scheme disagrees with this transaction's declared scheme is rejected
    /// before any framing or signing happens, exactly as
    /// [`crypto::SignatureSigner::sign_canonical`] documents.
    pub fn sign_and_finalize_with<S>(self, signer: &S) -> Result<Vec<u8>, ClientError>
    where
        S: SignatureSigner,
    {
        let signature = signer.sign_canonical(&self.domain, &self.signable)?;
        self.finalize(signature)
    }
}

impl ExternalSigner for LocalSigner {
    type Error = crypto::CryptoError;

    fn signature_scheme_id(&self) -> SignatureSchemeId {
        SignatureSigner::scheme_id(self)
    }

    fn address(&self) -> Address {
        LocalSigner::address(self)
    }

    fn sign_frame(&self, framed_message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_framed(framed_message)
    }
}

fn reject_unsupported_scheme(scheme: SignatureSchemeId) -> Result<(), ClientError> {
    match scheme {
        SignatureSchemeId::Ed25519 => Ok(()),
        SignatureSchemeId::Secp256k1 => Err(ClientError::UnsupportedSignatureScheme(scheme)),
    }
}

/// Builds and signs one canonical Transaction v1 under the exact stable
/// `"transaction-v1"` message family
/// ([`node_core::TRANSACTION_V1_MESSAGE_TYPE`]) and returns its exact
/// canonical wire bytes, ready to submit as a `SubmitTransaction` event.
///
/// `signature_scheme_id` must come from a trusted `/v1/context` query
/// result; this function never guesses or defaults the active scheme. It is
/// a thin convenience wrapper over [`PreparedTransaction::prepare`] and
/// [`PreparedTransaction::sign_and_finalize_with`]: its stable output bytes
/// are unchanged from before this module's two-stage external-signer API
/// existed.
pub fn build_signed_transaction(
    signer: &LocalSigner,
    signature_scheme_id: SignatureSchemeId,
    request: TransactionRequest,
) -> Result<Vec<u8>, ClientError> {
    let sender = signer.address();
    let prepared = PreparedTransaction::prepare(sender, signature_scheme_id, request)?;
    prepared.sign_and_finalize_with(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{AccessEntry, AccessManifest};
    use canonical_encoding::CanonicalStruct;
    use crypto::CryptoError;
    use execution::decode_transaction;
    use fees::{Amount, AssetId, FeePayment};
    use objects::{AccessMode, ObjectId};
    use protocol_types::{Digest32, HashAlgorithmId};
    use signing_view::{ClearSigningPolicyError, DEVNET_ASSET_TRANSFER_POLICY, SigningViewError};
    use std::{cell::Cell, fmt};

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

    fn recognized_transfer_request() -> TransactionRequest {
        let source_ref = ObjectRef {
            id: ObjectId::new([0x11; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        };
        let destination_ref = ObjectRef {
            id: ObjectId::new([0x21; 32]),
            version: 2,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        };
        let treasury_ref = ObjectRef {
            id: ObjectId::new([0x31; 32]),
            version: 3,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        };
        let mut access_manifest = AccessManifest::new();
        for object_ref in [source_ref.clone(), destination_ref, treasury_ref] {
            access_manifest.push(AccessEntry {
                object_ref,
                mode: AccessMode::Write,
            });
        }
        let mut arguments = CanonicalStruct::new(
            DEVNET_ASSET_TRANSFER_POLICY.args_type_id(),
            DEVNET_ASSET_TRANSFER_POLICY.args_version(),
        );
        arguments
            .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), 250)
            .unwrap();

        TransactionRequest {
            chain_id: ChainId::new("sunrise-local-devnet").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(0),
            nonce: 7,
            access_manifest,
            module_ref: ObjectRef {
                id: ObjectId::new(DEVNET_ASSET_TRANSFER_POLICY.module_id()),
                version: DEVNET_ASSET_TRANSFER_POLICY.module_version(),
                digest: Digest32::new(
                    DEVNET_ASSET_TRANSFER_POLICY.code_digest_algorithm(),
                    DEVNET_ASSET_TRANSFER_POLICY.code_digest_bytes(),
                ),
            },
            entrypoint: DEVNET_ASSET_TRANSFER_POLICY.entrypoint().to_string(),
            args: arguments.finish().unwrap(),
            gas_limit: 1_000,
            fee_payment: Some(FeePayment {
                asset_id: AssetId::new(DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id()),
                max_fee: Amount::new(1_001),
                fee_object: source_ref,
            }),
        }
    }

    #[derive(Debug)]
    struct TestExternalError;

    impl fmt::Display for TestExternalError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test signer failed")
        }
    }

    impl Error for TestExternalError {}

    struct TestExternalSigner {
        inner: LocalSigner,
        reported_address: Address,
        reported_scheme: SignatureSchemeId,
        calls: Cell<u32>,
        fail: bool,
    }

    impl TestExternalSigner {
        fn valid(seed: [u8; 32]) -> Self {
            let inner = LocalSigner::from_seed(seed);
            Self {
                reported_address: inner.address(),
                reported_scheme: SignatureSchemeId::Ed25519,
                inner,
                calls: Cell::new(0),
                fail: false,
            }
        }
    }

    impl ExternalSigner for TestExternalSigner {
        type Error = TestExternalError;

        fn signature_scheme_id(&self) -> SignatureSchemeId {
            self.reported_scheme
        }

        fn address(&self) -> Address {
            self.reported_address
        }

        fn sign_frame(&self, framed_message: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(TestExternalError);
            }
            self.inner
                .sign_framed(framed_message)
                .map_err(|_| TestExternalError)
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
    fn unsupported_scheme_is_rejected_before_any_framing() {
        let signer = LocalSigner::from_seed([0xAE; 32]);
        let result =
            build_signed_transaction(&signer, SignatureSchemeId::Secp256k1, base_request());
        assert!(matches!(
            result,
            Err(ClientError::UnsupportedSignatureScheme(
                SignatureSchemeId::Secp256k1
            ))
        ));
    }

    #[test]
    fn prepare_exposes_the_exact_bytes_an_external_signer_must_sign() {
        let signer = LocalSigner::from_seed([0xAF; 32]);
        let sender = signer.address();
        let prepared =
            PreparedTransaction::prepare(sender, SignatureSchemeId::Ed25519, base_request())
                .unwrap();
        let framed = prepared.signable_frame().unwrap();

        let raw_signature = signer.sign_framed(&framed).unwrap();
        let signed_bytes = prepared.finalize(raw_signature).unwrap();

        let decoded = decode_transaction(&signed_bytes).unwrap();
        assert_eq!(decoded.sender, sender);
    }

    #[test]
    fn finalize_rejects_a_wrong_length_signature() {
        let signer = LocalSigner::from_seed([0xB0; 32]);
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            base_request(),
        )
        .unwrap();

        let error = prepared.finalize(vec![0u8; 63]).unwrap_err();
        assert!(matches!(
            error,
            ClientError::Crypto(CryptoError::InvalidSignatureLength(63))
        ));
    }

    #[test]
    fn finalize_rejects_a_well_formed_but_invalid_signature() {
        let signer = LocalSigner::from_seed([0xB1; 32]);
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            base_request(),
        )
        .unwrap();

        let error = prepared.finalize(vec![0u8; 64]).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ExternalSignatureInvalid { sender } if sender == signer.address()
        ));
    }

    #[test]
    fn finalize_rejects_a_signature_from_the_wrong_signer() {
        let sender_signer = LocalSigner::from_seed([0xB2; 32]);
        let other_signer = LocalSigner::from_seed([0xB3; 32]);
        let prepared = PreparedTransaction::prepare(
            sender_signer.address(),
            SignatureSchemeId::Ed25519,
            base_request(),
        )
        .unwrap();
        let framed = prepared.signable_frame().unwrap();
        let wrong_signature = other_signer.sign_framed(&framed).unwrap();

        let error = prepared.finalize(wrong_signature).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ExternalSignatureInvalid { sender } if sender == sender_signer.address()
        ));
    }

    #[test]
    fn finalize_rejects_a_tampered_signature() {
        let signer = LocalSigner::from_seed([0xB4; 32]);
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            base_request(),
        )
        .unwrap();
        let framed = prepared.signable_frame().unwrap();
        let mut signature = signer.sign_framed(&framed).unwrap();
        signature[0] ^= 0xFF;

        let error = prepared.finalize(signature).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ExternalSignatureInvalid { .. }
        ));
    }

    #[test]
    fn finalize_rejects_a_signature_over_tampered_transaction_fields() {
        let signer = LocalSigner::from_seed([0xB5; 32]);
        let sender = signer.address();
        let honest =
            PreparedTransaction::prepare(sender, SignatureSchemeId::Ed25519, base_request())
                .unwrap();
        let honest_signature = signer
            .sign_framed(&honest.signable_frame().unwrap())
            .unwrap();

        let mut tampered_request = base_request();
        tampered_request.gas_limit = base_request().gas_limit + 1;
        let tampered =
            PreparedTransaction::prepare(sender, SignatureSchemeId::Ed25519, tampered_request)
                .unwrap();

        let error = tampered.finalize(honest_signature).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ExternalSignatureInvalid { .. }
        ));
    }

    #[test]
    fn clear_signing_view_is_derived_from_the_exact_prepared_frame() {
        let signer = LocalSigner::from_seed([0xC0; 32]);
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap();

        let view = prepared
            .clear_signing_view(&DeviceSigningProfile::V1, &DEVNET_ASSET_TRANSFER_POLICY)
            .unwrap();
        assert!(view.lines().iter().any(|line| line == "amount=250"));
        assert!(!view.lines().iter().any(|line| line.contains("request_id")));
    }

    #[test]
    fn external_signing_matches_the_existing_local_signing_bytes() {
        let signer = TestExternalSigner::valid([0xC1; 32]);
        let expected = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap()
        .sign_and_finalize_with(&signer.inner)
        .unwrap();
        let actual = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap()
        .sign_and_finalize_external(
            &signer,
            &DeviceSigningProfile::V1,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )
        .unwrap();

        assert_eq!(actual, expected);
        assert_eq!(signer.calls.get(), 1);
    }

    #[test]
    fn external_signer_identity_mismatch_stops_before_signing() {
        let mut signer = TestExternalSigner::valid([0xC2; 32]);
        let expected_address = signer.address();
        signer.reported_address = Address::new([0xFF; 32]);
        let prepared = PreparedTransaction::prepare(
            expected_address,
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap();

        assert!(matches!(
            prepared.sign_and_finalize_external(
                &signer,
                &DeviceSigningProfile::V1,
                &DEVNET_ASSET_TRANSFER_POLICY,
            ),
            Err(ClientError::ExternalSignerAddressMismatch { .. })
        ));
        assert_eq!(signer.calls.get(), 0);
    }

    #[test]
    fn external_signer_scheme_mismatch_stops_before_signing() {
        let mut signer = TestExternalSigner::valid([0xC3; 32]);
        signer.reported_scheme = SignatureSchemeId::Secp256k1;
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap();

        assert!(matches!(
            prepared.sign_and_finalize_external(
                &signer,
                &DeviceSigningProfile::V1,
                &DEVNET_ASSET_TRANSFER_POLICY,
            ),
            Err(ClientError::ExternalSignerSchemeMismatch { .. })
        ));
        assert_eq!(signer.calls.get(), 0);
    }

    #[test]
    fn clear_signing_policy_rejection_stops_before_external_signing() {
        let signer = TestExternalSigner::valid([0xC4; 32]);
        let mut request = recognized_transfer_request();
        request.module_ref.version += 1;
        let prepared =
            PreparedTransaction::prepare(signer.address(), SignatureSchemeId::Ed25519, request)
                .unwrap();

        assert!(matches!(
            prepared.sign_and_finalize_external(
                &signer,
                &DeviceSigningProfile::V1,
                &DEVNET_ASSET_TRANSFER_POLICY,
            ),
            Err(ClientError::SigningView(SigningViewError::Policy(
                ClearSigningPolicyError::ModuleVersion
            )))
        ));
        assert_eq!(signer.calls.get(), 0);
    }

    #[test]
    fn external_signer_failure_is_propagated_without_finalization() {
        let mut signer = TestExternalSigner::valid([0xC5; 32]);
        signer.fail = true;
        let prepared = PreparedTransaction::prepare(
            signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(),
        )
        .unwrap();

        assert!(matches!(
            prepared.sign_and_finalize_external(
                &signer,
                &DeviceSigningProfile::V1,
                &DEVNET_ASSET_TRANSFER_POLICY,
            ),
            Err(ClientError::ExternalSigner(_))
        ));
        assert_eq!(signer.calls.get(), 1);
    }
}
