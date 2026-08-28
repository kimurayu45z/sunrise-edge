//! Consensus-deterministic Ed25519 signature verification.
//!
//! Verification uses the pinned `ed25519-zebra` crate, which implements
//! [ZIP-215](https://github.com/zcash/zips/blob/master/zip-0215.rst)
//! semantics as this module's consensus validation profile: ZIP-215 gives an
//! exact, specified accept/reject decision (accepting non-canonical point
//! encodings and small-order points via the cofactored verification
//! equation) for signature/key encodings whose validity RFC 8032 itself does
//! not fully pin down. Using one specified profile, rather than leaving
//! those edge cases to each implementation's own interpretation, is what
//! lets every honest validator reach the same result on the same bytes. This
//! module implements verification only; no signer is provided here.
//! `runtime::MemorySigner` is a public in-memory wiring fixture used to
//! compose test/local runtimes; it is deliberately non-cryptographic and
//! must never be used for protocol authentication.

use core::convert::TryFrom;
use ed25519_zebra::{Signature, VerificationKey};
use protocol_types::SignatureSchemeId;

use crate::{CryptoError, SignatureVerifier};

const VERIFICATION_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// A ZIP-215-compliant Ed25519 [`SignatureVerifier`] bound to one
/// verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Verifier {
    verification_key: VerificationKey,
}

impl Ed25519Verifier {
    /// Builds a verifier from an exact 32-byte Ed25519 verification key.
    ///
    /// Returns a typed error if the slice is not exactly 32 bytes or does
    /// not decode to a valid curve point encoding.
    pub fn from_verifying_key_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != VERIFICATION_KEY_LEN {
            return Err(CryptoError::InvalidVerificationKeyLength(bytes.len()));
        }
        let verification_key =
            VerificationKey::try_from(bytes).map_err(|_| CryptoError::MalformedVerificationKey)?;
        Ok(Self { verification_key })
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn scheme_id(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    /// Verifies an exact 64-byte Ed25519 signature over `framed_message`
    /// using ZIP-215 semantics.
    ///
    /// Returns `Ok(false)` for a cryptographically invalid signature and
    /// `Err` only for a signature that is not exactly 64 bytes.
    fn verify_framed(&self, framed_message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if signature.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignatureLength(signature.len()));
        }
        let mut signature_bytes = [0u8; SIGNATURE_LEN];
        signature_bytes.copy_from_slice(signature);
        let signature = Signature::from(signature_bytes);
        Ok(self
            .verification_key
            .verify(&signature, framed_message)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureDomain, SignatureMessageType, frame_signature_message};
    use protocol_types::{ChainId, Epoch, ProtocolVersion};

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8032 Section 7.1, TEST 1, as embedded verbatim in `ed25519-zebra`
    // 4.2.0's own `tests/rfc8032.rs`. Confirmed against the pinned
    // dependency by executing `VerificationKey::verify` directly and
    // cross-checked against the published RFC 8032 text.
    const RFC8032_TEST1_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_TEST1_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn rfc8032_known_answer_signature_verifies() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        let signature = hex_to_bytes(RFC8032_TEST1_SIGNATURE);

        assert_eq!(verifier.verify_framed(b"", &signature), Ok(true));
    }

    #[test]
    fn rfc8032_known_answer_signature_rejects_a_different_message() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        let signature = hex_to_bytes(RFC8032_TEST1_SIGNATURE);

        assert_eq!(
            verifier.verify_framed(b"not the signed message", &signature),
            Ok(false)
        );
    }

    // Non-canonical `S` rejection evidence.
    //
    // RFC 8032 https://www.rfc-editor.org/rfc/rfc8032 §5.1.7 requires `S`
    // to decode in the range `0 <= S < L` and treats an out-of-range value
    // as invalid. It and
    // [ZIP-215](https://github.com/zcash/zips/blob/master/zip-0215.rst)
    // require the signature's `S` component to be a canonically encoded
    // scalar strictly less than the group order `l`; this is not an
    // edge case RFC 8032 leaves ambiguous (contrast the point-encoding and
    // small-order acceptance below, which genuinely is). This vector reuses
    // the RFC 8032 TEST 1 vector's real `R`, public key, and valid `S`, and
    // replaces `S` with `S + l` encoded little-endian over 32 bytes: `l` is
    // exactly `BASEPOINT_ORDER` (bytes unchanged from `ed25519-zebra`
    // 4.2.0's `curve25519-dalek` 4.1.3 dependency, `src/constants.rs`,
    // where it is present but deprecated since 4.1.1 as "should not have
    // been in public API"). `S + l` is numerically congruent to the
    // original valid `S` modulo `l` — a verifier that improperly reduced
    // `S` modulo `l` before checking the verification equation would
    // therefore accept this signature — but it is not itself less than
    // `l`, so it is not a canonical scalar encoding. This vector proves the
    // pinned implementation enforces the required canonical-scalar rule and
    // prevents modulo-`l` signature malleability: the pinned
    // `ed25519-zebra` 4.2.0 verifier must reject it (`Ok(false)`) purely
    // because of the non-canonical encoding, not because the underlying
    // scalar is wrong. The exact bytes below were computed independently by
    // (1) big-integer addition and (2) manual little-endian byte-wise
    // addition with carry, cross-checked to agree, and confirmed by
    // executing `curve25519_dalek::scalar::Scalar::from_canonical_bytes`
    // (`CtOption` converts to `None`, i.e. non-canonical),
    // `Scalar::from_bytes_mod_order` (equals the original valid `S`), and
    // `VerificationKey::verify` (`Err`, i.e. rejected) directly against the
    // pinned `ed25519-zebra` 4.2.0 / `curve25519-dalek` 4.1.3 dependencies.
    const NONCANONICAL_S_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901554c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b";

    #[test]
    fn rejects_a_signature_with_a_non_canonical_s_component() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        let signature = hex_to_bytes(NONCANONICAL_S_SIGNATURE);
        assert_eq!(signature.len(), 64);

        assert_eq!(verifier.verify_framed(b"", &signature), Ok(false));
    }

    // ZIP-215 small-order / non-canonical acceptance evidence.
    //
    // Both the verification key and the signature's `R` component encode the
    // Edwards25519 identity point (x = 0, y = 1): a canonical y = 1 encoding
    // is `01` followed by 31 zero bytes, and a non-canonical re-encoding of
    // the same point sets the otherwise-unused sign bit (`01` followed by 30
    // zero bytes and a trailing `80`). These are exactly the constants
    // `y1_noncanonical_sign_bit` and the canonical identity entry in
    // `EXCLUDED_POINT_ENCODINGS` from `ed25519-zebra` 4.2.0's own
    // `tests/util/mod.rs`. With `s = 0`, the ZIP-215 verification equation
    // `[8][s]B = [8]R + [8][k]A` reduces to `0 = 0` regardless of the message
    // hash `k`, so this signature verifies for every message under ZIP-215.
    // `ed25519-zebra` 4.2.0's own `tests/util/mod.rs` documents the
    // identical, canonically-encoded `R` as one of the point encodings
    // libsodium 1.0.15 specifically blacklisted in an attempt to exclude
    // low-order points; ZIP-215 accepting it here instead, per its own
    // specified cofactored equation, is the point of this test. Confirmed by
    // executing `VerificationKey::verify` directly against the pinned
    // `ed25519-zebra` 4.2.0 dependency.
    const ZIP215_NON_CANONICAL_VERIFICATION_KEY: &str =
        "0100000000000000000000000000000000000000000000000000000000000080";
    const ZIP215_SMALL_ORDER_SIGNATURE: &str = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn zip215_accepts_non_canonical_small_order_signature_for_any_message() {
        let verifier = Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(
            ZIP215_NON_CANONICAL_VERIFICATION_KEY,
        ))
        .unwrap();
        let signature = hex_to_bytes(ZIP215_SMALL_ORDER_SIGNATURE);

        assert_eq!(verifier.verify_framed(b"", &signature), Ok(true));
        assert_eq!(
            verifier.verify_framed(b"arbitrary message", &signature),
            Ok(true)
        );
        assert_eq!(
            verifier.verify_framed(b"a completely different message", &signature),
            Ok(true)
        );
    }

    #[test]
    fn verification_key_length_is_checked() {
        assert_eq!(
            Ed25519Verifier::from_verifying_key_bytes(&[0x11; 31]),
            Err(CryptoError::InvalidVerificationKeyLength(31))
        );
        assert_eq!(
            Ed25519Verifier::from_verifying_key_bytes(&[0x11; 33]),
            Err(CryptoError::InvalidVerificationKeyLength(33))
        );
    }

    #[test]
    fn malformed_verification_key_is_rejected() {
        // 31 bytes of 0xff followed by 0x00: not a valid Edwards25519 point
        // encoding. Confirmed by exhaustively probing the pinned
        // `ed25519-zebra` 4.2.0 `VerificationKey::try_from` with the
        // high 31 bytes fixed to 0xff.
        let bytes =
            hex_to_bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00");
        assert_eq!(
            Ed25519Verifier::from_verifying_key_bytes(&bytes),
            Err(CryptoError::MalformedVerificationKey)
        );
    }

    #[test]
    fn signature_length_is_checked() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();

        assert_eq!(
            verifier.verify_framed(b"", &[0x22; 63]),
            Err(CryptoError::InvalidSignatureLength(63))
        );
        assert_eq!(
            verifier.verify_framed(b"", &[0x22; 65]),
            Err(CryptoError::InvalidSignatureLength(65))
        );
    }

    #[test]
    fn scheme_id_is_ed25519() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        assert_eq!(verifier.scheme_id(), SignatureSchemeId::Ed25519);
    }

    fn domain(
        chain_id: &str,
        protocol_version: u32,
        epoch: u64,
        message_type: &str,
    ) -> SignatureDomain {
        SignatureDomain {
            chain_id: ChainId::new(chain_id).unwrap(),
            protocol_version: ProtocolVersion::new(protocol_version),
            epoch: Epoch::new(epoch),
            message_type: SignatureMessageType::new(message_type).unwrap(),
            signature_scheme_id: SignatureSchemeId::Ed25519,
        }
    }

    /// A signature valid over a raw payload must not verify once the same
    /// payload is wrapped in the centralized signature-domain frame: framing
    /// is mandatory context, not an optional wrapper a caller can skip. This
    /// complements `frame_signature_message`'s own byte-level domain-
    /// separation tests (chain/protocol-version/epoch/message-type) with a
    /// real cryptographic verification outcome.
    #[test]
    fn framing_a_known_answer_message_invalidates_its_signature() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        let signature = hex_to_bytes(RFC8032_TEST1_SIGNATURE);

        for domain in [
            domain("chain-a", 1, 7, "tx"),
            domain("chain-b", 1, 7, "tx"),
            domain("chain-a", 2, 7, "tx"),
            domain("chain-a", 1, 8, "tx"),
            domain("chain-a", 1, 7, "vote"),
        ] {
            let framed = frame_signature_message(&domain, b"").unwrap();
            assert_eq!(verifier.verify_framed(&framed, &signature), Ok(false));
        }
    }

    /// An Ed25519 verifier must reject a `SignatureDomain` that declares a
    /// different scheme before attempting any framing or verification, not
    /// merely produce a false verification result.
    #[test]
    fn verify_canonical_rejects_a_mismatched_scheme_without_verifying() {
        let verifier =
            Ed25519Verifier::from_verifying_key_bytes(&hex_to_bytes(RFC8032_TEST1_PUBLIC_KEY))
                .unwrap();
        let mismatched = SignatureDomain {
            signature_scheme_id: SignatureSchemeId::Secp256k1,
            ..domain("chain-a", 1, 7, "tx")
        };

        // A 3-byte "signature" would surface as `InvalidSignatureLength` if
        // verification were attempted at all; getting
        // `SignatureSchemeMismatch` instead proves the scheme check runs,
        // and rejects, before any framing or verification is attempted.
        assert_eq!(
            verifier.verify_canonical(&mismatched, b"payload", &[0u8; 3]),
            Err(CryptoError::SignatureSchemeMismatch {
                expected: SignatureSchemeId::Ed25519,
                actual: SignatureSchemeId::Secp256k1,
            })
        );
    }
}
