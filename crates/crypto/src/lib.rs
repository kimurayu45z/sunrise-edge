#![forbid(unsafe_code)]

//! Signature-domain framing and traits for future protocol cryptography.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId, TypeError};
use std::{error::Error, fmt};

mod ed25519;

pub use ed25519::Ed25519Verifier;

const SIGNATURE_FRAME_TYPE_ID: u16 = 0x2001;
const SIGNATURE_FRAME_VERSION: u16 = 1;

/// Errors returned by the cryptographic framing layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The signature message type was empty.
    EmptyMessageType,
    /// A verification key had a length other than the scheme's exact size.
    InvalidVerificationKeyLength(usize),
    /// A verification key was the correct length but did not decode to a
    /// valid curve point for the scheme.
    MalformedVerificationKey,
    /// A signature had a length other than the scheme's exact size.
    InvalidSignatureLength(usize),
    /// A `SignatureDomain` declared a scheme other than the signer's or
    /// verifier's own scheme. Signing or verification is rejected before any
    /// framing or cryptographic operation runs, so a caller can never
    /// produce or accept a frame that claims a scheme it did not actually
    /// use.
    SignatureSchemeMismatch {
        /// The signer's or verifier's own scheme.
        expected: SignatureSchemeId,
        /// The scheme declared by the `SignatureDomain` the caller supplied.
        actual: SignatureSchemeId,
    },
    /// Canonical framing failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical unframing failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A decoded protocol identifier failed validation.
    ProtocolType(TypeError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMessageType => write!(f, "signature message type must not be empty"),
            Self::InvalidVerificationKeyLength(length) => {
                write!(f, "verification key has an invalid length: {length} bytes")
            }
            Self::MalformedVerificationKey => {
                write!(f, "verification key is not a valid curve point encoding")
            }
            Self::InvalidSignatureLength(length) => {
                write!(f, "signature has an invalid length: {length} bytes")
            }
            Self::SignatureSchemeMismatch { expected, actual } => write!(
                f,
                "signature domain declares scheme {}, expected {}",
                actual.as_u16(),
                expected.as_u16()
            ),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::CanonicalDecoding(error) => error.fmt(f),
            Self::ProtocolType(error) => error.fmt(f),
        }
    }
}

impl Error for CryptoError {}

impl From<CanonicalEncodingError> for CryptoError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for CryptoError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<TypeError> for CryptoError {
    fn from(value: TypeError) -> Self {
        Self::ProtocolType(value)
    }
}

/// A stable message-type label used in signature replay protection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureMessageType(String);

impl SignatureMessageType {
    /// Creates a validated message type.
    pub fn new(value: impl Into<String>) -> Result<Self, CryptoError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CryptoError::EmptyMessageType);
        }

        Ok(Self(value))
    }

    /// Returns the string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The explicit signature-domain context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureDomain {
    /// The destination chain.
    pub chain_id: ChainId,
    /// The active protocol version.
    pub protocol_version: ProtocolVersion,
    /// The active epoch.
    pub epoch: Epoch,
    /// The semantic message family.
    pub message_type: SignatureMessageType,
    /// The signature scheme identifier.
    pub signature_scheme_id: SignatureSchemeId,
}

/// A signer that operates on framed protocol messages.
pub trait SignatureSigner {
    /// Returns the signer's scheme identifier.
    fn scheme_id(&self) -> SignatureSchemeId;

    /// Signs the provided framed message bytes.
    fn sign_framed(&self, framed_message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Frames and signs a canonical protocol payload.
    ///
    /// Rejects with [`CryptoError::SignatureSchemeMismatch`] before framing
    /// or signing if `domain.signature_scheme_id` does not equal
    /// [`SignatureSigner::scheme_id`], so this signer can never produce a
    /// frame that claims a scheme it did not use.
    fn sign_canonical(
        &self,
        domain: &SignatureDomain,
        canonical_payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let expected: SignatureSchemeId = self.scheme_id();
        if domain.signature_scheme_id != expected {
            return Err(CryptoError::SignatureSchemeMismatch {
                expected,
                actual: domain.signature_scheme_id,
            });
        }
        let framed = frame_signature_message(domain, canonical_payload)?;
        self.sign_framed(&framed)
    }
}

/// A verifier that operates on framed protocol messages.
pub trait SignatureVerifier {
    /// Returns the verifier's scheme identifier.
    fn scheme_id(&self) -> SignatureSchemeId;

    /// Verifies the provided framed message bytes.
    fn verify_framed(&self, framed_message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;

    /// Frames and verifies a canonical protocol payload.
    ///
    /// Rejects with [`CryptoError::SignatureSchemeMismatch`] before framing
    /// or verifying if `domain.signature_scheme_id` does not equal
    /// [`SignatureVerifier::scheme_id`], so this verifier never attempts to
    /// verify a signature under a scheme it does not implement.
    fn verify_canonical(
        &self,
        domain: &SignatureDomain,
        canonical_payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let expected: SignatureSchemeId = self.scheme_id();
        if domain.signature_scheme_id != expected {
            return Err(CryptoError::SignatureSchemeMismatch {
                expected,
                actual: domain.signature_scheme_id,
            });
        }
        let framed = frame_signature_message(domain, canonical_payload)?;
        self.verify_framed(&framed, signature)
    }
}

/// Frames a signature payload with explicit replay-protection context.
pub fn frame_signature_message(
    domain: &SignatureDomain,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut frame = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
    frame.field_str(1, domain.chain_id.as_str())?;
    frame.field_u32(2, domain.protocol_version.get())?;
    frame.field_u64(3, domain.epoch.get())?;
    frame.field_str(4, domain.message_type.as_str())?;
    frame.field_u16(5, domain.signature_scheme_id.as_u16())?;
    frame.field_bytes(6, canonical_payload)?;
    Ok(frame.finish()?)
}

/// One strictly decoded, zero-copy [`frame_signature_message`] output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureFrameView<'a> {
    /// The destination chain string.
    pub chain_id: &'a str,
    /// The active protocol version.
    pub protocol_version: ProtocolVersion,
    /// The active epoch.
    pub epoch: Epoch,
    /// The semantic message family.
    pub message_type: &'a str,
    /// The signature scheme identifier.
    pub signature_scheme_id: SignatureSchemeId,
    /// The framed canonical payload (field 6), exactly as signed.
    pub payload: &'a [u8],
}

/// Strictly decodes a [`frame_signature_message`] output.
///
/// This is the exact decoding counterpart to [`frame_signature_message`]:
/// beyond the shared [`decode_canonical_frame`] guarantees (correct magic, no
/// truncation/trailing bytes, strictly increasing field order, no duplicate
/// fields), this function additionally requires the signature-frame type id
/// (`0x2001`) and encoding version 1, requires exactly fields 1 through 6 —
/// each present exactly once, rejecting any other field id (in particular,
/// there is no field 7) — validates each field's exact integer width or
/// UTF-8 string rule through the shared canonical field accessors, and
/// rejects an empty `message_type` or an unknown `signature_scheme_id`
/// before returning. It never guesses, truncates, or substitutes a default
/// for a malformed field. Callers that need a stricter, deployment-specific
/// bound (for example a hardware signing profile) must apply their own
/// tighter checks on top of this generic decode.
pub fn decode_signature_frame(input: &[u8]) -> Result<SignatureFrameView<'_>, CryptoError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(SIGNATURE_FRAME_TYPE_ID)?;
    frame.require_version(SIGNATURE_FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;

    let chain_id: &str = frame.required_str(1)?;
    if chain_id.trim().is_empty() {
        return Err(CryptoError::ProtocolType(TypeError::EmptyChainId));
    }
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let message_type: &str = frame.required_str(4)?;
    if message_type.trim().is_empty() {
        return Err(CryptoError::EmptyMessageType);
    }
    let signature_scheme_id = SignatureSchemeId::try_from(frame.required_u16(5)?)?;
    let payload: &[u8] = frame.required_field(6)?;

    Ok(SignatureFrameView {
        chain_id,
        protocol_version,
        epoch,
        message_type,
        signature_scheme_id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(chain_id: &str, version: u32, epoch: u64, message_type: &str) -> SignatureDomain {
        SignatureDomain {
            chain_id: ChainId::new(chain_id).unwrap(),
            protocol_version: ProtocolVersion::new(version),
            epoch: Epoch::new(epoch),
            message_type: SignatureMessageType::new(message_type).unwrap(),
            signature_scheme_id: SignatureSchemeId::Ed25519,
        }
    }

    #[test]
    fn signature_frames_change_across_chains() {
        let left = frame_signature_message(&domain("chain-a", 1, 7, "vote"), b"payload").unwrap();
        let right = frame_signature_message(&domain("chain-b", 1, 7, "vote"), b"payload").unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn signature_frames_change_across_message_types() {
        let left = frame_signature_message(&domain("chain-a", 1, 7, "vote"), b"payload").unwrap();
        let right =
            frame_signature_message(&domain("chain-a", 1, 7, "certificate"), b"payload").unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn signature_frames_change_across_protocol_versions() {
        let left = frame_signature_message(&domain("chain-a", 1, 7, "vote"), b"payload").unwrap();
        let right = frame_signature_message(&domain("chain-a", 2, 7, "vote"), b"payload").unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn signature_frames_change_across_epochs() {
        let left = frame_signature_message(&domain("chain-a", 1, 7, "vote"), b"payload").unwrap();
        let right = frame_signature_message(&domain("chain-a", 1, 8, "vote"), b"payload").unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn message_type_must_not_be_empty() {
        assert_eq!(
            SignatureMessageType::new("  "),
            Err(CryptoError::EmptyMessageType)
        );
    }

    fn domain_with_scheme(scheme: SignatureSchemeId) -> SignatureDomain {
        SignatureDomain {
            signature_scheme_id: scheme,
            ..domain("chain-a", 1, 7, "tx")
        }
    }

    /// A minimal test-only signer, not a production signer: it exists solely
    /// to exercise `SignatureSigner::sign_canonical`'s default-method scheme
    /// guard, symmetric to `SignatureVerifier::verify_canonical`'s (see
    /// `ed25519::tests::verify_canonical_rejects_a_mismatched_scheme_without_verifying`).
    struct TestSigner(SignatureSchemeId);

    impl SignatureSigner for TestSigner {
        fn scheme_id(&self) -> SignatureSchemeId {
            self.0
        }

        fn sign_framed(&self, _framed_message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0u8; 64])
        }
    }

    #[test]
    fn sign_canonical_rejects_a_mismatched_scheme_before_framing_or_signing() {
        let signer = TestSigner(SignatureSchemeId::Ed25519);
        let mismatched = domain_with_scheme(SignatureSchemeId::Secp256k1);

        assert_eq!(
            signer.sign_canonical(&mismatched, b"payload"),
            Err(CryptoError::SignatureSchemeMismatch {
                expected: SignatureSchemeId::Ed25519,
                actual: SignatureSchemeId::Secp256k1,
            })
        );
    }

    #[test]
    fn sign_canonical_accepts_a_matching_scheme() {
        let signer = TestSigner(SignatureSchemeId::Ed25519);
        let matching = domain_with_scheme(SignatureSchemeId::Ed25519);

        assert_eq!(
            signer.sign_canonical(&matching, b"payload"),
            Ok(vec![0u8; 64])
        );
    }

    // ── decode_signature_frame ───────────────────────────────────────────

    #[test]
    fn decode_signature_frame_round_trips_frame_signature_message() {
        let d = domain("chain-a", 3, 7, "transaction-v1");
        let framed = frame_signature_message(&d, b"canonical-payload").unwrap();

        let decoded = decode_signature_frame(&framed).unwrap();

        assert_eq!(decoded.chain_id, d.chain_id.as_str());
        assert_eq!(decoded.protocol_version, d.protocol_version);
        assert_eq!(decoded.epoch, d.epoch);
        assert_eq!(decoded.message_type, d.message_type.as_str());
        assert_eq!(decoded.signature_scheme_id, d.signature_scheme_id);
        assert_eq!(decoded.payload, b"canonical-payload");
    }

    #[test]
    fn decode_signature_frame_rejects_wrong_type_id() {
        let mut wrong = CanonicalStruct::new(0x2002, SIGNATURE_FRAME_VERSION);
        wrong.field_str(1, "chain-a").unwrap();
        wrong.field_u32(2, 1).unwrap();
        wrong.field_u64(3, 7).unwrap();
        wrong.field_str(4, "tx").unwrap();
        wrong
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        wrong.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = wrong.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId {
                    expected: SIGNATURE_FRAME_TYPE_ID,
                    actual: 0x2002,
                }
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_wrong_version() {
        let mut wrong = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, 2);
        wrong.field_str(1, "chain-a").unwrap();
        wrong.field_u32(2, 1).unwrap();
        wrong.field_u64(3, 7).unwrap();
        wrong.field_str(4, "tx").unwrap();
        wrong
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        wrong.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = wrong.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion {
                    expected: SIGNATURE_FRAME_VERSION,
                    actual: 2,
                }
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_a_missing_field() {
        let mut missing = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        missing.field_str(1, "chain-a").unwrap();
        missing.field_u32(2, 1).unwrap();
        missing.field_u64(3, 7).unwrap();
        missing.field_str(4, "tx").unwrap();
        missing.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = missing.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(5)
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_an_unknown_field() {
        let mut extra = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        extra.field_str(1, "chain-a").unwrap();
        extra.field_u32(2, 1).unwrap();
        extra.field_u64(3, 7).unwrap();
        extra.field_str(4, "tx").unwrap();
        extra
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        extra.field_bytes(6, b"p".to_vec()).unwrap();
        extra.field_bytes(7, b"unexpected".to_vec()).unwrap();
        let bytes = extra.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(7)
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_trailing_bytes() {
        let d = domain("chain-a", 1, 7, "tx");
        let mut framed = frame_signature_message(&d, b"payload").unwrap();
        framed.push(0xAA);

        assert!(matches!(
            decode_signature_frame(&framed),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn decode_signature_frame_rejects_an_empty_message_type() {
        let mut empty_type = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        empty_type.field_str(1, "chain-a").unwrap();
        empty_type.field_u32(2, 1).unwrap();
        empty_type.field_u64(3, 7).unwrap();
        empty_type.field_str(4, "   ").unwrap();
        empty_type
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        empty_type.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = empty_type.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::EmptyMessageType)
        );
    }

    #[test]
    fn decode_signature_frame_rejects_an_unknown_signature_scheme() {
        let mut unknown_scheme =
            CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        unknown_scheme.field_str(1, "chain-a").unwrap();
        unknown_scheme.field_u32(2, 1).unwrap();
        unknown_scheme.field_u64(3, 7).unwrap();
        unknown_scheme.field_str(4, "tx").unwrap();
        unknown_scheme.field_u16(5, 0x9999).unwrap();
        unknown_scheme.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = unknown_scheme.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::ProtocolType(
                TypeError::UnknownSignatureSchemeId(0x9999)
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_non_utf8_chain_id() {
        let mut bad_utf8 = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        bad_utf8.field_bytes(1, vec![0xFF, 0xFE]).unwrap();
        bad_utf8.field_u32(2, 1).unwrap();
        bad_utf8.field_u64(3, 7).unwrap();
        bad_utf8.field_str(4, "tx").unwrap();
        bad_utf8
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        bad_utf8.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = bad_utf8.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::InvalidUtf8(1)
            ))
        );
    }

    #[test]
    fn decode_signature_frame_rejects_a_wrong_width_integer_field() {
        let mut bad_width = CanonicalStruct::new(SIGNATURE_FRAME_TYPE_ID, SIGNATURE_FRAME_VERSION);
        bad_width.field_str(1, "chain-a").unwrap();
        bad_width.field_bytes(2, vec![1, 0]).unwrap(); // protocol_version must be u32 (4 bytes)
        bad_width.field_u64(3, 7).unwrap();
        bad_width.field_str(4, "tx").unwrap();
        bad_width
            .field_u16(5, SignatureSchemeId::Ed25519.as_u16())
            .unwrap();
        bad_width.field_bytes(6, b"p".to_vec()).unwrap();
        let bytes = bad_width.finish().unwrap();

        assert_eq!(
            decode_signature_frame(&bytes),
            Err(CryptoError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 2,
                    expected: 4,
                    actual: 2,
                }
            ))
        );
    }
}
