#![forbid(unsafe_code)]

//! Signature-domain framing and traits for future protocol cryptography.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId};
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
        }
    }
}

impl Error for CryptoError {}

impl From<CanonicalEncodingError> for CryptoError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
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
}
