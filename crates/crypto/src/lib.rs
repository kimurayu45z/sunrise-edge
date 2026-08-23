#![forbid(unsafe_code)]

//! Signature-domain framing and traits for future protocol cryptography.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId};
use std::{error::Error, fmt};

const SIGNATURE_FRAME_TYPE_ID: u16 = 0x2001;
const SIGNATURE_FRAME_VERSION: u16 = 1;

/// Errors returned by the cryptographic framing layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The signature message type was empty.
    EmptyMessageType,
    /// Canonical framing failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMessageType => write!(f, "signature message type must not be empty"),
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
    fn sign_canonical(
        &self,
        domain: &SignatureDomain,
        canonical_payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
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
    fn verify_canonical(
        &self,
        domain: &SignatureDomain,
        canonical_payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
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
    frame.field_bytes(6, canonical_payload.to_vec())?;
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
    fn message_type_must_not_be_empty() {
        assert_eq!(
            SignatureMessageType::new("  "),
            Err(CryptoError::EmptyMessageType)
        );
    }
}
