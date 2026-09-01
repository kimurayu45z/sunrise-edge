//! Seed-based Ed25519 key/address handling.
//!
//! This is a local, in-memory development key, not a keystore, hardware
//! wallet, or production key-management surface. Production key generation
//! and storage remain deferred (see `ARCHITECTURE.md` §44 / DR-0083).

use crypto::{CryptoError, SignatureSigner};
use ed25519_zebra::{SigningKey, VerificationKey};
use objects::Address;
use protocol_types::SignatureSchemeId;

/// A deterministic Ed25519 signing key derived directly from a 32-byte seed,
/// bound to the `AddressIsPublicKey` address that is its own verification
/// key.
///
/// Only the `AddressIsPublicKey` binding is implemented anywhere in this
/// workspace today; a caller must confirm this matches the trusted
/// `/v1/context` result's `address_binding_id` before submitting a
/// transaction signed by this key.
#[derive(Clone)]
pub struct LocalSigner {
    signing_key: SigningKey,
    address: Address,
}

impl LocalSigner {
    /// Derives a signing key and its bound address from an exact 32-byte
    /// seed. The same seed always derives the same key and address.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from(seed);
        let verification_key = VerificationKey::from(&signing_key);
        let mut address_bytes = [0_u8; 32];
        address_bytes.copy_from_slice(verification_key.as_ref());
        Self {
            signing_key,
            address: Address::new(address_bytes),
        }
    }

    /// Returns the `AddressIsPublicKey` address bound to this key.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }
}

impl SignatureSigner for LocalSigner {
    fn scheme_id(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    fn sign_framed(&self, framed_message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.signing_key.sign(framed_message).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_derives_the_same_key_and_address() {
        let a = LocalSigner::from_seed([0x11; 32]);
        let b = LocalSigner::from_seed([0x11; 32]);
        assert_eq!(a.address(), b.address());
        assert_eq!(
            a.sign_framed(b"payload").unwrap(),
            b.sign_framed(b"payload").unwrap()
        );
    }

    #[test]
    fn different_seeds_derive_different_addresses() {
        let a = LocalSigner::from_seed([0x11; 32]);
        let b = LocalSigner::from_seed([0x22; 32]);
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn signatures_are_exactly_64_bytes() {
        let signer = LocalSigner::from_seed([0x33; 32]);
        assert_eq!(signer.sign_framed(b"payload").unwrap().len(), 64);
    }
}
