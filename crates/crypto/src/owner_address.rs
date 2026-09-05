//! Versioned Ed25519 owner-address admissibility.
//!
//! ZIP-215 signature verification deliberately accepts non-canonical and
//! non-prime-order Edwards25519 points so every validator has one exact
//! consensus decision. That verification profile is not, by itself, proof
//! that an address has one holder with exclusive signing-key possession.
//! This module therefore keeps owner admissibility separate and explicit:
//! historical profile 1 remains unrestricted, while profile 2 requires the
//! exact canonical encoding of a non-identity point in the prime-order
//! subgroup.

use core::fmt;
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use std::error::Error;

/// The owner-address policy selected by a committed authentication profile.
///
/// This is an in-memory policy value, not a canonical wire type. Stable wire
/// identity belongs to `protocol_config::TransactionAuthProfile` and its
/// `AddressBinding`; callers must derive this policy from that committed
/// binding rather than accepting it from a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519OwnerAddressPolicy {
    /// Historical profile 1 behavior: owner bytes are not restricted beyond
    /// the later ZIP-215 verification behavior when used as a sender.
    LegacyZip215,
    /// Require one canonical, non-identity, prime-order Edwards25519 point.
    CanonicalPrimeOrder,
}

/// Why an Ed25519 address cannot safely own value under the strict policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519OwnerAddressError {
    /// The bytes do not decode to an Edwards25519 point.
    MalformedPoint,
    /// The bytes decode but are not the point's unique canonical encoding.
    NonCanonicalPoint,
    /// The point is the identity and has no exclusive private-key holder.
    IdentityPoint,
    /// The point has a non-zero torsion component and is not in the
    /// prime-order subgroup.
    NonPrimeOrderPoint,
}

impl fmt::Display for Ed25519OwnerAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedPoint => {
                formatter.write_str("owner bytes do not decode to an Edwards25519 point")
            }
            Self::NonCanonicalPoint => {
                formatter.write_str("owner bytes are not the canonical Edwards25519 point encoding")
            }
            Self::IdentityPoint => {
                formatter.write_str("owner bytes encode the Edwards25519 identity point")
            }
            Self::NonPrimeOrderPoint => {
                formatter.write_str("owner bytes do not encode a prime-order Edwards25519 point")
            }
        }
    }
}

impl Error for Ed25519OwnerAddressError {}

/// Validates exact Ed25519 owner bytes under a committed, versioned policy.
///
/// The strict policy uses the already pinned `curve25519-dalek` 4.1.3
/// primitives directly: decompress, require byte-for-byte canonical
/// recompression, reject the identity, and require `is_torsion_free()`. The
/// order is intentional so the repository's universal non-canonical identity
/// vector is classified as non-canonical before its small order is considered.
pub fn validate_ed25519_owner_address(
    bytes: &[u8; 32],
    policy: Ed25519OwnerAddressPolicy,
) -> Result<(), Ed25519OwnerAddressError> {
    if policy == Ed25519OwnerAddressPolicy::LegacyZip215 {
        return Ok(());
    }

    let compressed: CompressedEdwardsY = CompressedEdwardsY(*bytes);
    let point = compressed
        .decompress()
        .ok_or(Ed25519OwnerAddressError::MalformedPoint)?;
    if point.compress().as_bytes() != bytes {
        return Err(Ed25519OwnerAddressError::NonCanonicalPoint);
    }
    if point.is_identity() {
        return Err(Ed25519OwnerAddressError::IdentityPoint);
    }
    if !point.is_torsion_free() {
        return Err(Ed25519OwnerAddressError::NonPrimeOrderPoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use ed25519_zebra::{SigningKey, VerificationKey};

    const UNIVERSAL_ZIP215_OWNER: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ];

    fn signer_owner(seed: u8) -> [u8; 32] {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let verification_key: VerificationKey = VerificationKey::from(&signing_key);
        let mut bytes: [u8; 32] = [0; 32];
        bytes.copy_from_slice(verification_key.as_ref());
        bytes
    }

    #[test]
    fn legacy_policy_preserves_unrestricted_zip215_owner_bytes() {
        assert_eq!(
            validate_ed25519_owner_address(
                &UNIVERSAL_ZIP215_OWNER,
                Ed25519OwnerAddressPolicy::LegacyZip215,
            ),
            Ok(())
        );
    }

    #[test]
    fn strict_policy_accepts_ordinary_signer_public_keys() {
        for seed in [0x11_u8, 0x22_u8, 0x33_u8] {
            assert_eq!(
                validate_ed25519_owner_address(
                    &signer_owner(seed),
                    Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn strict_policy_rejects_universal_noncanonical_small_order_owner() {
        assert_eq!(
            validate_ed25519_owner_address(
                &UNIVERSAL_ZIP215_OWNER,
                Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            ),
            Err(Ed25519OwnerAddressError::NonCanonicalPoint)
        );
    }

    #[test]
    fn strict_policy_rejects_canonical_identity_and_non_prime_order_points() {
        let canonical_identity: [u8; 32] = {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[0] = 1;
            bytes
        };
        assert_eq!(
            validate_ed25519_owner_address(
                &canonical_identity,
                Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            ),
            Err(Ed25519OwnerAddressError::IdentityPoint)
        );

        let mixed_order: [u8; 32] = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        assert_eq!(
            validate_ed25519_owner_address(
                &mixed_order,
                Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            ),
            Err(Ed25519OwnerAddressError::NonPrimeOrderPoint)
        );
    }
}
