//! The frozen provisional devnet-only derivation path (see `docs/signing/hardware-signing.md`,
//! "Provisional derivation policy").

use std::fmt;

/// The BIP32 hardened-component bit.
const HARDENED_BIT: u32 = 0x8000_0000;
/// Fixed `purpose` path component (BIP44), hardened.
const PURPOSE: u32 = 44;
/// Explicitly unregistered provisional coin-type marker, hardened. This is
/// not a claim on SLIP-0044 number 21333; see `docs/signing/hardware-signing.md`.
const COIN_TYPE: u32 = 21333;
/// Fixed `change` path component, hardened.
const CHANGE: u32 = 0;
/// Fixed `address_index` path component, hardened.
const ADDRESS_INDEX: u32 = 0;
/// Fixed path depth: `purpose'/coin_type'/account'/change'/address_index'`.
const DEPTH: u8 = 5;
/// Exact wire length: one depth byte plus five big-endian hardened `u32`
/// components.
pub const ENCODED_LEN: usize = 1 + 5 * 4;

/// Errors constructing a [`DerivationPath`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationPathError {
    /// `account` already has the hardened bit set. The wire encoding always
    /// sets that bit itself; a caller-supplied value that already has it set
    /// cannot be distinguished from a smaller hardened value and is
    /// rejected rather than silently reinterpreted.
    AccountAlreadyHardened(u32),
}

impl fmt::Display for DerivationPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountAlreadyHardened(account) => write!(
                f,
                "account {account} already has the hardened bit set; supply the plain non-hardened value"
            ),
        }
    }
}

impl std::error::Error for DerivationPathError {}

/// The frozen provisional path `m/44'/21333'/account'/0'/0'` (every
/// component hardened; see `docs/signing/hardware-signing.md`, "Provisional derivation policy").
///
/// `account` is a caller-selected non-hardened value; this type sets the
/// hardened bit for the wire encoding itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    account: u32,
}

impl DerivationPath {
    /// Builds the provisional path for `account`, rejecting an `account`
    /// value that already carries the hardened bit.
    pub fn provisional(account: u32) -> Result<Self, DerivationPathError> {
        if account & HARDENED_BIT != 0 {
            return Err(DerivationPathError::AccountAlreadyHardened(account));
        }
        Ok(Self { account })
    }

    /// Encodes the exact 21-byte wire form: one depth byte followed by five
    /// big-endian hardened `u32` components.
    #[must_use]
    pub fn encode(self) -> [u8; ENCODED_LEN] {
        let components = [
            PURPOSE | HARDENED_BIT,
            COIN_TYPE | HARDENED_BIT,
            self.account | HARDENED_BIT,
            CHANGE | HARDENED_BIT,
            ADDRESS_INDEX | HARDENED_BIT,
        ];
        let mut out = [0_u8; ENCODED_LEN];
        out[0] = DEPTH;
        for (index, component) in components.iter().enumerate() {
            let start = 1 + index * 4;
            out[start..start + 4].copy_from_slice(&component.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_exact_frozen_provisional_path() {
        let path = DerivationPath::provisional(0).unwrap();
        let encoded = path.encode();
        assert_eq!(encoded.len(), ENCODED_LEN);
        assert_eq!(encoded[0], 5);
        assert_eq!(&encoded[1..5], &(44_u32 | HARDENED_BIT).to_be_bytes());
        assert_eq!(&encoded[5..9], &(21333_u32 | HARDENED_BIT).to_be_bytes());
        assert_eq!(&encoded[9..13], &HARDENED_BIT.to_be_bytes());
        assert_eq!(&encoded[13..17], &HARDENED_BIT.to_be_bytes());
        assert_eq!(&encoded[17..21], &HARDENED_BIT.to_be_bytes());
    }

    #[test]
    fn encodes_a_non_zero_account_hardened() {
        let path = DerivationPath::provisional(7).unwrap();
        let encoded = path.encode();
        assert_eq!(&encoded[9..13], &(7_u32 | HARDENED_BIT).to_be_bytes());
    }

    #[test]
    fn rejects_an_account_that_already_has_the_hardened_bit_set() {
        let error = DerivationPath::provisional(HARDENED_BIT).unwrap_err();
        assert_eq!(
            error,
            DerivationPathError::AccountAlreadyHardened(HARDENED_BIT)
        );
    }

    #[test]
    fn distinct_accounts_encode_to_distinct_bytes() {
        let a = DerivationPath::provisional(0).unwrap().encode();
        let b = DerivationPath::provisional(1).unwrap().encode();
        assert_ne!(a, b);
    }
}
