#![forbid(unsafe_code)]

//! Epoch-scoped validator membership and voting-power snapshots.
//!
//! Validator identity, membership, voting power, and bond state are deliberately
//! separate. A [`ValidatorSet`] is the immutable consensus snapshot for one
//! epoch; bond amounts never implicitly determine voting power.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use hashing::{HashSuiteResolver, HashingError};
use protocol_types::{Digest32, Epoch, HashPurpose, SignatureSchemeId, ValidatorId};
use std::error::Error;

const VALIDATOR_INFO_TYPE_ID: u16 = 0xC001;
const VALIDATOR_SET_TYPE_ID: u16 = 0xC002;
const ENCODING_VERSION: u16 = 1;
const MAX_VALIDATORS: usize = 10_000;
const MAX_PUBLIC_KEY_BYTES: usize = 512;

/// Validator-set construction and encoding errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatorSetError {
    /// A validator set cannot be empty.
    Empty,
    /// The validator count exceeds the protocol bound.
    TooManyValidators(usize),
    /// Validator voting power must be non-zero.
    ZeroVotingPower(ValidatorId),
    /// A validator public key cannot be empty.
    EmptyPublicKey(ValidatorId),
    /// A validator public key exceeds the protocol bound.
    PublicKeyTooLarge {
        /// Validator carrying the key.
        validator: ValidatorId,
        /// Actual key length.
        length: usize,
    },
    /// A validator appears more than once.
    DuplicateValidator(ValidatorId),
    /// Total voting power overflowed `u64`.
    VotingPowerOverflow,
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Validator-set hashing failed.
    Hashing(HashingError),
}

impl fmt::Display for ValidatorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "validator set must not be empty"),
            Self::TooManyValidators(count) => {
                write!(
                    f,
                    "validator set has {count} entries, maximum is {MAX_VALIDATORS}"
                )
            }
            Self::ZeroVotingPower(id) => write!(f, "validator {id} has zero voting power"),
            Self::EmptyPublicKey(id) => write!(f, "validator {id} has an empty public key"),
            Self::PublicKeyTooLarge { validator, length } => write!(
                f,
                "validator {validator} public key is {length} bytes, maximum is {MAX_PUBLIC_KEY_BYTES}"
            ),
            Self::DuplicateValidator(id) => write!(f, "duplicate validator {id}"),
            Self::VotingPowerOverflow => write!(f, "total validator voting power overflowed"),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::Hashing(error) => error.fmt(f),
        }
    }
}

impl Error for ValidatorSetError {}

impl From<CanonicalEncodingError> for ValidatorSetError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<HashingError> for ValidatorSetError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

/// Consensus identity and voting power for one validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// Stable validator identity.
    pub id: ValidatorId,
    /// Governance-assigned voting power, independent of bond amount.
    pub voting_power: u64,
    /// Signature scheme used for consensus messages.
    pub signature_scheme: SignatureSchemeId,
    /// Public verification key in the scheme's canonical byte representation.
    pub public_key: Vec<u8>,
}

impl ValidatorInfo {
    /// Validates this validator record.
    pub fn validate(&self) -> Result<(), ValidatorSetError> {
        if self.voting_power == 0 {
            return Err(ValidatorSetError::ZeroVotingPower(self.id));
        }
        if self.public_key.is_empty() {
            return Err(ValidatorSetError::EmptyPublicKey(self.id));
        }
        if self.public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(ValidatorSetError::PublicKeyTooLarge {
                validator: self.id,
                length: self.public_key.len(),
            });
        }
        Ok(())
    }
}

/// Immutable validator membership snapshot for an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    epoch: Epoch,
    validators: Vec<ValidatorInfo>,
    total_voting_power: u64,
}

impl ValidatorSet {
    /// Creates a canonically ordered validator set.
    pub fn new(
        epoch: Epoch,
        mut validators: Vec<ValidatorInfo>,
    ) -> Result<Self, ValidatorSetError> {
        if validators.is_empty() {
            return Err(ValidatorSetError::Empty);
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(ValidatorSetError::TooManyValidators(validators.len()));
        }
        validators.sort_by_key(|validator| validator.id);

        let mut total_voting_power = 0u64;
        let mut previous = None;
        for validator in &validators {
            validator.validate()?;
            if previous == Some(validator.id) {
                return Err(ValidatorSetError::DuplicateValidator(validator.id));
            }
            previous = Some(validator.id);
            total_voting_power = total_voting_power
                .checked_add(validator.voting_power)
                .ok_or(ValidatorSetError::VotingPowerOverflow)?;
        }

        Ok(Self {
            epoch,
            validators,
            total_voting_power,
        })
    }

    /// Returns the epoch bound to this snapshot.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns validators in canonical identifier order.
    #[must_use]
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Returns the total voting power.
    #[must_use]
    pub const fn total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    /// Returns the strict greater-than-two-thirds quorum threshold.
    #[must_use]
    pub const fn quorum_threshold(&self) -> u64 {
        self.total_voting_power - ((self.total_voting_power - 1) / 3)
    }

    /// Looks up a validator by identity.
    #[must_use]
    pub fn get(&self, id: ValidatorId) -> Option<&ValidatorInfo> {
        self.validators
            .binary_search_by_key(&id, |validator| validator.id)
            .ok()
            .map(|index| &self.validators[index])
    }

    /// Returns the deterministic rotating leader for a non-zero view.
    #[must_use]
    pub fn leader(&self, view: u64) -> Option<ValidatorId> {
        let adjusted = view.checked_sub(1)?;
        let index = usize::try_from(adjusted % self.validators.len() as u64).ok()?;
        Some(self.validators[index].id)
    }

    /// Hashes this epoch snapshot in the validator-set domain.
    pub fn digest(&self, resolver: &HashSuiteResolver) -> Result<Digest32, ValidatorSetError> {
        Ok(resolver.hash_for_purpose(
            self.epoch,
            HashPurpose::ValidatorSet,
            &encode_validator_set(self)?,
        )?)
    }
}

/// Canonically encodes a validator record.
pub fn encode_validator_info(info: &ValidatorInfo) -> Result<Vec<u8>, ValidatorSetError> {
    info.validate()?;
    let mut canonical = CanonicalStruct::new(VALIDATOR_INFO_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, info.id.as_bytes())?;
    canonical.field_u64(2, info.voting_power)?;
    canonical.field_u16(3, info.signature_scheme.as_u16())?;
    canonical.field_bytes(4, info.public_key.clone())?;
    Ok(canonical.finish()?)
}

/// Canonically encodes a validator-set snapshot.
pub fn encode_validator_set(set: &ValidatorSet) -> Result<Vec<u8>, ValidatorSetError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_SET_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, set.epoch.get())?;
    canonical.field_u64(2, set.total_voting_power)?;
    canonical.field_u64(3, set.quorum_threshold())?;
    canonical.field_u32(
        4,
        u32::try_from(set.validators.len())
            .map_err(|_| ValidatorSetError::TooManyValidators(set.validators.len()))?,
    )?;
    for (index, validator) in set.validators.iter().enumerate() {
        let field_id = u16::try_from(index + 5)
            .map_err(|_| ValidatorSetError::TooManyValidators(set.validators.len()))?;
        canonical.field_bytes(field_id, encode_validator_info(validator)?)?;
    }
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};

    fn validator(byte: u8, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            id: ValidatorId::new([byte; 32]),
            voting_power: power,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![byte; 32],
        }
    }

    #[test]
    fn four_equal_validators_require_three_votes() {
        let set = ValidatorSet::new(
            Epoch::new(7),
            vec![
                validator(4, 1),
                validator(2, 1),
                validator(1, 1),
                validator(3, 1),
            ],
        )
        .unwrap();

        assert_eq!(set.total_voting_power(), 4);
        assert_eq!(set.quorum_threshold(), 3);
        assert_eq!(set.validators()[0].id, ValidatorId::new([1; 32]));
        assert_eq!(set.leader(1), Some(ValidatorId::new([1; 32])));
        assert_eq!(set.leader(5), Some(ValidatorId::new([1; 32])));
    }

    #[test]
    fn bond_size_does_not_implicitly_change_voting_power() {
        let set = ValidatorSet::new(
            Epoch::new(1),
            vec![
                validator(1, 1),
                validator(2, 1),
                validator(3, 1),
                validator(4, 1),
            ],
        )
        .unwrap();
        assert!(
            set.validators()
                .iter()
                .all(|validator| validator.voting_power == 1)
        );
    }

    #[test]
    fn duplicate_validator_is_rejected() {
        assert_eq!(
            ValidatorSet::new(Epoch::new(1), vec![validator(1, 1), validator(1, 2)]),
            Err(ValidatorSetError::DuplicateValidator(ValidatorId::new(
                [1; 32]
            )))
        );
    }

    #[test]
    fn encoding_and_digest_are_order_independent() {
        let left = ValidatorSet::new(
            Epoch::new(9),
            vec![validator(3, 1), validator(1, 1), validator(2, 1)],
        )
        .unwrap();
        let right = ValidatorSet::new(
            Epoch::new(9),
            vec![validator(2, 1), validator(3, 1), validator(1, 1)],
        )
        .unwrap();
        assert_eq!(
            encode_validator_set(&left).unwrap(),
            encode_validator_set(&right).unwrap()
        );

        let resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        assert_eq!(
            left.digest(&resolver).unwrap(),
            right.digest(&resolver).unwrap()
        );
    }
}
