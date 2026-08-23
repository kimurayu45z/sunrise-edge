#![forbid(unsafe_code)]

//! Stablecoin bond assets, slashable bond objects, and validator admission
//! primitives.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32, encode_epoch};
use core::fmt;
use fees::{Amount, AssetId, FeeError, encode_asset_id};
use protocol_types::{Digest32, Epoch};
use runtime::ValidatorId;
use std::error::Error;

const VALIDATOR_ADMISSION_POLICY_TYPE_ID: u16 = 0x8001;
const BOND_ASSET_CONFIG_TYPE_ID: u16 = 0x8002;
const BOND_ASSET_REGISTRY_TYPE_ID: u16 = 0x8003;
const BOND_OBJECT_TYPE_ID: u16 = 0x8004;
const SLASHING_REASON_TYPE_ID: u16 = 0x8005;
const SLASHING_EVIDENCE_TYPE_ID: u16 = 0x8006;
const VALIDATOR_ADMISSION_TYPE_ID: u16 = 0x8007;
const ENCODING_VERSION: u16 = 1;
const MAX_REGISTRY_ASSETS: usize = u16::MAX as usize - 1;

/// Errors returned by bond helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondError {
    /// Bond asset minima must be explicitly non-zero.
    ZeroMinBond,
    /// Unbonding periods must be explicitly non-zero.
    ZeroUnbondingEpochs,
    /// The maximum exposure must not be less than the minimum bond.
    ExposureBelowMinBond {
        /// The configured minimum bond.
        min_bond: Amount,
        /// The configured maximum exposure.
        max_validator_exposure: Amount,
    },
    /// The registry contains more entries than can be canonically encoded.
    RegistryTooLarge(usize),
    /// The registry already contains the asset.
    DuplicateAsset(AssetId),
    /// The registry does not contain the asset.
    UnknownAsset(AssetId),
    /// The bond asset is disabled.
    AssetDisabled(AssetId),
    /// The bond amount is below the configured minimum.
    BondBelowMinimum {
        /// The validator's bond amount.
        amount: Amount,
        /// The configured minimum.
        min_bond: Amount,
    },
    /// The bond amount exceeds the configured exposure cap.
    BondAboveExposure {
        /// The validator's bond amount.
        amount: Amount,
        /// The configured maximum.
        max_validator_exposure: Amount,
    },
    /// The bond already has an unlock epoch.
    AlreadyUnbonding,
    /// The unlock epoch calculation overflowed.
    UnlockEpochOverflow,
    /// The evidence payload did not contain two distinct signed statements.
    IdenticalEvidenceDigests,
    /// Governance approval is required for admission.
    MissingGovernanceApproval,
    /// A valid slashable bond is required for admission.
    MissingBond,
    /// The bond is no longer active at the requested epoch.
    BondNotActive {
        /// Epoch being evaluated.
        epoch: Epoch,
        /// First epoch when the bond is no longer slashable.
        unlock_epoch: Epoch,
    },
    /// Fee helper encoding failed.
    Fee(FeeError),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for BondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMinBond => write!(f, "minimum bond must be non-zero"),
            Self::ZeroUnbondingEpochs => write!(f, "unbonding epochs must be non-zero"),
            Self::ExposureBelowMinBond {
                min_bond,
                max_validator_exposure,
            } => write!(
                f,
                "max validator exposure {max_validator_exposure} is below minimum bond {min_bond}"
            ),
            Self::RegistryTooLarge(count) => write!(
                f,
                "bond-asset registry has {count} entries, exceeds canonical limit"
            ),
            Self::DuplicateAsset(asset_id) => write!(f, "duplicate bond asset: {asset_id}"),
            Self::UnknownAsset(asset_id) => write!(f, "unknown bond asset: {asset_id}"),
            Self::AssetDisabled(asset_id) => write!(f, "bond asset is disabled: {asset_id}"),
            Self::BondBelowMinimum { amount, min_bond } => {
                write!(f, "bond amount {amount} is below minimum bond {min_bond}")
            }
            Self::BondAboveExposure {
                amount,
                max_validator_exposure,
            } => write!(
                f,
                "bond amount {amount} exceeds max validator exposure {max_validator_exposure}"
            ),
            Self::AlreadyUnbonding => write!(f, "bond is already unbonding"),
            Self::UnlockEpochOverflow => write!(f, "bond unlock epoch overflowed"),
            Self::IdenticalEvidenceDigests => {
                write!(f, "slashing evidence must contain two distinct statement digests")
            }
            Self::MissingGovernanceApproval => {
                write!(f, "governance approval is required for validator admission")
            }
            Self::MissingBond => write!(f, "validator admission requires a valid bond"),
            Self::BondNotActive { epoch, unlock_epoch } => write!(
                f,
                "bond is no longer active at epoch {}; unlock epoch is {}",
                epoch.get(),
                unlock_epoch.get()
            ),
            Self::Fee(error) => error.fmt(f),
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for BondError {}

impl From<FeeError> for BondError {
    fn from(value: FeeError) -> Self {
        Self::Fee(value)
    }
}

impl From<CanonicalEncodingError> for BondError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// Validator admission policy for a protocol epoch.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidatorAdmissionPolicy {
    /// The genesis validator set is hard-coded and permissioned.
    GenesisPermissioned = 0x0001,
    /// New validators require explicit governance approval only.
    GovernancePermissioned = 0x0002,
    /// New validators require both governance approval and a slashable bond.
    BondAndGovernance = 0x0003,
    /// New validators require a valid slashable bond only.
    BondRequired = 0x0004,
}

impl ValidatorAdmissionPolicy {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns whether the policy requires governance approval.
    #[must_use]
    pub const fn requires_governance_approval(self) -> bool {
        matches!(
            self,
            Self::GenesisPermissioned | Self::GovernancePermissioned | Self::BondAndGovernance
        )
    }

    /// Returns whether the policy requires a valid slashable bond.
    #[must_use]
    pub const fn requires_bond(self) -> bool {
        matches!(self, Self::BondAndGovernance | Self::BondRequired)
    }
}

/// Deterministic bond-asset policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondAssetConfig {
    /// Stable bond asset identifier.
    pub asset_id: AssetId,
    /// Minimum slashable amount required for validator eligibility.
    pub min_bond: Amount,
    /// Whether the asset may currently be used for validator bonds.
    pub enabled: bool,
    /// Number of epochs a bond stays slashable after unbond is requested.
    pub unbonding_epochs: u64,
    /// Optional maximum slashable exposure accepted from one validator.
    pub max_validator_exposure: Option<Amount>,
}

impl BondAssetConfig {
    /// Validates the bond-asset policy.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.min_bond.get() == 0 {
            return Err(BondError::ZeroMinBond);
        }
        if self.unbonding_epochs == 0 {
            return Err(BondError::ZeroUnbondingEpochs);
        }
        if let Some(max_validator_exposure) = self.max_validator_exposure {
            if max_validator_exposure < self.min_bond {
                return Err(BondError::ExposureBelowMinBond {
                    min_bond: self.min_bond,
                    max_validator_exposure,
                });
            }
        }
        Ok(())
    }
}

/// Registry of approved bond assets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BondAssetRegistry {
    assets: Vec<BondAssetConfig>,
}

impl BondAssetRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { assets: Vec::new() }
    }

    /// Returns the registered assets in canonical order.
    #[must_use]
    pub fn assets(&self) -> &[BondAssetConfig] {
        &self.assets
    }

    /// Returns the number of registered assets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Validates the registry.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.assets.len() > MAX_REGISTRY_ASSETS {
            return Err(BondError::RegistryTooLarge(self.assets.len()));
        }

        let mut previous = None;
        for asset in &self.assets {
            asset.validate()?;
            if previous == Some(asset.asset_id) {
                return Err(BondError::DuplicateAsset(asset.asset_id));
            }
            previous = Some(asset.asset_id);
        }
        Ok(())
    }

    /// Returns one registered asset.
    #[must_use]
    pub fn get(&self, asset_id: AssetId) -> Option<&BondAssetConfig> {
        self.assets
            .binary_search_by_key(&asset_id, |asset| asset.asset_id)
            .ok()
            .map(|index| &self.assets[index])
    }

    /// Registers a new bond asset.
    pub fn add_asset(&mut self, asset: BondAssetConfig) -> Result<(), BondError> {
        asset.validate()?;
        match self
            .assets
            .binary_search_by_key(&asset.asset_id, |entry| entry.asset_id)
        {
            Ok(_) => Err(BondError::DuplicateAsset(asset.asset_id)),
            Err(index) => {
                self.assets.insert(index, asset);
                Ok(())
            }
        }
    }

    /// Disables an existing bond asset.
    pub fn disable_asset(&mut self, asset_id: AssetId) -> Result<(), BondError> {
        let index = self
            .assets
            .binary_search_by_key(&asset_id, |entry| entry.asset_id)
            .map_err(|_| BondError::UnknownAsset(asset_id))?;
        self.assets[index].enabled = false;
        Ok(())
    }

    /// Replaces the policy for an existing bond asset.
    pub fn update_asset(&mut self, asset: BondAssetConfig) -> Result<(), BondError> {
        asset.validate()?;
        let index = self
            .assets
            .binary_search_by_key(&asset.asset_id, |entry| entry.asset_id)
            .map_err(|_| BondError::UnknownAsset(asset.asset_id))?;
        self.assets[index] = asset;
        Ok(())
    }
}

/// Slashable validator collateral.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondObject {
    /// Validator that controls this bond.
    pub validator_id: ValidatorId,
    /// Asset used as collateral.
    pub asset_id: AssetId,
    /// Slashable amount.
    pub amount: Amount,
    /// Epoch when the bond became active.
    pub bonded_epoch: Epoch,
    /// First epoch when the bond may be withdrawn, if unbonding has started.
    pub unlock_epoch: Option<Epoch>,
}

impl BondObject {
    /// Validates the bond against one asset policy.
    pub fn validate_against(&self, config: &BondAssetConfig) -> Result<(), BondError> {
        config.validate()?;
        if !config.enabled {
            return Err(BondError::AssetDisabled(config.asset_id));
        }
        if self.amount < config.min_bond {
            return Err(BondError::BondBelowMinimum {
                amount: self.amount,
                min_bond: config.min_bond,
            });
        }
        if let Some(max_validator_exposure) = config.max_validator_exposure {
            if self.amount > max_validator_exposure {
                return Err(BondError::BondAboveExposure {
                    amount: self.amount,
                    max_validator_exposure,
                });
            }
        }
        Ok(())
    }

    /// Returns whether the bond is still slashable at `epoch`.
    #[must_use]
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        match self.unlock_epoch {
            Some(unlock_epoch) => epoch.get() < unlock_epoch.get(),
            None => true,
        }
    }

    /// Starts unbonding using the configured delay for the bond asset.
    pub fn request_unbond(&mut self, registry: &BondAssetRegistry, epoch: Epoch) -> Result<(), BondError> {
        if self.unlock_epoch.is_some() {
            return Err(BondError::AlreadyUnbonding);
        }
        let config = registry
            .get(self.asset_id)
            .ok_or(BondError::UnknownAsset(self.asset_id))?;
        self.validate_against(config)?;
        let unlock_epoch = epoch
            .get()
            .checked_add(config.unbonding_epochs)
            .ok_or(BondError::UnlockEpochOverflow)?;
        self.unlock_epoch = Some(Epoch::new(unlock_epoch));
        Ok(())
    }
}

/// Cryptographically provable slashable offense categories.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlashingReason {
    /// Conflicting vote on the same object version or fast-path decision.
    ConflictingObjectVote = 0x0001,
    /// Consensus-layer equivocation.
    ConsensusEquivocation = 0x0002,
    /// Conflicting finalized statements.
    ConflictingFinalizedStatement = 0x0003,
    /// Any other provable double-signing offense.
    DoubleSigning = 0x0004,
}

impl SlashingReason {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// One slashable proof with two conflicting signed statements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvidence {
    /// Offending validator.
    pub validator_id: ValidatorId,
    /// Epoch in which the offense occurred.
    pub epoch: Epoch,
    /// Categorical slash reason.
    pub reason: SlashingReason,
    /// Digest of the first signed statement.
    pub left_statement: Digest32,
    /// Digest of the conflicting signed statement.
    pub right_statement: Digest32,
}

impl SlashingEvidence {
    /// Validates local evidence invariants.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.left_statement == self.right_statement {
            return Err(BondError::IdenticalEvidenceDigests);
        }
        Ok(())
    }
}

/// Admission record evaluated against an epoch's validator policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorAdmission {
    /// Validator being considered for admission.
    pub validator_id: ValidatorId,
    /// Active epoch policy.
    pub policy: ValidatorAdmissionPolicy,
    /// Whether governance approved the validator under permissioned policies.
    pub governance_approved: bool,
    /// Optional slashable bond carried by the validator.
    pub bond: Option<BondObject>,
}

impl ValidatorAdmission {
    /// Validates the admission request under the active policy.
    pub fn validate(&self, registry: &BondAssetRegistry, epoch: Epoch) -> Result<(), BondError> {
        if self.policy.requires_governance_approval() && !self.governance_approved {
            return Err(BondError::MissingGovernanceApproval);
        }

        if let Some(bond) = &self.bond {
            validate_bond_for_epoch(bond, registry, epoch)?;
        } else if self.policy.requires_bond() {
            return Err(BondError::MissingBond);
        }

        Ok(())
    }
}

fn validate_bond_for_epoch(
    bond: &BondObject,
    registry: &BondAssetRegistry,
    epoch: Epoch,
) -> Result<(), BondError> {
    let config = registry
        .get(bond.asset_id)
        .ok_or(BondError::UnknownAsset(bond.asset_id))?;
    bond.validate_against(config)?;
    if !bond.is_active_at(epoch) {
        return Err(BondError::BondNotActive {
            epoch,
            unlock_epoch: bond
                .unlock_epoch
                .expect("inactive bonds always have an unlock epoch"),
        });
    }
    Ok(())
}

/// Encodes a validator admission policy.
pub fn encode_validator_admission_policy(
    policy: ValidatorAdmissionPolicy,
) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_ADMISSION_POLICY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, policy.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes one bond asset policy.
pub fn encode_bond_asset_config(config: &BondAssetConfig) -> Result<Vec<u8>, BondError> {
    config.validate()?;

    let mut canonical = CanonicalStruct::new(BOND_ASSET_CONFIG_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&config.asset_id)?)?;
    canonical.field_u64(2, config.min_bond.get())?;
    canonical.field_bytes(3, [u8::from(config.enabled)])?;
    canonical.field_u64(4, config.unbonding_epochs)?;
    if let Some(max_validator_exposure) = config.max_validator_exposure {
        canonical.field_u64(5, max_validator_exposure.get())?;
    }
    Ok(canonical.finish()?)
}

/// Encodes the bond asset registry.
pub fn encode_bond_asset_registry(registry: &BondAssetRegistry) -> Result<Vec<u8>, BondError> {
    registry.validate()?;

    let mut canonical = CanonicalStruct::new(BOND_ASSET_REGISTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, registry.assets.len() as u32)?;
    for (index, asset) in registry.assets.iter().enumerate() {
        let field_id = u16::try_from(index + 2)
            .map_err(|_| BondError::RegistryTooLarge(registry.assets.len()))?;
        canonical.field_bytes(field_id, encode_bond_asset_config(asset)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes one bond object.
pub fn encode_bond_object(bond: &BondObject) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(BOND_OBJECT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, bond.validator_id.as_bytes())?;
    canonical.field_bytes(2, encode_asset_id(&bond.asset_id)?)?;
    canonical.field_u64(3, bond.amount.get())?;
    canonical.field_bytes(4, encode_epoch(bond.bonded_epoch)?)?;
    if let Some(unlock_epoch) = bond.unlock_epoch {
        canonical.field_bytes(5, encode_epoch(unlock_epoch)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a slashing reason.
pub fn encode_slashing_reason(reason: SlashingReason) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(SLASHING_REASON_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, reason.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes slashable evidence.
pub fn encode_slashing_evidence(evidence: &SlashingEvidence) -> Result<Vec<u8>, BondError> {
    evidence.validate()?;

    let mut canonical = CanonicalStruct::new(SLASHING_EVIDENCE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, evidence.validator_id.as_bytes())?;
    canonical.field_bytes(2, encode_epoch(evidence.epoch)?)?;
    canonical.field_bytes(3, encode_slashing_reason(evidence.reason)?)?;
    canonical.field_bytes(4, encode_digest32(&evidence.left_statement)?)?;
    canonical.field_bytes(5, encode_digest32(&evidence.right_statement)?)?;
    Ok(canonical.finish()?)
}

/// Encodes one validator admission record.
pub fn encode_validator_admission(
    admission: &ValidatorAdmission,
) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_ADMISSION_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, admission.validator_id.as_bytes())?;
    canonical.field_bytes(2, encode_validator_admission_policy(admission.policy)?)?;
    canonical.field_bytes(3, [u8::from(admission.governance_approved)])?;
    if let Some(bond) = &admission.bond {
        canonical.field_bytes(4, encode_bond_object(bond)?)?;
    }
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;

    fn asset(byte: u8) -> AssetId {
        AssetId::new([byte; 32])
    }

    fn validator(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn sample_asset_config(byte: u8) -> BondAssetConfig {
        BondAssetConfig {
            asset_id: asset(byte),
            min_bond: Amount::new(100),
            enabled: true,
            unbonding_epochs: 7,
            max_validator_exposure: Some(Amount::new(500)),
        }
    }

    #[test]
    fn registry_keeps_assets_sorted() {
        let mut registry = BondAssetRegistry::new();
        registry.add_asset(sample_asset_config(0xBB)).unwrap();
        registry.add_asset(sample_asset_config(0xAA)).unwrap();

        assert_eq!(registry.assets()[0].asset_id, asset(0xAA));
        assert_eq!(registry.assets()[1].asset_id, asset(0xBB));
    }

    #[test]
    fn request_unbond_sets_unlock_epoch_from_asset_config() {
        let mut registry = BondAssetRegistry::new();
        registry.add_asset(sample_asset_config(0x11)).unwrap();

        let mut bond = BondObject {
            validator_id: validator(0x22),
            asset_id: asset(0x11),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(10),
            unlock_epoch: None,
        };

        bond.request_unbond(&registry, Epoch::new(40)).unwrap();

        assert_eq!(bond.unlock_epoch, Some(Epoch::new(47)));
        assert!(bond.is_active_at(Epoch::new(46)));
        assert!(!bond.is_active_at(Epoch::new(47)));
    }

    #[test]
    fn validator_admission_enforces_bond_and_governance_policy() {
        let mut registry = BondAssetRegistry::new();
        registry.add_asset(sample_asset_config(0x33)).unwrap();

        let bond = BondObject {
            validator_id: validator(0x44),
            asset_id: asset(0x33),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(3),
            unlock_epoch: None,
        };

        let missing_governance = ValidatorAdmission {
            validator_id: validator(0x44),
            policy: ValidatorAdmissionPolicy::BondAndGovernance,
            governance_approved: false,
            bond: Some(bond.clone()),
        };
        assert_eq!(
            missing_governance.validate(&registry, Epoch::new(5)),
            Err(BondError::MissingGovernanceApproval)
        );

        let valid = ValidatorAdmission {
            validator_id: validator(0x44),
            policy: ValidatorAdmissionPolicy::BondAndGovernance,
            governance_approved: true,
            bond: Some(bond),
        };
        assert_eq!(valid.validate(&registry, Epoch::new(5)), Ok(()));
    }

    #[test]
    fn slashing_evidence_requires_distinct_statement_digests() {
        let evidence = SlashingEvidence {
            validator_id: validator(0x55),
            epoch: Epoch::new(9),
            reason: SlashingReason::DoubleSigning,
            left_statement: digest(0xAA),
            right_statement: digest(0xAA),
        };

        assert_eq!(evidence.validate(), Err(BondError::IdenticalEvidenceDigests));
    }

    #[test]
    fn bond_registry_encoding_changes_when_policy_changes() {
        let registry = BondAssetRegistry::new();
        let empty = encode_bond_asset_registry(&registry).unwrap();

        let mut populated = BondAssetRegistry::new();
        populated.add_asset(sample_asset_config(0x77)).unwrap();
        let with_asset = encode_bond_asset_registry(&populated).unwrap();

        assert_ne!(empty, with_asset);
    }
}
