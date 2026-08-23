#![forbid(unsafe_code)]

//! Canonically encoded protocol configuration values.

use bonds::{
    BondAssetRegistry, BondError, ValidatorAdmissionPolicy, encode_bond_asset_registry,
    encode_validator_admission_policy,
};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use commitments::{CommitmentSchemeError, CommitmentSchemeId, encode_commitment_scheme_id};
use core::fmt;
use fees::{
    FeeAssetRegistry, FeeError, GasSchedule, encode_fee_asset_registry, encode_gas_schedule,
};
use governance::{GovernanceConfig, GovernanceError, encode_governance_config};
use protocol_types::{HashSuiteId, ProtocolVersion};
use protocol_upgrades::{
    FeatureFlags, HashSuiteScheduleConfig, ProtocolUpgradeError, ProtocolUpgradeSchedule,
    encode_feature_flags, encode_hash_suite_schedule, encode_protocol_upgrade_schedule,
};
use std::error::Error;
use system_modules::{SystemModuleError, SystemModuleRegistry, encode_system_module_registry};

const PROTOCOL_CONFIG_TYPE_ID: u16 = 0x5001;
const ENCODING_VERSION: u16 = 1;

/// Errors returned by protocol configuration helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolConfigError {
    /// Protocol versions must be explicitly non-zero.
    ZeroProtocolVersion,
    /// Hash-suite identifiers must be explicitly non-zero.
    ZeroHashSuiteId,
    /// Commitment scheme encoding failed.
    CommitmentScheme(CommitmentSchemeError),
    /// Bond configuration is invalid.
    Bond(BondError),
    /// Governance configuration is invalid.
    Governance(GovernanceError),
    /// Fee configuration is invalid.
    Fee(FeeError),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// System-module registry configuration is invalid.
    SystemModules(SystemModuleError),
    /// Protocol-upgrade configuration is invalid.
    ProtocolUpgrade(ProtocolUpgradeError),
}

impl fmt::Display for ProtocolConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroProtocolVersion => write!(f, "protocol version must be non-zero"),
            Self::ZeroHashSuiteId => write!(f, "hash-suite id must be non-zero"),
            Self::CommitmentScheme(error) => error.fmt(f),
            Self::Bond(error) => error.fmt(f),
            Self::Governance(error) => error.fmt(f),
            Self::Fee(error) => error.fmt(f),
            Self::SystemModules(error) => error.fmt(f),
            Self::ProtocolUpgrade(error) => error.fmt(f),
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for ProtocolConfigError {}

impl From<CanonicalEncodingError> for ProtocolConfigError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CommitmentSchemeError> for ProtocolConfigError {
    fn from(value: CommitmentSchemeError) -> Self {
        Self::CommitmentScheme(value)
    }
}

impl From<FeeError> for ProtocolConfigError {
    fn from(value: FeeError) -> Self {
        Self::Fee(value)
    }
}

impl From<BondError> for ProtocolConfigError {
    fn from(value: BondError) -> Self {
        Self::Bond(value)
    }
}

impl From<GovernanceError> for ProtocolConfigError {
    fn from(value: GovernanceError) -> Self {
        Self::Governance(value)
    }
}

impl From<SystemModuleError> for ProtocolConfigError {
    fn from(value: SystemModuleError) -> Self {
        Self::SystemModules(value)
    }
}

impl From<ProtocolUpgradeError> for ProtocolConfigError {
    fn from(value: ProtocolUpgradeError) -> Self {
        Self::ProtocolUpgrade(value)
    }
}

/// Protocol configuration fields that affect cryptographic commitments today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// Active protocol version.
    pub protocol_version: ProtocolVersion,
    /// Active hash-suite identifier.
    pub hash_suite_id: HashSuiteId,
    /// Active commitment scheme identifier.
    pub commitment_scheme_id: CommitmentSchemeId,
    /// Deterministic per-resource fee pricing.
    pub gas_schedule: GasSchedule,
    /// Approved fee assets and conversion parameters.
    pub fee_assets: FeeAssetRegistry,
    /// Approved bond assets and validator collateral rules.
    pub bond_assets: BondAssetRegistry,
    /// Current validator admission policy.
    pub validator_admission_policy: ValidatorAdmissionPolicy,
    /// On-chain governance parameters.
    pub governance_config: GovernanceConfig,
    /// Governance-installed system module registry.
    pub system_modules: SystemModuleRegistry,
    /// Explicit protocol feature gates.
    pub feature_flags: FeatureFlags,
    /// Canonical epoch-activated hash-suite schedule.
    pub hash_suite_schedule: HashSuiteScheduleConfig,
    /// Pending protocol-version transitions.
    pub protocol_upgrades: ProtocolUpgradeSchedule,
}

impl ProtocolConfig {
    /// Returns the genesis protocol configuration.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            protocol_version: ProtocolVersion::new(1),
            hash_suite_id: HashSuiteId::new(1),
            commitment_scheme_id: CommitmentSchemeId::SparseMerkleSha256V1,
            gas_schedule: GasSchedule::genesis(),
            fee_assets: FeeAssetRegistry::new(),
            bond_assets: BondAssetRegistry::new(),
            validator_admission_policy: ValidatorAdmissionPolicy::GenesisPermissioned,
            governance_config: GovernanceConfig::genesis(),
            system_modules: SystemModuleRegistry::new(),
            feature_flags: FeatureFlags::genesis(),
            hash_suite_schedule: HashSuiteScheduleConfig::genesis(),
            protocol_upgrades: ProtocolUpgradeSchedule::new(),
        }
    }

    /// Validates protocol invariants relevant to the currently encoded fields.
    pub fn validate(&self) -> Result<(), ProtocolConfigError> {
        if self.protocol_version.get() == 0 {
            return Err(ProtocolConfigError::ZeroProtocolVersion);
        }
        if self.hash_suite_id.get() == 0 {
            return Err(ProtocolConfigError::ZeroHashSuiteId);
        }
        self.fee_assets.validate()?;
        self.bond_assets.validate()?;
        self.governance_config.validate()?;
        self.system_modules.validate()?;
        self.feature_flags.validate()?;
        self.hash_suite_schedule.validate()?;
        self.protocol_upgrades.validate()?;
        Ok(())
    }

    /// Returns canonical bytes suitable for hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolConfigError> {
        encode_protocol_config(self)
    }
}

/// Encodes a protocol configuration deterministically.
pub fn encode_protocol_config(config: &ProtocolConfig) -> Result<Vec<u8>, ProtocolConfigError> {
    config.validate()?;

    let mut canonical = CanonicalStruct::new(PROTOCOL_CONFIG_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, config.protocol_version.get())?;
    canonical.field_u16(2, config.hash_suite_id.get())?;
    canonical.field_bytes(3, encode_commitment_scheme_id(config.commitment_scheme_id)?)?;
    canonical.field_bytes(4, encode_gas_schedule(&config.gas_schedule)?)?;
    canonical.field_bytes(5, encode_fee_asset_registry(&config.fee_assets)?)?;
    canonical.field_bytes(6, encode_bond_asset_registry(&config.bond_assets)?)?;
    canonical.field_bytes(
        7,
        encode_validator_admission_policy(config.validator_admission_policy)?,
    )?;
    canonical.field_bytes(8, encode_governance_config(&config.governance_config)?)?;
    canonical.field_bytes(9, encode_system_module_registry(&config.system_modules)?)?;
    canonical.field_bytes(10, encode_feature_flags(&config.feature_flags)?)?;
    canonical.field_bytes(11, encode_hash_suite_schedule(&config.hash_suite_schedule)?)?;
    canonical.field_bytes(
        12,
        encode_protocol_upgrade_schedule(&config.protocol_upgrades)?,
    )?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonds::BondAssetConfig;
    use fees::{Amount, AssetId, FeeAsset};
    use governance::GovernanceConfig;
    use protocol_types::{Epoch, HashAlgorithmId, HashSuite};
    use protocol_upgrades::{
        CompatibilityPolicy, FeatureFlag, ProtocolUpgrade, ProtocolUpgradeSchedule,
    };
    use system_modules::{ModuleId, ModuleStatus, SystemModule};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn genesis_config_encodes_stably() {
        let bytes = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                // outer ProtocolConfig frame (field count 12)
                "534e5245015001000c00",
                "01000400000001000000",
                "0200020000000100",
                "03009f000000",
                "534e5245013001000700",
                "0100020000000100",
                "0200170000007370617273652d6d65726b6c652d7368613235362d7631",
                "030008000000736861322d323536",
                "04001700000062696e6172792d7370617273652d6d65726b6c652d7631",
                "05001100000063616e6f6e6963616c2d6c6561662d7631",
                "06001100000063616e6f6e6963616c2d6e6f64652d7631",
                "070011000000726f6c652d616e642d6c6576656c2d7631",
                "04005e000000",
                "534e5245057001000600",
                "0100080000000000000000000000",
                "0200080000000000000000000000",
                "0300080000000000000000000000",
                "0400080000000000000000000000",
                "0500080000000000000000000000",
                "0600080000000000000000000000",
                "050014000000",
                "534e5245047001000100",
                "01000400000000000000",
                "060014000000",
                "534e5245038001000100",
                "01000400000000000000",
                "070012000000",
                "534e5245018001000100",
                "0100020000000100",
                // governance_config field (field 8)
                "08002c000000",
                "534e524505900100030001000400000001000000020004000000020000000300080000000200000000000000",
                // system_module_registry field (field 9)
                "090012000000",
                "534e524507b0010001000100020000000000",
                // feature_flags field (field 10)
                "0a0012000000",
                "534e524501c0010001000100020000000000",
                // hash_suite_schedule field (field 11)
                "0b0088000000",
                "534e524503c001000200",
                "0100020000000100",
                "020070000000",
                "534e524502c001000200",
                "010018000000534e52450701010001000100080000000000000000000000",
                "020042000000",
                "534e5245040101000700",
                "0100020000000100",
                "0200020000000100",
                "0300020000000100",
                "0400020000000100",
                "0500020000000100",
                "0600020000000100",
                "0700020000000100",
                // protocol_upgrade_schedule field (field 12)
                "0c0012000000",
                "534e524506c0010001000100020000000000"
            )
        );
    }

    #[test]
    fn protocol_version_is_included_in_encoding() {
        let mut config = ProtocolConfig::genesis();
        let v1 = encode_protocol_config(&config).unwrap();
        config.protocol_version = ProtocolVersion::new(2);
        let v2 = encode_protocol_config(&config).unwrap();

        assert_ne!(v1, v2);
        assert!(hex(&v1).contains("01000000"));
        assert!(hex(&v2).contains("02000000"));
    }

    #[test]
    fn zero_identifiers_are_rejected() {
        let err = encode_protocol_config(&ProtocolConfig {
            protocol_version: ProtocolVersion::new(0),
            hash_suite_id: HashSuiteId::new(0),
            commitment_scheme_id: CommitmentSchemeId::SparseMerkleSha256V1,
            gas_schedule: GasSchedule::genesis(),
            fee_assets: FeeAssetRegistry::new(),
            bond_assets: BondAssetRegistry::new(),
            validator_admission_policy: ValidatorAdmissionPolicy::GenesisPermissioned,
            governance_config: GovernanceConfig::genesis(),
            system_modules: SystemModuleRegistry::new(),
            feature_flags: FeatureFlags::genesis(),
            hash_suite_schedule: HashSuiteScheduleConfig::genesis(),
            protocol_upgrades: ProtocolUpgradeSchedule::new(),
        })
        .unwrap_err();

        assert_eq!(err, ProtocolConfigError::ZeroProtocolVersion);
    }

    #[test]
    fn zero_hash_suite_id_is_rejected() {
        let err = encode_protocol_config(&ProtocolConfig {
            protocol_version: ProtocolVersion::new(1),
            hash_suite_id: HashSuiteId::new(0),
            commitment_scheme_id: CommitmentSchemeId::SparseMerkleSha256V1,
            gas_schedule: GasSchedule::genesis(),
            fee_assets: FeeAssetRegistry::new(),
            bond_assets: BondAssetRegistry::new(),
            validator_admission_policy: ValidatorAdmissionPolicy::GenesisPermissioned,
            governance_config: GovernanceConfig::genesis(),
            system_modules: SystemModuleRegistry::new(),
            feature_flags: FeatureFlags::genesis(),
            hash_suite_schedule: HashSuiteScheduleConfig::genesis(),
            protocol_upgrades: ProtocolUpgradeSchedule::new(),
        })
        .unwrap_err();

        assert_eq!(err, ProtocolConfigError::ZeroHashSuiteId);
    }

    #[test]
    fn fee_asset_registry_is_included_in_encoding() {
        let mut config = ProtocolConfig::genesis();
        config
            .fee_assets
            .add_asset(FeeAsset {
                asset_id: AssetId::new([0xAB; 32]),
                fee_units_per_asset_unit: 1,
                enabled: true,
            })
            .unwrap();

        let with_asset = encode_protocol_config(&config).unwrap();
        let without_asset = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        assert_ne!(with_asset, without_asset);
    }

    #[test]
    fn bond_asset_registry_is_included_in_encoding() {
        let mut config = ProtocolConfig::genesis();
        config
            .bond_assets
            .add_asset(BondAssetConfig {
                asset_id: AssetId::new([0xBC; 32]),
                min_bond: Amount::new(100),
                enabled: true,
                unbonding_epochs: 7,
                max_validator_exposure: Some(Amount::new(500)),
            })
            .unwrap();

        let with_asset = encode_protocol_config(&config).unwrap();
        let without_asset = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        assert_ne!(with_asset, without_asset);
    }

    #[test]
    fn validator_admission_policy_is_included_in_encoding() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        let mut updated = ProtocolConfig::genesis();
        updated.validator_admission_policy = ValidatorAdmissionPolicy::BondRequired;
        let bond_required = encode_protocol_config(&updated).unwrap();

        assert_ne!(genesis, bond_required);
    }

    #[test]
    fn governance_config_is_included_in_encoding() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        let mut updated = ProtocolConfig::genesis();
        updated.governance_config = GovernanceConfig {
            quorum_numerator: 2,
            quorum_denominator: 3,
            voting_epochs: 4,
        };
        let updated_bytes = encode_protocol_config(&updated).unwrap();

        assert_ne!(genesis, updated_bytes);
    }

    #[test]
    fn system_module_registry_is_included_in_encoding() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        let mut updated = ProtocolConfig::genesis();
        updated
            .system_modules
            .add_module(SystemModule {
                module_id: ModuleId::new([0xCD; 32]),
                version: 1,
                canonical_code_hash: protocol_types::Digest32::new(
                    protocol_types::HashAlgorithmId::Sha2_256,
                    [0x11; 32],
                ),
                semantics_hash: protocol_types::Digest32::new(
                    protocol_types::HashAlgorithmId::Sha2_256,
                    [0x22; 32],
                ),
                manifest_hash: protocol_types::Digest32::new(
                    protocol_types::HashAlgorithmId::Sha2_256,
                    [0x33; 32],
                ),
                activation_epoch: protocol_types::Epoch::new(3),
                status: ModuleStatus::Pending,
            })
            .unwrap();
        let updated_bytes = encode_protocol_config(&updated).unwrap();

        assert_ne!(genesis, updated_bytes);
    }

    #[test]
    fn feature_flags_and_hash_suite_schedule_are_committed() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();
        let mut updated = ProtocolConfig::genesis();
        updated
            .feature_flags
            .enable(FeatureFlag::LazyObjectMigration)
            .unwrap();
        updated
            .hash_suite_schedule
            .schedule(
                HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                Epoch::new(100),
                Epoch::new(10),
            )
            .unwrap();
        assert_ne!(genesis, encode_protocol_config(&updated).unwrap());
    }

    #[test]
    fn protocol_upgrade_schedule_is_committed() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();
        let mut updated = ProtocolConfig::genesis();
        let mut upgrades = ProtocolUpgradeSchedule::new();
        upgrades
            .schedule(
                ProtocolUpgrade {
                    from_version: ProtocolVersion::new(1),
                    to_version: ProtocolVersion::new(2),
                    activation_epoch: Epoch::new(100),
                    new_config_hash: protocol_types::Digest32::new(
                        HashAlgorithmId::Sha2_256,
                        [0x99; 32],
                    ),
                    migration_hash: None,
                    compatibility_policy: CompatibilityPolicy::Strict,
                },
                Epoch::new(10),
            )
            .unwrap();
        updated.protocol_upgrades = upgrades;
        assert_ne!(genesis, encode_protocol_config(&updated).unwrap());
    }
}
