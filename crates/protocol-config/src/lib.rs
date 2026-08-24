#![forbid(unsafe_code)]

//! Canonically encoded protocol configuration values.

use bonds::{
    BondAssetRegistry, BondError, ValidatorAdmissionPolicy, encode_bond_asset_registry,
    encode_validator_admission_policy,
};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use commitments::{CommitmentSchemeError, CommitmentSchemeId, encode_commitment_scheme_id};
use consensus::{ConsensusError, ConsensusParameters, encode_consensus_parameters};
use core::fmt;
use fees::{
    FeeAssetRegistry, FeeError, GasSchedule, encode_fee_asset_registry, encode_gas_schedule,
};
use governance::{GovernanceConfig, GovernanceError, encode_governance_config};
use protocol_types::{AtomicityDomainId, Epoch, HashSuiteId, ProtocolVersion};
use protocol_upgrades::{
    FeatureFlags, HashSuiteScheduleConfig, ProtocolUpgradeError, ProtocolUpgradeSchedule,
    encode_feature_flags, encode_hash_suite_schedule, encode_protocol_upgrade_schedule,
};
use std::error::Error;
use system_modules::{SystemModuleError, SystemModuleRegistry, encode_system_module_registry};

const PROTOCOL_CONFIG_TYPE_ID: u16 = 0x5001;
const DOMAIN_PLACEMENT_RULE_TYPE_ID: u16 = 0x500A;
const DOMAIN_PLACEMENT_MANIFEST_TYPE_ID: u16 = 0x500B;
const ENCODING_VERSION: u16 = 1;
const DOMAIN_PLACEMENT_CONFIG_ENCODING_VERSION: u16 = 2;

/// Errors returned by protocol configuration helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolConfigError {
    /// Protocol versions must be explicitly non-zero.
    ZeroProtocolVersion,
    /// Hash-suite identifiers must be explicitly non-zero.
    ZeroHashSuiteId,
    /// Domain placement rule versions must be explicitly non-zero.
    ZeroDomainPlacementRuleVersion,
    /// Protocol version 1 must retain the historical configuration encoding.
    DomainPlacementRequiresProtocolVersion2,
    /// Protocol version 2 and later require committed domain placement.
    MissingDomainPlacement,
    /// Domain routing requires a declared application access plan.
    EmptyDomainAccessPlan,
    /// A domain-placement manifest was used before its activation epoch.
    InactiveDomainPlacement {
        /// First epoch where the manifest is active.
        activation_epoch: Epoch,
        /// Event epoch presented for routing.
        event_epoch: Epoch,
    },
    /// The active hash-suite id must have a committed schedule definition.
    ActiveHashSuiteNotScheduled(HashSuiteId),
    /// The first pending upgrade must start from the active protocol version.
    UnanchoredProtocolUpgrade {
        /// Active protocol version.
        active: ProtocolVersion,
        /// Source version declared by the first pending upgrade.
        scheduled_from: ProtocolVersion,
    },
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
    /// Shared-object consensus configuration is invalid.
    Consensus(ConsensusError),
}

impl fmt::Display for ProtocolConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroProtocolVersion => write!(f, "protocol version must be non-zero"),
            Self::ZeroHashSuiteId => write!(f, "hash-suite id must be non-zero"),
            Self::ZeroDomainPlacementRuleVersion => {
                write!(f, "domain placement rule version must be non-zero")
            }
            Self::DomainPlacementRequiresProtocolVersion2 => {
                write!(f, "domain placement requires protocol version 2 or later")
            }
            Self::MissingDomainPlacement => write!(
                f,
                "protocol version 2 or later requires a domain placement manifest"
            ),
            Self::EmptyDomainAccessPlan => {
                write!(f, "domain placement cannot resolve an empty access plan")
            }
            Self::InactiveDomainPlacement {
                activation_epoch,
                event_epoch,
            } => write!(
                f,
                "domain placement activates at epoch {}, event epoch is {}",
                activation_epoch.get(),
                event_epoch.get()
            ),
            Self::ActiveHashSuiteNotScheduled(id) => {
                write!(f, "active hash-suite id {} is not scheduled", id.get())
            }
            Self::UnanchoredProtocolUpgrade {
                active,
                scheduled_from,
            } => write!(
                f,
                "first pending upgrade starts from protocol version {}, active version is {}",
                scheduled_from.get(),
                active.get()
            ),
            Self::CommitmentScheme(error) => error.fmt(f),
            Self::Bond(error) => error.fmt(f),
            Self::Governance(error) => error.fmt(f),
            Self::Fee(error) => error.fmt(f),
            Self::SystemModules(error) => error.fmt(f),
            Self::ProtocolUpgrade(error) => error.fmt(f),
            Self::Consensus(error) => error.fmt(f),
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

impl From<ConsensusError> for ProtocolConfigError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}

/// Closed routing rules committed by a domain-placement manifest.
///
/// New variants require a new canonical tag and explicit activation semantics.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainPlacementRule {
    /// Every application key resolves to the manifest's sole logical domain.
    AllState = 0x0001,
}

impl DomainPlacementRule {
    /// Returns the stable canonical routing-rule tag.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Canonical first-profile mapping from application state to a logical domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainPlacementManifest {
    rule_version: u32,
    domain: AtomicityDomainId,
    rule: DomainPlacementRule,
    activation_epoch: Epoch,
}

impl DomainPlacementManifest {
    /// Creates the first production profile with exactly one `AllState` domain.
    pub fn single_domain(
        rule_version: u32,
        domain: AtomicityDomainId,
        activation_epoch: Epoch,
    ) -> Result<Self, ProtocolConfigError> {
        if rule_version == 0 {
            return Err(ProtocolConfigError::ZeroDomainPlacementRuleVersion);
        }
        Ok(Self {
            rule_version,
            domain,
            rule: DomainPlacementRule::AllState,
            activation_epoch,
        })
    }

    /// Returns the monotonically increasing routing-rule version.
    #[must_use]
    pub const fn rule_version(&self) -> u32 {
        self.rule_version
    }

    /// Returns the sole active logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the closed routing rule.
    #[must_use]
    pub const fn rule(&self) -> DomainPlacementRule {
        self.rule
    }

    /// Returns the first epoch where this manifest is active.
    #[must_use]
    pub const fn activation_epoch(&self) -> Epoch {
        self.activation_epoch
    }

    /// Resolves a non-empty bounded application plan at an active event epoch.
    pub fn resolve_domain(
        &self,
        event_epoch: Epoch,
        application_key_count: usize,
    ) -> Result<AtomicityDomainId, ProtocolConfigError> {
        if application_key_count == 0 {
            return Err(ProtocolConfigError::EmptyDomainAccessPlan);
        }
        if event_epoch < self.activation_epoch {
            return Err(ProtocolConfigError::InactiveDomainPlacement {
                activation_epoch: self.activation_epoch,
                event_epoch,
            });
        }
        match self.rule {
            DomainPlacementRule::AllState => Ok(self.domain),
        }
    }
}

/// Encodes a closed domain-placement routing rule.
pub fn encode_domain_placement_rule(
    rule: DomainPlacementRule,
) -> Result<Vec<u8>, ProtocolConfigError> {
    let mut canonical = CanonicalStruct::new(DOMAIN_PLACEMENT_RULE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, rule.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes one logical domain-placement manifest deterministically.
pub fn encode_domain_placement_manifest(
    manifest: &DomainPlacementManifest,
) -> Result<Vec<u8>, ProtocolConfigError> {
    if manifest.rule_version == 0 {
        return Err(ProtocolConfigError::ZeroDomainPlacementRuleVersion);
    }
    let mut canonical = CanonicalStruct::new(DOMAIN_PLACEMENT_MANIFEST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, manifest.rule_version)?;
    canonical.field_bytes(2, *manifest.domain.as_bytes())?;
    canonical.field_bytes(3, encode_domain_placement_rule(manifest.rule)?)?;
    canonical.field_u64(4, manifest.activation_epoch.get())?;
    Ok(canonical.finish()?)
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
    /// Shared-object consensus protocol and resource limits.
    pub consensus_parameters: ConsensusParameters,
    /// Logical state-domain routing, required from protocol version 2.
    pub domain_placement: Option<DomainPlacementManifest>,
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
            consensus_parameters: ConsensusParameters::genesis(),
            domain_placement: None,
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
        if !self
            .hash_suite_schedule
            .entries()
            .iter()
            .any(|entry| entry.suite.id == self.hash_suite_id)
        {
            return Err(ProtocolConfigError::ActiveHashSuiteNotScheduled(
                self.hash_suite_id,
            ));
        }
        self.protocol_upgrades.validate()?;
        self.consensus_parameters.validate()?;
        match (self.protocol_version.get(), &self.domain_placement) {
            (0 | 1, Some(_)) => {
                return Err(ProtocolConfigError::DomainPlacementRequiresProtocolVersion2);
            }
            (2.., None) => return Err(ProtocolConfigError::MissingDomainPlacement),
            (_, Some(manifest)) if manifest.rule_version == 0 => {
                return Err(ProtocolConfigError::ZeroDomainPlacementRuleVersion);
            }
            _ => {}
        }
        if let Some(first) = self.protocol_upgrades.upgrades().first()
            && first.from_version != self.protocol_version
        {
            return Err(ProtocolConfigError::UnanchoredProtocolUpgrade {
                active: self.protocol_version,
                scheduled_from: first.from_version,
            });
        }
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

    let encoding_version = if config.domain_placement.is_some() {
        DOMAIN_PLACEMENT_CONFIG_ENCODING_VERSION
    } else {
        ENCODING_VERSION
    };
    let mut canonical = CanonicalStruct::new(PROTOCOL_CONFIG_TYPE_ID, encoding_version);
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
    canonical.field_bytes(
        13,
        encode_consensus_parameters(config.consensus_parameters)?,
    )?;
    if let Some(manifest) = &config.domain_placement {
        canonical.field_bytes(14, encode_domain_placement_manifest(manifest)?)?;
    }
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

    fn domain_manifest(byte: u8, activation_epoch: u64) -> DomainPlacementManifest {
        DomainPlacementManifest::single_domain(
            1,
            AtomicityDomainId::new([byte; 32]).unwrap(),
            Epoch::new(activation_epoch),
        )
        .unwrap()
    }

    #[test]
    fn genesis_config_encodes_stably() {
        let bytes = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                // outer ProtocolConfig frame (field count 13)
                "534e5245015001000d00",
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
                "534e524506c0010001000100020000000000",
                // consensus_parameters field (field 13)
                "0d002a000000",
                "534e524505d001000300",
                "0100020000000100",
                "02000400000000040000",
                "0300080000001027000000000000"
            )
        );
    }

    #[test]
    fn protocol_version_is_included_in_encoding() {
        let mut config = ProtocolConfig::genesis();
        let v1 = encode_protocol_config(&config).unwrap();
        config.protocol_version = ProtocolVersion::new(2);
        config.domain_placement = Some(domain_manifest(0x11, 7));
        let v2 = encode_protocol_config(&config).unwrap();

        assert_ne!(v1, v2);
        assert_eq!(&v1[6..8], &ENCODING_VERSION.to_le_bytes());
        assert_eq!(
            &v2[6..8],
            &DOMAIN_PLACEMENT_CONFIG_ENCODING_VERSION.to_le_bytes()
        );
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
            consensus_parameters: ConsensusParameters::genesis(),
            domain_placement: None,
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
            consensus_parameters: ConsensusParameters::genesis(),
            domain_placement: None,
        })
        .unwrap_err();

        assert_eq!(err, ProtocolConfigError::ZeroHashSuiteId);
    }

    #[test]
    fn domain_placement_manifest_has_a_stable_canonical_vector() {
        let manifest = domain_manifest(0x11, 7);
        assert_eq!(manifest.rule_version(), 1);
        assert_eq!(manifest.rule(), DomainPlacementRule::AllState);
        assert_eq!(manifest.activation_epoch(), Epoch::new(7));
        assert_eq!(
            manifest.resolve_domain(Epoch::new(7), 1),
            Ok(manifest.domain())
        );
        assert_eq!(
            manifest.resolve_domain(Epoch::new(7), 0),
            Err(ProtocolConfigError::EmptyDomainAccessPlan)
        );
        assert_eq!(
            manifest.resolve_domain(Epoch::new(6), 1),
            Err(ProtocolConfigError::InactiveDomainPlacement {
                activation_epoch: Epoch::new(7),
                event_epoch: Epoch::new(6),
            })
        );
        assert_eq!(
            hex(&encode_domain_placement_manifest(&manifest).unwrap()),
            concat!(
                "534e52450b5001000400",
                "01000400000001000000",
                "020020000000",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "030012000000",
                "534e52450a50010001000100020000000100",
                "0400080000000700000000000000"
            )
        );
    }

    #[test]
    fn domain_placement_has_an_explicit_protocol_config_version_boundary() {
        assert_eq!(
            DomainPlacementManifest::single_domain(
                0,
                AtomicityDomainId::new([0x22; 32]).unwrap(),
                Epoch::new(7),
            ),
            Err(ProtocolConfigError::ZeroDomainPlacementRuleVersion)
        );

        let mut legacy = ProtocolConfig::genesis();
        legacy.domain_placement = Some(domain_manifest(0x22, 7));
        assert_eq!(
            legacy.validate(),
            Err(ProtocolConfigError::DomainPlacementRequiresProtocolVersion2)
        );

        let mut missing = ProtocolConfig::genesis();
        missing.protocol_version = ProtocolVersion::new(2);
        assert_eq!(
            missing.validate(),
            Err(ProtocolConfigError::MissingDomainPlacement)
        );

        missing.domain_placement = Some(domain_manifest(0x22, 7));
        assert!(missing.validate().is_ok());
        assert_ne!(
            encode_protocol_config(&missing).unwrap(),
            encode_protocol_config(&ProtocolConfig::genesis()).unwrap()
        );
    }

    #[test]
    fn active_hash_suite_must_have_a_committed_definition() {
        let mut config = ProtocolConfig::genesis();
        config.hash_suite_id = HashSuiteId::new(9);
        assert_eq!(
            config.validate(),
            Err(ProtocolConfigError::ActiveHashSuiteNotScheduled(
                HashSuiteId::new(9)
            ))
        );
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

    #[test]
    fn consensus_parameters_are_committed() {
        let genesis = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();
        let mut updated = ProtocolConfig::genesis();
        updated.consensus_parameters.view_timeout_millis = 20_000;

        assert_ne!(genesis, encode_protocol_config(&updated).unwrap());
    }

    #[test]
    fn protocol_upgrade_schedule_must_start_from_active_version() {
        let mut config = ProtocolConfig::genesis();
        config
            .protocol_upgrades
            .schedule(
                ProtocolUpgrade {
                    from_version: ProtocolVersion::new(2),
                    to_version: ProtocolVersion::new(3),
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

        assert_eq!(
            config.validate(),
            Err(ProtocolConfigError::UnanchoredProtocolUpgrade {
                active: ProtocolVersion::new(1),
                scheduled_from: ProtocolVersion::new(2),
            })
        );
    }
}
