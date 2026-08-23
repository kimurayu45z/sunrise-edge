#![forbid(unsafe_code)]

//! Governance proposal, vote, and approval primitives.
//!
//! Phase 8 introduces the on-chain governance layer. The first concrete use
//! is transitioning the validator admission policy from
//! [`ValidatorAdmissionPolicy::GenesisPermissioned`] to
//! [`ValidatorAdmissionPolicy::BondAndGovernance`].
//!
//! The crate exposes:
//! - [`ProposalId`] – opaque 32-byte proposal identifier.
//! - [`GovernanceAction`] – enumeration of protocol-level actions that
//!   governance may take.
//! - [`GovernanceProposal`] – a submitted governance proposal.
//! - [`ProposalOutcome`] – the final tally result.
//! - [`GovernanceApproval`] – a per-validator approval record produced when
//!   an admission-approval proposal passes.
//! - [`GovernanceConfig`] – on-chain governance parameters included in
//!   `ProtocolConfig`.

use bonds::{ValidatorAdmissionApproval, ValidatorAdmissionPolicy};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_epoch};
use core::fmt;
use protocol_types::{Epoch, HashSuiteSchedule};
use protocol_upgrades::{
    ProtocolUpgrade, ProtocolUpgradeError, encode_hash_suite_schedule_entry,
    encode_protocol_upgrade, validate_future_activation,
};
use runtime::ValidatorId;
use std::error::Error;
use system_modules::{
    ModuleId, SystemModule, SystemModuleError, encode_module_id, encode_system_module,
};

const GOVERNANCE_ACTION_TYPE_ID: u16 = 0x9001;
const GOVERNANCE_PROPOSAL_TYPE_ID: u16 = 0x9002;
const PROPOSAL_OUTCOME_TYPE_ID: u16 = 0x9003;
const GOVERNANCE_APPROVAL_TYPE_ID: u16 = 0x9004;
const GOVERNANCE_CONFIG_TYPE_ID: u16 = 0x9005;
const ENCODING_VERSION: u16 = 1;

/// Errors returned by governance helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// Quorum fraction numerator must not exceed the denominator.
    InvalidQuorumFraction {
        /// Numerator.
        numerator: u32,
        /// Denominator.
        denominator: u32,
    },
    /// Quorum denominator must be non-zero.
    ZeroQuorumDenominator,
    /// Voting duration must be at least one epoch.
    ZeroVotingEpochs,
    /// A `GenesisPermissioned` policy can only transition to
    /// `BondAndGovernance`, not to the supplied target.
    InvalidGenesisTransitionTarget(ValidatorAdmissionPolicy),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// System module registry action was invalid.
    SystemModule(SystemModuleError),
    /// Protocol-upgrade action was invalid.
    ProtocolUpgrade(ProtocolUpgradeError),
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuorumFraction {
                numerator,
                denominator,
            } => write!(f, "quorum fraction {numerator}/{denominator} exceeds 1.0"),
            Self::ZeroQuorumDenominator => write!(f, "quorum denominator must be non-zero"),
            Self::ZeroVotingEpochs => write!(f, "voting duration must be at least one epoch"),
            Self::InvalidGenesisTransitionTarget(policy) => write!(
                f,
                "GenesisPermissioned can only transition to BondAndGovernance, not {policy:?}"
            ),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::SystemModule(error) => error.fmt(f),
            Self::ProtocolUpgrade(error) => error.fmt(f),
        }
    }
}

impl Error for GovernanceError {}

impl From<CanonicalEncodingError> for GovernanceError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<SystemModuleError> for GovernanceError {
    fn from(value: SystemModuleError) -> Self {
        Self::SystemModule(value)
    }
}

impl From<ProtocolUpgradeError> for GovernanceError {
    fn from(value: ProtocolUpgradeError) -> Self {
        Self::ProtocolUpgrade(value)
    }
}

/// Opaque 32-byte governance proposal identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProposalId([u8; 32]);

impl ProposalId {
    /// Wraps a raw byte array as a proposal identifier.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ProposalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Wire tag for governance action variants.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum GovernanceActionTag {
    UpdateValidatorAdmissionPolicy = 0x0001,
    ApproveValidatorAdmission = 0x0002,
    InstallSystemModule = 0x0003,
    ScheduleHashSuite = 0x0004,
    ScheduleProtocolUpgrade = 0x0005,
    ActivateSystemModule = 0x0006,
    DeactivateSystemModule = 0x0007,
}

impl GovernanceActionTag {
    const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// A protocol-level action that governance may enact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovernanceAction {
    /// Change the validator admission policy.
    ///
    /// The only valid genesis-era transition is
    /// `GenesisPermissioned` → `BondAndGovernance`.
    UpdateValidatorAdmissionPolicy(ValidatorAdmissionPolicy),

    /// Approve a specific validator for admission under a permissioned policy.
    ApproveValidatorAdmission(ValidatorId),

    /// Install a new system module version through governance.
    InstallSystemModule(SystemModule),

    /// Schedule a complete hash-suite definition for future activation.
    ScheduleHashSuite(HashSuiteSchedule),

    /// Schedule a protocol-version transition for future activation.
    ScheduleProtocolUpgrade(ProtocolUpgrade),

    /// Activate a previously installed system module version.
    ActivateSystemModule {
        /// Module identifier.
        module_id: ModuleId,
        /// Installed module version.
        version: u64,
    },

    /// Disable an installed system module version.
    DeactivateSystemModule {
        /// Module identifier.
        module_id: ModuleId,
        /// Installed module version.
        version: u64,
    },
}

impl GovernanceAction {
    /// Validates the action.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if let Self::UpdateValidatorAdmissionPolicy(policy) = self {
            // Valid targets are BondAndGovernance, GovernancePermissioned, and
            // BondRequired.  Transitioning back to GenesisPermissioned is
            // rejected to prevent permanent lock-in of the genesis validator set.
            if *policy != ValidatorAdmissionPolicy::BondAndGovernance
                && *policy != ValidatorAdmissionPolicy::GovernancePermissioned
                && *policy != ValidatorAdmissionPolicy::BondRequired
            {
                return Err(GovernanceError::InvalidGenesisTransitionTarget(*policy));
            }
        }
        if let Self::InstallSystemModule(module) = self {
            module.validate()?;
        }
        if let Self::ScheduleHashSuite(entry) = self {
            encode_hash_suite_schedule_entry(entry)?;
        }
        if let Self::ScheduleProtocolUpgrade(upgrade) = self {
            upgrade.validate()?;
        }
        if let Self::ActivateSystemModule { version, .. }
        | Self::DeactivateSystemModule { version, .. } = self
        {
            if *version == 0 {
                return Err(GovernanceError::SystemModule(
                    SystemModuleError::ZeroModuleVersion,
                ));
            }
        }
        Ok(())
    }

    /// Validates action invariants that require the enactment epoch.
    pub fn validate_for_enactment(&self, current_epoch: Epoch) -> Result<(), GovernanceError> {
        self.validate()?;
        match self {
            Self::ScheduleHashSuite(entry) => {
                validate_future_activation(entry.activation_epoch, current_epoch)?;
            }
            Self::ScheduleProtocolUpgrade(upgrade) => {
                upgrade.validate_for_enactment(current_epoch)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// A submitted governance proposal pending a vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceProposal {
    /// Stable identifier for this proposal.
    pub id: ProposalId,
    /// Epoch in which the proposal was submitted.
    pub submitted_epoch: Epoch,
    /// The action to enact when the proposal passes.
    pub action: GovernanceAction,
}

impl GovernanceProposal {
    /// Validates the proposal.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        self.action.validate()
    }

    /// Validates the proposal against the epoch in which it is enacted.
    pub fn validate_for_enactment(&self, current_epoch: Epoch) -> Result<(), GovernanceError> {
        self.action.validate_for_enactment(current_epoch)
    }
}

/// The final tally outcome of a governance vote.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProposalOutcome {
    /// The proposal reached quorum and was enacted.
    Approved = 0x0001,
    /// The proposal failed to reach quorum or was vetoed.
    Rejected = 0x0002,
}

impl ProposalOutcome {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Per-validator governance approval record produced when an
/// `ApproveValidatorAdmission` proposal passes.
///
/// This record is stored alongside a [`bonds::ValidatorAdmission`] to prove
/// that governance explicitly approved the validator under a permissioned
/// policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceApproval {
    /// Proposal whose passage produced this approval.
    pub proposal_id: ProposalId,
    /// Validator that was approved.
    pub validator_id: ValidatorId,
    /// Epoch in which the approving proposal was enacted.
    pub approved_epoch: Epoch,
}

impl ValidatorAdmissionApproval for GovernanceApproval {
    fn approved_validator_id(&self) -> ValidatorId {
        self.validator_id
    }
}

/// On-chain governance parameters stored in `ProtocolConfig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceConfig {
    /// Numerator of the quorum fraction (votes-in-favour / total-validators).
    pub quorum_numerator: u32,
    /// Denominator of the quorum fraction.
    pub quorum_denominator: u32,
    /// Minimum number of epochs a proposal stays open for voting.
    pub voting_epochs: u64,
}

impl GovernanceConfig {
    /// Returns the genesis governance configuration.
    ///
    /// Genesis defaults: simple majority (1/2) quorum with a two-epoch voting
    /// window, matching a conservative permissioned-bootstrap phase.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            quorum_numerator: 1,
            quorum_denominator: 2,
            voting_epochs: 2,
        }
    }

    /// Validates the governance configuration.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.quorum_denominator == 0 {
            return Err(GovernanceError::ZeroQuorumDenominator);
        }
        if self.quorum_numerator > self.quorum_denominator {
            return Err(GovernanceError::InvalidQuorumFraction {
                numerator: self.quorum_numerator,
                denominator: self.quorum_denominator,
            });
        }
        if self.voting_epochs == 0 {
            return Err(GovernanceError::ZeroVotingEpochs);
        }
        Ok(())
    }
}

// ── Canonical encoding ────────────────────────────────────────────────────────

/// Encodes a [`GovernanceAction`] into canonical bytes.
pub fn encode_governance_action(action: &GovernanceAction) -> Result<Vec<u8>, GovernanceError> {
    action.validate()?;

    let mut canonical = CanonicalStruct::new(GOVERNANCE_ACTION_TYPE_ID, ENCODING_VERSION);
    match action {
        GovernanceAction::UpdateValidatorAdmissionPolicy(policy) => {
            canonical.field_u16(
                1,
                GovernanceActionTag::UpdateValidatorAdmissionPolicy.as_u16(),
            )?;
            canonical.field_u16(2, policy.as_u16())?;
        }
        GovernanceAction::ApproveValidatorAdmission(validator_id) => {
            canonical.field_u16(1, GovernanceActionTag::ApproveValidatorAdmission.as_u16())?;
            canonical.field_bytes(2, validator_id.as_bytes())?;
        }
        GovernanceAction::InstallSystemModule(module) => {
            canonical.field_u16(1, GovernanceActionTag::InstallSystemModule.as_u16())?;
            canonical.field_bytes(2, encode_system_module(module)?)?;
        }
        GovernanceAction::ScheduleHashSuite(entry) => {
            canonical.field_u16(1, GovernanceActionTag::ScheduleHashSuite.as_u16())?;
            canonical.field_bytes(2, encode_hash_suite_schedule_entry(entry)?)?;
        }
        GovernanceAction::ScheduleProtocolUpgrade(upgrade) => {
            canonical.field_u16(1, GovernanceActionTag::ScheduleProtocolUpgrade.as_u16())?;
            canonical.field_bytes(2, encode_protocol_upgrade(upgrade)?)?;
        }
        GovernanceAction::ActivateSystemModule { module_id, version } => {
            canonical.field_u16(1, GovernanceActionTag::ActivateSystemModule.as_u16())?;
            canonical.field_bytes(2, encode_module_id(*module_id)?)?;
            canonical.field_u64(3, *version)?;
        }
        GovernanceAction::DeactivateSystemModule { module_id, version } => {
            canonical.field_u16(1, GovernanceActionTag::DeactivateSystemModule.as_u16())?;
            canonical.field_bytes(2, encode_module_id(*module_id)?)?;
            canonical.field_u64(3, *version)?;
        }
    }
    Ok(canonical.finish()?)
}

/// Encodes a [`GovernanceProposal`] into canonical bytes.
pub fn encode_governance_proposal(
    proposal: &GovernanceProposal,
) -> Result<Vec<u8>, GovernanceError> {
    proposal.validate()?;

    let mut canonical = CanonicalStruct::new(GOVERNANCE_PROPOSAL_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, proposal.id.as_bytes())?;
    canonical.field_bytes(2, encode_epoch(proposal.submitted_epoch)?)?;
    canonical.field_bytes(3, encode_governance_action(&proposal.action)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a [`ProposalOutcome`] into canonical bytes.
pub fn encode_proposal_outcome(outcome: ProposalOutcome) -> Result<Vec<u8>, GovernanceError> {
    let mut canonical = CanonicalStruct::new(PROPOSAL_OUTCOME_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, outcome.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a [`GovernanceApproval`] into canonical bytes.
pub fn encode_governance_approval(
    approval: &GovernanceApproval,
) -> Result<Vec<u8>, GovernanceError> {
    let mut canonical = CanonicalStruct::new(GOVERNANCE_APPROVAL_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, approval.proposal_id.as_bytes())?;
    canonical.field_bytes(2, approval.validator_id.as_bytes())?;
    canonical.field_bytes(3, encode_epoch(approval.approved_epoch)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a [`GovernanceConfig`] into canonical bytes.
pub fn encode_governance_config(config: &GovernanceConfig) -> Result<Vec<u8>, GovernanceError> {
    config.validate()?;

    let mut canonical = CanonicalStruct::new(GOVERNANCE_CONFIG_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, config.quorum_numerator)?;
    canonical.field_u32(2, config.quorum_denominator)?;
    canonical.field_u64(3, config.voting_epochs)?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::Epoch;
    use protocol_types::{
        Digest32, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule, ProtocolVersion,
    };
    use protocol_upgrades::{CompatibilityPolicy, ProtocolUpgrade, ProtocolUpgradeError};
    use system_modules::{ModuleId, ModuleStatus, SystemModule};

    fn proposal_id(byte: u8) -> ProposalId {
        ProposalId::new([byte; 32])
    }

    fn validator(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn system_module(byte: u8) -> SystemModule {
        SystemModule {
            module_id: ModuleId::new([byte; 32]),
            version: 1,
            canonical_code_hash: digest(0x11),
            semantics_hash: digest(0x22),
            manifest_hash: digest(0x33),
            activation_epoch: Epoch::new(5),
            status: ModuleStatus::Pending,
        }
    }

    // ── GovernanceConfig ──────────────────────────────────────────────────────

    #[test]
    fn genesis_config_is_valid() {
        GovernanceConfig::genesis().validate().unwrap();
    }

    #[test]
    fn zero_denominator_is_rejected() {
        let err = GovernanceConfig {
            quorum_numerator: 1,
            quorum_denominator: 0,
            voting_epochs: 2,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err, GovernanceError::ZeroQuorumDenominator);
    }

    #[test]
    fn quorum_exceeding_one_is_rejected() {
        let err = GovernanceConfig {
            quorum_numerator: 3,
            quorum_denominator: 2,
            voting_epochs: 2,
        }
        .validate()
        .unwrap_err();
        assert_eq!(
            err,
            GovernanceError::InvalidQuorumFraction {
                numerator: 3,
                denominator: 2
            }
        );
    }

    #[test]
    fn zero_voting_epochs_is_rejected() {
        let err = GovernanceConfig {
            quorum_numerator: 1,
            quorum_denominator: 2,
            voting_epochs: 0,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err, GovernanceError::ZeroVotingEpochs);
    }

    // ── Encoding ──────────────────────────────────────────────────────────────

    #[test]
    fn governance_config_encodes_stably() {
        let a = encode_governance_config(&GovernanceConfig::genesis()).unwrap();
        let b = encode_governance_config(&GovernanceConfig::genesis()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn governance_config_encoding_changes_with_quorum() {
        let a = encode_governance_config(&GovernanceConfig::genesis()).unwrap();
        let b = encode_governance_config(&GovernanceConfig {
            quorum_numerator: 2,
            quorum_denominator: 3,
            voting_epochs: 2,
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn update_admission_policy_action_encodes() {
        let action = GovernanceAction::UpdateValidatorAdmissionPolicy(
            ValidatorAdmissionPolicy::BondAndGovernance,
        );
        let bytes = encode_governance_action(&action).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn approve_validator_action_encodes() {
        let action = GovernanceAction::ApproveValidatorAdmission(validator(0xAB));
        let bytes = encode_governance_action(&action).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn install_system_module_action_encodes() {
        let action = GovernanceAction::InstallSystemModule(system_module(0xAC));
        let bytes = encode_governance_action(&action).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn different_actions_produce_different_bytes() {
        let a = encode_governance_action(&GovernanceAction::UpdateValidatorAdmissionPolicy(
            ValidatorAdmissionPolicy::BondAndGovernance,
        ))
        .unwrap();
        let b = encode_governance_action(&GovernanceAction::ApproveValidatorAdmission(validator(
            0x01,
        )))
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn install_system_module_action_validates_module() {
        let mut invalid = system_module(0xAD);
        invalid.version = 0;
        let action = GovernanceAction::InstallSystemModule(invalid);
        let err = action.validate().unwrap_err();
        assert_eq!(
            err,
            GovernanceError::SystemModule(SystemModuleError::ZeroModuleVersion)
        );
    }

    #[test]
    fn hash_suite_schedule_action_requires_future_enactment() {
        let action = GovernanceAction::ScheduleHashSuite(HashSuiteSchedule {
            activation_epoch: Epoch::new(20),
            suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
        });
        assert!(!encode_governance_action(&action).unwrap().is_empty());
        assert_eq!(
            action.validate_for_enactment(Epoch::new(20)),
            Err(GovernanceError::ProtocolUpgrade(
                ProtocolUpgradeError::ActivationNotInFuture {
                    activation_epoch: Epoch::new(20),
                    current_epoch: Epoch::new(20)
                }
            ))
        );
    }

    #[test]
    fn protocol_upgrade_action_encodes_and_validates_at_enactment() {
        let action = GovernanceAction::ScheduleProtocolUpgrade(ProtocolUpgrade {
            from_version: ProtocolVersion::new(1),
            to_version: ProtocolVersion::new(2),
            activation_epoch: Epoch::new(30),
            new_config_hash: digest(0x91),
            migration_hash: Some(digest(0x92)),
            compatibility_policy: CompatibilityPolicy::ReadOldWriteNew,
        });
        assert!(!encode_governance_action(&action).unwrap().is_empty());
        action.validate_for_enactment(Epoch::new(29)).unwrap();
    }

    #[test]
    fn proposal_encodes_stably() {
        let proposal = GovernanceProposal {
            id: proposal_id(0x01),
            submitted_epoch: Epoch::new(3),
            action: GovernanceAction::UpdateValidatorAdmissionPolicy(
                ValidatorAdmissionPolicy::BondAndGovernance,
            ),
        };
        let a = encode_governance_proposal(&proposal).unwrap();
        let b = encode_governance_proposal(&proposal).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn proposal_encoding_includes_epoch() {
        let action = GovernanceAction::UpdateValidatorAdmissionPolicy(
            ValidatorAdmissionPolicy::BondAndGovernance,
        );
        let p1 = GovernanceProposal {
            id: proposal_id(0x01),
            submitted_epoch: Epoch::new(1),
            action: action.clone(),
        };
        let p2 = GovernanceProposal {
            id: proposal_id(0x01),
            submitted_epoch: Epoch::new(2),
            action,
        };
        assert_ne!(
            encode_governance_proposal(&p1).unwrap(),
            encode_governance_proposal(&p2).unwrap()
        );
    }

    #[test]
    fn proposal_outcome_approved_and_rejected_differ() {
        let a = encode_proposal_outcome(ProposalOutcome::Approved).unwrap();
        let b = encode_proposal_outcome(ProposalOutcome::Rejected).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn governance_approval_encodes_stably() {
        let approval = GovernanceApproval {
            proposal_id: proposal_id(0xAA),
            validator_id: validator(0xBB),
            approved_epoch: Epoch::new(5),
        };
        let a = encode_governance_approval(&approval).unwrap();
        let b = encode_governance_approval(&approval).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn governance_approval_differs_by_validator() {
        let a = GovernanceApproval {
            proposal_id: proposal_id(0xAA),
            validator_id: validator(0x01),
            approved_epoch: Epoch::new(5),
        };
        let b = GovernanceApproval {
            proposal_id: proposal_id(0xAA),
            validator_id: validator(0x02),
            approved_epoch: Epoch::new(5),
        };
        assert_ne!(
            encode_governance_approval(&a).unwrap(),
            encode_governance_approval(&b).unwrap()
        );
    }

    // ── GenesisPermissioned → BondAndGovernance transition ───────────────────

    #[test]
    fn genesis_permissioned_transition_to_bond_and_governance_is_valid() {
        let action = GovernanceAction::UpdateValidatorAdmissionPolicy(
            ValidatorAdmissionPolicy::BondAndGovernance,
        );
        action.validate().unwrap();
    }

    #[test]
    fn genesis_permissioned_target_itself_is_rejected() {
        let action = GovernanceAction::UpdateValidatorAdmissionPolicy(
            ValidatorAdmissionPolicy::GenesisPermissioned,
        );
        let err = action.validate().unwrap_err();
        assert_eq!(
            err,
            GovernanceError::InvalidGenesisTransitionTarget(
                ValidatorAdmissionPolicy::GenesisPermissioned
            )
        );
    }
}
