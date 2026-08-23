#![forbid(unsafe_code)]

//! Canonical protocol-upgrade, feature-flag, and hash-suite schedule types.

use canonical_encoding::{
    CanonicalEncodingError, CanonicalStruct, encode_digest32, encode_epoch, encode_hash_suite,
    encode_protocol_version,
};
use core::fmt;
use protocol_types::{Digest32, Epoch, HashSuite, HashSuiteId, HashSuiteSchedule, ProtocolVersion};
use std::error::Error;

const FEATURE_FLAGS_TYPE_ID: u16 = 0xC001;
const HASH_SUITE_SCHEDULE_ENTRY_TYPE_ID: u16 = 0xC002;
const HASH_SUITE_SCHEDULE_TYPE_ID: u16 = 0xC003;
const COMPATIBILITY_POLICY_TYPE_ID: u16 = 0xC004;
const PROTOCOL_UPGRADE_TYPE_ID: u16 = 0xC005;
const PROTOCOL_UPGRADE_SCHEDULE_TYPE_ID: u16 = 0xC006;
const MIGRATION_DESCRIPTOR_TYPE_ID: u16 = 0xC007;
const ENCODING_VERSION: u16 = 1;
const MAX_SCHEDULE_ENTRIES: usize = u16::MAX as usize - 1;

/// Errors returned by protocol-upgrade helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolUpgradeError {
    /// A feature flag occurred more than once.
    DuplicateFeatureFlag(FeatureFlag),
    /// Feature flags were not stored in canonical identifier order.
    FeatureFlagsOutOfOrder,
    /// A hash-suite schedule was empty.
    EmptyHashSuiteSchedule,
    /// A hash-suite schedule must begin at epoch zero.
    MissingGenesisHashSuite,
    /// A hash-suite identifier must be non-zero.
    ZeroHashSuiteId,
    /// A hash-suite identifier occurred more than once.
    DuplicateHashSuiteId(HashSuiteId),
    /// Schedule activation epochs must be strictly increasing.
    NonMonotonicActivationEpochs,
    /// A schedule contains more entries than canonical encoding permits.
    ScheduleTooLarge(usize),
    /// Scheduled activation must be later than the current epoch.
    ActivationNotInFuture {
        /// Requested activation epoch.
        activation_epoch: Epoch,
        /// Epoch in which the schedule is being enacted.
        current_epoch: Epoch,
    },
    /// Protocol versions must be non-zero.
    ZeroProtocolVersion,
    /// A protocol upgrade must increase the protocol version.
    NonIncreasingProtocolVersion {
        /// Version being upgraded from.
        from: ProtocolVersion,
        /// Requested target version.
        to: ProtocolVersion,
    },
    /// Adjacent scheduled upgrades must form one continuous version chain.
    DiscontinuousProtocolVersions {
        /// Expected source version.
        expected_from: ProtocolVersion,
        /// Actual source version.
        actual_from: ProtocolVersion,
    },
    /// Migration versions and schema versions must be non-zero.
    ZeroMigrationVersion,
    /// A migration must increase the object schema version.
    NonIncreasingSchemaVersion {
        /// Existing schema version.
        from: u32,
        /// Requested target schema version.
        to: u32,
    },
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for ProtocolUpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFeatureFlag(flag) => write!(f, "duplicate feature flag: {flag:?}"),
            Self::FeatureFlagsOutOfOrder => write!(f, "feature flags are out of canonical order"),
            Self::EmptyHashSuiteSchedule => write!(f, "hash-suite schedule must not be empty"),
            Self::MissingGenesisHashSuite => {
                write!(f, "hash-suite schedule must begin at epoch zero")
            }
            Self::ZeroHashSuiteId => write!(f, "hash-suite id must be non-zero"),
            Self::DuplicateHashSuiteId(id) => {
                write!(f, "duplicate hash-suite id: {}", id.get())
            }
            Self::NonMonotonicActivationEpochs => {
                write!(f, "activation epochs must be strictly increasing")
            }
            Self::ScheduleTooLarge(count) => {
                write!(f, "schedule has {count} entries, exceeds canonical limit")
            }
            Self::ActivationNotInFuture {
                activation_epoch,
                current_epoch,
            } => write!(
                f,
                "activation epoch {} must be later than current epoch {}",
                activation_epoch.get(),
                current_epoch.get()
            ),
            Self::ZeroProtocolVersion => write!(f, "protocol versions must be non-zero"),
            Self::NonIncreasingProtocolVersion { from, to } => write!(
                f,
                "protocol upgrade must increase version ({} -> {})",
                from.get(),
                to.get()
            ),
            Self::DiscontinuousProtocolVersions {
                expected_from,
                actual_from,
            } => write!(
                f,
                "protocol upgrade chain expected source version {}, got {}",
                expected_from.get(),
                actual_from.get()
            ),
            Self::ZeroMigrationVersion => {
                write!(f, "migration and schema versions must be non-zero")
            }
            Self::NonIncreasingSchemaVersion { from, to } => {
                write!(f, "migration must increase schema version ({from} -> {to})")
            }
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for ProtocolUpgradeError {}

impl From<CanonicalEncodingError> for ProtocolUpgradeError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// Closed set of protocol features that may be activated by configuration.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FeatureFlag {
    /// Enables execution of versioned Chain IR programs.
    ChainIrExecution = 0x0001,
    /// Enables calls into governance-installed system modules.
    SystemModuleExecution = 0x0002,
    /// Enables deterministic per-object lazy schema migrations.
    LazyObjectMigration = 0x0003,
}

impl FeatureFlag {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Canonically ordered active feature flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlags {
    flags: Vec<FeatureFlag>,
}

impl FeatureFlags {
    /// Returns the genesis feature set.
    #[must_use]
    pub const fn genesis() -> Self {
        Self { flags: Vec::new() }
    }

    /// Returns active flags in canonical identifier order.
    #[must_use]
    pub fn flags(&self) -> &[FeatureFlag] {
        &self.flags
    }

    /// Returns whether a feature is active.
    #[must_use]
    pub fn contains(&self, flag: FeatureFlag) -> bool {
        self.flags.binary_search(&flag).is_ok()
    }

    /// Enables a feature while preserving canonical order.
    pub fn enable(&mut self, flag: FeatureFlag) -> Result<(), ProtocolUpgradeError> {
        match self.flags.binary_search(&flag) {
            Ok(_) => Err(ProtocolUpgradeError::DuplicateFeatureFlag(flag)),
            Err(index) => {
                self.flags.insert(index, flag);
                Ok(())
            }
        }
    }

    /// Disables a feature, returning whether it was active.
    pub fn disable(&mut self, flag: FeatureFlag) -> bool {
        match self.flags.binary_search(&flag) {
            Ok(index) => {
                self.flags.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    /// Validates canonical ordering and uniqueness.
    pub fn validate(&self) -> Result<(), ProtocolUpgradeError> {
        for pair in self.flags.windows(2) {
            if pair[0] == pair[1] {
                return Err(ProtocolUpgradeError::DuplicateFeatureFlag(pair[0]));
            }
            if pair[0] > pair[1] {
                return Err(ProtocolUpgradeError::FeatureFlagsOutOfOrder);
            }
        }
        Ok(())
    }
}

/// A canonically committed hash-suite activation schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSuiteScheduleConfig {
    entries: Vec<HashSuiteSchedule>,
}

impl HashSuiteScheduleConfig {
    /// Returns the genesis SHA-256 schedule.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            entries: vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        }
    }

    /// Creates and validates a schedule.
    pub fn new(entries: Vec<HashSuiteSchedule>) -> Result<Self, ProtocolUpgradeError> {
        let schedule = Self { entries };
        schedule.validate()?;
        Ok(schedule)
    }

    /// Returns schedule entries in activation order.
    #[must_use]
    pub fn entries(&self) -> &[HashSuiteSchedule] {
        &self.entries
    }

    /// Returns the suite active at an epoch.
    #[must_use]
    pub fn active_at(&self, epoch: Epoch) -> Option<&HashSuite> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.activation_epoch <= epoch)
            .map(|entry| &entry.suite)
    }

    /// Appends a future hash-suite activation.
    pub fn schedule(
        &mut self,
        suite: HashSuite,
        activation_epoch: Epoch,
        current_epoch: Epoch,
    ) -> Result<(), ProtocolUpgradeError> {
        validate_future_activation(activation_epoch, current_epoch)?;
        if suite.id.get() == 0 {
            return Err(ProtocolUpgradeError::ZeroHashSuiteId);
        }
        if self.entries.iter().any(|entry| entry.suite.id == suite.id) {
            return Err(ProtocolUpgradeError::DuplicateHashSuiteId(suite.id));
        }
        if self
            .entries
            .last()
            .is_some_and(|entry| entry.activation_epoch >= activation_epoch)
        {
            return Err(ProtocolUpgradeError::NonMonotonicActivationEpochs);
        }
        if self.entries.len() >= MAX_SCHEDULE_ENTRIES {
            return Err(ProtocolUpgradeError::ScheduleTooLarge(
                self.entries.len() + 1,
            ));
        }
        self.entries.push(HashSuiteSchedule {
            activation_epoch,
            suite,
        });
        Ok(())
    }

    /// Validates schedule bounds, ordering, and suite identifiers.
    pub fn validate(&self) -> Result<(), ProtocolUpgradeError> {
        if self.entries.is_empty() {
            return Err(ProtocolUpgradeError::EmptyHashSuiteSchedule);
        }
        if self.entries.len() > MAX_SCHEDULE_ENTRIES {
            return Err(ProtocolUpgradeError::ScheduleTooLarge(self.entries.len()));
        }
        if self.entries[0].activation_epoch.get() != 0 {
            return Err(ProtocolUpgradeError::MissingGenesisHashSuite);
        }

        let mut seen_ids = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            if entry.suite.id.get() == 0 {
                return Err(ProtocolUpgradeError::ZeroHashSuiteId);
            }
            if seen_ids.contains(&entry.suite.id) {
                return Err(ProtocolUpgradeError::DuplicateHashSuiteId(entry.suite.id));
            }
            seen_ids.push(entry.suite.id);
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].activation_epoch >= pair[1].activation_epoch)
        {
            return Err(ProtocolUpgradeError::NonMonotonicActivationEpochs);
        }
        Ok(())
    }
}

impl Default for HashSuiteScheduleConfig {
    fn default() -> Self {
        Self::genesis()
    }
}

/// Compatibility behavior for historical data after a protocol upgrade.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompatibilityPolicy {
    /// Only the activated protocol version may be used for new messages.
    Strict = 0x0001,
    /// Historical values remain readable, while new writes use the new version.
    ReadOldWriteNew = 0x0002,
}

impl CompatibilityPolicy {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// One governance-scheduled protocol version transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolUpgrade {
    /// Version expected before activation.
    pub from_version: ProtocolVersion,
    /// Version activated at the target epoch.
    pub to_version: ProtocolVersion,
    /// First epoch using the target version.
    pub activation_epoch: Epoch,
    /// Digest of the complete target protocol configuration.
    pub new_config_hash: Digest32,
    /// Optional digest of the deterministic migration implementation.
    pub migration_hash: Option<Digest32>,
    /// Historical-data compatibility behavior.
    pub compatibility_policy: CompatibilityPolicy,
}

impl ProtocolUpgrade {
    /// Validates structural upgrade invariants.
    pub fn validate(&self) -> Result<(), ProtocolUpgradeError> {
        if self.from_version.get() == 0 || self.to_version.get() == 0 {
            return Err(ProtocolUpgradeError::ZeroProtocolVersion);
        }
        if self.to_version <= self.from_version {
            return Err(ProtocolUpgradeError::NonIncreasingProtocolVersion {
                from: self.from_version,
                to: self.to_version,
            });
        }
        Ok(())
    }

    /// Validates structural invariants and future activation at enactment.
    pub fn validate_for_enactment(&self, current_epoch: Epoch) -> Result<(), ProtocolUpgradeError> {
        self.validate()?;
        validate_future_activation(self.activation_epoch, current_epoch)
    }
}

/// Canonically ordered pending protocol upgrades.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolUpgradeSchedule {
    upgrades: Vec<ProtocolUpgrade>,
}

impl ProtocolUpgradeSchedule {
    /// Creates an empty schedule.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            upgrades: Vec::new(),
        }
    }

    /// Returns upgrades in activation order.
    #[must_use]
    pub fn upgrades(&self) -> &[ProtocolUpgrade] {
        &self.upgrades
    }

    /// Appends an upgrade after validating enactment-time invariants.
    pub fn schedule(
        &mut self,
        upgrade: ProtocolUpgrade,
        current_epoch: Epoch,
    ) -> Result<(), ProtocolUpgradeError> {
        upgrade.validate_for_enactment(current_epoch)?;
        if self.upgrades.len() >= MAX_SCHEDULE_ENTRIES {
            return Err(ProtocolUpgradeError::ScheduleTooLarge(
                self.upgrades.len() + 1,
            ));
        }
        if let Some(previous) = self.upgrades.last() {
            if previous.activation_epoch >= upgrade.activation_epoch {
                return Err(ProtocolUpgradeError::NonMonotonicActivationEpochs);
            }
            if previous.to_version != upgrade.from_version {
                return Err(ProtocolUpgradeError::DiscontinuousProtocolVersions {
                    expected_from: previous.to_version,
                    actual_from: upgrade.from_version,
                });
            }
        }
        self.upgrades.push(upgrade);
        Ok(())
    }

    /// Returns the last transition active at an epoch.
    #[must_use]
    pub fn active_at(&self, epoch: Epoch) -> Option<&ProtocolUpgrade> {
        self.upgrades
            .iter()
            .rev()
            .find(|upgrade| upgrade.activation_epoch <= epoch)
    }

    /// Removes transitions already activated at or before an epoch.
    ///
    /// Target configuration hashes are computed after this pruning step so an
    /// enacted transition does not recursively commit to itself.
    pub fn prune_activated(&mut self, epoch: Epoch) {
        let first_pending = self
            .upgrades
            .partition_point(|upgrade| upgrade.activation_epoch <= epoch);
        self.upgrades.drain(..first_pending);
    }

    /// Validates schedule bounds, ordering, and version continuity.
    pub fn validate(&self) -> Result<(), ProtocolUpgradeError> {
        if self.upgrades.len() > MAX_SCHEDULE_ENTRIES {
            return Err(ProtocolUpgradeError::ScheduleTooLarge(self.upgrades.len()));
        }
        for upgrade in &self.upgrades {
            upgrade.validate()?;
        }
        for pair in self.upgrades.windows(2) {
            if pair[0].activation_epoch >= pair[1].activation_epoch {
                return Err(ProtocolUpgradeError::NonMonotonicActivationEpochs);
            }
            if pair[0].to_version != pair[1].from_version {
                return Err(ProtocolUpgradeError::DiscontinuousProtocolVersions {
                    expected_from: pair[0].to_version,
                    actual_from: pair[1].from_version,
                });
            }
        }
        Ok(())
    }
}

/// Canonical identity and schema transition for a lazy object migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationDescriptor {
    /// Version of the deterministic migration implementation.
    pub migration_version: u32,
    /// Object type handled by the migration.
    pub object_type: Digest32,
    /// Schema version expected on read.
    pub from_schema_version: u32,
    /// Schema version produced on write.
    pub to_schema_version: u32,
    /// Digest of the deterministic migration implementation.
    pub migration_hash: Digest32,
}

impl MigrationDescriptor {
    /// Validates migration version progression.
    pub fn validate(&self) -> Result<(), ProtocolUpgradeError> {
        if self.migration_version == 0
            || self.from_schema_version == 0
            || self.to_schema_version == 0
        {
            return Err(ProtocolUpgradeError::ZeroMigrationVersion);
        }
        if self.to_schema_version <= self.from_schema_version {
            return Err(ProtocolUpgradeError::NonIncreasingSchemaVersion {
                from: self.from_schema_version,
                to: self.to_schema_version,
            });
        }
        Ok(())
    }
}

/// Encodes feature flags deterministically.
pub fn encode_feature_flags(flags: &FeatureFlags) -> Result<Vec<u8>, ProtocolUpgradeError> {
    flags.validate()?;
    let mut canonical = CanonicalStruct::new(FEATURE_FLAGS_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(
        1,
        u16::try_from(flags.flags().len())
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(flags.flags().len()))?,
    )?;
    for (index, flag) in flags.flags().iter().enumerate() {
        let field_id = u16::try_from(index + 2)
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(flags.flags().len()))?;
        canonical.field_u16(field_id, flag.as_u16())?;
    }
    Ok(canonical.finish()?)
}

/// Encodes one hash-suite schedule entry.
pub fn encode_hash_suite_schedule_entry(
    entry: &HashSuiteSchedule,
) -> Result<Vec<u8>, ProtocolUpgradeError> {
    if entry.suite.id.get() == 0 {
        return Err(ProtocolUpgradeError::ZeroHashSuiteId);
    }
    let mut canonical = CanonicalStruct::new(HASH_SUITE_SCHEDULE_ENTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_epoch(entry.activation_epoch)?)?;
    canonical.field_bytes(2, encode_hash_suite(&entry.suite)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a complete hash-suite schedule.
pub fn encode_hash_suite_schedule(
    schedule: &HashSuiteScheduleConfig,
) -> Result<Vec<u8>, ProtocolUpgradeError> {
    schedule.validate()?;
    let mut canonical = CanonicalStruct::new(HASH_SUITE_SCHEDULE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(
        1,
        u16::try_from(schedule.entries().len())
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(schedule.entries().len()))?,
    )?;
    for (index, entry) in schedule.entries().iter().enumerate() {
        let field_id = u16::try_from(index + 2)
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(schedule.entries().len()))?;
        canonical.field_bytes(field_id, encode_hash_suite_schedule_entry(entry)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a compatibility policy.
pub fn encode_compatibility_policy(
    policy: CompatibilityPolicy,
) -> Result<Vec<u8>, ProtocolUpgradeError> {
    let mut canonical = CanonicalStruct::new(COMPATIBILITY_POLICY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, policy.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes one protocol upgrade.
pub fn encode_protocol_upgrade(upgrade: &ProtocolUpgrade) -> Result<Vec<u8>, ProtocolUpgradeError> {
    upgrade.validate()?;
    let mut canonical = CanonicalStruct::new(PROTOCOL_UPGRADE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_protocol_version(upgrade.from_version)?)?;
    canonical.field_bytes(2, encode_protocol_version(upgrade.to_version)?)?;
    canonical.field_bytes(3, encode_epoch(upgrade.activation_epoch)?)?;
    canonical.field_bytes(4, encode_digest32(&upgrade.new_config_hash)?)?;
    if let Some(migration_hash) = &upgrade.migration_hash {
        canonical.field_bytes(5, encode_digest32(migration_hash)?)?;
    }
    canonical.field_bytes(
        6,
        encode_compatibility_policy(upgrade.compatibility_policy)?,
    )?;
    Ok(canonical.finish()?)
}

/// Encodes all pending protocol upgrades.
pub fn encode_protocol_upgrade_schedule(
    schedule: &ProtocolUpgradeSchedule,
) -> Result<Vec<u8>, ProtocolUpgradeError> {
    schedule.validate()?;
    let mut canonical = CanonicalStruct::new(PROTOCOL_UPGRADE_SCHEDULE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(
        1,
        u16::try_from(schedule.upgrades().len())
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(schedule.upgrades().len()))?,
    )?;
    for (index, upgrade) in schedule.upgrades().iter().enumerate() {
        let field_id = u16::try_from(index + 2)
            .map_err(|_| ProtocolUpgradeError::ScheduleTooLarge(schedule.upgrades().len()))?;
        canonical.field_bytes(field_id, encode_protocol_upgrade(upgrade)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a lazy-migration descriptor.
pub fn encode_migration_descriptor(
    descriptor: &MigrationDescriptor,
) -> Result<Vec<u8>, ProtocolUpgradeError> {
    descriptor.validate()?;
    let mut canonical = CanonicalStruct::new(MIGRATION_DESCRIPTOR_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, descriptor.migration_version)?;
    canonical.field_bytes(2, encode_digest32(&descriptor.object_type)?)?;
    canonical.field_u32(3, descriptor.from_schema_version)?;
    canonical.field_u32(4, descriptor.to_schema_version)?;
    canonical.field_bytes(5, encode_digest32(&descriptor.migration_hash)?)?;
    Ok(canonical.finish()?)
}

/// Validates that a scheduled activation remains future-dated at enactment.
pub fn validate_future_activation(
    activation_epoch: Epoch,
    current_epoch: Epoch,
) -> Result<(), ProtocolUpgradeError> {
    if activation_epoch <= current_epoch {
        return Err(ProtocolUpgradeError::ActivationNotInFuture {
            activation_epoch,
            current_epoch,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashAlgorithmId, HashSuiteId};

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn upgrade(from: u32, to: u32, activation_epoch: u64) -> ProtocolUpgrade {
        ProtocolUpgrade {
            from_version: ProtocolVersion::new(from),
            to_version: ProtocolVersion::new(to),
            activation_epoch: Epoch::new(activation_epoch),
            new_config_hash: digest(0x11),
            migration_hash: Some(digest(0x22)),
            compatibility_policy: CompatibilityPolicy::ReadOldWriteNew,
        }
    }

    #[test]
    fn feature_flags_are_canonical_and_deduplicated() {
        let mut flags = FeatureFlags::genesis();
        flags.enable(FeatureFlag::LazyObjectMigration).unwrap();
        flags.enable(FeatureFlag::ChainIrExecution).unwrap();
        assert_eq!(
            flags.flags(),
            &[
                FeatureFlag::ChainIrExecution,
                FeatureFlag::LazyObjectMigration
            ]
        );
        assert_eq!(
            flags.enable(FeatureFlag::ChainIrExecution),
            Err(ProtocolUpgradeError::DuplicateFeatureFlag(
                FeatureFlag::ChainIrExecution
            ))
        );
    }

    #[test]
    fn hash_suite_upgrade_requires_future_epoch() {
        let mut schedule = HashSuiteScheduleConfig::genesis();
        let error = schedule
            .schedule(
                HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                Epoch::new(10),
                Epoch::new(10),
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProtocolUpgradeError::ActivationNotInFuture {
                activation_epoch: Epoch::new(10),
                current_epoch: Epoch::new(10)
            }
        );
    }

    #[test]
    fn hash_suite_schedule_activates_without_rewriting_history() {
        let mut schedule = HashSuiteScheduleConfig::genesis();
        schedule
            .schedule(
                HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                Epoch::new(500),
                Epoch::new(20),
            )
            .unwrap();
        assert_eq!(
            schedule.active_at(Epoch::new(499)).unwrap().id,
            HashSuiteId::new(1)
        );
        assert_eq!(
            schedule.active_at(Epoch::new(500)).unwrap().id,
            HashSuiteId::new(2)
        );
    }

    #[test]
    fn protocol_upgrade_schedule_requires_continuous_versions() {
        let mut schedule = ProtocolUpgradeSchedule::new();
        schedule
            .schedule(upgrade(1, 2, 100), Epoch::new(10))
            .unwrap();
        let error = schedule
            .schedule(upgrade(3, 4, 200), Epoch::new(20))
            .unwrap_err();
        assert_eq!(
            error,
            ProtocolUpgradeError::DiscontinuousProtocolVersions {
                expected_from: ProtocolVersion::new(2),
                actual_from: ProtocolVersion::new(3)
            }
        );
    }

    #[test]
    fn activated_upgrades_are_pruned_from_target_config() {
        let mut schedule = ProtocolUpgradeSchedule::new();
        schedule
            .schedule(upgrade(1, 2, 100), Epoch::new(10))
            .unwrap();
        schedule
            .schedule(upgrade(2, 3, 200), Epoch::new(20))
            .unwrap();
        schedule.prune_activated(Epoch::new(100));
        assert_eq!(schedule.upgrades(), &[upgrade(2, 3, 200)]);
    }

    #[test]
    fn encodings_are_stable_for_equal_values() {
        let flags = FeatureFlags::genesis();
        assert_eq!(
            encode_feature_flags(&flags).unwrap(),
            encode_feature_flags(&flags).unwrap()
        );
        let protocol_upgrade = upgrade(1, 2, 100);
        assert_eq!(
            encode_protocol_upgrade(&protocol_upgrade).unwrap(),
            encode_protocol_upgrade(&protocol_upgrade).unwrap()
        );
    }

    #[test]
    fn migration_descriptor_requires_forward_schema_change() {
        let descriptor = MigrationDescriptor {
            migration_version: 1,
            object_type: digest(0x33),
            from_schema_version: 2,
            to_schema_version: 2,
            migration_hash: digest(0x44),
        };
        assert_eq!(
            descriptor.validate(),
            Err(ProtocolUpgradeError::NonIncreasingSchemaVersion { from: 2, to: 2 })
        );
    }
}
