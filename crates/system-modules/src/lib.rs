#![forbid(unsafe_code)]

//! Governance-installed system module registry and manifest primitives.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32, encode_epoch};
use core::fmt;
use protocol_types::{Digest32, Epoch};
use std::error::Error;

const MODULE_ID_TYPE_ID: u16 = 0xB001;
const TYPE_SCHEMA_TYPE_ID: u16 = 0xB002;
const GAS_MODEL_TYPE_ID: u16 = 0xB003;
const ZK_HINT_TYPE_ID: u16 = 0xB004;
const SYSTEM_MODULE_MANIFEST_TYPE_ID: u16 = 0xB005;
const SYSTEM_MODULE_TYPE_ID: u16 = 0xB006;
const SYSTEM_MODULE_REGISTRY_TYPE_ID: u16 = 0xB007;
const ENCODING_VERSION: u16 = 1;
const IDENTIFIER_LEN: usize = 32;
const MAX_MODULES: usize = u16::MAX as usize - 1;

/// Errors returned by system-module helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemModuleError {
    /// A module identifier had the wrong length.
    InvalidModuleIdLength(usize),
    /// Module version must be non-zero.
    ZeroModuleVersion,
    /// Manifest input size cap must be non-zero.
    ZeroMaxInputSize,
    /// The schema descriptor cannot be empty.
    EmptySchemaDescriptor,
    /// The zk hint name cannot be empty.
    EmptyZkHint,
    /// The registry contains too many modules for canonical encoding.
    RegistryTooLarge(usize),
    /// Duplicate `(module_id, version)` entries are not allowed.
    DuplicateModuleVersion {
        /// Duplicate module id.
        module_id: ModuleId,
        /// Duplicate version.
        version: u64,
    },
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for SystemModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModuleIdLength(length) => write!(
                f,
                "module identifiers must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::ZeroModuleVersion => write!(f, "module version must be non-zero"),
            Self::ZeroMaxInputSize => write!(f, "manifest max_input_size must be non-zero"),
            Self::EmptySchemaDescriptor => write!(f, "schema descriptor must not be empty"),
            Self::EmptyZkHint => write!(f, "zk hint must not be empty"),
            Self::RegistryTooLarge(count) => write!(
                f,
                "system-module registry has {count} entries, exceeds canonical limit"
            ),
            Self::DuplicateModuleVersion { module_id, version } => {
                write!(
                    f,
                    "duplicate system module entry: {module_id} version {version}"
                )
            }
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for SystemModuleError {}

impl From<CanonicalEncodingError> for SystemModuleError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// Stable identifier for a governance-installed system module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId {
    bytes: [u8; IDENTIFIER_LEN],
}

impl ModuleId {
    /// Creates a module identifier.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Parses a module identifier from raw bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SystemModuleError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(SystemModuleError::InvalidModuleIdLength(bytes.len()));
        }

        let mut array = [0u8; IDENTIFIER_LEN];
        array.copy_from_slice(bytes);
        Ok(Self::new(array))
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.bytes
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Lifecycle state of a system module entry.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModuleStatus {
    /// Accepted by governance and waiting for activation epoch.
    Pending = 1,
    /// Active and callable from execution.
    Active = 2,
    /// Deactivated and no longer callable.
    Disabled = 3,
}

impl ModuleStatus {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Deterministic type schema descriptor for module I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeSchema {
    /// Human-readable stable schema descriptor (e.g. namespace + version).
    pub descriptor: String,
    /// Digest of the canonical schema definition.
    pub schema_hash: Digest32,
}

impl TypeSchema {
    fn validate(&self) -> Result<(), SystemModuleError> {
        if self.descriptor.is_empty() {
            return Err(SystemModuleError::EmptySchemaDescriptor);
        }
        Ok(())
    }
}

/// Deterministic gas accounting model for a module call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasModel {
    /// Constant cost charged per invocation.
    pub base_cost: u64,
    /// Additional cost per input byte.
    pub per_input_byte_cost: u64,
}

/// Optional hint allowing optimized ZK back-ends to map calls to gadgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkHint {
    /// Stable gadget identifier.
    pub gadget: String,
    /// Gadget schema version.
    pub version: u16,
}

impl ZkHint {
    fn validate(&self) -> Result<(), SystemModuleError> {
        if self.gadget.is_empty() {
            return Err(SystemModuleError::EmptyZkHint);
        }
        Ok(())
    }
}

/// Canonical manifest declaring callable system-module semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemModuleManifest {
    /// Target module id.
    pub module_id: ModuleId,
    /// Input schema.
    pub input_schema: TypeSchema,
    /// Output schema.
    pub output_schema: TypeSchema,
    /// Hard cap on input payload size.
    pub max_input_size: u64,
    /// Deterministic gas accounting formula.
    pub gas_model: GasModel,
    /// Optional ZK acceleration hint.
    pub zk_hint: Option<ZkHint>,
}

impl SystemModuleManifest {
    /// Validates the manifest.
    pub fn validate(&self) -> Result<(), SystemModuleError> {
        self.input_schema.validate()?;
        self.output_schema.validate()?;
        if self.max_input_size == 0 {
            return Err(SystemModuleError::ZeroMaxInputSize);
        }
        if let Some(hint) = &self.zk_hint {
            hint.validate()?;
        }
        Ok(())
    }
}

/// Registry entry for one versioned module implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemModule {
    /// Module identifier.
    pub module_id: ModuleId,
    /// Monotonic module version.
    pub version: u64,
    /// Digest of canonical portable code.
    pub canonical_code_hash: Digest32,
    /// Digest of semantic test vectors / behavior commitment.
    pub semantics_hash: Digest32,
    /// Digest of the corresponding [`SystemModuleManifest`].
    pub manifest_hash: Digest32,
    /// Epoch when this version becomes active.
    pub activation_epoch: Epoch,
    /// Current module lifecycle status.
    pub status: ModuleStatus,
}

impl SystemModule {
    /// Validates the module entry.
    pub fn validate(&self) -> Result<(), SystemModuleError> {
        if self.version == 0 {
            return Err(SystemModuleError::ZeroModuleVersion);
        }
        Ok(())
    }
}

/// Versioned registry of governance-installed system modules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemModuleRegistry {
    modules: Vec<SystemModule>,
}

impl SystemModuleRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Returns modules in canonical `(module_id, version)` order.
    #[must_use]
    pub fn modules(&self) -> &[SystemModule] {
        &self.modules
    }

    /// Adds a module entry while preserving canonical order.
    pub fn add_module(&mut self, module: SystemModule) -> Result<(), SystemModuleError> {
        module.validate()?;
        let key = (module.module_id, module.version);
        match self
            .modules
            .binary_search_by_key(&key, |entry| (entry.module_id, entry.version))
        {
            Ok(_) => Err(SystemModuleError::DuplicateModuleVersion {
                module_id: module.module_id,
                version: module.version,
            }),
            Err(index) => {
                self.modules.insert(index, module);
                Ok(())
            }
        }
    }

    /// Returns one module version if present.
    #[must_use]
    pub fn get(&self, module_id: ModuleId, version: u64) -> Option<&SystemModule> {
        self.modules
            .binary_search_by_key(&(module_id, version), |entry| (entry.module_id, entry.version))
            .ok()
            .map(|index| &self.modules[index])
    }

    /// Validates registry bounds and uniqueness.
    pub fn validate(&self) -> Result<(), SystemModuleError> {
        if self.modules.len() > MAX_MODULES {
            return Err(SystemModuleError::RegistryTooLarge(self.modules.len()));
        }

        let mut previous: Option<(ModuleId, u64)> = None;
        for module in &self.modules {
            module.validate()?;
            let current = (module.module_id, module.version);
            if previous == Some(current) {
                return Err(SystemModuleError::DuplicateModuleVersion {
                    module_id: module.module_id,
                    version: module.version,
                });
            }
            previous = Some(current);
        }
        Ok(())
    }
}

/// Encodes a [`ModuleId`] into canonical bytes.
pub fn encode_module_id(module_id: ModuleId) -> Result<Vec<u8>, SystemModuleError> {
    let mut canonical = CanonicalStruct::new(MODULE_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, module_id.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes a [`TypeSchema`] into canonical bytes.
pub fn encode_type_schema(schema: &TypeSchema) -> Result<Vec<u8>, SystemModuleError> {
    schema.validate()?;
    let mut canonical = CanonicalStruct::new(TYPE_SCHEMA_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, &schema.descriptor)?;
    canonical.field_bytes(2, encode_digest32(&schema.schema_hash)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a [`GasModel`] into canonical bytes.
pub fn encode_gas_model(gas_model: GasModel) -> Result<Vec<u8>, SystemModuleError> {
    let mut canonical = CanonicalStruct::new(GAS_MODEL_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, gas_model.base_cost)?;
    canonical.field_u64(2, gas_model.per_input_byte_cost)?;
    Ok(canonical.finish()?)
}

/// Encodes a [`ZkHint`] into canonical bytes.
pub fn encode_zk_hint(hint: &ZkHint) -> Result<Vec<u8>, SystemModuleError> {
    hint.validate()?;
    let mut canonical = CanonicalStruct::new(ZK_HINT_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, &hint.gadget)?;
    canonical.field_u16(2, hint.version)?;
    Ok(canonical.finish()?)
}

/// Encodes a [`SystemModuleManifest`] into canonical bytes.
pub fn encode_system_module_manifest(
    manifest: &SystemModuleManifest,
) -> Result<Vec<u8>, SystemModuleError> {
    manifest.validate()?;

    let mut canonical = CanonicalStruct::new(SYSTEM_MODULE_MANIFEST_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_module_id(manifest.module_id)?)?;
    canonical.field_bytes(2, encode_type_schema(&manifest.input_schema)?)?;
    canonical.field_bytes(3, encode_type_schema(&manifest.output_schema)?)?;
    canonical.field_u64(4, manifest.max_input_size)?;
    canonical.field_bytes(5, encode_gas_model(manifest.gas_model)?)?;
    if let Some(hint) = &manifest.zk_hint {
        canonical.field_bytes(6, encode_zk_hint(hint)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a [`SystemModule`] into canonical bytes.
pub fn encode_system_module(module: &SystemModule) -> Result<Vec<u8>, SystemModuleError> {
    module.validate()?;

    let mut canonical = CanonicalStruct::new(SYSTEM_MODULE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_module_id(module.module_id)?)?;
    canonical.field_u64(2, module.version)?;
    canonical.field_bytes(3, encode_digest32(&module.canonical_code_hash)?)?;
    canonical.field_bytes(4, encode_digest32(&module.semantics_hash)?)?;
    canonical.field_bytes(5, encode_digest32(&module.manifest_hash)?)?;
    canonical.field_bytes(6, encode_epoch(module.activation_epoch)?)?;
    canonical.field_u16(7, module.status.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a [`SystemModuleRegistry`] into canonical bytes.
pub fn encode_system_module_registry(
    registry: &SystemModuleRegistry,
) -> Result<Vec<u8>, SystemModuleError> {
    registry.validate()?;

    let mut canonical = CanonicalStruct::new(SYSTEM_MODULE_REGISTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, registry.modules().len() as u16)?;
    for (index, module) in registry.modules().iter().enumerate() {
        let field_id = u16::try_from(2 + index)
            .map_err(|_| SystemModuleError::RegistryTooLarge(registry.modules().len()))?;
        canonical.field_bytes(field_id, encode_system_module(module)?)?;
    }
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;

    fn module_id(byte: u8) -> ModuleId {
        ModuleId::new([byte; 32])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn sample_manifest(module_id: ModuleId) -> SystemModuleManifest {
        SystemModuleManifest {
            module_id,
            input_schema: TypeSchema {
                descriptor: "system.input.v1".to_string(),
                schema_hash: digest(0x11),
            },
            output_schema: TypeSchema {
                descriptor: "system.output.v1".to_string(),
                schema_hash: digest(0x22),
            },
            max_input_size: 4096,
            gas_model: GasModel {
                base_cost: 100,
                per_input_byte_cost: 2,
            },
            zk_hint: Some(ZkHint {
                gadget: "poseidon2-permute".to_string(),
                version: 1,
            }),
        }
    }

    fn sample_module(id_byte: u8, version: u64, status: ModuleStatus) -> SystemModule {
        SystemModule {
            module_id: module_id(id_byte),
            version,
            canonical_code_hash: digest(0x33),
            semantics_hash: digest(0x44),
            manifest_hash: digest(0x55),
            activation_epoch: Epoch::new(7),
            status,
        }
    }

    #[test]
    fn module_id_rejects_wrong_length() {
        let err = ModuleId::try_from_slice(&[1, 2, 3]).unwrap_err();
        assert_eq!(err, SystemModuleError::InvalidModuleIdLength(3));
    }

    #[test]
    fn manifest_requires_non_empty_schema_descriptor() {
        let mut manifest = sample_manifest(module_id(0xAA));
        manifest.input_schema.descriptor.clear();
        let err = manifest.validate().unwrap_err();
        assert_eq!(err, SystemModuleError::EmptySchemaDescriptor);
    }

    #[test]
    fn module_requires_non_zero_version() {
        let err = sample_module(0xAA, 0, ModuleStatus::Pending)
            .validate()
            .unwrap_err();
        assert_eq!(err, SystemModuleError::ZeroModuleVersion);
    }

    #[test]
    fn registry_orders_and_deduplicates_entries() {
        let mut registry = SystemModuleRegistry::new();
        registry
            .add_module(sample_module(0xBB, 1, ModuleStatus::Pending))
            .unwrap();
        registry
            .add_module(sample_module(0xAA, 3, ModuleStatus::Active))
            .unwrap();
        registry
            .add_module(sample_module(0xAA, 1, ModuleStatus::Pending))
            .unwrap();

        assert_eq!(registry.modules()[0].module_id, module_id(0xAA));
        assert_eq!(registry.modules()[0].version, 1);
        assert_eq!(registry.modules()[1].module_id, module_id(0xAA));
        assert_eq!(registry.modules()[1].version, 3);
        assert_eq!(registry.modules()[2].module_id, module_id(0xBB));
        assert_eq!(registry.modules()[2].version, 1);
    }

    #[test]
    fn registry_rejects_duplicate_module_versions() {
        let mut registry = SystemModuleRegistry::new();
        registry
            .add_module(sample_module(0xAA, 1, ModuleStatus::Pending))
            .unwrap();
        let err = registry
            .add_module(sample_module(0xAA, 1, ModuleStatus::Active))
            .unwrap_err();
        assert_eq!(
            err,
            SystemModuleError::DuplicateModuleVersion {
                module_id: module_id(0xAA),
                version: 1,
            }
        );
    }

    #[test]
    fn manifest_encoding_changes_with_zk_hint() {
        let mut manifest = sample_manifest(module_id(0xAA));
        let with_hint = encode_system_module_manifest(&manifest).unwrap();
        manifest.zk_hint = None;
        let without_hint = encode_system_module_manifest(&manifest).unwrap();
        assert_ne!(with_hint, without_hint);
    }

    #[test]
    fn registry_encoding_is_stable() {
        let mut registry = SystemModuleRegistry::new();
        registry
            .add_module(sample_module(0xAA, 1, ModuleStatus::Pending))
            .unwrap();
        registry
            .add_module(sample_module(0xAA, 2, ModuleStatus::Active))
            .unwrap();

        let a = encode_system_module_registry(&registry).unwrap();
        let b = encode_system_module_registry(&registry).unwrap();
        assert_eq!(a, b);
    }
}
