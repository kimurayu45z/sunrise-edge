//! Bounded, caller-supplied preinstalled WASM module composition.
//!
//! This module is intentionally private-by-default: only
//! [`PreinstalledModuleCatalogEntry`], [`PreinstalledModuleCatalog`], and the
//! validated construction functions are exported. There is no way to build a
//! catalog entry from request bytes, a network fetch, or an arbitrary
//! upload — the only constructor is [`PreinstalledModuleCatalogEntry::new`],
//! called by trusted node composition before serving traffic. Native HTTP
//! wiring, JIT/AOT execution, and production gas metering remain deferred;
//! see `ARCHITECTURE.md` and `TODO.md` (Developer MVP Gate, step 3).
//!
//! # `Transaction.module_ref` mapping (MVP)
//!
//! [`resolve_preinstalled_module`] interprets an authenticated transaction's
//! `module_ref: ObjectRef` as a direct reference into the governance-managed
//! [`SystemModuleRegistry`], not a storage object:
//!
//! * `module_id = ObjectId` bytes (`module_ref.id.as_bytes()`);
//! * `version = ObjectRef.version`;
//! * `digest = canonical_code_hash` (the registry's committed WASM code
//!   digest for that exact `(module_id, version)`).
//!
//! This reuses the existing `ObjectRef` wire shape without adding a new
//! transaction field, at the cost of `module_ref` never denoting an actual
//! stored `Object` on this MVP path.

use hashing::HashSuiteResolver;
use objects::ObjectRef;
use protocol_types::{Digest32, Epoch, HashPurpose};
use system_modules::{
    ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
    encode_system_module_manifest,
};

use super::NodeCoreError;

/// Deterministic upper bound on one preinstalled module's canonical WASM
/// bytes.
///
/// Matches `execution::wasm_engine`'s own (crate-private) `MAX_MODULE_BYTES`
/// bound, so a catalog entry admitted here is never later rejected by
/// `WasmExecutionEngine` purely on module size.
pub const MAX_PREINSTALLED_MODULE_WASM_BYTES: usize = 4 * 1024 * 1024;

/// Pre-activation cap on the number of preinstalled module versions one
/// composition may hold.
///
/// This is an MVP admission bound, not a measured capacity limit.
pub const MAX_PREINSTALLED_MODULES: usize = 64;

/// One immutable, caller-supplied preinstalled module: its exact identity,
/// canonical WASM bytes, canonical manifest, and committed semantics digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreinstalledModuleCatalogEntry {
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    manifest: SystemModuleManifest,
    semantics_hash: Digest32,
}

impl PreinstalledModuleCatalogEntry {
    /// Validates and constructs one catalog entry.
    ///
    /// Rejects WASM bytes over [`MAX_PREINSTALLED_MODULE_WASM_BYTES`], an
    /// invalid [`SystemModuleManifest`], and a manifest whose `module_id`
    /// disagrees with this entry's own `module_id`, before the entry can ever
    /// be resolved against a transaction.
    pub fn new(
        module_id: ModuleId,
        version: u64,
        wasm_bytes: Vec<u8>,
        manifest: SystemModuleManifest,
        semantics_hash: Digest32,
    ) -> Result<Self, NodeCoreError> {
        if version == 0 {
            return Err(SystemModuleError::ZeroModuleVersion.into());
        }
        if wasm_bytes.len() > MAX_PREINSTALLED_MODULE_WASM_BYTES {
            return Err(NodeCoreError::PreinstalledModuleWasmTooLarge {
                module_id,
                version,
                actual: wasm_bytes.len(),
                maximum: MAX_PREINSTALLED_MODULE_WASM_BYTES,
            });
        }
        manifest.validate().map_err(NodeCoreError::from)?;
        if manifest.module_id != module_id {
            return Err(NodeCoreError::PreinstalledModuleManifestIdMismatch { module_id, version });
        }
        Ok(Self {
            module_id,
            version,
            wasm_bytes,
            manifest,
            semantics_hash,
        })
    }

    /// Returns the module identifier.
    #[must_use]
    pub const fn module_id(&self) -> ModuleId {
        self.module_id
    }

    /// Returns the module version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the canonical WASM bytes.
    #[must_use]
    pub fn wasm_bytes(&self) -> &[u8] {
        &self.wasm_bytes
    }

    /// Returns the canonical manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SystemModuleManifest {
        &self.manifest
    }

    /// Returns the committed semantics digest.
    #[must_use]
    pub const fn semantics_hash(&self) -> Digest32 {
        self.semantics_hash
    }
}

/// Bounded, immutable collection of caller-supplied preinstalled modules.
///
/// There is no mutation API: a catalog is built once, from trusted node
/// composition, and never grows or shrinks while serving traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreinstalledModuleCatalog {
    entries: std::collections::BTreeMap<(ModuleId, u64), PreinstalledModuleCatalogEntry>,
}

impl PreinstalledModuleCatalog {
    /// Validates and constructs a bounded catalog from caller-supplied entries.
    ///
    /// Rejects more than [`MAX_PREINSTALLED_MODULES`] entries and a duplicate
    /// `(module_id, version)` pair.
    pub fn new(entries: Vec<PreinstalledModuleCatalogEntry>) -> Result<Self, NodeCoreError> {
        if entries.len() > MAX_PREINSTALLED_MODULES {
            return Err(NodeCoreError::PreinstalledModuleCatalogTooLarge {
                count: entries.len(),
                maximum: MAX_PREINSTALLED_MODULES,
            });
        }
        let mut map = std::collections::BTreeMap::new();
        for entry in entries {
            let key = (entry.module_id, entry.version);
            if map.insert(key, entry).is_some() {
                return Err(NodeCoreError::DuplicatePreinstalledModule {
                    module_id: key.0,
                    version: key.1,
                });
            }
        }
        Ok(Self { entries: map })
    }

    /// Returns the exact `(module_id, version)` entry, if cataloged.
    #[must_use]
    pub fn get(
        &self,
        module_id: ModuleId,
        version: u64,
    ) -> Option<&PreinstalledModuleCatalogEntry> {
        self.entries.get(&(module_id, version))
    }
}

/// Maps an authenticated transaction's `module_ref` to the MVP preinstalled
/// module identity. See the module-level docs for the exact field mapping.
#[must_use]
pub(crate) fn preinstalled_module_identity(module_ref: &ObjectRef) -> (ModuleId, u64, Digest32) {
    (
        ModuleId::new(*module_ref.id.as_bytes()),
        module_ref.version,
        module_ref.digest,
    )
}

/// Resolves and fully verifies one preinstalled module against the committed
/// exact registry record captured from committed `ProtocolConfig` and the
/// caller-supplied [`PreinstalledModuleCatalog`].
///
/// Every check fails closed, in this order:
///
/// 1. the exact `(module_id, version)` must exist in `registry`, be
///    [`ModuleStatus::Active`], and have `activation_epoch <= epoch`;
/// 2. the exact `(module_id, version)` must exist in `catalog`;
/// 3. the transaction's declared `module_ref.digest` must equal the
///    registry's committed `canonical_code_hash`;
/// 4. the catalog entry's WASM bytes are independently rehashed with
///    [`HashPurpose::ContractCode`] under `resolver` and must also equal
///    `canonical_code_hash`;
/// 5. the catalog entry's manifest is canonically re-encoded and rehashed
///    with [`HashPurpose::ProtocolConfig`] (see below) and must equal the
///    registry's committed `manifest_hash`;
/// 6. the catalog entry's `semantics_hash` must equal the registry's
///    committed `semantics_hash`.
///
/// # Manifest hash purpose
///
/// [`protocol_types::HashPurpose`] has no dedicated system-module-manifest
/// purpose today (only [`protocol_types::HashDomain::SystemModule`] exists as
/// an unused domain identifier). Rather than mint a new discriminant for this
/// additive MVP slice, this function reuses the existing
/// [`HashPurpose::ProtocolConfig`] purpose: a [`SystemModuleManifest`] is
/// itself committed, governance-installed protocol configuration (it lives
/// inside [`protocol_config::ProtocolConfig::system_modules`]), so its
/// domain-separation semantics already match. Introducing a dedicated
/// `HashPurpose::SystemModuleManifest` remains open follow-up work tracked in
/// `ARCHITECTURE.md`.
pub(crate) fn resolve_preinstalled_module<'a>(
    module_ref: &ObjectRef,
    registered: Option<&SystemModule>,
    catalog: &'a PreinstalledModuleCatalog,
    epoch: Epoch,
    resolver: &HashSuiteResolver,
) -> Result<&'a PreinstalledModuleCatalogEntry, NodeCoreError> {
    let (module_id, version, declared_code_hash) = preinstalled_module_identity(module_ref);

    let registered: &SystemModule =
        registered.ok_or(NodeCoreError::PreinstalledModuleUnknown { module_id, version })?;
    if registered.module_id != module_id || registered.version != version {
        return Err(NodeCoreError::PreinstalledModuleUnknown { module_id, version });
    }
    if registered.status != ModuleStatus::Active {
        return Err(NodeCoreError::PreinstalledModuleInactive { module_id, version });
    }
    if epoch < registered.activation_epoch {
        return Err(NodeCoreError::PreinstalledModuleNotYetActive {
            module_id,
            version,
            activation_epoch: registered.activation_epoch,
            current_epoch: epoch,
        });
    }

    let entry = catalog
        .get(module_id, version)
        .ok_or(NodeCoreError::PreinstalledModuleNotCataloged { module_id, version })?;

    if declared_code_hash != registered.canonical_code_hash {
        return Err(NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
            module_id,
            version,
        });
    }
    let recomputed_code_hash =
        resolver.hash_for_purpose(epoch, HashPurpose::ContractCode, entry.wasm_bytes())?;
    if recomputed_code_hash != registered.canonical_code_hash {
        return Err(NodeCoreError::PreinstalledModuleCodeHashMismatch { module_id, version });
    }

    let manifest_bytes =
        encode_system_module_manifest(entry.manifest()).map_err(NodeCoreError::from)?;
    let recomputed_manifest_hash =
        resolver.hash_for_purpose(epoch, HashPurpose::ProtocolConfig, &manifest_bytes)?;
    if recomputed_manifest_hash != registered.manifest_hash {
        return Err(NodeCoreError::PreinstalledModuleManifestHashMismatch { module_id, version });
    }

    if entry.semantics_hash() != registered.semantics_hash {
        return Err(NodeCoreError::PreinstalledModuleSemanticsHashMismatch { module_id, version });
    }

    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use system_modules::{GasModel, SystemModuleRegistry, TypeSchema};

    fn resolve_from_registry<'a>(
        module_ref: &ObjectRef,
        registry: &SystemModuleRegistry,
        catalog: &'a PreinstalledModuleCatalog,
        epoch: Epoch,
        resolver: &HashSuiteResolver,
    ) -> Result<&'a PreinstalledModuleCatalogEntry, NodeCoreError> {
        let (module_id, version, _) = preinstalled_module_identity(module_ref);
        resolve_preinstalled_module(
            module_ref,
            registry.get(module_id, version),
            catalog,
            epoch,
            resolver,
        )
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn module_id(byte: u8) -> ModuleId {
        ModuleId::new([byte; 32])
    }

    fn resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-mvp").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn sample_manifest(module_id: ModuleId) -> SystemModuleManifest {
        SystemModuleManifest {
            module_id,
            input_schema: TypeSchema {
                descriptor: "counter.input.v1".to_string(),
                schema_hash: digest(0x11),
            },
            output_schema: TypeSchema {
                descriptor: "counter.output.v1".to_string(),
                schema_hash: digest(0x22),
            },
            max_input_size: 64,
            gas_model: GasModel {
                base_cost: 1,
                per_input_byte_cost: 1,
            },
            zk_hint: None,
        }
    }

    fn wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory 1)
                (export "memory" (memory 0))
                (func (export "run")))"#,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn committed_module(
        resolver: &HashSuiteResolver,
        module_id: ModuleId,
        version: u64,
        wasm: &[u8],
        manifest: &SystemModuleManifest,
        semantics_hash: Digest32,
        activation_epoch: Epoch,
        status: ModuleStatus,
    ) -> SystemModule {
        let code_hash = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, wasm)
            .unwrap();
        let manifest_bytes = encode_system_module_manifest(manifest).unwrap();
        let manifest_hash = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::ProtocolConfig, &manifest_bytes)
            .unwrap();
        SystemModule {
            module_id,
            version,
            canonical_code_hash: code_hash,
            semantics_hash,
            manifest_hash,
            activation_epoch,
            status,
        }
    }

    #[test]
    fn resolves_exact_active_module_when_every_commitment_matches() {
        let resolver = resolver();
        let id = module_id(0x01);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let semantics_hash = digest(0x33);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            semantics_hash,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module.clone()).unwrap();
        let entry =
            PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, semantics_hash).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
        let module_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 1,
            digest: module.canonical_code_hash,
        };

        let resolved =
            resolve_from_registry(&module_ref, &registry, &catalog, Epoch::new(0), &resolver)
                .unwrap();
        assert_eq!(resolved.module_id(), id);
        assert_eq!(resolved.version(), 1);
    }

    #[test]
    fn rejects_unknown_and_inactive_and_not_yet_active_versions() {
        let resolver = resolver();
        let id = module_id(0x02);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let semantics_hash = digest(0x44);
        let pending = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            semantics_hash,
            Epoch::new(5),
            ModuleStatus::Pending,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(pending.clone()).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm.clone(),
            manifest.clone(),
            semantics_hash,
        )
        .unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        let unknown_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 2,
            digest: pending.canonical_code_hash,
        };
        assert_eq!(
            resolve_from_registry(&unknown_ref, &registry, &catalog, Epoch::new(5), &resolver),
            Err(NodeCoreError::PreinstalledModuleUnknown {
                module_id: id,
                version: 2
            })
        );

        let pending_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 1,
            digest: pending.canonical_code_hash,
        };
        assert_eq!(
            resolve_from_registry(&pending_ref, &registry, &catalog, Epoch::new(5), &resolver),
            Err(NodeCoreError::PreinstalledModuleInactive {
                module_id: id,
                version: 1
            })
        );

        let mut registry_active = SystemModuleRegistry::new();
        let mut active = pending;
        active.status = ModuleStatus::Active;
        registry_active.add_module(active.clone()).unwrap();
        assert_eq!(
            resolve_from_registry(
                &pending_ref,
                &registry_active,
                &catalog,
                Epoch::new(4),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleNotYetActive {
                module_id: id,
                version: 1,
                activation_epoch: Epoch::new(5),
                current_epoch: Epoch::new(4),
            })
        );
        assert!(
            resolve_from_registry(
                &pending_ref,
                &registry_active,
                &catalog,
                Epoch::new(5),
                &resolver
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_uncataloged_module_reference_digest_code_manifest_and_semantics_mismatch() {
        let resolver = resolver();
        let id = module_id(0x03);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let semantics_hash = digest(0x55);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            semantics_hash,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module.clone()).unwrap();
        let module_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 1,
            digest: module.canonical_code_hash,
        };

        // Not cataloged.
        let empty_catalog = PreinstalledModuleCatalog::new(vec![]).unwrap();
        assert_eq!(
            resolve_from_registry(
                &module_ref,
                &registry,
                &empty_catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleNotCataloged {
                module_id: id,
                version: 1
            })
        );

        let entry = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm.clone(),
            manifest.clone(),
            semantics_hash,
        )
        .unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        // Declared reference digest disagrees with the registry commitment.
        let mut wrong_digest_ref = module_ref.clone();
        wrong_digest_ref.digest = digest(0xEE);
        assert_eq!(
            resolve_from_registry(
                &wrong_digest_ref,
                &registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
                module_id: id,
                version: 1
            })
        );

        // Registry code hash disagrees with the actual catalog WASM bytes.
        let mut tampered_code_registry = SystemModuleRegistry::new();
        let mut tampered_code_module = module.clone();
        tampered_code_module.canonical_code_hash = digest(0xEE);
        tampered_code_registry
            .add_module(tampered_code_module.clone())
            .unwrap();
        let mut tampered_ref = module_ref.clone();
        tampered_ref.digest = tampered_code_module.canonical_code_hash;
        assert_eq!(
            resolve_from_registry(
                &tampered_ref,
                &tampered_code_registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: id,
                version: 1
            })
        );

        // Registry manifest hash disagrees with the actual catalog manifest.
        let mut tampered_manifest_registry = SystemModuleRegistry::new();
        let mut tampered_manifest_module = module.clone();
        tampered_manifest_module.manifest_hash = digest(0xEE);
        tampered_manifest_registry
            .add_module(tampered_manifest_module)
            .unwrap();
        assert_eq!(
            resolve_from_registry(
                &module_ref,
                &tampered_manifest_registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleManifestHashMismatch {
                module_id: id,
                version: 1
            })
        );

        // Registry semantics hash disagrees with the catalog entry.
        let mut tampered_semantics_registry = SystemModuleRegistry::new();
        let mut tampered_semantics_module = module;
        tampered_semantics_module.semantics_hash = digest(0xEE);
        tampered_semantics_registry
            .add_module(tampered_semantics_module)
            .unwrap();
        assert_eq!(
            resolve_from_registry(
                &module_ref,
                &tampered_semantics_registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
                module_id: id,
                version: 1
            })
        );
    }

    #[test]
    fn catalog_entry_rejects_oversized_wasm_and_manifest_id_mismatch() {
        let id = module_id(0x04);
        let other_id = module_id(0x05);
        let zero_version_error = PreinstalledModuleCatalogEntry::new(
            id,
            0,
            wasm_bytes(),
            sample_manifest(id),
            digest(0x66),
        )
        .unwrap_err();
        assert_eq!(
            zero_version_error,
            NodeCoreError::SystemModules(SystemModuleError::ZeroModuleVersion)
        );

        let manifest = sample_manifest(other_id);
        let err = PreinstalledModuleCatalogEntry::new(id, 1, wasm_bytes(), manifest, digest(0x66))
            .unwrap_err();
        assert_eq!(
            err,
            NodeCoreError::PreinstalledModuleManifestIdMismatch {
                module_id: id,
                version: 1
            }
        );

        let oversized = vec![0u8; MAX_PREINSTALLED_MODULE_WASM_BYTES + 1];
        let err = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            oversized,
            sample_manifest(id),
            digest(0x66),
        )
        .unwrap_err();
        assert_eq!(
            err,
            NodeCoreError::PreinstalledModuleWasmTooLarge {
                module_id: id,
                version: 1,
                actual: MAX_PREINSTALLED_MODULE_WASM_BYTES + 1,
                maximum: MAX_PREINSTALLED_MODULE_WASM_BYTES,
            }
        );
    }

    #[test]
    fn catalog_rejects_duplicate_module_version() {
        let id = module_id(0x06);
        let manifest = sample_manifest(id);
        let entry_a = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm_bytes(),
            manifest.clone(),
            digest(0x01),
        )
        .unwrap();
        let entry_b =
            PreinstalledModuleCatalogEntry::new(id, 1, wasm_bytes(), manifest, digest(0x02))
                .unwrap();
        assert_eq!(
            PreinstalledModuleCatalog::new(vec![entry_a, entry_b]),
            Err(NodeCoreError::DuplicatePreinstalledModule {
                module_id: id,
                version: 1
            })
        );
    }
}
