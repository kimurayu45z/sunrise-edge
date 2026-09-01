//! Bounded, caller-supplied preinstalled WASM module composition.
//!
//! This module is intentionally private-by-default: only
//! [`PreinstalledModuleCatalogEntry`], [`PreinstalledModuleCatalog`],
//! [`PreinstalledModuleSemanticsEnvelope`], [`PreinstalledObjectAccessPolicy`],
//! and the validated construction/encoding functions are exported. There is
//! no way to build a catalog entry from request bytes, a network fetch, or an
//! arbitrary upload — the only constructor is
//! [`PreinstalledModuleCatalogEntry::new`], called by trusted node
//! composition before serving traffic. An additive
//! `native_http::preinstalled_wasm_structured_durable_router` now wires this
//! module's entrypoint over HTTP; `native_http::structured_durable_router`
//! remains on the read-only entrypoint and is unaffected. JIT/AOT execution
//! and production gas metering remain deferred; see `ARCHITECTURE.md` and
//! `TODO.md` (Developer MVP Gate, step 3). See also DR-0078 (historical:
//! written before native HTTP wiring existed) and DR-0080 in
//! `ARCHITECTURE.md`.
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
//!
//! # Committed semantics envelope and the cross-owner authorization boundary
//!
//! `SystemModule.semantics_hash` commits to one exact generic
//! [`PreinstalledModuleSemanticsEnvelope`]: opaque, node-core-uninterpreted
//! application semantics bytes plus a bounded set of
//! [`PreinstalledObjectAccessPolicy`] values. [`resolve_preinstalled_module`]
//! independently re-encodes the catalog entry's actual envelope via
//! [`encode_preinstalled_semantics_envelope`] and reverifies it against the
//! registry's committed digest exactly like the WASM code and manifest
//! digests — it never trusts a caller-supplied semantics hash. Node-core's
//! default object-authorization rule requires every `Owner::Address` object a
//! transaction accesses to be owned by the authenticated sender (see
//! `load_and_authorize_objects`). A `PreinstalledObjectAccessPolicy` is the
//! *only* way to relax that rule, and only narrowly: for one exact declared
//! object-access index (never index `0`, the transaction's own authorization
//! source), one exact entrypoint, one exact `Write` access, and only when the
//! resolved object's current `type_hash`/`schema_version` match the policy
//! exactly. The policy is resolved once, from the committed registry and
//! trusted catalog only (no storage I/O), after receipt/nonce reconciliation
//! and strictly before any object is loaded — see
//! `handle_durable_idempotent_event_with_plan` in `lib.rs`. It never permits
//! a literal owner reassignment; that is independently enforced by
//! `authenticated_object_effects::translate_update`. The generic public
//! owned-effects entrypoint
//! (`handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects`)
//! never supplies a policy and therefore stays strictly sender-only.
//!
//! # Protocol-version bumps and commitment provenance
//!
//! [`hashing::frame_hash_input`] mixes `protocol_version` directly into the
//! domain-separated hash frame, so a protocol-version bump changes every
//! digest computed under it — including a registered module's
//! `canonical_code_hash` and `manifest_hash`. This crate does not persist
//! which protocol version originally produced a committed
//! [`SystemModule`] entry, so those commitments are implicitly pinned to the
//! `ProtocolConfig` version active when governance installed them. Until
//! module commitment provenance is itself versioned (an explicit, tracked
//! follow-up; no new persisted schema is added in this MVP slice),
//! governance MUST re-commit every module's `canonical_code_hash` and
//! `manifest_hash` in the new `ProtocolConfig` whenever `protocol_version`
//! changes. An epoch-only
//! hash-suite rotation, by contrast, does not require recommitment: see
//! [`resolve_preinstalled_module`]'s use of [`hashing::verify_digest`].

use canonical_encoding::{CanonicalStruct, encode_digest32};
use execution::{ExecutionEffects, ExecutionStatus, MAX_TRANSACTION_ENTRYPOINT_BYTES};
use hashing::{HashSuiteResolver, verify_digest};
use objects::{AccessMode, ObjectError, ObjectId, ObjectRef, encode_access_mode};
use protocol_types::{Digest32, Epoch, HashPurpose};
use std::collections::BTreeSet;
use system_modules::{
    ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
    SystemModuleRegistry, encode_system_module_manifest,
};

use super::{MAX_AUTHENTICATED_OBJECT_READS, NodeCoreError};

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

/// Conservative pre-activation ceiling on a preinstalled-WASM transaction's
/// `gas_limit`, enforced before the WASM engine ever runs.
///
/// `execution::wasm_engine` enables `wasmi` fuel metering for executed WASM
/// operations, so this bounds worst-case per-call interpreter work
/// independent of any future fee-weighted gas schedule or production
/// metering (both remain deferred; see the module-level docs). The value is
/// deliberately conservative rather than tuned: it exists so one
/// preinstalled call cannot request unbounded engine work, not to model a
/// real gas market.
pub const MAX_PREINSTALLED_MODULE_GAS_LIMIT: u64 = 10_000_000;

/// Deterministic upper bound on one committed semantics envelope's opaque
/// application-semantics bytes.
///
/// This bounds a description, not executable input: it is sized generously
/// above any realistic committed declaration text.
pub const MAX_PREINSTALLED_SEMANTICS_BYTES: usize = 64 * 1024;

/// Deterministic upper bound on the number of object-access authorization
/// policies one committed semantics envelope may declare.
pub const MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES: usize = 16;

const PREINSTALLED_OBJECT_ACCESS_POLICY_TYPE_ID: u16 = 0xE007;
const PREINSTALLED_SEMANTICS_ENVELOPE_TYPE_ID: u16 = 0xE008;
const PREINSTALLED_ENCODING_VERSION: u16 = 1;

/// One narrow, fail-closed exception to node-core's default same-sender
/// object-owner rule, committed as part of a preinstalled module's semantics
/// envelope.
///
/// By default `load_and_authorize_objects` requires every `Owner::Address`
/// object a transaction accesses to be owned by the authenticated sender.
/// This type lets a trusted, governance-committed preinstalled module
/// narrowly relax that rule for exactly one declared object-access position,
/// exactly one entrypoint, and exactly one `Write` access to an object whose
/// current type/schema match exactly. `access_index` can never be `0`: the
/// first declared access is always the transaction's own authorization
/// source and must always remain sender-owned. The exception never allows a
/// literal owner reassignment; that is independently enforced by
/// `authenticated_object_effects::translate_update`, which requires the
/// mutated object's owner to equal the object's owner before mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreinstalledObjectAccessPolicy {
    access_index: u32,
    entrypoint: String,
    mode: AccessMode,
    expected_type_hash: Digest32,
    expected_schema_version: u32,
}

impl PreinstalledObjectAccessPolicy {
    /// Validates and constructs one object-access authorization policy.
    ///
    /// Rejects the reserved source index `0`, an index at or beyond
    /// node-core's authenticated object-read bound, an empty or oversized
    /// entrypoint name, and any access mode other than [`AccessMode::Write`]
    /// (a non-sender `Read` or `Consume` exception is never authorized).
    pub fn new(
        access_index: u32,
        entrypoint: String,
        mode: AccessMode,
        expected_type_hash: Digest32,
        expected_schema_version: u32,
    ) -> Result<Self, NodeCoreError> {
        if access_index == 0 {
            return Err(NodeCoreError::PreinstalledObjectAccessPolicySourceIndexReserved);
        }
        let maximum =
            u32::try_from(MAX_AUTHENTICATED_OBJECT_READS.saturating_sub(1)).unwrap_or(u32::MAX);
        if access_index > maximum {
            return Err(
                NodeCoreError::PreinstalledObjectAccessPolicyIndexOutOfBounds {
                    access_index,
                    maximum,
                },
            );
        }
        if entrypoint.is_empty() || entrypoint.len() > MAX_TRANSACTION_ENTRYPOINT_BYTES {
            return Err(
                NodeCoreError::PreinstalledObjectAccessPolicyEntrypointInvalid {
                    actual: entrypoint.len(),
                    maximum: MAX_TRANSACTION_ENTRYPOINT_BYTES,
                },
            );
        }
        if mode != AccessMode::Write {
            return Err(NodeCoreError::PreinstalledObjectAccessPolicyModeUnsupported { mode });
        }
        Ok(Self {
            access_index,
            entrypoint,
            mode,
            expected_type_hash,
            expected_schema_version,
        })
    }

    /// Returns the exact zero-based signed access index this policy governs.
    #[must_use]
    pub const fn access_index(&self) -> u32 {
        self.access_index
    }

    /// Returns the exact entrypoint name this policy governs.
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Returns the exact access mode this policy authorizes.
    #[must_use]
    pub const fn mode(&self) -> AccessMode {
        self.mode
    }

    /// Returns the exact committed object type hash this policy requires.
    #[must_use]
    pub const fn expected_type_hash(&self) -> Digest32 {
        self.expected_type_hash
    }

    /// Returns the exact committed object schema version this policy requires.
    #[must_use]
    pub const fn expected_schema_version(&self) -> u32 {
        self.expected_schema_version
    }
}

/// Canonically encodes one [`PreinstalledObjectAccessPolicy`].
pub fn encode_preinstalled_object_access_policy(
    policy: &PreinstalledObjectAccessPolicy,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = CanonicalStruct::new(
        PREINSTALLED_OBJECT_ACCESS_POLICY_TYPE_ID,
        PREINSTALLED_ENCODING_VERSION,
    );
    canonical
        .field_u32(1, policy.access_index)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    canonical
        .field_str(2, &policy.entrypoint)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    let mode_bytes: Vec<u8> =
        encode_access_mode(policy.mode).map_err(|error: ObjectError| match error {
            ObjectError::CanonicalEncoding(error) => NodeCoreError::CanonicalEncoding(error),
            _ => NodeCoreError::PersistenceInvariant(
                "validated preinstalled access mode failed canonical encoding",
            ),
        })?;
    canonical
        .field_bytes(3, mode_bytes)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    canonical
        .field_bytes(4, encode_digest32(&policy.expected_type_hash)?)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    canonical
        .field_u32(5, policy.expected_schema_version)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    canonical.finish().map_err(NodeCoreError::CanonicalEncoding)
}

/// A trusted preinstalled module's exact generic committed semantics
/// envelope: opaque application-semantics bytes plus a bounded set of
/// [`PreinstalledObjectAccessPolicy`] object-owner exceptions.
///
/// This is the exact byte shape `SystemModule.semantics_hash` commits to.
/// node-core treats `opaque_semantics` as caller-defined, uninterpreted
/// bytes; only `object_access_policies` is ever read by node-core's
/// authorization logic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreinstalledModuleSemanticsEnvelope {
    opaque_semantics: Vec<u8>,
    object_access_policies: Vec<PreinstalledObjectAccessPolicy>,
}

impl PreinstalledModuleSemanticsEnvelope {
    /// Validates and constructs one committed semantics envelope.
    ///
    /// Rejects opaque semantics bytes over
    /// [`MAX_PREINSTALLED_SEMANTICS_BYTES`], more policies than
    /// [`MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES`], and a duplicate declared
    /// `access_index`.
    pub fn new(
        opaque_semantics: Vec<u8>,
        mut object_access_policies: Vec<PreinstalledObjectAccessPolicy>,
    ) -> Result<Self, NodeCoreError> {
        if opaque_semantics.len() > MAX_PREINSTALLED_SEMANTICS_BYTES {
            return Err(NodeCoreError::PreinstalledSemanticsBytesTooLarge {
                actual: opaque_semantics.len(),
                maximum: MAX_PREINSTALLED_SEMANTICS_BYTES,
            });
        }
        if object_access_policies.len() > MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES {
            return Err(
                NodeCoreError::PreinstalledObjectAccessPolicyCollectionTooLarge {
                    count: object_access_policies.len(),
                    maximum: MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES,
                },
            );
        }
        let mut seen_indices: BTreeSet<u32> = BTreeSet::new();
        for policy in &object_access_policies {
            if !seen_indices.insert(policy.access_index) {
                return Err(
                    NodeCoreError::DuplicatePreinstalledObjectAccessPolicyIndex {
                        access_index: policy.access_index,
                    },
                );
            }
        }
        object_access_policies.sort_by_key(PreinstalledObjectAccessPolicy::access_index);
        Ok(Self {
            opaque_semantics,
            object_access_policies,
        })
    }

    /// Constructs an envelope with no object-access policies: every access
    /// stays sender-only.
    pub fn opaque_only(opaque_semantics: Vec<u8>) -> Result<Self, NodeCoreError> {
        Self::new(opaque_semantics, Vec::new())
    }

    /// Returns the opaque, node-core-uninterpreted application semantics bytes.
    #[must_use]
    pub fn opaque_semantics(&self) -> &[u8] {
        &self.opaque_semantics
    }

    /// Returns every declared object-access policy.
    #[must_use]
    pub fn object_access_policies(&self) -> &[PreinstalledObjectAccessPolicy] {
        &self.object_access_policies
    }

    /// Returns the exact policy, if any, authorizing `entrypoint` to relax
    /// the sender-owner rule at declared access index `access_index`.
    #[must_use]
    pub(crate) fn matching_object_access_policy(
        &self,
        entrypoint: &str,
        access_index: u32,
    ) -> Option<&PreinstalledObjectAccessPolicy> {
        self.object_access_policies
            .iter()
            .find(|policy| policy.access_index == access_index && policy.entrypoint == entrypoint)
    }
}

/// Canonically encodes one [`PreinstalledModuleSemanticsEnvelope`].
///
/// This is the exact byte shape independently rehashed and compared against
/// `SystemModule.semantics_hash` by the internal module resolver; no
/// caller-supplied semantics digest is ever trusted directly.
pub fn encode_preinstalled_semantics_envelope(
    envelope: &PreinstalledModuleSemanticsEnvelope,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = CanonicalStruct::new(
        PREINSTALLED_SEMANTICS_ENVELOPE_TYPE_ID,
        PREINSTALLED_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, envelope.opaque_semantics.clone())
        .map_err(NodeCoreError::CanonicalEncoding)?;
    let policy_count = u16::try_from(envelope.object_access_policies.len()).map_err(|_| {
        NodeCoreError::PreinstalledObjectAccessPolicyCollectionTooLarge {
            count: envelope.object_access_policies.len(),
            maximum: MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES,
        }
    })?;
    canonical
        .field_u16(2, policy_count)
        .map_err(NodeCoreError::CanonicalEncoding)?;
    for (index, policy) in envelope.object_access_policies.iter().enumerate() {
        let field_id = u16::try_from(3 + index).map_err(|_| {
            NodeCoreError::PreinstalledObjectAccessPolicyCollectionTooLarge {
                count: envelope.object_access_policies.len(),
                maximum: MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES,
            }
        })?;
        canonical
            .field_bytes(field_id, encode_preinstalled_object_access_policy(policy)?)
            .map_err(NodeCoreError::CanonicalEncoding)?;
    }
    canonical.finish().map_err(NodeCoreError::CanonicalEncoding)
}

/// One immutable, caller-supplied preinstalled module: its exact identity,
/// canonical WASM bytes, canonical manifest, and committed semantics
/// envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreinstalledModuleCatalogEntry {
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    manifest: SystemModuleManifest,
    semantics_envelope: PreinstalledModuleSemanticsEnvelope,
}

impl PreinstalledModuleCatalogEntry {
    /// Validates and constructs one catalog entry.
    ///
    /// Rejects WASM bytes over [`MAX_PREINSTALLED_MODULE_WASM_BYTES`], an
    /// invalid [`SystemModuleManifest`], and a manifest whose `module_id`
    /// disagrees with this entry's own `module_id`, before the entry can ever
    /// be resolved against a transaction. `semantics_envelope`'s own
    /// constructor already bounds its opaque bytes and policy count; this
    /// entry never recomputes or trusts a caller-supplied semantics digest —
    /// see the internal preinstalled-module resolver.
    pub fn new(
        module_id: ModuleId,
        version: u64,
        wasm_bytes: Vec<u8>,
        manifest: SystemModuleManifest,
        semantics_envelope: PreinstalledModuleSemanticsEnvelope,
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
            semantics_envelope,
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

    /// Returns the committed semantics envelope.
    #[must_use]
    pub const fn semantics_envelope(&self) -> &PreinstalledModuleSemanticsEnvelope {
        &self.semantics_envelope
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

    /// Returns every cataloged entry in canonical `(module_id, version)`
    /// order.
    ///
    /// This is a bounded, read-only view (the catalog holds at most
    /// [`MAX_PREINSTALLED_MODULES`] entries and is never mutated after
    /// construction); it exists so trusted node composition can reconcile the
    /// whole catalog against a registry, not to let a caller reconstruct or
    /// grow the catalog.
    pub fn entries(&self) -> impl Iterator<Item = &PreinstalledModuleCatalogEntry> {
        self.entries.values()
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
/// 4. the catalog entry's WASM bytes are independently reverified against
///    `canonical_code_hash` under [`HashPurpose::ContractCode`] (see below);
/// 5. the catalog entry's manifest is canonically re-encoded and reverified
///    against the registry's committed `manifest_hash` under
///    [`HashPurpose::SystemModuleManifest`] (see below);
/// 6. the catalog entry's [`PreinstalledModuleSemanticsEnvelope`] is
///    canonically re-encoded via [`encode_preinstalled_semantics_envelope`]
///    and independently reverified against the registry's committed
///    `semantics_hash`, exactly like steps 4 and 5 — this function never
///    trusts a caller-supplied semantics digest, only the registry's own
///    committed value and the catalog's actual envelope bytes.
///
/// # Verification uses the committed digest's own algorithm
///
/// Steps 4 and 5 call [`hashing::verify_digest`] rather than
/// `resolver.hash_for_purpose`. `verify_digest` rehashes using the algorithm
/// already recorded inside the committed [`Digest32`] itself (`canonical_code_hash`/
/// `manifest_hash`), together with `resolver`'s trusted `chain_id` and
/// `protocol_version` — not the hash suite currently active at `epoch`. This
/// keeps resolution correct across an epoch-only hash-suite rotation: a
/// module committed under one suite's algorithm stays verifiable at a later
/// epoch where a different suite is active, because the check only depends
/// on the algorithm the commitment itself was made with, never on
/// `resolver.suite_for_epoch(epoch)`. A `chain_id`/`protocol_version`
/// mismatch between the event and `resolver` is still rejected before this
/// function runs by the durable handler's event digest, and a
/// `protocol_version` bump changes the hash frame itself — see the
/// module-level docs on why that instead requires governance recommitment.
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
    let code_hash_verified = verify_digest(
        &registered.canonical_code_hash,
        HashPurpose::ContractCode,
        resolver.protocol_version(),
        resolver.chain_id(),
        entry.wasm_bytes(),
    )?;
    if !code_hash_verified {
        return Err(NodeCoreError::PreinstalledModuleCodeHashMismatch { module_id, version });
    }

    let manifest_bytes =
        encode_system_module_manifest(entry.manifest()).map_err(NodeCoreError::from)?;
    let manifest_hash_verified = verify_digest(
        &registered.manifest_hash,
        HashPurpose::SystemModuleManifest,
        resolver.protocol_version(),
        resolver.chain_id(),
        &manifest_bytes,
    )?;
    if !manifest_hash_verified {
        return Err(NodeCoreError::PreinstalledModuleManifestHashMismatch { module_id, version });
    }

    let semantics_envelope_bytes =
        encode_preinstalled_semantics_envelope(entry.semantics_envelope())?;
    let semantics_hash_verified = verify_digest(
        &registered.semantics_hash,
        HashPurpose::SystemModuleManifest,
        resolver.protocol_version(),
        resolver.chain_id(),
        &semantics_envelope_bytes,
    )?;
    if !semantics_hash_verified {
        return Err(NodeCoreError::PreinstalledModuleSemanticsHashMismatch { module_id, version });
    }

    Ok(entry)
}

/// Bounded, fail-closed reconciliation between a governance-committed
/// [`SystemModuleRegistry`] and a caller-supplied [`PreinstalledModuleCatalog`]
/// at one `epoch`, intended to run once during trusted node startup (before
/// any request is served) rather than on every request.
///
/// A module is treated as "active" for this reconciliation exactly the way
/// the internal preinstalled-module resolver treats it at request time:
/// `status == `[`ModuleStatus::Active`]` && activation_epoch <= epoch`. Both
/// `registry` and `catalog` are already bounded ([`SystemModuleRegistry`] by
/// its own [`SystemModuleRegistry::validate`] limit, `catalog` by
/// [`MAX_PREINSTALLED_MODULES`] at construction), so this function runs in
/// bounded time proportional to their sizes; it revalidates `registry`'s own
/// bound/order/duplicate invariants before trusting it.
///
/// Checks both directions and fails closed on the first violation found, in
/// this order:
///
/// 1. **Every cataloged entry resolves.** For each `(module_id, version)` in
///    `catalog`, this calls the exact same internal module resolver
///    used at request time — reusing its existing commitment/resolution
///    rules and error variants rather than duplicating them — with the
///    registered module's own `canonical_code_hash` supplied as the
///    "declared" digest. That specific comparison
///    ([`NodeCoreError::PreinstalledModuleReferenceDigestMismatch`]) only
///    ever means a request's own declared reference disagreed with the
///    registry and is therefore not meaningful outside a real request, so
///    this call trivially satisfies it; every other step — existence,
///    active status, activation epoch, code hash, manifest hash, and
///    semantics hash — runs unchanged and can still fail closed with
///    [`NodeCoreError::PreinstalledModuleUnknown`],
///    [`NodeCoreError::PreinstalledModuleInactive`],
///    [`NodeCoreError::PreinstalledModuleNotYetActive`],
///    [`NodeCoreError::PreinstalledModuleCodeHashMismatch`],
///    [`NodeCoreError::PreinstalledModuleManifestHashMismatch`], or
///    [`NodeCoreError::PreinstalledModuleSemanticsHashMismatch`]. This also
///    catches an "extra" catalog entry that does not correspond to any
///    active registry module.
/// 2. **Every active registry module is cataloged.** For each module in
///    `registry` that is active at `epoch`, this requires
///    `catalog.get(module_id, version)` to be `Some`, failing closed with
///    the existing [`NodeCoreError::PreinstalledModuleNotCataloged`]
///    otherwise (a module governance has activated but this node cannot
///    execute).
///
/// This performs no request-time behavior change: `resolve_preinstalled_module`
/// itself is neither modified nor bypassed, only invoked with startup inputs
/// instead of request inputs.
pub fn reconcile_preinstalled_registry_and_catalog(
    registry: &SystemModuleRegistry,
    catalog: &PreinstalledModuleCatalog,
    epoch: Epoch,
    resolver: &HashSuiteResolver,
) -> Result<(), NodeCoreError> {
    registry.validate()?;

    for entry in catalog.entries() {
        let module_id = entry.module_id();
        let version = entry.version();
        let registered = registry
            .get(module_id, version)
            .ok_or(NodeCoreError::PreinstalledModuleUnknown { module_id, version })?;
        let module_ref = ObjectRef {
            id: ObjectId::new(*module_id.as_bytes()),
            version,
            digest: registered.canonical_code_hash,
        };
        resolve_preinstalled_module(&module_ref, Some(registered), catalog, epoch, resolver)?;
    }

    for module in registry.modules() {
        let is_active_now =
            module.status == ModuleStatus::Active && module.activation_epoch <= epoch;
        if is_active_now && catalog.get(module.module_id, module.version).is_none() {
            return Err(NodeCoreError::PreinstalledModuleNotCataloged {
                module_id: module.module_id,
                version: module.version,
            });
        }
    }

    Ok(())
}

/// Rejects a preinstalled-WASM `gas_limit` above
/// [`MAX_PREINSTALLED_MODULE_GAS_LIMIT`] before the engine ever runs.
pub(crate) fn check_preinstalled_module_gas_limit(gas_limit: u64) -> Result<(), NodeCoreError> {
    if gas_limit > MAX_PREINSTALLED_MODULE_GAS_LIMIT {
        return Err(NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
            requested: gas_limit,
            maximum: MAX_PREINSTALLED_MODULE_GAS_LIMIT,
        });
    }
    Ok(())
}

/// The canonical, engine-independent failure reason recorded for every
/// trapped preinstalled-WASM invocation.
///
/// A raw `wasmi`/contract trap message (see `execution::wasm_engine`) is
/// untrusted, `wasmi`-version-dependent free text that can embed
/// contract-controlled bytes (for example whatever a contract passes to the
/// `abort` host function). Persisting it verbatim would make the committed
/// receipt payload depend on engine internals and could leak contract text
/// into storage. Every trapped call is normalized to this one fixed reason
/// instead; see [`normalize_trapped_preinstalled_execution`].
pub(crate) const PREINSTALLED_WASM_TRAP_REASON: &str = "preinstalled module execution trapped";

/// Normalizes a trapped preinstalled-WASM execution result to the canonical,
/// engine-independent closed failure shape before it is canonically encoded
/// and persisted.
///
/// The normalized value fixes the failure reason to
/// [`PREINSTALLED_WASM_TRAP_REASON`] (discarding the engine's own,
/// untrusted trap text), charges the full `gas_limit` deterministically
/// (discarding the engine's own fuel-remaining accounting, which is not
/// guaranteed stable across engine versions for a trapped call), and leaves
/// `object_effects`/`events` empty — matching
/// `execution::wasm_engine::WasmExecutionEngine`'s own existing behavior of
/// discarding every candidate effect on trap; this function enforces the
/// empty result directly rather than retaining engine output.
#[must_use]
pub(crate) fn normalize_trapped_preinstalled_execution(
    tx_hash: Digest32,
    gas_limit: u64,
) -> ExecutionEffects {
    ExecutionEffects {
        tx_hash,
        status: ExecutionStatus::Failure {
            reason: PREINSTALLED_WASM_TRAP_REASON.to_string(),
        },
        object_effects: Vec::new(),
        events: Vec::new(),
        gas_used: gas_limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use system_modules::{GasModel, SystemModuleRegistry, TypeSchema};

    const PREINSTALLED_OBJECT_ACCESS_POLICY_VECTOR: [u8; 129] = [
        83, 78, 82, 69, 7, 224, 1, 0, 5, 0, 1, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0, 8, 0, 0, 0, 116,
        114, 97, 110, 115, 102, 101, 114, 3, 0, 17, 0, 0, 0, 83, 78, 82, 69, 6, 64, 1, 0, 1, 0, 1,
        0, 1, 0, 0, 0, 2, 4, 0, 56, 0, 0, 0, 83, 78, 82, 69, 3, 1, 1, 0, 2, 0, 1, 0, 2, 0, 0, 0, 1,
        0, 2, 0, 32, 0, 0, 0, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154,
        154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154,
        5, 0, 4, 0, 0, 0, 3, 0, 0, 0,
    ];
    const PREINSTALLED_SEMANTICS_ENVELOPE_VECTOR: [u8; 179] = [
        83, 78, 82, 69, 8, 224, 1, 0, 3, 0, 1, 0, 20, 0, 0, 0, 111, 112, 97, 113, 117, 101, 45, 97,
        112, 112, 45, 115, 101, 109, 97, 110, 116, 105, 99, 115, 2, 0, 2, 0, 0, 0, 1, 0, 3, 0, 129,
        0, 0, 0, 83, 78, 82, 69, 7, 224, 1, 0, 5, 0, 1, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0, 8, 0, 0,
        0, 116, 114, 97, 110, 115, 102, 101, 114, 3, 0, 17, 0, 0, 0, 83, 78, 82, 69, 6, 64, 1, 0,
        1, 0, 1, 0, 1, 0, 0, 0, 2, 4, 0, 56, 0, 0, 0, 83, 78, 82, 69, 3, 1, 1, 0, 2, 0, 1, 0, 2, 0,
        0, 0, 1, 0, 2, 0, 32, 0, 0, 0, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154,
        154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154,
        154, 154, 5, 0, 4, 0, 0, 0, 3, 0, 0, 0,
    ];

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

    /// A resolver with two hash-suite schedule entries: the genesis
    /// SHA2-256 suite at epoch 0, and a second SHA3-256 suite activating at
    /// `rotation_epoch`.
    fn resolver_with_rotation(rotation_epoch: Epoch) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-mvp").unwrap(),
            ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: rotation_epoch,
                    suite: HashSuite::uniform(
                        protocol_types::HashSuiteId::new(2),
                        HashAlgorithmId::Sha3_256,
                    ),
                },
            ],
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

    /// Builds one committed semantics envelope with no object-access
    /// policies, distinguished only by `byte`.
    fn semantics_envelope(byte: u8) -> PreinstalledModuleSemanticsEnvelope {
        PreinstalledModuleSemanticsEnvelope::opaque_only(vec![byte]).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn committed_module_at_epoch(
        resolver: &HashSuiteResolver,
        commit_epoch: Epoch,
        module_id: ModuleId,
        version: u64,
        wasm: &[u8],
        manifest: &SystemModuleManifest,
        semantics_envelope: &PreinstalledModuleSemanticsEnvelope,
        activation_epoch: Epoch,
        status: ModuleStatus,
    ) -> SystemModule {
        let code_hash = resolver
            .hash_for_purpose(commit_epoch, HashPurpose::ContractCode, wasm)
            .unwrap();
        let manifest_bytes = encode_system_module_manifest(manifest).unwrap();
        let manifest_hash = resolver
            .hash_for_purpose(
                commit_epoch,
                HashPurpose::SystemModuleManifest,
                &manifest_bytes,
            )
            .unwrap();
        let semantics_envelope_bytes =
            encode_preinstalled_semantics_envelope(semantics_envelope).unwrap();
        let semantics_hash = resolver
            .hash_for_purpose(
                commit_epoch,
                HashPurpose::SystemModuleManifest,
                &semantics_envelope_bytes,
            )
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

    #[allow(clippy::too_many_arguments)]
    fn committed_module(
        resolver: &HashSuiteResolver,
        module_id: ModuleId,
        version: u64,
        wasm: &[u8],
        manifest: &SystemModuleManifest,
        semantics_envelope: &PreinstalledModuleSemanticsEnvelope,
        activation_epoch: Epoch,
        status: ModuleStatus,
    ) -> SystemModule {
        committed_module_at_epoch(
            resolver,
            Epoch::new(0),
            module_id,
            version,
            wasm,
            manifest,
            semantics_envelope,
            activation_epoch,
            status,
        )
    }

    #[test]
    fn resolves_exact_active_module_when_every_commitment_matches() {
        let resolver = resolver();
        let id = module_id(0x01);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x33);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module.clone()).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
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
    fn resolves_across_an_epoch_only_hash_suite_rotation() {
        // The module is committed while the SHA2-256 genesis suite is
        // active, at epoch 0.
        let commit_resolver = resolver();
        let id = module_id(0x08);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x88);
        let module = committed_module_at_epoch(
            &commit_resolver,
            Epoch::new(0),
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        assert_eq!(
            module.canonical_code_hash.algorithm(),
            HashAlgorithmId::Sha2_256
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module.clone()).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
        let module_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 1,
            digest: module.canonical_code_hash,
        };

        // A resolver whose hash suite rotates to SHA3-256 at epoch 10: the
        // *same* resolver config governs both the original commitment epoch
        // and this later resolution epoch, but the transaction is resolved
        // well after rotation.
        let rotated_resolver = resolver_with_rotation(Epoch::new(10));
        assert_eq!(
            rotated_resolver
                .suite_for_epoch(Epoch::new(20))
                .unwrap()
                .algorithm_for(HashPurpose::ContractCode),
            HashAlgorithmId::Sha3_256
        );

        // Resolution at epoch 20 (after rotation) still succeeds: commitment
        // verification uses the digest's own recorded SHA2-256 algorithm via
        // `hashing::verify_digest`, not the SHA3-256 suite active at epoch
        // 20.
        let resolved = resolve_from_registry(
            &module_ref,
            &registry,
            &catalog,
            Epoch::new(20),
            &rotated_resolver,
        )
        .unwrap();
        assert_eq!(resolved.module_id(), id);
        assert_eq!(resolved.version(), 1);

        // A second module committed *after* rotation, under SHA3-256,
        // resolves too, proving both schedule halves work through the same
        // resolver.
        let id2 = module_id(0x09);
        let manifest2 = sample_manifest(id2);
        let wasm2 = wasm_bytes();
        let envelope2 = semantics_envelope(0x89);
        let module2 = committed_module_at_epoch(
            &rotated_resolver,
            Epoch::new(20),
            id2,
            1,
            &wasm2,
            &manifest2,
            &envelope2,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        assert_eq!(
            module2.canonical_code_hash.algorithm(),
            HashAlgorithmId::Sha3_256
        );
        let mut registry2 = SystemModuleRegistry::new();
        registry2.add_module(module2.clone()).unwrap();
        let entry2 =
            PreinstalledModuleCatalogEntry::new(id2, 1, wasm2, manifest2, envelope2).unwrap();
        let catalog2 = PreinstalledModuleCatalog::new(vec![entry2]).unwrap();
        let module_ref2 = ObjectRef {
            id: objects::ObjectId::new(*id2.as_bytes()),
            version: 1,
            digest: module2.canonical_code_hash,
        };
        let resolved2 = resolve_from_registry(
            &module_ref2,
            &registry2,
            &catalog2,
            Epoch::new(20),
            &rotated_resolver,
        )
        .unwrap();
        assert_eq!(resolved2.module_id(), id2);
    }

    #[test]
    fn rejects_unknown_and_inactive_and_not_yet_active_versions() {
        let resolver = resolver();
        let id = module_id(0x02);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x44);
        let pending = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(5),
            ModuleStatus::Pending,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(pending.clone()).unwrap();
        let entry =
            PreinstalledModuleCatalogEntry::new(id, 1, wasm.clone(), manifest.clone(), envelope)
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
        let envelope = semantics_envelope(0x55);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
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

        let entry =
            PreinstalledModuleCatalogEntry::new(id, 1, wasm.clone(), manifest.clone(), envelope)
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
            semantics_envelope(0x66),
        )
        .unwrap_err();
        assert_eq!(
            zero_version_error,
            NodeCoreError::SystemModules(SystemModuleError::ZeroModuleVersion)
        );

        let manifest = sample_manifest(other_id);
        let err = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm_bytes(),
            manifest,
            semantics_envelope(0x66),
        )
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
            semantics_envelope(0x66),
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
            semantics_envelope(0x01),
        )
        .unwrap();
        let entry_b = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm_bytes(),
            manifest,
            semantics_envelope(0x02),
        )
        .unwrap();
        assert_eq!(
            PreinstalledModuleCatalog::new(vec![entry_a, entry_b]),
            Err(NodeCoreError::DuplicatePreinstalledModule {
                module_id: id,
                version: 1
            })
        );
    }

    #[test]
    fn reconcile_accepts_matching_active_registry_and_catalog() {
        let resolver = resolver();
        let id = module_id(0x10);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x77);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        reconcile_preinstalled_registry_and_catalog(&registry, &catalog, Epoch::new(0), &resolver)
            .unwrap();
    }

    #[test]
    fn reconcile_rejects_active_module_missing_from_catalog() {
        let resolver = resolver();
        let id = module_id(0x11);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x78);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![]).unwrap();

        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleNotCataloged {
                module_id: id,
                version: 1
            })
        );
    }

    #[test]
    fn reconcile_rejects_extra_catalog_entry_absent_from_registry() {
        let resolver = resolver();
        let id = module_id(0x12);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x79);
        let registry = SystemModuleRegistry::new();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &registry,
                &catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleUnknown {
                module_id: id,
                version: 1
            })
        );
    }

    #[test]
    fn reconcile_rejects_cataloged_module_still_pending() {
        let resolver = resolver();
        let id = module_id(0x13);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x7A);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(5),
            ModuleStatus::Pending,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &registry,
                &catalog,
                Epoch::new(5),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleInactive {
                module_id: id,
                version: 1
            })
        );
    }

    #[test]
    fn reconcile_rejects_cataloged_active_module_before_activation_epoch() {
        let resolver = resolver();
        let id = module_id(0x15);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x7C);
        let activation_epoch = Epoch::new(6);
        let current_epoch = Epoch::new(5);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            activation_epoch,
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();

        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &registry,
                &catalog,
                current_epoch,
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleNotYetActive {
                module_id: id,
                version: 1,
                activation_epoch,
                current_epoch,
            })
        );
    }

    #[test]
    fn reconcile_rejects_code_manifest_and_semantics_hash_mismatch() {
        let resolver = resolver();
        let id = module_id(0x14);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope = semantics_envelope(0x7B);
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope,
            Epoch::new(0),
            ModuleStatus::Active,
        );

        // Registry code hash disagrees with the catalog's actual WASM bytes.
        let mut tampered_code_registry = SystemModuleRegistry::new();
        let mut tampered_code_module = module.clone();
        tampered_code_module.canonical_code_hash = digest(0xEE);
        tampered_code_registry
            .add_module(tampered_code_module)
            .unwrap();
        let code_entry = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm.clone(),
            manifest.clone(),
            envelope.clone(),
        )
        .unwrap();
        let code_catalog = PreinstalledModuleCatalog::new(vec![code_entry]).unwrap();
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &tampered_code_registry,
                &code_catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: id,
                version: 1
            })
        );

        // Registry manifest hash disagrees with the catalog's actual manifest.
        let mut tampered_manifest_registry = SystemModuleRegistry::new();
        let mut tampered_manifest_module = module.clone();
        tampered_manifest_module.manifest_hash = digest(0xEE);
        tampered_manifest_registry
            .add_module(tampered_manifest_module)
            .unwrap();
        let manifest_entry = PreinstalledModuleCatalogEntry::new(
            id,
            1,
            wasm.clone(),
            manifest.clone(),
            envelope.clone(),
        )
        .unwrap();
        let manifest_catalog = PreinstalledModuleCatalog::new(vec![manifest_entry]).unwrap();
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &tampered_manifest_registry,
                &manifest_catalog,
                Epoch::new(0),
                &resolver
            ),
            Err(NodeCoreError::PreinstalledModuleManifestHashMismatch {
                module_id: id,
                version: 1
            })
        );

        // Registry semantics hash disagrees with the catalog entry's own value.
        let mut tampered_semantics_registry = SystemModuleRegistry::new();
        let mut tampered_semantics_module = module;
        tampered_semantics_module.semantics_hash = digest(0xEE);
        tampered_semantics_registry
            .add_module(tampered_semantics_module)
            .unwrap();
        let semantics_entry =
            PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope).unwrap();
        let semantics_catalog = PreinstalledModuleCatalog::new(vec![semantics_entry]).unwrap();
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &tampered_semantics_registry,
                &semantics_catalog,
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
    fn resolve_rejects_catalog_envelope_bytes_that_disagree_with_committed_semantics_hash() {
        // The registry commits the hash of `envelope_a`'s canonical bytes,
        // but the catalog serves a *different* envelope. This proves
        // `resolve_preinstalled_module` independently rehashes the catalog's
        // actual bytes rather than trusting any caller-supplied digest: the
        // old naive "entry.semantics_hash() == registered.semantics_hash"
        // equality this replaces could not have been fooled this way either,
        // but this catalog entry type no longer carries a caller-supplied
        // digest field at all, so this is the only way a bytes mismatch can
        // now be expressed.
        let resolver = resolver();
        let id = module_id(0x16);
        let manifest = sample_manifest(id);
        let wasm = wasm_bytes();
        let envelope_a = semantics_envelope(0xA0);
        let envelope_b = semantics_envelope(0xB0);
        assert_ne!(
            encode_preinstalled_semantics_envelope(&envelope_a).unwrap(),
            encode_preinstalled_semantics_envelope(&envelope_b).unwrap()
        );
        let module = committed_module(
            &resolver,
            id,
            1,
            &wasm,
            &manifest,
            &envelope_a,
            Epoch::new(0),
            ModuleStatus::Active,
        );
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module.clone()).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(id, 1, wasm, manifest, envelope_b).unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
        let module_ref = ObjectRef {
            id: objects::ObjectId::new(*id.as_bytes()),
            version: 1,
            digest: module.canonical_code_hash,
        };

        assert_eq!(
            resolve_from_registry(&module_ref, &registry, &catalog, Epoch::new(0), &resolver),
            Err(NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
                module_id: id,
                version: 1
            })
        );
    }

    fn sample_policy(access_index: u32, entrypoint: &str) -> PreinstalledObjectAccessPolicy {
        PreinstalledObjectAccessPolicy::new(
            access_index,
            entrypoint.to_string(),
            AccessMode::Write,
            digest(0x9A),
            3,
        )
        .unwrap()
    }

    #[test]
    fn object_access_policy_rejects_reserved_index_out_of_bounds_index_bad_entrypoint_and_mode() {
        assert_eq!(
            PreinstalledObjectAccessPolicy::new(
                0,
                "transfer".to_string(),
                AccessMode::Write,
                digest(0x01),
                1,
            ),
            Err(NodeCoreError::PreinstalledObjectAccessPolicySourceIndexReserved)
        );

        let maximum = u32::try_from(MAX_AUTHENTICATED_OBJECT_READS - 1).unwrap();
        assert_eq!(
            PreinstalledObjectAccessPolicy::new(
                maximum + 1,
                "transfer".to_string(),
                AccessMode::Write,
                digest(0x01),
                1,
            ),
            Err(
                NodeCoreError::PreinstalledObjectAccessPolicyIndexOutOfBounds {
                    access_index: maximum + 1,
                    maximum,
                }
            )
        );
        assert!(
            PreinstalledObjectAccessPolicy::new(
                maximum,
                "transfer".to_string(),
                AccessMode::Write,
                digest(0x01),
                1,
            )
            .is_ok()
        );

        assert_eq!(
            PreinstalledObjectAccessPolicy::new(
                1,
                String::new(),
                AccessMode::Write,
                digest(0x01),
                1,
            ),
            Err(
                NodeCoreError::PreinstalledObjectAccessPolicyEntrypointInvalid {
                    actual: 0,
                    maximum: MAX_TRANSACTION_ENTRYPOINT_BYTES,
                }
            )
        );
        let oversized_entrypoint = "x".repeat(MAX_TRANSACTION_ENTRYPOINT_BYTES + 1);
        assert_eq!(
            PreinstalledObjectAccessPolicy::new(
                1,
                oversized_entrypoint.clone(),
                AccessMode::Write,
                digest(0x01),
                1,
            ),
            Err(
                NodeCoreError::PreinstalledObjectAccessPolicyEntrypointInvalid {
                    actual: oversized_entrypoint.len(),
                    maximum: MAX_TRANSACTION_ENTRYPOINT_BYTES,
                }
            )
        );

        for mode in [AccessMode::Read, AccessMode::Consume] {
            assert_eq!(
                PreinstalledObjectAccessPolicy::new(
                    1,
                    "transfer".to_string(),
                    mode,
                    digest(0x01),
                    1,
                ),
                Err(NodeCoreError::PreinstalledObjectAccessPolicyModeUnsupported { mode })
            );
        }
    }

    #[test]
    fn semantics_envelope_rejects_oversized_bytes_too_many_policies_and_duplicate_index() {
        let oversized = vec![0u8; MAX_PREINSTALLED_SEMANTICS_BYTES + 1];
        assert_eq!(
            PreinstalledModuleSemanticsEnvelope::new(oversized.clone(), Vec::new()),
            Err(NodeCoreError::PreinstalledSemanticsBytesTooLarge {
                actual: oversized.len(),
                maximum: MAX_PREINSTALLED_SEMANTICS_BYTES,
            })
        );

        let too_many_policies: Vec<PreinstalledObjectAccessPolicy> = (0
            ..=MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES)
            .map(|index| sample_policy(u32::try_from(index).unwrap() + 1, "transfer"))
            .collect();
        assert_eq!(
            PreinstalledModuleSemanticsEnvelope::new(Vec::new(), too_many_policies),
            Err(
                NodeCoreError::PreinstalledObjectAccessPolicyCollectionTooLarge {
                    count: MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES + 1,
                    maximum: MAX_PREINSTALLED_OBJECT_ACCESS_POLICIES,
                }
            )
        );

        let duplicate_index = vec![sample_policy(1, "transfer"), sample_policy(1, "other")];
        assert_eq!(
            PreinstalledModuleSemanticsEnvelope::new(Vec::new(), duplicate_index),
            Err(NodeCoreError::DuplicatePreinstalledObjectAccessPolicyIndex { access_index: 1 })
        );
    }

    #[test]
    fn semantics_envelope_matches_only_exact_index_and_entrypoint() {
        let envelope = PreinstalledModuleSemanticsEnvelope::new(
            b"opaque".to_vec(),
            vec![sample_policy(1, "transfer")],
        )
        .unwrap();

        assert_eq!(
            envelope.matching_object_access_policy("transfer", 1),
            envelope.object_access_policies().first()
        );
        assert_eq!(envelope.matching_object_access_policy("other", 1), None);
        assert_eq!(envelope.matching_object_access_policy("transfer", 2), None);
        assert_eq!(envelope.matching_object_access_policy("transfer", 0), None);
    }

    #[test]
    fn preinstalled_object_access_policy_canonical_bytes_are_stable() {
        let policy = sample_policy(1, "transfer");
        let encoded = encode_preinstalled_object_access_policy(&policy).unwrap();
        assert_eq!(encoded, PREINSTALLED_OBJECT_ACCESS_POLICY_VECTOR);
    }

    #[test]
    fn preinstalled_semantics_envelope_canonical_bytes_are_stable() {
        let envelope = PreinstalledModuleSemanticsEnvelope::new(
            b"opaque-app-semantics".to_vec(),
            vec![sample_policy(1, "transfer")],
        )
        .unwrap();
        let encoded = encode_preinstalled_semantics_envelope(&envelope).unwrap();
        assert_eq!(encoded, PREINSTALLED_SEMANTICS_ENVELOPE_VECTOR);

        let empty_policies =
            PreinstalledModuleSemanticsEnvelope::opaque_only(b"opaque-app-semantics".to_vec())
                .unwrap();
        let empty_encoded = encode_preinstalled_semantics_envelope(&empty_policies).unwrap();
        assert_ne!(encoded, empty_encoded);
    }
}
