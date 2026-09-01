//! Trusted preinstalled asset-account module composition for the local devnet.

use crate::{
    asset_account::{
        AssetAccount, AssetAccountCodecError, DEVNET_ASSET_ID, ENCODING_VERSION, MODULE_NAME,
        TRANSFER_ARGS_ENCODED_LEN, TRANSFER_ENTRYPOINT, TRANSFER_EVENT_TYPE_TAG, TransferArgs,
        TransferEvent, asset_account_type_hash, encode_asset_account, encode_transfer_args,
        encode_transfer_event,
    },
    genesis::DevnetProtocolContext,
};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use hashing::{HashSuiteResolver, HashingError};
use node_core::{
    NodeCoreError, PreinstalledModuleCatalog, PreinstalledModuleCatalogEntry,
    PreinstalledModuleSemanticsEnvelope, PreinstalledObjectAccessPolicy,
    encode_preinstalled_semantics_envelope, reconcile_preinstalled_registry_and_catalog,
};
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_config::{ProtocolConfig, ProtocolConfigError};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, Epoch, HashPurpose};
use std::{error::Error, fmt};
use system_modules::{
    GasModel, ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
    TypeSchema, encode_system_module_manifest,
};

/// Stable dev-profile module ID (SHA-256 of
/// `sunrise.devnet.asset_account.module.v1`, used as an opaque ID rather than
/// a protocol hash claim).
pub const ASSET_ACCOUNT_MODULE_ID: ModuleId = ModuleId::new([
    0x0D, 0x5D, 0xD1, 0x0A, 0xEC, 0x2C, 0x31, 0x5B, 0x1D, 0xC5, 0x64, 0xC6, 0x94, 0x43, 0x9E, 0x46,
    0xBA, 0xC4, 0xB6, 0x14, 0x26, 0xD2, 0x2E, 0x0D, 0x7D, 0xDB, 0x76, 0x4C, 0x49, 0x19, 0x7F, 0xE7,
]);

/// S2 preinstalled asset-account implementation version.
///
/// Version 1 remains a historical same-sender semantics declaration and is
/// intentionally not installed by this dev profile. S2's committed destination
/// policy changes module semantics, so the active module is version 2 even
/// though the WASM and asset body/argument/event schemas remain unchanged.
pub const ASSET_ACCOUNT_MODULE_VERSION: u64 = 2;

/// The transfer argument's exact canonical frame size from DR-0081.
pub const ASSET_TRANSFER_MAX_INPUT_SIZE: u64 = TRANSFER_ARGS_ENCODED_LEN as u64;

const ASSET_SCHEMA_DECLARATION_TYPE_ID: u16 = 0xF010;
const ASSET_SEMANTICS_DECLARATION_TYPE_ID: u16 = 0xF011;
const ASSET_SCHEMA_DECLARATION_ENCODING_VERSION: u16 = 1;
#[cfg(test)]
const HISTORICAL_ASSET_MODULE_VERSION: u64 = 1;
#[cfg(test)]
const HISTORICAL_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 1;
const S2_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 2;
#[cfg(test)]
const HISTORICAL_SAME_SENDER_ACCESS_SEMANTICS: &str =
    "exactly two ordered Write objects owned by the authenticated sender";
const S2_CROSS_OWNER_ACCESS_SEMANTICS: &str = "exactly two ordered Write objects: source index 0 owned by the authenticated sender; existing destination index 1 may have another Address owner under the committed node-core policy; owners remain unchanged";
const ASSET_TRANSFER_INPUT_DESCRIPTOR: &str = "sunrise.devnet.asset_account.transfer.input.v1";
const ASSET_TRANSFER_OUTPUT_DESCRIPTOR: &str = "sunrise.devnet.asset_account.transfer.output.v1";
const ASSET_TRANSFER_INPUT_SCHEMA: &str =
    "CanonicalStruct(0xF002,v1){1:non-zero amount u64 little-endian}";
const ASSET_TRANSFER_OUTPUT_SCHEMA: &str = concat!(
    "two ordered owned-object Update effects using CanonicalStruct(0xF001,v1); ",
    "event sunrise.devnet.asset_account.transferred.v1 uses CanonicalStruct(0xF003,v1)"
);

/// A fully reconciled preinstalled asset module and the updated protocol
/// configuration that commits its active registry entry.
#[derive(Clone, Debug)]
pub struct DevnetAssetModule {
    chain_id: ChainId,
    epoch: Epoch,
    domain: AtomicityDomainId,
    protocol_config: ProtocolConfig,
    resolver: HashSuiteResolver,
    catalog: PreinstalledModuleCatalog,
    module_ref: ObjectRef,
    semantics_hash: Digest32,
}

impl DevnetAssetModule {
    /// Returns the chain identifier bound into module commitments.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the epoch at which startup reconciliation succeeded.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the sole logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the updated configuration containing the active asset module.
    #[must_use]
    pub const fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the resolver derived from the updated configuration.
    #[must_use]
    pub const fn resolver(&self) -> &HashSuiteResolver {
        &self.resolver
    }

    /// Returns the immutable, startup-reconciled preinstalled catalog.
    #[must_use]
    pub const fn catalog(&self) -> &PreinstalledModuleCatalog {
        &self.catalog
    }

    /// Returns the object reference transactions use to select this module.
    #[must_use]
    pub const fn module_ref(&self) -> &ObjectRef {
        &self.module_ref
    }

    /// Returns the computed behavior-declaration commitment.
    #[must_use]
    pub const fn semantics_hash(&self) -> Digest32 {
        self.semantics_hash
    }

    /// Consumes the composition into the ownership pieces required by the
    /// native router.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
        PreinstalledModuleCatalog,
        ObjectRef,
    ) {
        (
            self.chain_id,
            self.epoch,
            self.domain,
            self.protocol_config,
            self.resolver,
            self.catalog,
            self.module_ref,
        )
    }
}

/// Commits the canonical asset-account WASM bytes into protocol configuration
/// and builds the exact catalog that can execute them.
///
/// All code, schema, manifest, and semantic digests are computed through the
/// resolver tied to `context`; no caller-supplied or pasted digest is trusted.
/// The returned `ProtocolConfig` contains the active `SystemModule` entry, and
/// the returned resolver is freshly derived from that updated configuration's
/// own version and schedule before full registry/catalog reconciliation.
pub fn build_asset_module(
    context: DevnetProtocolContext,
    wasm_bytes: Vec<u8>,
) -> Result<DevnetAssetModule, DevnetCatalogError> {
    let (chain_id, epoch, domain, mut protocol_config, commitment_resolver): (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
    ) = context.into_parts();

    let input_schema: TypeSchema = build_schema(
        &commitment_resolver,
        epoch,
        ASSET_TRANSFER_INPUT_DESCRIPTOR,
        ASSET_TRANSFER_INPUT_SCHEMA,
    )?;
    let output_schema: TypeSchema = build_schema(
        &commitment_resolver,
        epoch,
        ASSET_TRANSFER_OUTPUT_DESCRIPTOR,
        ASSET_TRANSFER_OUTPUT_SCHEMA,
    )?;
    let manifest: SystemModuleManifest = SystemModuleManifest {
        module_id: ASSET_ACCOUNT_MODULE_ID,
        input_schema,
        output_schema,
        max_input_size: ASSET_TRANSFER_MAX_INPUT_SIZE,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    };
    manifest
        .validate()
        .map_err(DevnetCatalogError::SystemModule)?;

    let code_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::ContractCode, &wasm_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let manifest_bytes: Vec<u8> =
        encode_system_module_manifest(&manifest).map_err(DevnetCatalogError::SystemModule)?;
    let manifest_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &manifest_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let opaque_semantics: Vec<u8> = encode_s2_asset_semantics()?;
    let destination_policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        TRANSFER_ENTRYPOINT.to_string(),
        AccessMode::Write,
        asset_account_type_hash(),
        u32::from(ENCODING_VERSION),
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(opaque_semantics, vec![destination_policy])
            .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&semantics_envelope)
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &semantics_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let module: SystemModule = SystemModule {
        module_id: ASSET_ACCOUNT_MODULE_ID,
        version: ASSET_ACCOUNT_MODULE_VERSION,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Active,
    };
    protocol_config
        .system_modules
        .add_module(module)
        .map_err(DevnetCatalogError::SystemModule)?;
    protocol_config
        .validate()
        .map_err(DevnetCatalogError::ProtocolConfig)?;

    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_config.protocol_version,
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetCatalogError::Hashing)?;
    let entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
        ASSET_ACCOUNT_MODULE_ID,
        ASSET_ACCOUNT_MODULE_VERSION,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    let catalog: PreinstalledModuleCatalog =
        PreinstalledModuleCatalog::new(vec![entry]).map_err(DevnetCatalogError::NodeCore)?;
    reconcile_preinstalled_registry_and_catalog(
        &protocol_config.system_modules,
        &catalog,
        epoch,
        &resolver,
    )
    .map_err(DevnetCatalogError::NodeCore)?;

    let module_ref: ObjectRef = ObjectRef {
        id: ObjectId::new(*ASSET_ACCOUNT_MODULE_ID.as_bytes()),
        version: ASSET_ACCOUNT_MODULE_VERSION,
        digest: code_hash,
    };
    Ok(DevnetAssetModule {
        chain_id,
        epoch,
        domain,
        protocol_config,
        resolver,
        catalog,
        module_ref,
        semantics_hash,
    })
}

fn build_schema(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    descriptor: &'static str,
    definition: &'static str,
) -> Result<TypeSchema, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        ASSET_SCHEMA_DECLARATION_TYPE_ID,
        ASSET_SCHEMA_DECLARATION_ENCODING_VERSION,
    );
    canonical
        .field_str(1, descriptor)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(2, definition)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    let bytes: Vec<u8> = canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    let schema_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    Ok(TypeSchema {
        descriptor: descriptor.to_string(),
        schema_hash,
    })
}

#[cfg(test)]
fn encode_historical_asset_semantics_v1() -> Result<Vec<u8>, DevnetCatalogError> {
    encode_asset_semantics_declaration(
        HISTORICAL_ASSET_SEMANTICS_ENCODING_VERSION,
        HISTORICAL_ASSET_MODULE_VERSION,
        HISTORICAL_SAME_SENDER_ACCESS_SEMANTICS,
    )
}

fn encode_s2_asset_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    encode_asset_semantics_declaration(
        S2_ASSET_SEMANTICS_ENCODING_VERSION,
        ASSET_ACCOUNT_MODULE_VERSION,
        S2_CROSS_OWNER_ACCESS_SEMANTICS,
    )
}

fn encode_asset_semantics_declaration(
    encoding_version: u16,
    module_version: u64,
    access_semantics: &'static str,
) -> Result<Vec<u8>, DevnetCatalogError> {
    let account_vector: Vec<u8> =
        encode_asset_account(&AssetAccount::new(DEVNET_ASSET_ID, 1_000_000, 7))
            .map_err(DevnetCatalogError::AssetAccount)?;
    let transfer_args: TransferArgs =
        TransferArgs::new(250).map_err(DevnetCatalogError::AssetAccount)?;
    let args_vector: Vec<u8> =
        encode_transfer_args(transfer_args).map_err(DevnetCatalogError::AssetAccount)?;
    let event_vector: Vec<u8> = encode_transfer_event(&TransferEvent {
        asset_id: DEVNET_ASSET_ID,
        amount: 250,
        source_balance: 999_750,
        destination_balance: 250,
    })
    .map_err(DevnetCatalogError::AssetAccount)?;

    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(ASSET_SEMANTICS_DECLARATION_TYPE_ID, encoding_version);
    canonical
        .field_bytes(1, ASSET_ACCOUNT_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, module_version)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(5, access_semantics)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(
            6,
            "one AssetId/account/transfer path; equal asset ids; non-zero amount; checked balances and sequences; conserved combined balance",
        )
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_bytes(7, TRANSFER_EVENT_TYPE_TAG)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_bytes(8, account_vector)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_bytes(9, args_vector)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_bytes(10, event_vector)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(
            11,
            "no privileged native coin; no fee debit; fee_payment is None",
        )
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)
}

/// Failures while committing and reconciling the trusted devnet catalog.
#[derive(Debug)]
pub enum DevnetCatalogError {
    /// A committed asset-account semantics vector could not be encoded.
    AssetAccount(AssetAccountCodecError),
    /// A dev-local commitment declaration could not be canonically encoded.
    CanonicalEncoding(CanonicalEncodingError),
    /// Hash-suite resolution or commitment hashing failed.
    Hashing(HashingError),
    /// System-module manifest or registry construction failed.
    SystemModule(SystemModuleError),
    /// The updated protocol configuration failed validation.
    ProtocolConfig(ProtocolConfigError),
    /// Catalog construction or full startup reconciliation failed closed.
    NodeCore(NodeCoreError),
}

impl fmt::Display for DevnetCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssetAccount(error) => {
                write!(formatter, "devnet asset semantics vector failed: {error}")
            }
            Self::CanonicalEncoding(error) => {
                write!(
                    formatter,
                    "devnet asset declaration encoding failed: {error}"
                )
            }
            Self::Hashing(error) => {
                write!(formatter, "devnet asset commitment hashing failed: {error}")
            }
            Self::SystemModule(error) => {
                write!(
                    formatter,
                    "devnet asset system-module definition failed: {error}"
                )
            }
            Self::ProtocolConfig(error) => {
                write!(
                    formatter,
                    "devnet asset protocol configuration failed: {error}"
                )
            }
            Self::NodeCore(error) => {
                write!(
                    formatter,
                    "devnet asset catalog reconciliation failed: {error}"
                )
            }
        }
    }
}

impl Error for DevnetCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AssetAccount(error) => Some(error),
            Self::CanonicalEncoding(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::SystemModule(error) => Some(error),
            Self::ProtocolConfig(error) => Some(error),
            Self::NodeCore(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::build_devnet_protocol_context;

    const HISTORICAL_ASSET_SEMANTICS_V1_HEX: &str = "534e524511f001000b000100200000000d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7020008000000010000000000000003001f00000073756e726973652e6465766e65742e61737365745f6163636f756e742e76310400080000007472616e7366657205004300000065786163746c792074776f206f726465726564205772697465206f626a65637473206f776e6564206279207468652061757468656e746963617465642073656e64657206007f0000006f6e6520417373657449642f6163636f756e742f7472616e7366657220706174683b20657175616c206173736574206964733b206e6f6e2d7a65726f20616d6f756e743b20636865636b65642062616c616e63657320616e642073657175656e6365733b20636f6e73657276656420636f6d62696e65642062616c616e636507002b00000073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e763108004c000000534e524501f001000300010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea802000800000040420f00000000000300080000000700000000000000090018000000534e524502f001000100010008000000fa000000000000000a005a000000534e524503f001000400010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8020008000000fa0000000000000003000800000046410f0000000000040008000000fa000000000000000b003c0000006e6f2070726976696c65676564206e617469766520636f696e3b206e6f206665652064656269743b206665655f7061796d656e74206973204e6f6e65";
    const S2_ASSET_SEMANTICS_V2_HEX: &str = "534e524511f002000b000100200000000d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7020008000000020000000000000003001f00000073756e726973652e6465766e65742e61737365745f6163636f756e742e76310400080000007472616e736665720500ce00000065786163746c792074776f206f726465726564205772697465206f626a656374733a20736f7572636520696e6465782030206f776e6564206279207468652061757468656e746963617465642073656e6465723b206578697374696e672064657374696e6174696f6e20696e6465782031206d6179206861766520616e6f746865722041646472657373206f776e657220756e6465722074686520636f6d6d6974746564206e6f64652d636f726520706f6c6963793b206f776e6572732072656d61696e20756e6368616e67656406007f0000006f6e6520417373657449642f6163636f756e742f7472616e7366657220706174683b20657175616c206173736574206964733b206e6f6e2d7a65726f20616d6f756e743b20636865636b65642062616c616e63657320616e642073657175656e6365733b20636f6e73657276656420636f6d62696e65642062616c616e636507002b00000073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e763108004c000000534e524501f001000300010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea802000800000040420f00000000000300080000000700000000000000090018000000534e524502f001000100010008000000fa000000000000000a005a000000534e524503f001000400010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8020008000000fa0000000000000003000800000046410f0000000000040008000000fa000000000000000b003c0000006e6f2070726976696c65676564206e617469766520636f696e3b206e6f206665652064656269743b206665655f7061796d656e74206973204e6f6e65";

    fn module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_asset_module(context, b"canonical-asset-wasm".to_vec()).unwrap()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded: String = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn semantics_declaration_versions_have_pinned_distinct_bytes() {
        let historical: Vec<u8> = encode_historical_asset_semantics_v1().unwrap();
        let s2: Vec<u8> = encode_s2_asset_semantics().unwrap();

        assert_eq!(encode_hex(&historical), HISTORICAL_ASSET_SEMANTICS_V1_HEX);
        assert_eq!(encode_hex(&s2), S2_ASSET_SEMANTICS_V2_HEX);
        assert_ne!(historical, s2);
    }

    #[test]
    fn updated_config_and_catalog_reconcile() {
        let module: DevnetAssetModule = module();
        let registered: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(ASSET_ACCOUNT_MODULE_ID, ASSET_ACCOUNT_MODULE_VERSION)
            .unwrap();

        assert_eq!(registered.status, ModuleStatus::Active);
        assert_eq!(registered.version, ASSET_ACCOUNT_MODULE_VERSION);
        assert_eq!(registered.canonical_code_hash, module.module_ref().digest);
        assert_eq!(registered.semantics_hash, module.semantics_hash());
        assert!(
            module
                .protocol_config()
                .system_modules
                .get(ASSET_ACCOUNT_MODULE_ID, HISTORICAL_ASSET_MODULE_VERSION)
                .is_none()
        );
        assert!(
            module
                .catalog()
                .get(ASSET_ACCOUNT_MODULE_ID, HISTORICAL_ASSET_MODULE_VERSION)
                .is_none()
        );
        assert!(module.protocol_config().fee_assets.is_empty());
        assert_eq!(module.resolver().chain_id(), module.chain_id());
        assert_eq!(
            module.resolver().protocol_version(),
            module.protocol_config().protocol_version
        );
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &module.protocol_config().system_modules,
                module.catalog(),
                module.epoch(),
                module.resolver(),
            ),
            Ok(())
        );
    }

    #[test]
    fn tampered_wasm_fails_startup_reconciliation() {
        let module: DevnetAssetModule = module();
        let original: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(ASSET_ACCOUNT_MODULE_ID, ASSET_ACCOUNT_MODULE_VERSION)
            .unwrap();
        let tampered_entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
            ASSET_ACCOUNT_MODULE_ID,
            ASSET_ACCOUNT_MODULE_VERSION,
            b"tampered-asset-wasm".to_vec(),
            original.manifest().clone(),
            original.semantics_envelope().clone(),
        )
        .unwrap();
        let tampered_catalog: PreinstalledModuleCatalog =
            PreinstalledModuleCatalog::new(vec![tampered_entry]).unwrap();

        assert!(matches!(
            reconcile_preinstalled_registry_and_catalog(
                &module.protocol_config().system_modules,
                &tampered_catalog,
                module.epoch(),
                module.resolver(),
            ),
            Err(NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: ASSET_ACCOUNT_MODULE_ID,
                version: ASSET_ACCOUNT_MODULE_VERSION,
            })
        ));
    }

    #[test]
    fn commitment_is_bound_to_chain_context() {
        let first: DevnetAssetModule = module();
        let second_context: DevnetProtocolContext = build_devnet_protocol_context(
            ChainId::new("sunrise-other-devnet").unwrap(),
            Epoch::new(7),
        )
        .unwrap();
        let second: DevnetAssetModule =
            build_asset_module(second_context, b"canonical-asset-wasm".to_vec()).unwrap();

        assert_ne!(first.module_ref().digest, second.module_ref().digest);
        assert_ne!(first.semantics_hash(), second.semantics_hash());
    }

    #[test]
    fn catalog_commits_exact_cross_owner_destination_policy() {
        let module: DevnetAssetModule = module();
        let entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(ASSET_ACCOUNT_MODULE_ID, ASSET_ACCOUNT_MODULE_VERSION)
            .unwrap();
        let policies: &[PreinstalledObjectAccessPolicy] =
            entry.semantics_envelope().object_access_policies();

        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].access_index(), 1);
        assert_eq!(policies[0].entrypoint(), TRANSFER_ENTRYPOINT);
        assert_eq!(policies[0].mode(), AccessMode::Write);
        assert_eq!(policies[0].expected_type_hash(), asset_account_type_hash());
        assert_eq!(
            policies[0].expected_schema_version(),
            u32::from(ENCODING_VERSION)
        );
    }
}
