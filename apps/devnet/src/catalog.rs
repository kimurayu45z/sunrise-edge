//! Trusted preinstalled asset-account module composition for the local devnet.

use crate::{
    asset_account::{
        AssetAccount, AssetAccountCodecError, DEVNET_ASSET_ID, MODULE_NAME,
        TRANSFER_ARGS_ENCODED_LEN, TRANSFER_ENTRYPOINT, TRANSFER_EVENT_TYPE_TAG, TransferArgs,
        TransferEvent, encode_asset_account, encode_transfer_args, encode_transfer_event,
    },
    genesis::DevnetProtocolContext,
};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use hashing::{HashSuiteResolver, HashingError};
use node_core::{
    NodeCoreError, PreinstalledModuleCatalog, PreinstalledModuleCatalogEntry,
    reconcile_preinstalled_registry_and_catalog,
};
use objects::{ObjectId, ObjectRef};
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

/// Initial preinstalled asset-account implementation version.
pub const ASSET_ACCOUNT_MODULE_VERSION: u64 = 1;

/// The transfer argument's exact canonical frame size from DR-0081.
pub const ASSET_TRANSFER_MAX_INPUT_SIZE: u64 = TRANSFER_ARGS_ENCODED_LEN as u64;

const ASSET_SCHEMA_DECLARATION_TYPE_ID: u16 = 0xF010;
const ASSET_SEMANTICS_DECLARATION_TYPE_ID: u16 = 0xF011;
const DEVNET_DECLARATION_ENCODING_VERSION: u16 = 1;
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
    let semantics_bytes: Vec<u8> = encode_asset_semantics()?;
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
        semantics_hash,
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
        DEVNET_DECLARATION_ENCODING_VERSION,
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

fn encode_asset_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
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

    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        ASSET_SEMANTICS_DECLARATION_TYPE_ID,
        DEVNET_DECLARATION_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, ASSET_ACCOUNT_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, ASSET_ACCOUNT_MODULE_VERSION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(
            5,
            "exactly two ordered Write objects owned by the authenticated sender",
        )
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

    fn module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_asset_module(context, b"canonical-asset-wasm".to_vec()).unwrap()
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
        assert_eq!(registered.canonical_code_hash, module.module_ref().digest);
        assert_eq!(registered.semantics_hash, module.semantics_hash());
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
            original.semantics_hash(),
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
}
