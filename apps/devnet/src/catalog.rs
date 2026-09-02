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

/// S3 preinstalled asset-account implementation version.
///
/// Versions 1 (historical same-sender semantics) and 2 (S2's committed
/// cross-owner destination policy) are intentionally not installed by this
/// dev profile; only their semantics-declaration bytes stay pinned as
/// historical vectors. S3 activates node-core's post-execution,
/// `gas_used`-derived fee settlement over a module-invisible trusted
/// treasury access, so the active module is version 3, even though the WASM
/// bytes and the asset body/argument/event schemas remain unchanged.
pub const ASSET_ACCOUNT_MODULE_VERSION: u64 = 3;

/// The transfer argument's exact canonical frame size from DR-0081.
pub const ASSET_TRANSFER_MAX_INPUT_SIZE: u64 = TRANSFER_ARGS_ENCODED_LEN as u64;

const ASSET_SCHEMA_DECLARATION_TYPE_ID: u16 = 0xF010;
const ASSET_SEMANTICS_DECLARATION_TYPE_ID: u16 = 0xF011;
const ASSET_SCHEMA_DECLARATION_ENCODING_VERSION: u16 = 1;
#[cfg(test)]
const HISTORICAL_ASSET_MODULE_VERSION: u64 = 1;
#[cfg(test)]
const HISTORICAL_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 1;
#[cfg(test)]
const HISTORICAL_S2_ASSET_MODULE_VERSION: u64 = 2;
#[cfg(test)]
const HISTORICAL_S2_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 2;
#[cfg(test)]
const HISTORICAL_SAME_SENDER_ACCESS_SEMANTICS: &str =
    "exactly two ordered Write objects owned by the authenticated sender";
#[cfg(test)]
const HISTORICAL_S2_CROSS_OWNER_ACCESS_SEMANTICS: &str = "exactly two ordered Write objects: source index 0 owned by the authenticated sender; existing destination index 1 may have another Address owner under the committed node-core policy; owners remain unchanged";
const S3_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 3;
const S3_FEE_METERED_ACCESS_SEMANTICS: &str = "exactly two ordered Write objects: source index 0 owned by the authenticated sender; existing destination index 1 may have another Address owner under the committed node-core policy; owners remain unchanged; a required trusted-composition fee-treasury Write access, when the committed fee schedule requires a charge, is appended by node-core strictly after these two indices and is never included in this module's execution inputs";
const S3_FEE_SETTLEMENT_FACTS: &str = concat!(
    "fee settlement, when the committed non-zero gas schedule requires a charge, is billed ",
    "entirely by trusted node-core composition after this module returns, from the exact ",
    "gas_used the committed receipt records, never from gas_limit or any pre-execution ",
    "estimate; the fee sink is one ordinary AssetAccount treasury credited by a trusted ",
    "composer, never a privileged native coin or special balance path"
);
const S3_TREASURY_VISIBILITY_FACTS: &str = concat!(
    "the fee-treasury object, when accessed, is excluded from this module's execution ",
    "inputs by node-core before this entrypoint runs: this module cannot read, observe, or ",
    "authorize the treasury access, and get_object_count reflects only the two ordinary ",
    "source/destination accounts above"
);
const S3_TRANSFER_EVENT_BALANCE_FACTS: &str = concat!(
    "the sunrise.devnet.asset_account.transferred.v1 event's source_balance field is the ",
    "source account's balance immediately after the application transfer and strictly ",
    "before any fee settlement; the exact post-fee source balance is source_balance minus ",
    "the fee derived from the committed receipt's gas_used and the committed gas schedule"
);
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
    let opaque_semantics: Vec<u8> = encode_s3_asset_semantics()?;
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
const HISTORICAL_FEE_LIFECYCLE_TEXT: &str =
    "no privileged native coin; no fee debit; fee_payment is None";

#[cfg(test)]
fn encode_historical_asset_semantics_v1() -> Result<Vec<u8>, DevnetCatalogError> {
    encode_asset_semantics_declaration(
        HISTORICAL_ASSET_SEMANTICS_ENCODING_VERSION,
        HISTORICAL_ASSET_MODULE_VERSION,
        HISTORICAL_SAME_SENDER_ACCESS_SEMANTICS,
        HISTORICAL_FEE_LIFECYCLE_TEXT,
        &[],
    )
}

#[cfg(test)]
fn encode_historical_asset_semantics_v2() -> Result<Vec<u8>, DevnetCatalogError> {
    encode_asset_semantics_declaration(
        HISTORICAL_S2_ASSET_SEMANTICS_ENCODING_VERSION,
        HISTORICAL_S2_ASSET_MODULE_VERSION,
        HISTORICAL_S2_CROSS_OWNER_ACCESS_SEMANTICS,
        HISTORICAL_FEE_LIFECYCLE_TEXT,
        &[],
    )
}

/// Encodes the active S3 opaque semantics declaration.
///
/// Reuses the shared v1/v2 eleven-field shape but replaces field 11's
/// fee-free claim with [`S3_FEE_SETTLEMENT_FACTS`] and appends two further
/// fields recording exactly the facts a fee-metered module version must
/// candidly declare: the module-invisible trusted treasury access
/// ([`S3_TREASURY_VISIBILITY_FACTS`]) and the transfer event's pre-fee
/// `source_balance` ([`S3_TRANSFER_EVENT_BALANCE_FACTS`]).
fn encode_s3_asset_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    encode_asset_semantics_declaration(
        S3_ASSET_SEMANTICS_ENCODING_VERSION,
        ASSET_ACCOUNT_MODULE_VERSION,
        S3_FEE_METERED_ACCESS_SEMANTICS,
        S3_FEE_SETTLEMENT_FACTS,
        &[
            (12, S3_TREASURY_VISIBILITY_FACTS),
            (13, S3_TRANSFER_EVENT_BALANCE_FACTS),
        ],
    )
}

fn encode_asset_semantics_declaration(
    encoding_version: u16,
    module_version: u64,
    access_semantics: &'static str,
    fee_lifecycle_text: &'static str,
    extra_fields: &[(u16, &'static str)],
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
        .field_str(11, fee_lifecycle_text)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    for (field_id, text) in extra_fields {
        canonical
            .field_str(*field_id, text)
            .map_err(DevnetCatalogError::CanonicalEncoding)?;
    }
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
    use crate::{asset_account::ASSET_ACCOUNT_WASM, genesis::build_devnet_protocol_context};

    const HISTORICAL_ASSET_SEMANTICS_V1_HEX: &str = "534e524511f001000b000100200000000d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7020008000000010000000000000003001f00000073756e726973652e6465766e65742e61737365745f6163636f756e742e76310400080000007472616e7366657205004300000065786163746c792074776f206f726465726564205772697465206f626a65637473206f776e6564206279207468652061757468656e746963617465642073656e64657206007f0000006f6e6520417373657449642f6163636f756e742f7472616e7366657220706174683b20657175616c206173736574206964733b206e6f6e2d7a65726f20616d6f756e743b20636865636b65642062616c616e63657320616e642073657175656e6365733b20636f6e73657276656420636f6d62696e65642062616c616e636507002b00000073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e763108004c000000534e524501f001000300010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea802000800000040420f00000000000300080000000700000000000000090018000000534e524502f001000100010008000000fa000000000000000a005a000000534e524503f001000400010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8020008000000fa0000000000000003000800000046410f0000000000040008000000fa000000000000000b003c0000006e6f2070726976696c65676564206e617469766520636f696e3b206e6f206665652064656269743b206665655f7061796d656e74206973204e6f6e65";
    const S3_ASSET_SEMANTICS_V3_HEX: &str = "534e524511f003000d000100200000000d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7020008000000030000000000000003001f00000073756e726973652e6465766e65742e61737365745f6163636f756e742e76310400080000007472616e736665720500ae01000065786163746c792074776f206f726465726564205772697465206f626a656374733a20736f7572636520696e6465782030206f776e6564206279207468652061757468656e746963617465642073656e6465723b206578697374696e672064657374696e6174696f6e20696e6465782031206d6179206861766520616e6f746865722041646472657373206f776e657220756e6465722074686520636f6d6d6974746564206e6f64652d636f726520706f6c6963793b206f776e6572732072656d61696e20756e6368616e6765643b206120726571756972656420747275737465642d636f6d706f736974696f6e206665652d7472656173757279205772697465206163636573732c207768656e2074686520636f6d6d697474656420666565207363686564756c652072657175697265732061206368617267652c20697320617070656e646564206279206e6f64652d636f7265207374726963746c792061667465722074686573652074776f20696e646963657320616e64206973206e6576657220696e636c7564656420696e2074686973206d6f64756c65277320657865637574696f6e20696e7075747306007f0000006f6e6520417373657449642f6163636f756e742f7472616e7366657220706174683b20657175616c206173736574206964733b206e6f6e2d7a65726f20616d6f756e743b20636865636b65642062616c616e63657320616e642073657175656e6365733b20636f6e73657276656420636f6d62696e65642062616c616e636507002b00000073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e763108004c000000534e524501f001000300010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea802000800000040420f00000000000300080000000700000000000000090018000000534e524502f001000100010008000000fa000000000000000a005a000000534e524503f001000400010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8020008000000fa0000000000000003000800000046410f0000000000040008000000fa000000000000000b008f01000066656520736574746c656d656e742c207768656e2074686520636f6d6d6974746564206e6f6e2d7a65726f20676173207363686564756c652072657175697265732061206368617267652c2069732062696c6c656420656e746972656c792062792074727573746564206e6f64652d636f726520636f6d706f736974696f6e2061667465722074686973206d6f64756c652072657475726e732c2066726f6d20746865206578616374206761735f757365642074686520636f6d6d69747465642072656365697074207265636f7264732c206e657665722066726f6d206761735f6c696d6974206f7220616e79207072652d657865637574696f6e20657374696d6174653b20746865206665652073696e6b206973206f6e65206f7264696e6172792041737365744163636f756e742074726561737572792063726564697465642062792061207472757374656420636f6d706f7365722c206e6576657220612070726976696c65676564206e617469766520636f696e206f72207370656369616c2062616c616e636520706174680c001b010000746865206665652d7472656173757279206f626a6563742c207768656e2061636365737365642c206973206578636c756465642066726f6d2074686973206d6f64756c65277320657865637574696f6e20696e70757473206279206e6f64652d636f7265206265666f7265207468697320656e747279706f696e742072756e733a2074686973206d6f64756c652063616e6e6f7420726561642c206f6273657276652c206f7220617574686f72697a6520746865207472656173757279206163636573732c20616e64206765745f6f626a6563745f636f756e74207265666c65637473206f6e6c79207468652074776f206f7264696e61727920736f757263652f64657374696e6174696f6e206163636f756e74732061626f76650d004e0100007468652073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e7631206576656e74277320736f757263655f62616c616e6365206669656c642069732074686520736f75726365206163636f756e7427732062616c616e636520696d6d6564696174656c7920616674657220746865206170706c69636174696f6e207472616e7366657220616e64207374726963746c79206265666f726520616e792066656520736574746c656d656e743b2074686520657861637420706f73742d66656520736f757263652062616c616e636520697320736f757263655f62616c616e6365206d696e7573207468652066656520646572697665642066726f6d2074686520636f6d6d697474656420726563656970742773206761735f7573656420616e642074686520636f6d6d697474656420676173207363686564756c65";
    const HISTORICAL_ASSET_SEMANTICS_V2_HEX: &str = "534e524511f002000b000100200000000d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7020008000000020000000000000003001f00000073756e726973652e6465766e65742e61737365745f6163636f756e742e76310400080000007472616e736665720500ce00000065786163746c792074776f206f726465726564205772697465206f626a656374733a20736f7572636520696e6465782030206f776e6564206279207468652061757468656e746963617465642073656e6465723b206578697374696e672064657374696e6174696f6e20696e6465782031206d6179206861766520616e6f746865722041646472657373206f776e657220756e6465722074686520636f6d6d6974746564206e6f64652d636f726520706f6c6963793b206f776e6572732072656d61696e20756e6368616e67656406007f0000006f6e6520417373657449642f6163636f756e742f7472616e7366657220706174683b20657175616c206173736574206964733b206e6f6e2d7a65726f20616d6f756e743b20636865636b65642062616c616e63657320616e642073657175656e6365733b20636f6e73657276656420636f6d62696e65642062616c616e636507002b00000073756e726973652e6465766e65742e61737365745f6163636f756e742e7472616e736665727265642e763108004c000000534e524501f001000300010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea802000800000040420f00000000000300080000000700000000000000090018000000534e524502f001000100010008000000fa000000000000000a005a000000534e524503f001000400010020000000ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8020008000000fa0000000000000003000800000046410f0000000000040008000000fa000000000000000b003c0000006e6f2070726976696c65676564206e617469766520636f696e3b206e6f206665652064656269743b206665655f7061796d656e74206973204e6f6e65";

    fn module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_asset_module(context, b"canonical-asset-wasm".to_vec()).unwrap()
    }

    fn actual_asset_module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_asset_module(context, ASSET_ACCOUNT_WASM.to_vec()).unwrap()
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
        let v1: Vec<u8> = encode_historical_asset_semantics_v1().unwrap();
        let v2: Vec<u8> = encode_historical_asset_semantics_v2().unwrap();
        let v3: Vec<u8> = encode_s3_asset_semantics().unwrap();

        assert_eq!(encode_hex(&v1), HISTORICAL_ASSET_SEMANTICS_V1_HEX);
        assert_eq!(encode_hex(&v2), HISTORICAL_ASSET_SEMANTICS_V2_HEX);
        assert_eq!(encode_hex(&v3), S3_ASSET_SEMANTICS_V3_HEX);
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    #[test]
    fn s3_semantics_declares_fee_settlement_treasury_and_pre_fee_event_facts() {
        let v3: Vec<u8> = encode_s3_asset_semantics().unwrap();
        let text: String = String::from_utf8_lossy(&v3).into_owned();
        assert!(text.contains("gas_used"));
        assert!(text.contains("never from gas_limit"));
        assert!(text.contains("excluded from this module's execution"));
        assert!(text.contains("strictly before any fee settlement"));
        assert!(text.contains("ordinary AssetAccount treasury"));
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
        for historical_version in [
            HISTORICAL_ASSET_MODULE_VERSION,
            HISTORICAL_S2_ASSET_MODULE_VERSION,
        ] {
            assert!(
                module
                    .protocol_config()
                    .system_modules
                    .get(ASSET_ACCOUNT_MODULE_ID, historical_version)
                    .is_none()
            );
            assert!(
                module
                    .catalog()
                    .get(ASSET_ACCOUNT_MODULE_ID, historical_version)
                    .is_none()
            );
        }
        let fee_asset = module
            .protocol_config()
            .fee_assets
            .get(DEVNET_ASSET_ID)
            .unwrap();
        assert!(fee_asset.enabled);
        assert_eq!(fee_asset.fee_units_per_asset_unit, 1);
        assert_eq!(module.protocol_config().gas_schedule.base_fee, 1);
        assert_eq!(module.protocol_config().gas_schedule.execution_price, 1);
        assert_eq!(module.protocol_config().gas_schedule.read_price, 0);
        assert_eq!(module.protocol_config().gas_schedule.write_price, 0);
        assert_eq!(module.protocol_config().gas_schedule.storage_price, 0);
        assert_eq!(module.protocol_config().gas_schedule.system_module_price, 0);
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
    fn s3_keeps_the_committed_asset_wasm_and_code_hash_unchanged() {
        let module: DevnetAssetModule = actual_asset_module();
        let entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(ASSET_ACCOUNT_MODULE_ID, ASSET_ACCOUNT_MODULE_VERSION)
            .unwrap();
        assert_eq!(entry.wasm_bytes(), ASSET_ACCOUNT_WASM);
        assert_eq!(
            module.module_ref().digest,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x57, 0x7A, 0x72, 0xC6, 0xC2, 0xAD, 0xAC, 0xF5, 0xFE, 0x31, 0xA5, 0xD2, 0x1E,
                    0x57, 0xD5, 0xF3, 0x77, 0x36, 0x62, 0xBA, 0x6C, 0x66, 0x1A, 0x3C, 0x4E, 0xBF,
                    0x14, 0xA3, 0xF2, 0xE0, 0x31, 0x6A,
                ],
            )
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
