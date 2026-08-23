#![forbid(unsafe_code)]

//! Stablecoin-denominated fee assets, deterministic fee calculation, and
//! validator fee distribution.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use objects::{ObjectRef, encode_object_ref};
use runtime::ValidatorId;
use std::error::Error;

const ASSET_ID_TYPE_ID: u16 = 0x7001;
const FEE_PAYMENT_TYPE_ID: u16 = 0x7002;
const FEE_ASSET_TYPE_ID: u16 = 0x7003;
const FEE_ASSET_REGISTRY_TYPE_ID: u16 = 0x7004;
const GAS_SCHEDULE_TYPE_ID: u16 = 0x7005;
const FEE_USAGE_TYPE_ID: u16 = 0x7006;
const VALIDATOR_FEE_SHARE_TYPE_ID: u16 = 0x7007;
const FEE_DISTRIBUTION_TYPE_ID: u16 = 0x7008;
const ENCODING_VERSION: u16 = 1;
const IDENTIFIER_LEN: usize = 32;
const MAX_REGISTRY_ASSETS: usize = u16::MAX as usize - 1;
const MAX_SIGNERS: usize = u16::MAX as usize - 3;

/// Errors returned by fee helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeError {
    /// An asset identifier had the wrong length.
    InvalidAssetIdLength(usize),
    /// Fee conversion rates must be explicitly non-zero.
    ZeroFeeUnitsPerAssetUnit,
    /// The fee-asset registry contains more items than can be canonically encoded.
    RegistryTooLarge(usize),
    /// The signer set contains more items than can be canonically encoded.
    TooManySigners(usize),
    /// The fee-asset registry already contains the asset.
    DuplicateAsset(AssetId),
    /// The fee-asset registry does not contain the asset.
    UnknownAsset(AssetId),
    /// The selected fee asset is disabled.
    AssetDisabled(AssetId),
    /// The signer set is empty.
    EmptySignerSet,
    /// The signer set contains duplicates.
    DuplicateSigner(ValidatorId),
    /// The fee payment's max fee is lower than the required charge.
    MaxFeeExceeded { required: Amount, max_fee: Amount },
    /// Checked arithmetic overflowed.
    ArithmeticOverflow,
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Object encoding failed.
    Object(objects::ObjectError),
}

impl fmt::Display for FeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssetIdLength(length) => write!(
                f,
                "asset identifiers must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::ZeroFeeUnitsPerAssetUnit => {
                write!(f, "fee-units-per-asset-unit must be non-zero")
            }
            Self::RegistryTooLarge(count) => write!(
                f,
                "fee-asset registry has {count} entries, exceeds canonical limit"
            ),
            Self::TooManySigners(count) => {
                write!(
                    f,
                    "fee distribution has {count} signers, exceeds canonical limit"
                )
            }
            Self::DuplicateAsset(asset_id) => write!(f, "duplicate fee asset: {asset_id}"),
            Self::UnknownAsset(asset_id) => write!(f, "unknown fee asset: {asset_id}"),
            Self::AssetDisabled(asset_id) => write!(f, "fee asset is disabled: {asset_id}"),
            Self::EmptySignerSet => write!(f, "signer set must not be empty"),
            Self::DuplicateSigner(validator_id) => {
                write!(f, "duplicate validator in signer set: {validator_id}")
            }
            Self::MaxFeeExceeded { required, max_fee } => {
                write!(f, "required fee {required} exceeds max fee {max_fee}")
            }
            Self::ArithmeticOverflow => write!(f, "fee arithmetic overflow"),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::Object(error) => error.fmt(f),
        }
    }
}

impl Error for FeeError {}

impl From<CanonicalEncodingError> for FeeError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<objects::ObjectError> for FeeError {
    fn from(value: objects::ObjectError) -> Self {
        Self::Object(value)
    }
}

/// A stable canonical asset identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetId {
    bytes: [u8; IDENTIFIER_LEN],
}

impl AssetId {
    /// Creates an asset identifier.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Parses an asset identifier from raw bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FeeError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(FeeError::InvalidAssetIdLength(bytes.len()));
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

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A stable amount in canonical integer units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// Creates an amount.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// A user-authorized fee payment for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePayment {
    /// Canonical fee asset chosen by the sender.
    pub asset_id: AssetId,
    /// Maximum amount the sender authorizes in that asset.
    pub max_fee: Amount,
    /// Object containing the approved fee balance.
    pub fee_object: ObjectRef,
}

/// An approved fee asset and its deterministic conversion parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeAsset {
    /// Canonical asset identifier.
    pub asset_id: AssetId,
    /// Number of internal fee units represented by one on-chain asset unit.
    pub fee_units_per_asset_unit: u64,
    /// Whether the asset may currently be used for transaction fees.
    pub enabled: bool,
}

impl FeeAsset {
    /// Validates the fee asset parameters.
    pub fn validate(&self) -> Result<(), FeeError> {
        if self.fee_units_per_asset_unit == 0 {
            return Err(FeeError::ZeroFeeUnitsPerAssetUnit);
        }
        Ok(())
    }
}

/// Registry of approved fee assets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeAssetRegistry {
    assets: Vec<FeeAsset>,
}

impl FeeAssetRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { assets: Vec::new() }
    }

    /// Returns the registered assets in canonical order.
    #[must_use]
    pub fn assets(&self) -> &[FeeAsset] {
        &self.assets
    }

    /// Returns the number of registered assets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Validates the registry.
    pub fn validate(&self) -> Result<(), FeeError> {
        if self.assets.len() > MAX_REGISTRY_ASSETS {
            return Err(FeeError::RegistryTooLarge(self.assets.len()));
        }

        let mut previous = None;
        for asset in &self.assets {
            asset.validate()?;
            if previous == Some(asset.asset_id) {
                return Err(FeeError::DuplicateAsset(asset.asset_id));
            }
            previous = Some(asset.asset_id);
        }
        Ok(())
    }

    /// Returns the registered asset.
    #[must_use]
    pub fn get(&self, asset_id: AssetId) -> Option<&FeeAsset> {
        self.assets
            .binary_search_by_key(&asset_id, |asset| asset.asset_id)
            .ok()
            .map(|index| &self.assets[index])
    }

    /// Registers a fee asset.
    pub fn add_asset(&mut self, asset: FeeAsset) -> Result<(), FeeError> {
        asset.validate()?;
        match self
            .assets
            .binary_search_by_key(&asset.asset_id, |entry| entry.asset_id)
        {
            Ok(_) => Err(FeeError::DuplicateAsset(asset.asset_id)),
            Err(index) => {
                self.assets.insert(index, asset);
                Ok(())
            }
        }
    }

    /// Disables an existing fee asset.
    pub fn disable_asset(&mut self, asset_id: AssetId) -> Result<(), FeeError> {
        let index = self
            .assets
            .binary_search_by_key(&asset_id, |entry| entry.asset_id)
            .map_err(|_| FeeError::UnknownAsset(asset_id))?;
        self.assets[index].enabled = false;
        Ok(())
    }

    /// Replaces the deterministic parameters for an existing fee asset.
    pub fn update_asset(&mut self, asset: FeeAsset) -> Result<(), FeeError> {
        asset.validate()?;
        let index = self
            .assets
            .binary_search_by_key(&asset.asset_id, |entry| entry.asset_id)
            .map_err(|_| FeeError::UnknownAsset(asset.asset_id))?;
        self.assets[index] = asset;
        Ok(())
    }
}

/// Deterministic fee price schedule, all denominated in internal fee units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasSchedule {
    /// Flat base cost.
    pub base_fee: u64,
    /// Cost per execution unit.
    pub execution_price: u64,
    /// Cost per state read.
    pub read_price: u64,
    /// Cost per state write.
    pub write_price: u64,
    /// Cost per storage unit written.
    pub storage_price: u64,
    /// Additional system-module cost.
    pub system_module_price: u64,
}

impl GasSchedule {
    /// Returns the zero-cost genesis schedule.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            base_fee: 0,
            execution_price: 0,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        }
    }
}

/// Resource usage used to calculate one transaction fee.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeUsage {
    /// Execution units consumed.
    pub execution_units: u64,
    /// State reads performed.
    pub state_read_units: u64,
    /// State writes performed.
    pub state_write_units: u64,
    /// Storage units written.
    pub storage_units: u64,
    /// System-module usage units.
    pub system_module_units: u64,
}

/// One validator's deterministic fee share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorFeeShare {
    /// Validator receiving the share.
    pub validator_id: ValidatorId,
    /// Amount of the shared fee.
    pub amount: Amount,
}

/// Canonical fee distribution for one certified transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeDistribution {
    /// Asset in which the fee is paid.
    pub asset_id: AssetId,
    /// Total fee amount charged to the sender.
    pub total_amount: Amount,
    /// Deterministic signer payouts in canonical validator order.
    pub shares: Vec<ValidatorFeeShare>,
}

/// Encodes an asset identifier.
pub fn encode_asset_id(asset_id: &AssetId) -> Result<Vec<u8>, FeeError> {
    let mut canonical = CanonicalStruct::new(ASSET_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, asset_id.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes a fee payment.
pub fn encode_fee_payment(payment: &FeePayment) -> Result<Vec<u8>, FeeError> {
    let mut canonical = CanonicalStruct::new(FEE_PAYMENT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&payment.asset_id)?)?;
    canonical.field_u64(2, payment.max_fee.get())?;
    canonical.field_bytes(3, encode_object_ref(&payment.fee_object)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a fee asset configuration.
pub fn encode_fee_asset(asset: &FeeAsset) -> Result<Vec<u8>, FeeError> {
    asset.validate()?;

    let mut canonical = CanonicalStruct::new(FEE_ASSET_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&asset.asset_id)?)?;
    canonical.field_u64(2, asset.fee_units_per_asset_unit)?;
    canonical.field_bytes(3, [u8::from(asset.enabled)])?;
    Ok(canonical.finish()?)
}

/// Encodes the full fee-asset registry.
pub fn encode_fee_asset_registry(registry: &FeeAssetRegistry) -> Result<Vec<u8>, FeeError> {
    registry.validate()?;

    let mut canonical = CanonicalStruct::new(FEE_ASSET_REGISTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, registry.assets.len() as u32)?;
    for (index, asset) in registry.assets.iter().enumerate() {
        canonical.field_bytes((index + 2) as u16, encode_fee_asset(asset)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a gas schedule.
pub fn encode_gas_schedule(schedule: &GasSchedule) -> Result<Vec<u8>, FeeError> {
    let mut canonical = CanonicalStruct::new(GAS_SCHEDULE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, schedule.base_fee)?;
    canonical.field_u64(2, schedule.execution_price)?;
    canonical.field_u64(3, schedule.read_price)?;
    canonical.field_u64(4, schedule.write_price)?;
    canonical.field_u64(5, schedule.storage_price)?;
    canonical.field_u64(6, schedule.system_module_price)?;
    Ok(canonical.finish()?)
}

/// Encodes fee usage.
pub fn encode_fee_usage(usage: &FeeUsage) -> Result<Vec<u8>, FeeError> {
    let mut canonical = CanonicalStruct::new(FEE_USAGE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, usage.execution_units)?;
    canonical.field_u64(2, usage.state_read_units)?;
    canonical.field_u64(3, usage.state_write_units)?;
    canonical.field_u64(4, usage.storage_units)?;
    canonical.field_u64(5, usage.system_module_units)?;
    Ok(canonical.finish()?)
}

/// Encodes one validator fee share.
pub fn encode_validator_fee_share(share: &ValidatorFeeShare) -> Result<Vec<u8>, FeeError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_FEE_SHARE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, share.validator_id.as_bytes())?;
    canonical.field_u64(2, share.amount.get())?;
    Ok(canonical.finish()?)
}

/// Encodes a full fee distribution.
pub fn encode_fee_distribution(distribution: &FeeDistribution) -> Result<Vec<u8>, FeeError> {
    if distribution.shares.len() > MAX_SIGNERS {
        return Err(FeeError::TooManySigners(distribution.shares.len()));
    }

    let mut canonical = CanonicalStruct::new(FEE_DISTRIBUTION_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&distribution.asset_id)?)?;
    canonical.field_u64(2, distribution.total_amount.get())?;
    canonical.field_u32(3, distribution.shares.len() as u32)?;
    for (index, share) in distribution.shares.iter().enumerate() {
        let field_id = u16::try_from(index + 4)
            .map_err(|_| FeeError::TooManySigners(distribution.shares.len()))?;
        canonical.field_bytes(field_id, encode_validator_fee_share(share)?)?;
    }
    Ok(canonical.finish()?)
}

/// Calculates the canonical fee in internal fee units.
pub fn calculate_fee(usage: &FeeUsage, schedule: &GasSchedule) -> Result<Amount, FeeError> {
    let execution = usage
        .execution_units
        .checked_mul(schedule.execution_price)
        .ok_or(FeeError::ArithmeticOverflow)?;
    let reads = usage
        .state_read_units
        .checked_mul(schedule.read_price)
        .ok_or(FeeError::ArithmeticOverflow)?;
    let writes = usage
        .state_write_units
        .checked_mul(schedule.write_price)
        .ok_or(FeeError::ArithmeticOverflow)?;
    let storage = usage
        .storage_units
        .checked_mul(schedule.storage_price)
        .ok_or(FeeError::ArithmeticOverflow)?;
    let system = usage
        .system_module_units
        .checked_mul(schedule.system_module_price)
        .ok_or(FeeError::ArithmeticOverflow)?;

    let total = schedule
        .base_fee
        .checked_add(execution)
        .and_then(|value| value.checked_add(reads))
        .and_then(|value| value.checked_add(writes))
        .and_then(|value| value.checked_add(storage))
        .and_then(|value| value.checked_add(system))
        .ok_or(FeeError::ArithmeticOverflow)?;
    Ok(Amount::new(total))
}

/// Converts internal fee units into one enabled fee asset amount.
pub fn quote_fee_in_asset(
    registry: &FeeAssetRegistry,
    asset_id: AssetId,
    fee_units: Amount,
) -> Result<Amount, FeeError> {
    let asset = registry
        .get(asset_id)
        .ok_or(FeeError::UnknownAsset(asset_id))?;
    if !asset.enabled {
        return Err(FeeError::AssetDisabled(asset_id));
    }
    asset.validate()?;

    let required = ceil_div(fee_units.get(), asset.fee_units_per_asset_unit)?;
    Ok(Amount::new(required))
}

/// Validates one sender-authorized fee payment against the registry and required fee.
pub fn settle_fee_payment(
    registry: &FeeAssetRegistry,
    payment: &FeePayment,
    fee_units: Amount,
) -> Result<Amount, FeeError> {
    let required = quote_fee_in_asset(registry, payment.asset_id, fee_units)?;
    if required > payment.max_fee {
        return Err(FeeError::MaxFeeExceeded {
            required,
            max_fee: payment.max_fee,
        });
    }
    Ok(required)
}

/// Distributes a settled fee deterministically across certificate signers.
pub fn distribute_fee(
    asset_id: AssetId,
    total_amount: Amount,
    signers: &[ValidatorId],
) -> Result<FeeDistribution, FeeError> {
    if signers.is_empty() {
        return Err(FeeError::EmptySignerSet);
    }
    if signers.len() > MAX_SIGNERS {
        return Err(FeeError::TooManySigners(signers.len()));
    }

    let mut ordered = signers.to_vec();
    ordered.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for pair in ordered.windows(2) {
        if pair[0] == pair[1] {
            return Err(FeeError::DuplicateSigner(pair[0]));
        }
    }

    let divisor = ordered.len() as u64;
    let base_share = total_amount.get() / divisor;
    let remainder = total_amount.get() % divisor;

    let shares = ordered
        .into_iter()
        .enumerate()
        .map(|(index, validator_id)| ValidatorFeeShare {
            validator_id,
            amount: Amount::new(base_share + u64::from(index < remainder as usize)),
        })
        .collect();

    Ok(FeeDistribution {
        asset_id,
        total_amount,
        shares,
    })
}

fn ceil_div(numerator: u64, denominator: u64) -> Result<u64, FeeError> {
    let adjusted = numerator
        .checked_add(denominator - 1)
        .ok_or(FeeError::ArithmeticOverflow)?;
    Ok(adjusted / denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects::{ObjectId, ObjectRef};
    use protocol_types::{Digest32, HashAlgorithmId};

    fn sample_asset_id(byte: u8) -> AssetId {
        AssetId::new([byte; 32])
    }

    fn sample_object_ref(byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([byte; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
        }
    }

    fn sample_validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    #[test]
    fn asset_id_display_is_hex() {
        let asset_id = sample_asset_id(0xAB);
        assert_eq!(asset_id.to_string(), "ab".repeat(32));
    }

    #[test]
    fn fee_payment_encodes_deterministically() {
        let payment = FeePayment {
            asset_id: sample_asset_id(0x11),
            max_fee: Amount::new(25),
            fee_object: sample_object_ref(0x22),
        };

        let left = encode_fee_payment(&payment).unwrap();
        let right = encode_fee_payment(&payment).unwrap();

        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn registry_sorts_assets_canonically() {
        let mut registry = FeeAssetRegistry::new();
        registry
            .add_asset(FeeAsset {
                asset_id: sample_asset_id(0xBB),
                fee_units_per_asset_unit: 5,
                enabled: true,
            })
            .unwrap();
        registry
            .add_asset(FeeAsset {
                asset_id: sample_asset_id(0x11),
                fee_units_per_asset_unit: 1,
                enabled: true,
            })
            .unwrap();

        assert_eq!(registry.assets()[0].asset_id, sample_asset_id(0x11));
        assert_eq!(registry.assets()[1].asset_id, sample_asset_id(0xBB));
    }

    #[test]
    fn duplicate_assets_are_rejected() {
        let asset = FeeAsset {
            asset_id: sample_asset_id(0x33),
            fee_units_per_asset_unit: 1,
            enabled: true,
        };
        let mut registry = FeeAssetRegistry::new();
        registry.add_asset(asset.clone()).unwrap();

        assert_eq!(
            registry.add_asset(asset),
            Err(FeeError::DuplicateAsset(sample_asset_id(0x33)))
        );
    }

    #[test]
    fn disabled_assets_cannot_be_used_for_quotes() {
        let mut registry = FeeAssetRegistry::new();
        registry
            .add_asset(FeeAsset {
                asset_id: sample_asset_id(0x44),
                fee_units_per_asset_unit: 10,
                enabled: true,
            })
            .unwrap();
        registry.disable_asset(sample_asset_id(0x44)).unwrap();

        assert_eq!(
            quote_fee_in_asset(&registry, sample_asset_id(0x44), Amount::new(10)),
            Err(FeeError::AssetDisabled(sample_asset_id(0x44)))
        );
    }

    #[test]
    fn fee_calculation_uses_integer_schedule() {
        let usage = FeeUsage {
            execution_units: 4,
            state_read_units: 3,
            state_write_units: 2,
            storage_units: 5,
            system_module_units: 1,
        };
        let schedule = GasSchedule {
            base_fee: 10,
            execution_price: 2,
            read_price: 3,
            write_price: 5,
            storage_price: 7,
            system_module_price: 11,
        };

        assert_eq!(calculate_fee(&usage, &schedule).unwrap(), Amount::new(83));
    }

    #[test]
    fn fee_payment_rounds_up_by_conversion_rate() {
        let mut registry = FeeAssetRegistry::new();
        registry
            .add_asset(FeeAsset {
                asset_id: sample_asset_id(0x55),
                fee_units_per_asset_unit: 3,
                enabled: true,
            })
            .unwrap();

        assert_eq!(
            quote_fee_in_asset(&registry, sample_asset_id(0x55), Amount::new(10)).unwrap(),
            Amount::new(4)
        );
    }

    #[test]
    fn fee_payment_rejects_when_max_fee_is_too_low() {
        let mut registry = FeeAssetRegistry::new();
        registry
            .add_asset(FeeAsset {
                asset_id: sample_asset_id(0x66),
                fee_units_per_asset_unit: 2,
                enabled: true,
            })
            .unwrap();

        let payment = FeePayment {
            asset_id: sample_asset_id(0x66),
            max_fee: Amount::new(4),
            fee_object: sample_object_ref(0x99),
        };

        assert_eq!(
            settle_fee_payment(&registry, &payment, Amount::new(9)),
            Err(FeeError::MaxFeeExceeded {
                required: Amount::new(5),
                max_fee: Amount::new(4),
            })
        );
    }

    #[test]
    fn validator_fee_distribution_is_sorted_and_remainder_is_canonical() {
        let distribution = distribute_fee(
            sample_asset_id(0x77),
            Amount::new(10),
            &[
                sample_validator_id(0xCC),
                sample_validator_id(0xAA),
                sample_validator_id(0xBB),
            ],
        )
        .unwrap();

        assert_eq!(distribution.shares.len(), 3);
        assert_eq!(
            distribution.shares[0].validator_id,
            sample_validator_id(0xAA)
        );
        assert_eq!(
            distribution.shares[1].validator_id,
            sample_validator_id(0xBB)
        );
        assert_eq!(
            distribution.shares[2].validator_id,
            sample_validator_id(0xCC)
        );
        assert_eq!(distribution.shares[0].amount, Amount::new(4));
        assert_eq!(distribution.shares[1].amount, Amount::new(3));
        assert_eq!(distribution.shares[2].amount, Amount::new(3));
    }

    #[test]
    fn duplicate_signers_are_rejected() {
        assert_eq!(
            distribute_fee(
                sample_asset_id(0x88),
                Amount::new(1),
                &[sample_validator_id(0x11), sample_validator_id(0x11)],
            ),
            Err(FeeError::DuplicateSigner(sample_validator_id(0x11)))
        );
    }
}
