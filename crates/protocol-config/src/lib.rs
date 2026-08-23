#![forbid(unsafe_code)]

//! Canonically encoded protocol configuration values.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use commitments::{CommitmentSchemeError, CommitmentSchemeId, encode_commitment_scheme_id};
use core::fmt;
use fees::{
    FeeAssetRegistry, FeeError, GasSchedule, encode_fee_asset_registry, encode_gas_schedule,
};
use protocol_types::{HashSuiteId, ProtocolVersion};
use std::error::Error;

const PROTOCOL_CONFIG_TYPE_ID: u16 = 0x5001;
const ENCODING_VERSION: u16 = 1;

/// Errors returned by protocol configuration helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolConfigError {
    /// Protocol versions must be explicitly non-zero.
    ZeroProtocolVersion,
    /// Hash-suite identifiers must be explicitly non-zero.
    ZeroHashSuiteId,
    /// Commitment scheme encoding failed.
    CommitmentScheme(CommitmentSchemeError),
    /// Fee configuration is invalid.
    Fee(FeeError),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for ProtocolConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroProtocolVersion => write!(f, "protocol version must be non-zero"),
            Self::ZeroHashSuiteId => write!(f, "hash-suite id must be non-zero"),
            Self::CommitmentScheme(error) => error.fmt(f),
            Self::Fee(error) => error.fmt(f),
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
}

impl ProtocolConfig {
    /// Returns the genesis protocol configuration.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            protocol_version: ProtocolVersion::new(1),
            hash_suite_id: HashSuiteId::new(1),
            commitment_scheme_id: CommitmentSchemeId::SparseMerkleSha256V1,
            gas_schedule: GasSchedule::genesis(),
            fee_assets: FeeAssetRegistry::new(),
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

    let mut canonical = CanonicalStruct::new(PROTOCOL_CONFIG_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, config.protocol_version.get())?;
    canonical.field_u16(2, config.hash_suite_id.get())?;
    canonical.field_bytes(3, encode_commitment_scheme_id(config.commitment_scheme_id)?)?;
    canonical.field_bytes(4, encode_gas_schedule(&config.gas_schedule)?)?;
    canonical.field_bytes(5, encode_fee_asset_registry(&config.fee_assets)?)?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fees::{AssetId, FeeAsset};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn genesis_config_encodes_stably() {
        let bytes = encode_protocol_config(&ProtocolConfig::genesis()).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "534e5245015001000500",
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
                "01000400000000000000"
            )
        );
    }

    #[test]
    fn protocol_version_is_included_in_encoding() {
        let mut config = ProtocolConfig::genesis();
        let v1 = encode_protocol_config(&config).unwrap();
        config.protocol_version = ProtocolVersion::new(2);
        let v2 = encode_protocol_config(&config).unwrap();

        assert_ne!(v1, v2);
        assert!(hex(&v1).contains("01000000"));
        assert!(hex(&v2).contains("02000000"));
    }

    #[test]
    fn zero_identifiers_are_rejected() {
        let err = encode_protocol_config(&ProtocolConfig {
            protocol_version: ProtocolVersion::new(0),
            hash_suite_id: HashSuiteId::new(0),
            commitment_scheme_id: CommitmentSchemeId::SparseMerkleSha256V1,
            gas_schedule: GasSchedule::genesis(),
            fee_assets: FeeAssetRegistry::new(),
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
        })
        .unwrap_err();

        assert_eq!(err, ProtocolConfigError::ZeroHashSuiteId);
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
}
