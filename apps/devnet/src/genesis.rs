//! Committed protocol configuration for the local-only developer network.

use hashing::{HashSuiteResolver, HashingError};
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, ProtocolConfigError, TransactionAuthProfile,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion};
use std::{error::Error, fmt};

/// Protocol version used by the local developer network.
pub const DEVNET_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(3);

/// The single logical atomicity domain used by the local developer network.
///
/// This value must remain aligned with the namespace opened by `boot`.
pub const DEVNET_DOMAIN_BYTES: [u8; 32] = [0x44; 32];

const DEVNET_DOMAIN_PLACEMENT_RULE_VERSION: u32 = 1;

/// One validated devnet protocol configuration and the resolver derived from
/// that exact configuration's committed hash-suite schedule.
#[derive(Clone, Debug)]
pub struct DevnetProtocolContext {
    chain_id: ChainId,
    epoch: Epoch,
    domain: AtomicityDomainId,
    protocol_config: ProtocolConfig,
    resolver: HashSuiteResolver,
}

impl DevnetProtocolContext {
    /// Returns the chain identifier bound into every devnet hash frame.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured devnet epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the devnet's sole logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the committed protocol configuration.
    #[must_use]
    pub const fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the resolver derived from `protocol_config`.
    #[must_use]
    pub const fn resolver(&self) -> &HashSuiteResolver {
        &self.resolver
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
    ) {
        (
            self.chain_id,
            self.epoch,
            self.domain,
            self.protocol_config,
            self.resolver,
        )
    }
}

/// Builds protocol version 3 configuration for one local developer network.
///
/// The configuration uses one fixed non-zero domain, the committed Ed25519
/// address-is-public-key authentication profile, and the genesis hash-suite
/// schedule. Its fee-asset registry intentionally remains empty: the devnet
/// has no privileged native coin and charges no transaction fee.
pub fn build_devnet_protocol_context(
    chain_id: ChainId,
    epoch: Epoch,
) -> Result<DevnetProtocolContext, DevnetGenesisError> {
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetGenesisError::InvalidStaticDomain)?;
    let domain_placement: DomainPlacementManifest = DomainPlacementManifest::single_domain(
        DEVNET_DOMAIN_PLACEMENT_RULE_VERSION,
        domain,
        Epoch::new(0),
    )
    .map_err(DevnetGenesisError::ProtocolConfig)?;

    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = DEVNET_PROTOCOL_VERSION;
    protocol_config.domain_placement = Some(domain_placement);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_address_is_public_key());
    protocol_config
        .validate()
        .map_err(DevnetGenesisError::ProtocolConfig)?;

    // The resolver is deliberately constructed only after validation, from
    // the same config's chain/version/schedule. Callers never supply an
    // independent schedule that could disagree with committed configuration.
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_config.protocol_version,
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetGenesisError::Hashing)?;
    resolver
        .suite_for_epoch(epoch)
        .map_err(DevnetGenesisError::Hashing)?;

    Ok(DevnetProtocolContext {
        chain_id,
        epoch,
        domain,
        protocol_config,
        resolver,
    })
}

/// Failures while constructing committed devnet protocol configuration.
#[derive(Debug)]
pub enum DevnetGenesisError {
    /// The compile-time domain constant unexpectedly violated its non-zero
    /// invariant.
    InvalidStaticDomain,
    /// Protocol configuration validation failed closed.
    ProtocolConfig(ProtocolConfigError),
    /// The committed hash-suite schedule could not build or resolve.
    Hashing(HashingError),
}

impl fmt::Display for DevnetGenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStaticDomain => {
                formatter.write_str("devnet's static atomicity domain is invalid")
            }
            Self::ProtocolConfig(error) => {
                write!(
                    formatter,
                    "devnet protocol configuration is invalid: {error}"
                )
            }
            Self::Hashing(error) => {
                write!(
                    formatter,
                    "devnet hash-suite configuration is invalid: {error}"
                )
            }
        }
    }
}

impl Error for DevnetGenesisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidStaticDomain => None,
            Self::ProtocolConfig(error) => Some(error),
            Self::Hashing(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_config::{AddressBinding, ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID};
    use protocol_types::{HashPurpose, SignatureSchemeId};

    fn test_chain() -> ChainId {
        ChainId::new("sunrise-devnet-test").unwrap()
    }

    #[test]
    fn config_and_resolver_share_chain_version_and_schedule() {
        let epoch: Epoch = Epoch::new(17);
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), epoch).unwrap();
        let config: &ProtocolConfig = context.protocol_config();

        assert_eq!(config.protocol_version, DEVNET_PROTOCOL_VERSION);
        assert_eq!(
            context.resolver().protocol_version(),
            config.protocol_version
        );
        assert_eq!(context.resolver().chain_id(), context.chain_id());
        assert_eq!(
            context.resolver().suite_for_epoch(epoch).unwrap(),
            config.hash_suite_schedule.active_at(epoch).unwrap()
        );
        assert_eq!(
            config
                .domain_placement
                .as_ref()
                .unwrap()
                .resolve_domain(epoch, 1),
            Ok(context.domain())
        );

        let first: protocol_types::Digest32 = context
            .resolver()
            .hash_for_purpose(epoch, HashPurpose::ProtocolConfig, b"alignment")
            .unwrap();
        let derived: HashSuiteResolver = HashSuiteResolver::new(
            context.chain_id().clone(),
            config.protocol_version,
            config.hash_suite_schedule.entries().to_vec(),
        )
        .unwrap();
        assert_eq!(
            derived
                .hash_for_purpose(epoch, HashPurpose::ProtocolConfig, b"alignment")
                .unwrap(),
            first
        );
    }

    #[test]
    fn devnet_has_ed25519_auth_and_no_fee_asset() {
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(0)).unwrap();
        let config: &ProtocolConfig = context.protocol_config();
        let profile = config.transaction_auth_profile.as_ref().unwrap();

        assert!(config.fee_assets.is_empty());
        assert_eq!(
            profile.profile_id(),
            ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID
        );
        assert_eq!(profile.signature_scheme_id(), SignatureSchemeId::Ed25519);
        assert_eq!(
            profile.address_binding(),
            AddressBinding::AddressIsPublicKey
        );
        assert_eq!(config.validate(), Ok(()));
    }
}
