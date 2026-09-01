//! S1's mandatory, locally trusted expected-protocol-context verification
//! boundary (`ARCHITECTURE.md` DR-0085; `TODO.md` CLI-First Node Production
//! Gate S1a).
//!
//! A successful transport connection — including a future TLS connection
//! with a valid, hostname-verified certificate — proves only that the
//! client reached *some* server holding a trusted key for that hostname. It
//! does not prove that server actually serves the client's intended
//! chain/protocol: TLS authenticates the transport endpoint, not the
//! protocol context, so it cannot by itself prevent cross-chain signing.
//! [`ExpectedProtocolContext`] is the separate, mandatory check this
//! decision requires before any nonce/object query or signing: a caller
//! supplies every field it locally trusts, and
//! [`ExpectedProtocolContext::verify`] compares each one against an
//! untrusted `/v1/context` response, independently of transport trust,
//! before that response is used for anything else.
//!
//! This slice deliberately does not pin or decode
//! [`node_wire::HttpContextQueryResult::protocol_config_bytes`]: that
//! remains explicit future work, not silently approximated here. Remote TLS
//! transport is also a separate, not-yet-implemented S1 concern (see
//! `README.md` current status); this module only implements the
//! expected-context verification half of S1.

use core::fmt;
use std::error::Error;

use node_wire::HttpContextQueryResult;
use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashSuiteId, ProtocolVersion};

/// A caller's complete, locally trusted expectation for the remote
/// `/v1/context` result.
///
/// Every field here is one this workspace's implemented signer/verifier
/// depends on: the chain/protocol/epoch replay boundary, the active hash
/// suite, the committed transaction-authentication profile, the signature
/// scheme, the address binding, and the logical routing/placement domain.
///
/// This slice uses an **exact**-epoch policy: `epoch` is the one epoch a
/// caller currently trusts, not a floor or a range. A caller must update it
/// deliberately at every epoch rollover — this type never derives, advances,
/// or widens it automatically — so a stale expectation correctly fails
/// closed as soon as the remote epoch advances, rather than silently
/// accepting a newer epoch.
///
/// `domain` here is a routing/placement expectation only — which logical
/// atomicity domain the caller intends to reach — never an additional
/// signature-domain binding. It is never combined into
/// `crypto::SignatureDomain`; domain separation for signing stays exactly as
/// documented in `ARCHITECTURE.md` §8/§11 (chain id, protocol version,
/// epoch, message type, signature scheme).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedProtocolContext {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    hash_suite_id: HashSuiteId,
    transaction_auth_profile_id: u16,
    signature_scheme_id: u16,
    address_binding_id: u16,
    domain: AtomicityDomainId,
}

impl ExpectedProtocolContext {
    /// Creates a validated expected protocol context.
    ///
    /// Rejects a zero `protocol_version`, `hash_suite_id`,
    /// `transaction_auth_profile_id`, `signature_scheme_id`, or
    /// `address_binding_id`. `chain_id` and `domain` are already validated
    /// non-empty/non-zero by their own types
    /// ([`ChainId::new`]/[`AtomicityDomainId::new`]) before reaching this
    /// constructor. `epoch` is intentionally never rejected for being zero:
    /// epoch zero is the legitimate genesis epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        hash_suite_id: HashSuiteId,
        transaction_auth_profile_id: u16,
        signature_scheme_id: u16,
        address_binding_id: u16,
        domain: AtomicityDomainId,
    ) -> Result<Self, ExpectedProtocolContextError> {
        if protocol_version.get() == 0 {
            return Err(ExpectedProtocolContextError::ZeroProtocolVersion);
        }
        if hash_suite_id.get() == 0 {
            return Err(ExpectedProtocolContextError::ZeroHashSuiteId);
        }
        if transaction_auth_profile_id == 0 {
            return Err(ExpectedProtocolContextError::ZeroTransactionAuthProfileId);
        }
        if signature_scheme_id == 0 {
            return Err(ExpectedProtocolContextError::ZeroSignatureSchemeId);
        }
        if address_binding_id == 0 {
            return Err(ExpectedProtocolContextError::ZeroAddressBindingId);
        }
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            hash_suite_id,
            transaction_auth_profile_id,
            signature_scheme_id,
            address_binding_id,
            domain,
        })
    }

    /// Returns the expected chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the expected protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact expected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the expected hash-suite identifier.
    #[must_use]
    pub const fn hash_suite_id(&self) -> HashSuiteId {
        self.hash_suite_id
    }

    /// Returns the expected transaction-authentication profile identifier.
    #[must_use]
    pub const fn transaction_auth_profile_id(&self) -> u16 {
        self.transaction_auth_profile_id
    }

    /// Returns the expected signature-scheme identifier.
    #[must_use]
    pub const fn signature_scheme_id(&self) -> u16 {
        self.signature_scheme_id
    }

    /// Returns the expected address-binding identifier.
    #[must_use]
    pub const fn address_binding_id(&self) -> u16 {
        self.address_binding_id
    }

    /// Returns the expected logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Compares every field above against `remote`, an untrusted
    /// `/v1/context` result, and returns the first mismatch found, in a
    /// fixed, deterministic field order (chain id, protocol version, epoch,
    /// hash suite, transaction-auth profile, signature scheme, address
    /// binding, domain). `remote.protocol_config_bytes()` is never
    /// compared: pinning or decoding the full canonical `ProtocolConfig`
    /// remains out of scope for this slice.
    pub fn verify(&self, remote: &HttpContextQueryResult) -> Result<(), ProtocolContextMismatch> {
        if &self.chain_id != remote.chain_id() {
            return Err(ProtocolContextMismatch::ChainId {
                expected: self.chain_id.clone(),
                actual: remote.chain_id().clone(),
            });
        }
        if self.protocol_version != remote.protocol_version() {
            return Err(ProtocolContextMismatch::ProtocolVersion {
                expected: self.protocol_version,
                actual: remote.protocol_version(),
            });
        }
        if self.epoch != remote.epoch() {
            return Err(ProtocolContextMismatch::Epoch {
                expected: self.epoch,
                actual: remote.epoch(),
            });
        }
        if self.hash_suite_id != remote.hash_suite_id() {
            return Err(ProtocolContextMismatch::HashSuiteId {
                expected: self.hash_suite_id,
                actual: remote.hash_suite_id(),
            });
        }
        if self.transaction_auth_profile_id != remote.transaction_auth_profile_id() {
            return Err(ProtocolContextMismatch::TransactionAuthProfileId {
                expected: self.transaction_auth_profile_id,
                actual: remote.transaction_auth_profile_id(),
            });
        }
        if self.signature_scheme_id != remote.signature_scheme_id() {
            return Err(ProtocolContextMismatch::SignatureSchemeId {
                expected: self.signature_scheme_id,
                actual: remote.signature_scheme_id(),
            });
        }
        if self.address_binding_id != remote.address_binding_id() {
            return Err(ProtocolContextMismatch::AddressBindingId {
                expected: self.address_binding_id,
                actual: remote.address_binding_id(),
            });
        }
        if self.domain != remote.domain() {
            return Err(ProtocolContextMismatch::Domain {
                expected: self.domain,
                actual: remote.domain(),
            });
        }
        Ok(())
    }
}

/// Construction-time validation failures for [`ExpectedProtocolContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedProtocolContextError {
    /// `protocol_version` was zero.
    ZeroProtocolVersion,
    /// `hash_suite_id` was zero.
    ZeroHashSuiteId,
    /// `transaction_auth_profile_id` was zero.
    ZeroTransactionAuthProfileId,
    /// `signature_scheme_id` was zero.
    ZeroSignatureSchemeId,
    /// `address_binding_id` was zero.
    ZeroAddressBindingId,
}

impl fmt::Display for ExpectedProtocolContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroProtocolVersion => f.write_str("expected protocol version must be non-zero"),
            Self::ZeroHashSuiteId => f.write_str("expected hash-suite id must be non-zero"),
            Self::ZeroTransactionAuthProfileId => {
                f.write_str("expected transaction-auth profile id must be non-zero")
            }
            Self::ZeroSignatureSchemeId => {
                f.write_str("expected signature-scheme id must be non-zero")
            }
            Self::ZeroAddressBindingId => {
                f.write_str("expected address-binding id must be non-zero")
            }
        }
    }
}

impl Error for ExpectedProtocolContextError {}

/// A field-specific mismatch between a locally trusted
/// [`ExpectedProtocolContext`] and an untrusted remote `/v1/context` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolContextMismatch {
    /// The remote chain id disagreed with the locally expected chain id.
    ChainId {
        /// Locally expected chain id.
        expected: ChainId,
        /// Chain id reported by the remote server.
        actual: ChainId,
    },
    /// The remote protocol version disagreed with the locally expected
    /// protocol version.
    ProtocolVersion {
        /// Locally expected protocol version.
        expected: ProtocolVersion,
        /// Protocol version reported by the remote server.
        actual: ProtocolVersion,
    },
    /// The remote epoch disagreed with the locally expected exact epoch.
    Epoch {
        /// Locally expected exact epoch.
        expected: Epoch,
        /// Epoch reported by the remote server.
        actual: Epoch,
    },
    /// The remote hash-suite id disagreed with the locally expected
    /// hash-suite id.
    HashSuiteId {
        /// Locally expected hash-suite id.
        expected: HashSuiteId,
        /// Hash-suite id reported by the remote server.
        actual: HashSuiteId,
    },
    /// The remote transaction-authentication profile id disagreed with the
    /// locally expected profile id.
    TransactionAuthProfileId {
        /// Locally expected transaction-auth profile id.
        expected: u16,
        /// Transaction-auth profile id reported by the remote server.
        actual: u16,
    },
    /// The remote signature-scheme id disagreed with the locally expected
    /// signature-scheme id.
    SignatureSchemeId {
        /// Locally expected signature-scheme id.
        expected: u16,
        /// Signature-scheme id reported by the remote server.
        actual: u16,
    },
    /// The remote address-binding id disagreed with the locally expected
    /// address-binding id.
    AddressBindingId {
        /// Locally expected address-binding id.
        expected: u16,
        /// Address-binding id reported by the remote server.
        actual: u16,
    },
    /// The remote logical atomicity domain disagreed with the locally
    /// expected domain.
    Domain {
        /// Locally expected logical atomicity domain.
        expected: AtomicityDomainId,
        /// Logical atomicity domain reported by the remote server.
        actual: AtomicityDomainId,
    },
}

impl fmt::Display for ProtocolContextMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainId { expected, actual } => write!(
                f,
                "remote /v1/context chain id {actual} disagrees with locally expected chain id {expected}"
            ),
            Self::ProtocolVersion { expected, actual } => write!(
                f,
                "remote /v1/context protocol version {} disagrees with locally expected protocol version {}",
                actual.get(),
                expected.get()
            ),
            Self::Epoch { expected, actual } => write!(
                f,
                "remote /v1/context epoch {} disagrees with locally expected exact epoch {}",
                actual.get(),
                expected.get()
            ),
            Self::HashSuiteId { expected, actual } => write!(
                f,
                "remote /v1/context hash-suite id {} disagrees with locally expected hash-suite id {}",
                actual.get(),
                expected.get()
            ),
            Self::TransactionAuthProfileId { expected, actual } => write!(
                f,
                "remote /v1/context transaction-auth profile id {actual} disagrees with locally expected profile id {expected}"
            ),
            Self::SignatureSchemeId { expected, actual } => write!(
                f,
                "remote /v1/context signature-scheme id {actual} disagrees with locally expected signature-scheme id {expected}"
            ),
            Self::AddressBindingId { expected, actual } => write!(
                f,
                "remote /v1/context address-binding id {actual} disagrees with locally expected address-binding id {expected}"
            ),
            Self::Domain { expected, actual } => write!(
                f,
                "remote /v1/context domain {actual} disagrees with locally expected domain {expected}"
            ),
        }
    }
}

impl Error for ProtocolContextMismatch {}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_ID: u16 = 1;
    const SCHEME_ID: u16 = 1;
    const BINDING_ID: u16 = 1;

    fn sample_domain() -> AtomicityDomainId {
        AtomicityDomainId::new([0x44; 32]).unwrap()
    }

    fn sample_expected() -> ExpectedProtocolContext {
        ExpectedProtocolContext::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
        )
        .unwrap()
    }

    fn matching_remote() -> HttpContextQueryResult {
        HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap()
    }

    #[test]
    fn verify_accepts_an_exact_match() {
        assert_eq!(sample_expected().verify(&matching_remote()), Ok(()));
    }

    #[test]
    fn new_rejects_zero_protocol_version() {
        let error = ExpectedProtocolContext::new(
            ChainId::new("chain").unwrap(),
            ProtocolVersion::new(0),
            Epoch::new(1),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
        )
        .unwrap_err();
        assert_eq!(error, ExpectedProtocolContextError::ZeroProtocolVersion);
    }

    #[test]
    fn new_rejects_zero_hash_suite_id() {
        let error = ExpectedProtocolContext::new(
            ChainId::new("chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
            HashSuiteId::new(0),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
        )
        .unwrap_err();
        assert_eq!(error, ExpectedProtocolContextError::ZeroHashSuiteId);
    }

    #[test]
    fn new_rejects_zero_transaction_auth_profile_id() {
        let error = ExpectedProtocolContext::new(
            ChainId::new("chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
            HashSuiteId::new(1),
            0,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ExpectedProtocolContextError::ZeroTransactionAuthProfileId
        );
    }

    #[test]
    fn new_rejects_zero_signature_scheme_id() {
        let error = ExpectedProtocolContext::new(
            ChainId::new("chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
            HashSuiteId::new(1),
            PROFILE_ID,
            0,
            BINDING_ID,
            sample_domain(),
        )
        .unwrap_err();
        assert_eq!(error, ExpectedProtocolContextError::ZeroSignatureSchemeId);
    }

    #[test]
    fn new_rejects_zero_address_binding_id() {
        let error = ExpectedProtocolContext::new(
            ChainId::new("chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            0,
            sample_domain(),
        )
        .unwrap_err();
        assert_eq!(error, ExpectedProtocolContextError::ZeroAddressBindingId);
    }

    #[test]
    fn new_accepts_a_zero_epoch() {
        // Epoch zero is the legitimate genesis epoch and must not be
        // rejected merely for being zero.
        assert!(
            ExpectedProtocolContext::new(
                ChainId::new("chain").unwrap(),
                ProtocolVersion::new(1),
                Epoch::new(0),
                HashSuiteId::new(1),
                PROFILE_ID,
                SCHEME_ID,
                BINDING_ID,
                sample_domain(),
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_reports_a_chain_id_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("some-other-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(error, ProtocolContextMismatch::ChainId { .. }));
    }

    #[test]
    fn verify_reports_a_protocol_version_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(
            error,
            ProtocolContextMismatch::ProtocolVersion { .. }
        ));
    }

    #[test]
    fn verify_reports_an_epoch_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(6),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(error, ProtocolContextMismatch::Epoch { .. }));
    }

    #[test]
    fn verify_reports_a_hash_suite_id_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(2),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(error, ProtocolContextMismatch::HashSuiteId { .. }));
    }

    #[test]
    fn verify_reports_a_transaction_auth_profile_id_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            2,
            SCHEME_ID,
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(
            error,
            ProtocolContextMismatch::TransactionAuthProfileId { .. }
        ));
    }

    #[test]
    fn verify_reports_a_signature_scheme_id_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            protocol_types::SignatureSchemeId::Secp256k1.as_u16(),
            BINDING_ID,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(
            error,
            ProtocolContextMismatch::SignatureSchemeId { .. }
        ));
    }

    #[test]
    fn verify_reports_an_address_binding_id_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            2,
            sample_domain(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(
            error,
            ProtocolContextMismatch::AddressBindingId { .. }
        ));
    }

    #[test]
    fn verify_reports_a_domain_mismatch() {
        let remote = HttpContextQueryResult::new(
            ChainId::new("expected-context-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            PROFILE_ID,
            SCHEME_ID,
            BINDING_ID,
            AtomicityDomainId::new([0x55; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        let error = sample_expected().verify(&remote).unwrap_err();
        assert!(matches!(error, ProtocolContextMismatch::Domain { .. }));
    }

    #[test]
    fn verify_ignores_protocol_config_bytes() {
        let expected = sample_expected();
        let remote_a = matching_remote();
        let mut remote_b = matching_remote();
        // `HttpContextQueryResult` fields are private; rebuild with a
        // different `protocol_config_bytes` payload to prove `verify` never
        // inspects it.
        remote_b = HttpContextQueryResult::new(
            remote_b.chain_id().clone(),
            remote_b.protocol_version(),
            remote_b.epoch(),
            remote_b.hash_suite_id(),
            remote_b.transaction_auth_profile_id(),
            remote_b.signature_scheme_id(),
            remote_b.address_binding_id(),
            remote_b.domain(),
            vec![0xBB, 0xCC, 0xDD],
        )
        .unwrap();

        assert_eq!(expected.verify(&remote_a), Ok(()));
        assert_eq!(expected.verify(&remote_b), Ok(()));
    }
}
