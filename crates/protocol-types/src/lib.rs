#![forbid(unsafe_code)]

//! Core protocol identifiers and self-describing cryptographic types.

use core::fmt;
use std::error::Error;

/// Validation errors for protocol identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// The chain identifier was empty or whitespace-only.
    EmptyChainId,
    /// The hash algorithm identifier is unknown.
    UnknownHashAlgorithmId(u16),
    /// The hash domain identifier is unknown.
    UnknownHashDomain(u16),
    /// The signature scheme identifier is unknown.
    UnknownSignatureSchemeId(u16),
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChainId => write!(f, "chain identifiers must not be empty"),
            Self::UnknownHashAlgorithmId(id) => write!(f, "unknown hash algorithm id: {id:#06x}"),
            Self::UnknownHashDomain(id) => write!(f, "unknown hash domain id: {id:#06x}"),
            Self::UnknownSignatureSchemeId(id) => {
                write!(f, "unknown signature scheme id: {id:#06x}")
            }
        }
    }
}

impl Error for TypeError {}

/// A stable chain identifier used for replay protection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(String);

impl ChainId {
    /// Creates a validated chain identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TypeError::EmptyChainId);
        }

        Ok(Self(value))
    }

    /// Returns the string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An explicit protocol version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Creates a protocol version.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the inner value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An explicit epoch number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// Creates an epoch value.
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

/// Stable validator identity, independent of membership, voting power, and bond state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValidatorId([u8; 32]);

impl ValidatorId {
    /// Creates a validator identifier from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An identifier for a hash suite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashSuiteId(u16);

impl HashSuiteId {
    /// Creates a hash-suite identifier.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the inner value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Consensus-supported hash algorithm identifiers.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithmId {
    /// SHA-256.
    Sha2_256 = 0x0001,
    /// SHA3-256.
    Sha3_256 = 0x0002,
    /// BLAKE3-256.
    Blake3_256 = 0x0003,
}

impl HashAlgorithmId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns a stable display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha2_256 => "sha2-256",
            Self::Sha3_256 => "sha3-256",
            Self::Blake3_256 => "blake3-256",
        }
    }
}

impl TryFrom<u16> for HashAlgorithmId {
    type Error = TypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Sha2_256),
            0x0002 => Ok(Self::Sha3_256),
            0x0003 => Ok(Self::Blake3_256),
            other => Err(TypeError::UnknownHashAlgorithmId(other)),
        }
    }
}

impl fmt::Display for HashAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Domain identifiers for protocol hash separation.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashDomain {
    /// Transaction payloads.
    Transaction = 0x0001,
    /// Object payloads.
    Object = 0x0002,
    /// Execution effects.
    ExecutionEffects = 0x0003,
    /// Contract code.
    ContractCode = 0x0004,
    /// Protocol configuration.
    ProtocolConfig = 0x0005,
    /// Certificates.
    Certificate = 0x0006,
    /// Validator-set snapshots.
    ValidatorSet = 0x0007,
    /// Governance actions.
    GovernanceAction = 0x0008,
    /// System modules.
    SystemModule = 0x0009,
    /// Migration payloads.
    Migration = 0x000A,
    /// Persistent state nodes.
    StateNode = 0x000B,
    /// Shared-object consensus messages.
    ConsensusMessage = 0x000C,
}

impl HashDomain {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for HashDomain {
    type Error = TypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Transaction),
            0x0002 => Ok(Self::Object),
            0x0003 => Ok(Self::ExecutionEffects),
            0x0004 => Ok(Self::ContractCode),
            0x0005 => Ok(Self::ProtocolConfig),
            0x0006 => Ok(Self::Certificate),
            0x0007 => Ok(Self::ValidatorSet),
            0x0008 => Ok(Self::GovernanceAction),
            0x0009 => Ok(Self::SystemModule),
            0x000A => Ok(Self::Migration),
            0x000B => Ok(Self::StateNode),
            0x000C => Ok(Self::ConsensusMessage),
            other => Err(TypeError::UnknownHashDomain(other)),
        }
    }
}

/// A self-describing 32-byte digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest32 {
    algorithm: HashAlgorithmId,
    bytes: [u8; 32],
}

impl Digest32 {
    /// Creates a digest value.
    #[must_use]
    pub const fn new(algorithm: HashAlgorithmId, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the algorithm identifier.
    #[must_use]
    pub const fn algorithm(self) -> HashAlgorithmId {
        self.algorithm
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.algorithm)?;
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A logical use-site for a hash within the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashPurpose {
    /// Transaction hashing.
    Transaction,
    /// Object digest hashing.
    Object,
    /// Execution effects hashing.
    ExecutionEffects,
    /// Contract code hashing.
    ContractCode,
    /// Protocol configuration hashing.
    ProtocolConfig,
    /// Certificate hashing.
    Certificate,
    /// Validator-set snapshot hashing.
    ValidatorSet,
    /// Shared-object consensus proposal hashing.
    ConsensusMessage,
}

impl HashPurpose {
    /// Returns the canonical hash domain for the purpose.
    #[must_use]
    pub const fn domain(self) -> HashDomain {
        match self {
            Self::Transaction => HashDomain::Transaction,
            Self::Object => HashDomain::Object,
            Self::ExecutionEffects => HashDomain::ExecutionEffects,
            Self::ContractCode => HashDomain::ContractCode,
            Self::ProtocolConfig => HashDomain::ProtocolConfig,
            Self::Certificate => HashDomain::Certificate,
            Self::ValidatorSet => HashDomain::ValidatorSet,
            Self::ConsensusMessage => HashDomain::ConsensusMessage,
        }
    }
}

/// The active hash algorithms for each protocol purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSuite {
    /// The suite identifier.
    pub id: HashSuiteId,
    /// Transaction hash algorithm.
    pub transaction_hash: HashAlgorithmId,
    /// Object digest algorithm.
    pub object_digest: HashAlgorithmId,
    /// Execution effects hash algorithm.
    pub effects_hash: HashAlgorithmId,
    /// Contract code hash algorithm.
    pub code_hash: HashAlgorithmId,
    /// Protocol configuration hash algorithm.
    pub config_hash: HashAlgorithmId,
    /// Certificate hash algorithm.
    pub certificate_hash: HashAlgorithmId,
}

impl HashSuite {
    /// Creates a suite that uses the same algorithm for every purpose.
    #[must_use]
    pub const fn uniform(id: HashSuiteId, algorithm: HashAlgorithmId) -> Self {
        Self {
            id,
            transaction_hash: algorithm,
            object_digest: algorithm,
            effects_hash: algorithm,
            code_hash: algorithm,
            config_hash: algorithm,
            certificate_hash: algorithm,
        }
    }

    /// Returns the conservative genesis suite.
    #[must_use]
    pub const fn genesis() -> Self {
        Self::uniform(HashSuiteId::new(1), HashAlgorithmId::Sha2_256)
    }

    /// Returns the algorithm for a specific purpose.
    #[must_use]
    pub const fn algorithm_for(&self, purpose: HashPurpose) -> HashAlgorithmId {
        match purpose {
            HashPurpose::Transaction => self.transaction_hash,
            HashPurpose::Object => self.object_digest,
            HashPurpose::ExecutionEffects => self.effects_hash,
            HashPurpose::ContractCode => self.code_hash,
            HashPurpose::ProtocolConfig => self.config_hash,
            HashPurpose::Certificate => self.certificate_hash,
            HashPurpose::ValidatorSet => self.certificate_hash,
            HashPurpose::ConsensusMessage => self.certificate_hash,
        }
    }
}

/// An epoch-activated hash-suite schedule entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSuiteSchedule {
    /// The first epoch where the suite is active.
    pub activation_epoch: Epoch,
    /// The suite activated at that epoch.
    pub suite: HashSuite,
}

/// Signature scheme identifiers used for signature-domain framing.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureSchemeId {
    /// Ed25519.
    Ed25519 = 0x0001,
    /// Secp256k1.
    Secp256k1 = 0x0002,
}

impl SignatureSchemeId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for SignatureSchemeId {
    type Error = TypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Ed25519),
            0x0002 => Ok(Self::Secp256k1),
            other => Err(TypeError::UnknownSignatureSchemeId(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_hash_algorithm() {
        assert_eq!(
            HashAlgorithmId::try_from(0x9999),
            Err(TypeError::UnknownHashAlgorithmId(0x9999))
        );
    }

    #[test]
    fn digest_display_is_self_describing() {
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]);
        let text = digest.to_string();

        assert!(text.starts_with("sha2-256:"));
        assert!(text.ends_with(&"ab".repeat(32)));
    }
}
