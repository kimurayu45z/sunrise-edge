#![forbid(unsafe_code)]

//! Domain-separated hashing primitives and hash-suite resolution.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion,
};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use std::{error::Error, fmt};

const HASH_DOMAIN_VERSION: u16 = 1;
const HASH_FRAME_ENCODING_VERSION: u16 = 1;
const HASH_FRAME_TYPE_ID: u16 = 0x1001;

/// Hashing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashingError {
    /// The requested hash algorithm is not currently implemented.
    UnsupportedAlgorithm(HashAlgorithmId),
    /// Canonical framing failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// The hash-suite schedule was empty.
    EmptySchedule,
    /// The schedule must start at epoch 0.
    MissingGenesisSuite,
    /// The schedule contains a non-monotonic epoch entry.
    NonMonotonicSchedule,
    /// No suite is active for the requested epoch.
    NoActiveHashSuite(Epoch),
}

impl fmt::Display for HashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported hash algorithm: {algorithm}")
            }
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::EmptySchedule => write!(f, "hash-suite schedule must not be empty"),
            Self::MissingGenesisSuite => write!(f, "hash-suite schedule must start at epoch 0"),
            Self::NonMonotonicSchedule => {
                write!(f, "hash-suite schedule epochs must be strictly increasing")
            }
            Self::NoActiveHashSuite(epoch) => {
                write!(f, "no active hash suite for epoch {}", epoch.get())
            }
        }
    }
}

impl Error for HashingError {}

impl From<CanonicalEncodingError> for HashingError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// A hash function implementation.
pub trait HashFunction {
    /// Returns the algorithm identifier.
    fn algorithm_id(&self) -> HashAlgorithmId;

    /// Hashes a canonical payload inside the protocol domain-separation frame.
    fn hash(
        &self,
        purpose: HashPurpose,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError>;
}

/// Built-in protocol hash implementations.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinHashFunction {
    algorithm: HashAlgorithmId,
}

impl BuiltinHashFunction {
    /// Creates a built-in hash implementation.
    #[must_use]
    pub const fn new(algorithm: HashAlgorithmId) -> Self {
        Self { algorithm }
    }
}

impl HashFunction for BuiltinHashFunction {
    fn algorithm_id(&self) -> HashAlgorithmId {
        self.algorithm
    }

    fn hash(
        &self,
        purpose: HashPurpose,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError> {
        if matches!(self.algorithm, HashAlgorithmId::Blake3_256) {
            return Err(HashingError::UnsupportedAlgorithm(self.algorithm));
        }

        let frame = frame_hash_input(
            self.algorithm,
            purpose,
            protocol_version,
            chain_id,
            canonical_payload,
        )?;
        let bytes = hash_unframed_bytes(self.algorithm, &frame)?;
        Ok(Digest32::new(self.algorithm, bytes))
    }
}

/// Frames a hash input according to the canonical domain-separation rules.
pub fn frame_hash_input(
    algorithm: HashAlgorithmId,
    purpose: HashPurpose,
    protocol_version: ProtocolVersion,
    chain_id: &ChainId,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, HashingError> {
    let mut frame = CanonicalStruct::new(HASH_FRAME_TYPE_ID, HASH_FRAME_ENCODING_VERSION);
    frame.field_u16(1, algorithm.as_u16())?;
    frame.field_u16(2, purpose.domain().as_u16())?;
    frame.field_u16(3, HASH_DOMAIN_VERSION)?;
    frame.field_str(4, chain_id.as_str())?;
    frame.field_u32(5, protocol_version.get())?;
    frame.field_bytes(6, canonical_payload)?;
    Ok(frame.finish()?)
}

/// Verifies a digest using the algorithm recorded in the digest itself.
pub fn verify_digest(
    digest: &Digest32,
    purpose: HashPurpose,
    protocol_version: ProtocolVersion,
    chain_id: &ChainId,
    canonical_payload: &[u8],
) -> Result<bool, HashingError> {
    let computed = BuiltinHashFunction::new(digest.algorithm()).hash(
        purpose,
        protocol_version,
        chain_id,
        canonical_payload,
    )?;
    Ok(computed == *digest)
}

/// Resolves the active hash suite for a `(chain_id, protocol_version, epoch)` tuple.
#[derive(Debug, Clone)]
pub struct HashSuiteResolver {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    schedules: Vec<HashSuiteSchedule>,
}

impl HashSuiteResolver {
    /// Creates a validated hash-suite resolver.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        schedules: Vec<HashSuiteSchedule>,
    ) -> Result<Self, HashingError> {
        if schedules.is_empty() {
            return Err(HashingError::EmptySchedule);
        }
        if schedules.first().map(|entry| entry.activation_epoch.get()) != Some(0) {
            return Err(HashingError::MissingGenesisSuite);
        }
        if schedules
            .windows(2)
            .any(|pair| pair[0].activation_epoch >= pair[1].activation_epoch)
        {
            return Err(HashingError::NonMonotonicSchedule);
        }

        Ok(Self {
            chain_id,
            protocol_version,
            schedules,
        })
    }

    /// Returns the active suite for an epoch.
    pub fn suite_for_epoch(&self, epoch: Epoch) -> Result<&HashSuite, HashingError> {
        self.schedules
            .iter()
            .rev()
            .find(|entry| entry.activation_epoch <= epoch)
            .map(|entry| &entry.suite)
            .ok_or(HashingError::NoActiveHashSuite(epoch))
    }

    /// Returns the chain context bound to this resolver.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the protocol version bound to this resolver.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Hashes a canonical payload for the given purpose and epoch.
    pub fn hash_for_purpose(
        &self,
        epoch: Epoch,
        purpose: HashPurpose,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError> {
        let suite = self.suite_for_epoch(epoch)?;
        let algorithm = suite.algorithm_for(purpose);
        BuiltinHashFunction::new(algorithm).hash(
            purpose,
            self.protocol_version,
            &self.chain_id,
            canonical_payload,
        )
    }
}

fn hash_unframed_bytes(algorithm: HashAlgorithmId, input: &[u8]) -> Result<[u8; 32], HashingError> {
    match algorithm {
        HashAlgorithmId::Sha2_256 => Ok(Sha256::digest(input).into()),
        HashAlgorithmId::Sha3_256 => Ok(Sha3_256::digest(input).into()),
        HashAlgorithmId::Blake3_256 => Err(HashingError::UnsupportedAlgorithm(algorithm)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashSuiteId, TypeError};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sample_resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(500),
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn sha256_vector_matches_reference() {
        assert_eq!(
            hex(&hash_unframed_bytes(HashAlgorithmId::Sha2_256, b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha3_vector_matches_reference() {
        assert_eq!(
            hex(&hash_unframed_bytes(HashAlgorithmId::Sha3_256, b"abc").unwrap()),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn cross_domain_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let version = ProtocolVersion::new(7);

        let transaction = hasher
            .hash(HashPurpose::Transaction, version, &chain_id, b"payload")
            .unwrap();
        let object = hasher
            .hash(HashPurpose::Object, version, &chain_id, b"payload")
            .unwrap();

        assert_ne!(transaction, object);
    }

    #[test]
    fn cross_chain_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let version = ProtocolVersion::new(7);

        let left = hasher
            .hash(
                HashPurpose::Transaction,
                version,
                &ChainId::new("chain-a").unwrap(),
                b"payload",
            )
            .unwrap();
        let right = hasher
            .hash(
                HashPurpose::Transaction,
                version,
                &ChainId::new("chain-b").unwrap(),
                b"payload",
            )
            .unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn cross_protocol_version_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let chain_id = ChainId::new("sunrise-devnet").unwrap();

        let left = hasher
            .hash(
                HashPurpose::Transaction,
                ProtocolVersion::new(1),
                &chain_id,
                b"payload",
            )
            .unwrap();
        let right = hasher
            .hash(
                HashPurpose::Transaction,
                ProtocolVersion::new(2),
                &chain_id,
                b"payload",
            )
            .unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn old_digest_verifies_after_suite_transition() {
        let resolver = sample_resolver();
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(42), HashPurpose::Object, b"object-v1")
            .unwrap();

        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
        assert!(
            verify_digest(
                &digest,
                HashPurpose::Object,
                ProtocolVersion::new(1),
                &chain_id,
                b"object-v1"
            )
            .unwrap()
        );
    }

    #[test]
    fn hash_suite_epoch_transition_activates_new_algorithm() {
        let resolver = sample_resolver();

        let before = resolver.suite_for_epoch(Epoch::new(499)).unwrap();
        let after = resolver.suite_for_epoch(Epoch::new(500)).unwrap();

        assert_eq!(
            before.algorithm_for(HashPurpose::Transaction),
            HashAlgorithmId::Sha2_256
        );
        assert_eq!(
            after.algorithm_for(HashPurpose::Transaction),
            HashAlgorithmId::Sha3_256
        );
    }

    #[test]
    fn unsupported_algorithms_fail_without_fallback() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Blake3_256);
        let result = hasher.hash(
            HashPurpose::Transaction,
            ProtocolVersion::new(1),
            &ChainId::new("sunrise-devnet").unwrap(),
            b"payload",
        );

        assert_eq!(
            result,
            Err(HashingError::UnsupportedAlgorithm(
                HashAlgorithmId::Blake3_256
            ))
        );
    }

    #[test]
    fn invalid_schedule_is_rejected() {
        let err = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap_err();

        assert_eq!(err, HashingError::MissingGenesisSuite);
    }

    #[test]
    fn unknown_algorithm_ids_are_rejected_upstream() {
        assert_eq!(
            HashAlgorithmId::try_from(99),
            Err(TypeError::UnknownHashAlgorithmId(99))
        );
    }
}
