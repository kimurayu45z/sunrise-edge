#![forbid(unsafe_code)]

//! Commitment schemes and self-describing commitment values.
//!
//! General-purpose protocol hashes and state commitments deliberately use
//! separate identifiers and framing. This crate currently provides SHA-256
//! and an experimental Poseidon2/BN254 implementation for the same versioned
//! binary sparse-Merkle leaf and node construction.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use sha2::{Digest as _, Sha256};
use std::error::Error;

mod poseidon2_bn254;

const COMMITMENT_SCHEME_TYPE_ID: u16 = 0x3001;
const COMMITMENT_TYPE_ID: u16 = 0x3002;
const COMMITMENT_LEAF_TYPE_ID: u16 = 0x3003;
const COMMITMENT_NODE_TYPE_ID: u16 = 0x3004;
const ENCODING_VERSION: u16 = 1;
const COMMITMENT_BYTES: usize = 32;
const SPARSE_MERKLE_DEPTH: u16 = 256;
/// Maximum canonical value size accepted by [`CommitmentScheme::commit_leaf`].
pub const MAX_COMMITMENT_LEAF_BYTES: usize = 16 * 1024 * 1024;
/// Temporary leaf bound for the safe-Rust experimental Poseidon2 implementation.
pub const MAX_POSEIDON2_LEAF_BYTES: usize = 4 * 1024;
const SPARSE_MERKLE_TREE_CONSTRUCTION: &str = "binary-sparse-merkle-v1";
const CANONICAL_LEAF_ENCODING: &str = "canonical-leaf-v1";
const CANONICAL_NODE_ENCODING: &str = "canonical-node-v1";
const ROLE_AND_LEVEL_DOMAIN_SEPARATION: &str = "role-and-level-v1";

/// Errors returned by commitment scheme handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentSchemeError {
    /// The commitment scheme identifier is unknown.
    UnknownCommitmentSchemeId(u16),
    /// The commitment scheme is identified but has no implementation here.
    UnsupportedCommitmentScheme(CommitmentSchemeId),
    /// A leaf payload exceeded the deterministic resource bound.
    LeafPayloadTooLarge {
        /// Actual payload length.
        length: usize,
        /// Maximum accepted payload length.
        maximum: usize,
    },
    /// A child commitment used a different scheme than its parent operation.
    CommitmentSchemeMismatch {
        /// Scheme selected for the operation.
        expected: CommitmentSchemeId,
        /// Scheme carried by the supplied commitment.
        actual: CommitmentSchemeId,
    },
    /// A scheme-specific commitment had an invalid byte length.
    InvalidCommitmentLength {
        /// Actual commitment byte length.
        length: usize,
        /// Required commitment byte length.
        expected: usize,
    },
    /// An internal-node level was outside the 256-bit sparse tree.
    InvalidTreeLevel(u16),
    /// An input length could not be represented by the commitment framing.
    InputLengthOverflow(usize),
    /// The fixed Poseidon2 parameter set could not be initialized.
    InvalidPoseidon2Parameters,
    /// Poseidon2 byte-to-field encoding rejected an input chunk.
    InvalidPoseidon2Input,
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for CommitmentSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommitmentSchemeId(id) => {
                write!(f, "unknown commitment scheme id: {id:#06x}")
            }
            Self::UnsupportedCommitmentScheme(scheme) => {
                write!(f, "unsupported commitment scheme: {scheme}")
            }
            Self::LeafPayloadTooLarge { length, maximum } => write!(
                f,
                "commitment leaf payload is {length} bytes, maximum is {maximum}"
            ),
            Self::CommitmentSchemeMismatch { expected, actual } => write!(
                f,
                "commitment scheme mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidCommitmentLength { length, expected } => {
                write!(f, "commitment is {length} bytes, expected {expected}")
            }
            Self::InvalidTreeLevel(level) => write!(
                f,
                "sparse-Merkle node level is {level}, maximum is {}",
                SPARSE_MERKLE_DEPTH - 1
            ),
            Self::InputLengthOverflow(length) => {
                write!(f, "commitment input length cannot be represented: {length}")
            }
            Self::InvalidPoseidon2Parameters => {
                f.write_str("Poseidon2 parameter initialization failed")
            }
            Self::InvalidPoseidon2Input => f.write_str("Poseidon2 input encoding failed"),
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for CommitmentSchemeError {}

impl From<CanonicalEncodingError> for CommitmentSchemeError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// Commitment scheme identifiers.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitmentSchemeId {
    /// Sparse Merkle tree commitments using SHA-256.
    SparseMerkleSha256V1 = 0x0001,
    /// Sparse Merkle tree commitments using Poseidon2 over BN254.
    SparseMerklePoseidon2Bn254V1 = 0x0002,
    /// Sparse Merkle tree commitments using Poseidon2 over BLS12-381.
    SparseMerklePoseidon2Bls12381V1 = 0x0003,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Poseidon2Parameters {
    finite_field: &'static str,
    width: u16,
    rate: u16,
    capacity: u16,
    full_rounds: u16,
    partial_rounds: u16,
    constants_version: &'static str,
}

impl CommitmentSchemeId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns a stable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SparseMerkleSha256V1 => "sparse-merkle-sha256-v1",
            Self::SparseMerklePoseidon2Bn254V1 => "sparse-merkle-poseidon2-bn254-v1",
            Self::SparseMerklePoseidon2Bls12381V1 => "sparse-merkle-poseidon2-bls12-381-v1",
        }
    }

    const fn primitive_label(self) -> &'static str {
        match self {
            Self::SparseMerkleSha256V1 => "sha2-256",
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => {
                "poseidon2"
            }
        }
    }

    const fn poseidon2_parameters(self) -> Option<Poseidon2Parameters> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 => Some(Poseidon2Parameters {
                finite_field: "bn254",
                width: 3,
                rate: 2,
                capacity: 1,
                full_rounds: 8,
                partial_rounds: 56,
                constants_version: "v1",
            }),
            Self::SparseMerklePoseidon2Bls12381V1 => Some(Poseidon2Parameters {
                finite_field: "bls12-381",
                width: 3,
                rate: 2,
                capacity: 1,
                full_rounds: 8,
                partial_rounds: 56,
                constants_version: "v1",
            }),
        }
    }

    const fn tree_construction(self) -> &'static str {
        SPARSE_MERKLE_TREE_CONSTRUCTION
    }

    const fn leaf_encoding(self) -> &'static str {
        CANONICAL_LEAF_ENCODING
    }

    const fn node_encoding(self) -> &'static str {
        CANONICAL_NODE_ENCODING
    }

    const fn domain_separation(self) -> &'static str {
        ROLE_AND_LEVEL_DOMAIN_SEPARATION
    }
}

impl TryFrom<u16> for CommitmentSchemeId {
    type Error = CommitmentSchemeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SparseMerkleSha256V1),
            0x0002 => Ok(Self::SparseMerklePoseidon2Bn254V1),
            0x0003 => Ok(Self::SparseMerklePoseidon2Bls12381V1),
            other => Err(CommitmentSchemeError::UnknownCommitmentSchemeId(other)),
        }
    }
}

impl fmt::Display for CommitmentSchemeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(primitive={}, tree={}, leaf-encoding={}, node-encoding={}, domain-separation={}",
            self.label(),
            self.primitive_label(),
            self.tree_construction(),
            self.leaf_encoding(),
            self.node_encoding(),
            self.domain_separation(),
        )?;

        if let Some(parameters) = self.poseidon2_parameters() {
            write!(
                f,
                ", finite-field={finite_field}, width={}, rate={}, capacity={}, full-rounds={}, partial-rounds={}, constants={}",
                parameters.width,
                parameters.rate,
                parameters.capacity,
                parameters.full_rounds,
                parameters.partial_rounds,
                parameters.constants_version,
                finite_field = parameters.finite_field,
            )?;
        }

        f.write_str(")")
    }
}

/// A self-describing commitment value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// The commitment scheme identifier.
    pub scheme_id: CommitmentSchemeId,
    /// The scheme-specific commitment bytes.
    pub bytes: Vec<u8>,
}

impl Commitment {
    /// Creates a commitment value.
    #[must_use]
    pub fn new(scheme_id: CommitmentSchemeId, bytes: Vec<u8>) -> Self {
        Self { scheme_id, bytes }
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme_id)?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A state-commitment implementation.
///
/// `commit_leaf` binds a 256-bit sparse-tree key to canonical value bytes.
/// `commit_node` binds two child commitments at a caller-supplied tree level;
/// level zero denotes the root and larger levels move toward the leaves.
pub trait CommitmentScheme {
    /// Returns the stable scheme identifier implemented by this value.
    fn scheme_id(&self) -> CommitmentSchemeId;

    /// Commits one sparse-Merkle leaf.
    fn commit_leaf(
        &self,
        key: &[u8; 32],
        canonical_value: &[u8],
    ) -> Result<Commitment, CommitmentSchemeError>;

    /// Commits one sparse-Merkle internal node.
    fn commit_node(
        &self,
        level: u16,
        left: &Commitment,
        right: &Commitment,
    ) -> Result<Commitment, CommitmentSchemeError>;
}

/// Built-in commitment implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinCommitmentScheme {
    scheme_id: CommitmentSchemeId,
}

impl BuiltinCommitmentScheme {
    /// Resolves a built-in implementation, failing closed for reserved schemes.
    pub fn new(scheme_id: CommitmentSchemeId) -> Result<Self, CommitmentSchemeError> {
        match scheme_id {
            CommitmentSchemeId::SparseMerkleSha256V1
            | CommitmentSchemeId::SparseMerklePoseidon2Bn254V1 => Ok(Self { scheme_id }),
            CommitmentSchemeId::SparseMerklePoseidon2Bls12381V1 => Err(
                CommitmentSchemeError::UnsupportedCommitmentScheme(scheme_id),
            ),
        }
    }

    fn commit_frame(&self, frame: &[u8]) -> Result<Commitment, CommitmentSchemeError> {
        let bytes = match self.scheme_id {
            CommitmentSchemeId::SparseMerkleSha256V1 => sha256(frame),
            CommitmentSchemeId::SparseMerklePoseidon2Bn254V1 => poseidon2_bn254(frame)?,
            CommitmentSchemeId::SparseMerklePoseidon2Bls12381V1 => {
                return Err(CommitmentSchemeError::UnsupportedCommitmentScheme(
                    self.scheme_id,
                ));
            }
        };
        Ok(Commitment::new(self.scheme_id, bytes.to_vec()))
    }

    fn validate_child(&self, commitment: &Commitment) -> Result<(), CommitmentSchemeError> {
        if commitment.scheme_id != self.scheme_id {
            return Err(CommitmentSchemeError::CommitmentSchemeMismatch {
                expected: self.scheme_id,
                actual: commitment.scheme_id,
            });
        }
        validate_commitment(commitment)
    }
}

impl CommitmentScheme for BuiltinCommitmentScheme {
    fn scheme_id(&self) -> CommitmentSchemeId {
        self.scheme_id
    }

    fn commit_leaf(
        &self,
        key: &[u8; 32],
        canonical_value: &[u8],
    ) -> Result<Commitment, CommitmentSchemeError> {
        let maximum = match self.scheme_id {
            CommitmentSchemeId::SparseMerkleSha256V1 => MAX_COMMITMENT_LEAF_BYTES,
            CommitmentSchemeId::SparseMerklePoseidon2Bn254V1 => MAX_POSEIDON2_LEAF_BYTES,
            CommitmentSchemeId::SparseMerklePoseidon2Bls12381V1 => {
                return Err(CommitmentSchemeError::UnsupportedCommitmentScheme(
                    self.scheme_id,
                ));
            }
        };
        if canonical_value.len() > maximum {
            return Err(CommitmentSchemeError::LeafPayloadTooLarge {
                length: canonical_value.len(),
                maximum,
            });
        }

        let mut canonical = CanonicalStruct::new(COMMITMENT_LEAF_TYPE_ID, ENCODING_VERSION);
        canonical.field_u16(1, self.scheme_id.as_u16())?;
        canonical.field_bytes(2, key.as_slice())?;
        canonical.field_bytes(3, canonical_value)?;
        self.commit_frame(&canonical.finish()?)
    }

    fn commit_node(
        &self,
        level: u16,
        left: &Commitment,
        right: &Commitment,
    ) -> Result<Commitment, CommitmentSchemeError> {
        if level >= SPARSE_MERKLE_DEPTH {
            return Err(CommitmentSchemeError::InvalidTreeLevel(level));
        }
        self.validate_child(left)?;
        self.validate_child(right)?;

        let mut canonical = CanonicalStruct::new(COMMITMENT_NODE_TYPE_ID, ENCODING_VERSION);
        canonical.field_u16(1, self.scheme_id.as_u16())?;
        canonical.field_u16(2, level)?;
        canonical.field_bytes(3, left.bytes.as_slice())?;
        canonical.field_bytes(4, right.bytes.as_slice())?;
        self.commit_frame(&canonical.finish()?)
    }
}

/// Validates the fixed-width representation used by all version-1 schemes.
pub fn validate_commitment(commitment: &Commitment) -> Result<(), CommitmentSchemeError> {
    if commitment.bytes.len() != COMMITMENT_BYTES {
        return Err(CommitmentSchemeError::InvalidCommitmentLength {
            length: commitment.bytes.len(),
            expected: COMMITMENT_BYTES,
        });
    }
    Ok(())
}

fn sha256(input: &[u8]) -> [u8; COMMITMENT_BYTES] {
    let digest = Sha256::digest(input);
    let mut output = [0_u8; COMMITMENT_BYTES];
    output.copy_from_slice(&digest);
    output
}

/// Hashes a canonical byte frame with a rate-2 Poseidon2 sponge.
///
/// Bytes are injected into the BN254 scalar field as little-endian chunks of
/// at most 31 bytes, so conversion is injective. The byte length is placed in
/// the capacity lane and the state is permuted after each rate block. The
/// canonical frame itself supplies role, scheme, and tree-level separation.
fn poseidon2_bn254(input: &[u8]) -> Result<[u8; COMMITMENT_BYTES], CommitmentSchemeError> {
    let input_len = u64::try_from(input.len())
        .map_err(|_| CommitmentSchemeError::InputLengthOverflow(input.len()))?;
    match poseidon2_bn254::hash_bytes(input, input_len) {
        Ok(output) => Ok(output),
        Err(poseidon2_bn254::Poseidon2Error::InvalidRoundConstant) => {
            Err(CommitmentSchemeError::InvalidPoseidon2Parameters)
        }
        Err(poseidon2_bn254::Poseidon2Error::InputChunkTooLarge) => {
            Err(CommitmentSchemeError::InvalidPoseidon2Input)
        }
    }
}

/// Encodes a commitment scheme identifier and descriptor.
pub fn encode_commitment_scheme_id(
    scheme_id: CommitmentSchemeId,
) -> Result<Vec<u8>, CommitmentSchemeError> {
    let mut canonical = CanonicalStruct::new(COMMITMENT_SCHEME_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, scheme_id.as_u16())?;
    canonical.field_str(2, scheme_id.label())?;
    canonical.field_str(3, scheme_id.primitive_label())?;
    canonical.field_str(4, scheme_id.tree_construction())?;
    canonical.field_str(5, scheme_id.leaf_encoding())?;
    canonical.field_str(6, scheme_id.node_encoding())?;
    canonical.field_str(7, scheme_id.domain_separation())?;

    if let Some(parameters) = scheme_id.poseidon2_parameters() {
        canonical.field_str(8, parameters.finite_field)?;
        canonical.field_u16(9, parameters.width)?;
        canonical.field_u16(10, parameters.rate)?;
        canonical.field_u16(11, parameters.capacity)?;
        canonical.field_u16(12, parameters.full_rounds)?;
        canonical.field_u16(13, parameters.partial_rounds)?;
        canonical.field_str(14, parameters.constants_version)?;
    }

    Ok(canonical.finish()?)
}

/// Encodes a self-describing commitment value.
pub fn encode_commitment(commitment: &Commitment) -> Result<Vec<u8>, CommitmentSchemeError> {
    let mut canonical = CanonicalStruct::new(COMMITMENT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_commitment_scheme_id(commitment.scheme_id)?)?;
    canonical.field_bytes(2, commitment.bytes.as_slice())?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn unknown_commitment_scheme_id_is_rejected() {
        assert_eq!(
            CommitmentSchemeId::try_from(0x9999),
            Err(CommitmentSchemeError::UnknownCommitmentSchemeId(0x9999))
        );
    }

    #[test]
    fn display_is_self_describing() {
        let commitment = Commitment::new(
            CommitmentSchemeId::SparseMerklePoseidon2Bn254V1,
            vec![0xab, 0xcd],
        );
        let text = commitment.to_string();

        assert!(text.contains("sparse-merkle-poseidon2-bn254-v1"));
        assert!(text.contains("finite-field=bn254"));
        assert!(text.ends_with(":abcd"));
    }

    #[test]
    fn commitment_scheme_encoding_is_stable() {
        let bytes =
            encode_commitment_scheme_id(CommitmentSchemeId::SparseMerklePoseidon2Bn254V1).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "534e5245013001000e00",
                "0100020000000200",
                "0200200000007370617273652d6d65726b6c652d706f736569646f6e322d626e3235342d7631",
                "030009000000706f736569646f6e32",
                "04001700000062696e6172792d7370617273652d6d65726b6c652d7631",
                "05001100000063616e6f6e6963616c2d6c6561662d7631",
                "06001100000063616e6f6e6963616c2d6e6f64652d7631",
                "070011000000726f6c652d616e642d6c6576656c2d7631",
                "080005000000626e323534",
                "0900020000000300",
                "0a00020000000200",
                "0b00020000000100",
                "0c00020000000800",
                "0d00020000003800",
                "0e00020000007631"
            )
        );
    }

    #[test]
    fn commitment_encoding_is_stable() {
        let commitment = Commitment::new(
            CommitmentSchemeId::SparseMerkleSha256V1,
            vec![0xaa, 0xbb, 0xcc],
        );
        let bytes = encode_commitment(&commitment).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "534e5245023001000200",
                "01009f000000",
                "534e5245013001000700",
                "0100020000000100",
                "0200170000007370617273652d6d65726b6c652d7368613235362d7631",
                "030008000000736861322d323536",
                "04001700000062696e6172792d7370617273652d6d65726b6c652d7631",
                "05001100000063616e6f6e6963616c2d6c6561662d7631",
                "06001100000063616e6f6e6963616c2d6e6f64652d7631",
                "070011000000726f6c652d616e642d6c6576656c2d7631",
                "020003000000aabbcc"
            )
        );
    }

    #[test]
    fn commitment_leaf_vectors_are_stable() {
        let key = [0x11; 32];
        let sha = BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerkleSha256V1)
            .unwrap()
            .commit_leaf(&key, b"sunrise")
            .unwrap();
        let poseidon =
            BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerklePoseidon2Bn254V1)
                .unwrap()
                .commit_leaf(&key, b"sunrise")
                .unwrap();

        assert_eq!(
            hex(&sha.bytes),
            "5dab07297a7d602678880b27e4768ab06690859902c4f14e1a0e6a0e9a221dde"
        );
        assert_eq!(
            hex(&poseidon.bytes),
            "8a454cd2a5e243b166c53e1a071d1ba7877cbb90f0ca18ae4125a6479e409c29"
        );
    }

    #[test]
    fn node_commitments_bind_level_order_and_scheme() {
        let sha = BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerkleSha256V1).unwrap();
        let left = sha.commit_leaf(&[0x11; 32], b"left").unwrap();
        let right = sha.commit_leaf(&[0x22; 32], b"right").unwrap();

        assert_ne!(
            sha.commit_node(7, &left, &right).unwrap(),
            sha.commit_node(8, &left, &right).unwrap()
        );
        assert_ne!(
            sha.commit_node(7, &left, &right).unwrap(),
            sha.commit_node(7, &right, &left).unwrap()
        );

        let poseidon =
            BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerklePoseidon2Bn254V1).unwrap();
        let poseidon_child = poseidon.commit_leaf(&[0x33; 32], b"poseidon").unwrap();
        assert!(matches!(
            sha.commit_node(0, &left, &poseidon_child),
            Err(CommitmentSchemeError::CommitmentSchemeMismatch { .. })
        ));
        assert_eq!(
            sha.commit_node(256, &left, &right),
            Err(CommitmentSchemeError::InvalidTreeLevel(256))
        );
    }

    #[test]
    fn unsupported_and_malformed_commitments_fail_closed() {
        assert_eq!(
            BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerklePoseidon2Bls12381V1),
            Err(CommitmentSchemeError::UnsupportedCommitmentScheme(
                CommitmentSchemeId::SparseMerklePoseidon2Bls12381V1
            ))
        );

        let sha = BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerkleSha256V1).unwrap();
        let malformed = Commitment::new(CommitmentSchemeId::SparseMerkleSha256V1, vec![0; 31]);
        assert!(matches!(
            sha.commit_node(0, &malformed, &malformed),
            Err(CommitmentSchemeError::InvalidCommitmentLength { .. })
        ));
    }

    #[test]
    fn leaf_payload_size_is_bounded() {
        let sha = BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerkleSha256V1).unwrap();
        let too_large = vec![0_u8; MAX_COMMITMENT_LEAF_BYTES + 1];
        assert!(matches!(
            sha.commit_leaf(&[0_u8; 32], &too_large),
            Err(CommitmentSchemeError::LeafPayloadTooLarge { .. })
        ));

        let poseidon =
            BuiltinCommitmentScheme::new(CommitmentSchemeId::SparseMerklePoseidon2Bn254V1).unwrap();
        let poseidon_too_large = vec![0_u8; MAX_POSEIDON2_LEAF_BYTES + 1];
        assert_eq!(
            poseidon.commit_leaf(&[0_u8; 32], &poseidon_too_large),
            Err(CommitmentSchemeError::LeafPayloadTooLarge {
                length: MAX_POSEIDON2_LEAF_BYTES + 1,
                maximum: MAX_POSEIDON2_LEAF_BYTES,
            })
        );
    }
}
