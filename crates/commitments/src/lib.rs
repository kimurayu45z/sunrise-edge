#![forbid(unsafe_code)]

//! Commitment scheme identifiers and self-describing commitment values.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use std::error::Error;

const COMMITMENT_SCHEME_TYPE_ID: u16 = 0x3001;
const COMMITMENT_TYPE_ID: u16 = 0x3002;
const ENCODING_VERSION: u16 = 1;
const SPARSE_MERKLE_TREE_CONSTRUCTION: &str = "binary-sparse-merkle-v1";
const CANONICAL_LEAF_ENCODING: &str = "canonical-leaf-v1";
const CANONICAL_NODE_ENCODING: &str = "canonical-node-v1";
const ROLE_AND_LEVEL_DOMAIN_SEPARATION: &str = "role-and-level-v1";

/// Errors returned by commitment scheme handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentSchemeError {
    /// The commitment scheme identifier is unknown.
    UnknownCommitmentSchemeId(u16),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for CommitmentSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommitmentSchemeId(id) => {
                write!(f, "unknown commitment scheme id: {id:#06x}")
            }
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

    const fn finite_field(self) -> Option<&'static str> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 => Some("bn254"),
            Self::SparseMerklePoseidon2Bls12381V1 => Some("bls12-381"),
        }
    }

    const fn width(self) -> Option<u16> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => Some(3),
        }
    }

    const fn rate(self) -> Option<u16> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => Some(2),
        }
    }

    const fn capacity(self) -> Option<u16> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => Some(1),
        }
    }

    const fn full_rounds(self) -> Option<u16> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => Some(8),
        }
    }

    const fn partial_rounds(self) -> Option<u16> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => Some(56),
        }
    }

    const fn constants_version(self) -> Option<&'static str> {
        match self {
            Self::SparseMerkleSha256V1 => None,
            Self::SparseMerklePoseidon2Bn254V1 | Self::SparseMerklePoseidon2Bls12381V1 => {
                Some("v1")
            }
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

        if let Some(finite_field) = self.finite_field() {
            write!(
                f,
                ", finite-field={finite_field}, width={}, rate={}, capacity={}, full-rounds={}, partial-rounds={}, constants={}",
                self.width().expect("poseidon2 width must exist"),
                self.rate().expect("poseidon2 rate must exist"),
                self.capacity().expect("poseidon2 capacity must exist"),
                self.full_rounds()
                    .expect("poseidon2 full rounds must exist"),
                self.partial_rounds()
                    .expect("poseidon2 partial rounds must exist"),
                self.constants_version()
                    .expect("poseidon2 constants version must exist"),
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

    if let Some(finite_field) = scheme_id.finite_field() {
        canonical.field_str(8, finite_field)?;
        canonical.field_u16(9, scheme_id.width().expect("poseidon2 width must exist"))?;
        canonical.field_u16(10, scheme_id.rate().expect("poseidon2 rate must exist"))?;
        canonical.field_u16(
            11,
            scheme_id.capacity().expect("poseidon2 capacity must exist"),
        )?;
        canonical.field_u16(
            12,
            scheme_id
                .full_rounds()
                .expect("poseidon2 rounds must exist"),
        )?;
        canonical.field_u16(
            13,
            scheme_id
                .partial_rounds()
                .expect("poseidon2 rounds must exist"),
        )?;
        canonical.field_str(
            14,
            scheme_id
                .constants_version()
                .expect("poseidon2 constants must exist"),
        )?;
    }

    Ok(canonical.finish()?)
}

/// Encodes a self-describing commitment value.
pub fn encode_commitment(commitment: &Commitment) -> Result<Vec<u8>, CommitmentSchemeError> {
    let mut canonical = CanonicalStruct::new(COMMITMENT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_commitment_scheme_id(commitment.scheme_id)?)?;
    canonical.field_bytes(2, commitment.bytes.clone())?;
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
}
