//! Canonical execution-proof envelopes and pluggable verification boundary.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32};
use commitments::{Commitment, CommitmentSchemeError, encode_commitment, validate_commitment};
use core::fmt;
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion};
use std::error::Error;

const PROOF_SYSTEM_ID_TYPE_ID: u16 = 0x6007;
const EXECUTION_PROOF_STATEMENT_TYPE_ID: u16 = 0x6008;
const EXECUTION_PROOF_TYPE_ID: u16 = 0x6009;
const ENCODING_VERSION: u16 = 1;

/// Maximum proof payload accepted by the generic execution-proof envelope.
pub const MAX_EXECUTION_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// A non-zero, protocol-assigned proof-system identifier.
///
/// This identifier is intentionally extensible. An ID becomes usable only
/// when protocol configuration selects it and the caller supplies a verifier
/// for the exact same ID; there is no fallback verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofSystemId(u16);

impl ProofSystemId {
    /// Creates a proof-system identifier. Zero is permanently invalid.
    pub const fn new(value: u16) -> Result<Self, ExecutionProofError> {
        if value == 0 {
            return Err(ExecutionProofError::InvalidProofSystemId(value));
        }
        Ok(Self(value))
    }

    /// Returns the wire identifier.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ProofSystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proof-system-{:#06x}", self.0)
    }
}

/// The public statement bound by an execution proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProofStatement {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol semantics version.
    pub protocol_version: ProtocolVersion,
    /// Epoch/configuration boundary.
    pub epoch: Epoch,
    /// Transaction whose deterministic execution is proven.
    pub tx_hash: Digest32,
    /// State/access-set commitment before execution.
    pub input_commitment: Commitment,
    /// State/access-set commitment after execution.
    pub output_commitment: Commitment,
}

/// A self-describing execution proof with opaque backend bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Proof backend and proof-format identifier.
    pub proof_system: ProofSystemId,
    /// Public statement verified by the proof.
    pub statement: ExecutionProofStatement,
    /// Backend-specific proof bytes.
    pub proof_bytes: Vec<u8>,
}

impl ExecutionProof {
    /// Creates a validated proof envelope.
    pub fn new(
        proof_system: ProofSystemId,
        statement: ExecutionProofStatement,
        proof_bytes: Vec<u8>,
    ) -> Result<Self, ExecutionProofError> {
        let proof = Self {
            proof_system,
            statement,
            proof_bytes,
        };
        validate_execution_proof(&proof)?;
        Ok(proof)
    }
}

/// Backend verification failures that are safe to expose at the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerificationError {
    /// The proof was well-formed but did not verify.
    InvalidProof,
    /// The proof payload was not valid for the selected backend.
    MalformedProof,
}

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof => f.write_str("execution proof did not verify"),
            Self::MalformedProof => f.write_str("execution proof payload is malformed"),
        }
    }
}

impl Error for ProofVerificationError {}

/// Errors produced by execution-proof framing and dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionProofError {
    /// Proof-system identifier zero is reserved and invalid.
    InvalidProofSystemId(u16),
    /// A proof envelope carried no backend proof bytes.
    EmptyProof,
    /// A proof exceeded the deterministic resource bound.
    ProofTooLarge {
        /// Actual proof length.
        length: usize,
        /// Maximum accepted length.
        maximum: usize,
    },
    /// The supplied verifier did not implement the proof envelope's system.
    UnsupportedProofSystem {
        /// Proof system carried by the envelope.
        proof: ProofSystemId,
        /// Proof system implemented by the verifier.
        verifier: ProofSystemId,
    },
    /// The envelope did not bind the statement expected by the caller.
    StatementMismatch,
    /// A commitment was malformed.
    Commitment(CommitmentSchemeError),
    /// Canonical framing failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// The selected backend rejected the proof.
    Verification(ProofVerificationError),
}

impl fmt::Display for ExecutionProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProofSystemId(id) => {
                write!(f, "invalid proof system id: {id:#06x}")
            }
            Self::EmptyProof => f.write_str("execution proof bytes must not be empty"),
            Self::ProofTooLarge { length, maximum } => {
                write!(f, "execution proof is {length} bytes, maximum is {maximum}")
            }
            Self::UnsupportedProofSystem { proof, verifier } => write!(
                f,
                "unsupported proof system: proof uses {proof}, verifier implements {verifier}"
            ),
            Self::StatementMismatch => {
                f.write_str("execution proof statement does not match expected statement")
            }
            Self::Commitment(error) => error.fmt(f),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::Verification(error) => error.fmt(f),
        }
    }
}

impl Error for ExecutionProofError {}

impl From<CommitmentSchemeError> for ExecutionProofError {
    fn from(value: CommitmentSchemeError) -> Self {
        Self::Commitment(value)
    }
}

impl From<CanonicalEncodingError> for ExecutionProofError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<ProofVerificationError> for ExecutionProofError {
    fn from(value: ProofVerificationError) -> Self {
        Self::Verification(value)
    }
}

/// A verifier for exactly one proof-system ID and proof format.
pub trait ExecutionProofVerifier {
    /// Returns the exact proof system implemented by this verifier.
    fn proof_system_id(&self) -> ProofSystemId;

    /// Verifies backend proof bytes against the canonical public statement.
    fn verify(
        &self,
        statement: &ExecutionProofStatement,
        proof_bytes: &[u8],
    ) -> Result<(), ProofVerificationError>;
}

/// Validates generic envelope bounds and commitment representations.
pub fn validate_execution_proof(proof: &ExecutionProof) -> Result<(), ExecutionProofError> {
    if proof.proof_bytes.is_empty() {
        return Err(ExecutionProofError::EmptyProof);
    }
    if proof.proof_bytes.len() > MAX_EXECUTION_PROOF_BYTES {
        return Err(ExecutionProofError::ProofTooLarge {
            length: proof.proof_bytes.len(),
            maximum: MAX_EXECUTION_PROOF_BYTES,
        });
    }
    validate_commitment(&proof.statement.input_commitment)?;
    validate_commitment(&proof.statement.output_commitment)?;
    Ok(())
}

/// Dispatches a proof only after checking its context and exact backend ID.
pub fn verify_execution_proof(
    proof: &ExecutionProof,
    expected_statement: &ExecutionProofStatement,
    verifier: &dyn ExecutionProofVerifier,
) -> Result<(), ExecutionProofError> {
    validate_execution_proof(proof)?;
    if &proof.statement != expected_statement {
        return Err(ExecutionProofError::StatementMismatch);
    }
    let verifier_id = verifier.proof_system_id();
    if proof.proof_system != verifier_id {
        return Err(ExecutionProofError::UnsupportedProofSystem {
            proof: proof.proof_system,
            verifier: verifier_id,
        });
    }
    verifier.verify(&proof.statement, &proof.proof_bytes)?;
    Ok(())
}

/// Encodes a proof-system ID in the canonical wire format.
pub fn encode_proof_system_id(proof_system: ProofSystemId) -> Result<Vec<u8>, ExecutionProofError> {
    let mut canonical = CanonicalStruct::new(PROOF_SYSTEM_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, proof_system.get())?;
    Ok(canonical.finish()?)
}

/// Encodes an execution-proof public statement.
pub fn encode_execution_proof_statement(
    statement: &ExecutionProofStatement,
) -> Result<Vec<u8>, ExecutionProofError> {
    validate_commitment(&statement.input_commitment)?;
    validate_commitment(&statement.output_commitment)?;

    let mut canonical = CanonicalStruct::new(EXECUTION_PROOF_STATEMENT_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, statement.chain_id.as_str())?;
    canonical.field_u32(2, statement.protocol_version.get())?;
    canonical.field_u64(3, statement.epoch.get())?;
    canonical.field_bytes(4, encode_digest32(&statement.tx_hash)?)?;
    canonical.field_bytes(5, encode_commitment(&statement.input_commitment)?)?;
    canonical.field_bytes(6, encode_commitment(&statement.output_commitment)?)?;
    Ok(canonical.finish()?)
}

/// Encodes a complete execution-proof envelope.
pub fn encode_execution_proof(proof: &ExecutionProof) -> Result<Vec<u8>, ExecutionProofError> {
    validate_execution_proof(proof)?;

    let mut canonical = CanonicalStruct::new(EXECUTION_PROOF_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_proof_system_id(proof.proof_system)?)?;
    canonical.field_bytes(2, encode_execution_proof_statement(&proof.statement)?)?;
    canonical.field_bytes(3, proof.proof_bytes.as_slice())?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commitments::CommitmentSchemeId;
    use protocol_types::HashAlgorithmId;
    use sha2::{Digest as _, Sha256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn proof_system(value: u16) -> ProofSystemId {
        ProofSystemId::new(value).unwrap()
    }

    fn statement() -> ExecutionProofStatement {
        ExecutionProofStatement {
            chain_id: ChainId::new("sunrise-devnet").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
            input_commitment: Commitment::new(
                CommitmentSchemeId::SparseMerkleSha256V1,
                vec![0x22; 32],
            ),
            output_commitment: Commitment::new(
                CommitmentSchemeId::SparseMerkleSha256V1,
                vec![0x33; 32],
            ),
        }
    }

    struct TestVerifier {
        id: ProofSystemId,
        valid_bytes: Vec<u8>,
    }

    impl ExecutionProofVerifier for TestVerifier {
        fn proof_system_id(&self) -> ProofSystemId {
            self.id
        }

        fn verify(
            &self,
            _statement: &ExecutionProofStatement,
            proof_bytes: &[u8],
        ) -> Result<(), ProofVerificationError> {
            if proof_bytes == self.valid_bytes {
                Ok(())
            } else {
                Err(ProofVerificationError::InvalidProof)
            }
        }
    }

    #[test]
    fn zero_proof_system_id_is_rejected() {
        assert_eq!(
            ProofSystemId::new(0),
            Err(ExecutionProofError::InvalidProofSystemId(0))
        );
    }

    #[test]
    fn proof_system_id_encoding_is_stable() {
        let bytes = encode_proof_system_id(proof_system(0x1234)).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x53, 0x4e, 0x52, 0x45, 0x07, 0x60, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00,
                0x00, 0x00, 0x34, 0x12,
            ]
        );
    }

    #[test]
    fn matching_statement_and_verifier_accept_proof() {
        let statement = statement();
        let proof = ExecutionProof::new(proof_system(7), statement.clone(), vec![1, 2, 3]).unwrap();
        let verifier = TestVerifier {
            id: proof_system(7),
            valid_bytes: vec![1, 2, 3],
        };

        assert_eq!(
            verify_execution_proof(&proof, &statement, &verifier),
            Ok(())
        );
        let encoded = encode_execution_proof(&proof).unwrap();
        assert_eq!(encoded.len(), 603);
        assert_eq!(
            hex(&Sha256::digest(&encoded)),
            "469d11956c783eb9a458d8ac3f5dd2c472c44a879909fb520cc21f37c75c6404"
        );
    }

    #[test]
    fn statement_mismatch_fails_before_backend_dispatch() {
        let original = statement();
        let proof = ExecutionProof::new(proof_system(7), original.clone(), vec![1]).unwrap();
        let mut unexpected = original;
        unexpected.epoch = Epoch::new(10);
        let verifier = TestVerifier {
            id: proof_system(7),
            valid_bytes: vec![1],
        };

        assert_eq!(
            verify_execution_proof(&proof, &unexpected, &verifier),
            Err(ExecutionProofError::StatementMismatch)
        );
    }

    #[test]
    fn unsupported_backend_does_not_fall_back() {
        let statement = statement();
        let proof = ExecutionProof::new(proof_system(7), statement.clone(), vec![1]).unwrap();
        let verifier = TestVerifier {
            id: proof_system(8),
            valid_bytes: vec![1],
        };

        assert_eq!(
            verify_execution_proof(&proof, &statement, &verifier),
            Err(ExecutionProofError::UnsupportedProofSystem {
                proof: proof_system(7),
                verifier: proof_system(8),
            })
        );
    }

    #[test]
    fn invalid_proof_and_malformed_commitments_are_rejected() {
        let statement = statement();
        let proof = ExecutionProof::new(proof_system(7), statement.clone(), vec![9]).unwrap();
        let verifier = TestVerifier {
            id: proof_system(7),
            valid_bytes: vec![1],
        };
        assert_eq!(
            verify_execution_proof(&proof, &statement, &verifier),
            Err(ExecutionProofError::Verification(
                ProofVerificationError::InvalidProof
            ))
        );

        let mut malformed = statement;
        malformed.input_commitment.bytes.pop();
        assert!(matches!(
            ExecutionProof::new(proof_system(7), malformed, vec![1]),
            Err(ExecutionProofError::Commitment(
                CommitmentSchemeError::InvalidCommitmentLength { .. }
            ))
        ));
    }

    #[test]
    fn proof_size_is_bounded() {
        let too_large = vec![0_u8; MAX_EXECUTION_PROOF_BYTES + 1];
        assert!(matches!(
            ExecutionProof::new(proof_system(7), statement(), too_large),
            Err(ExecutionProofError::ProofTooLarge { .. })
        ));
    }
}
