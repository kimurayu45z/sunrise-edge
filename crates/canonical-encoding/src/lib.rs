#![forbid(unsafe_code)]

//! Deterministic framed serialization for protocol-critical payloads.

use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashDomain, HashSuite, ProtocolVersion,
    SignatureSchemeId,
};
use std::{collections::BTreeMap, error::Error, fmt};

/// Stable protocol magic prefixed to every canonical payload.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"SNRE";

/// Errors returned when canonical encoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEncodingError {
    /// The same field identifier was provided twice.
    DuplicateField(u16),
    /// The field count exceeded the current encoding limit.
    TooManyFields(usize),
    /// A field payload exceeded the current encoding limit.
    FieldTooLarge(usize),
}

impl fmt::Display for CanonicalEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateField(id) => write!(f, "duplicate canonical field id: {id}"),
            Self::TooManyFields(count) => write!(f, "too many canonical fields: {count}"),
            Self::FieldTooLarge(len) => write!(f, "canonical field too large: {len} bytes"),
        }
    }
}

impl Error for CanonicalEncodingError {}

/// A deterministic field-framed canonical structure.
#[derive(Debug, Clone)]
pub struct CanonicalStruct {
    type_id: u16,
    version: u16,
    fields: BTreeMap<u16, Vec<u8>>,
}

impl CanonicalStruct {
    /// Creates a new canonical structure frame.
    #[must_use]
    pub fn new(type_id: u16, version: u16) -> Self {
        Self {
            type_id,
            version,
            fields: BTreeMap::new(),
        }
    }

    /// Stores a raw byte field.
    pub fn field_bytes(
        &mut self,
        field_id: u16,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<(), CanonicalEncodingError> {
        self.insert(field_id, bytes.into())
    }

    /// Stores a UTF-8 string field.
    pub fn field_str(
        &mut self,
        field_id: u16,
        value: impl AsRef<str>,
    ) -> Result<(), CanonicalEncodingError> {
        self.insert(field_id, value.as_ref().as_bytes().to_vec())
    }

    /// Stores a `u16` field.
    pub fn field_u16(&mut self, field_id: u16, value: u16) -> Result<(), CanonicalEncodingError> {
        self.insert(field_id, value.to_le_bytes().to_vec())
    }

    /// Stores a `u32` field.
    pub fn field_u32(&mut self, field_id: u16, value: u32) -> Result<(), CanonicalEncodingError> {
        self.insert(field_id, value.to_le_bytes().to_vec())
    }

    /// Stores a `u64` field.
    pub fn field_u64(&mut self, field_id: u16, value: u64) -> Result<(), CanonicalEncodingError> {
        self.insert(field_id, value.to_le_bytes().to_vec())
    }

    fn insert(&mut self, field_id: u16, bytes: Vec<u8>) -> Result<(), CanonicalEncodingError> {
        if self.fields.contains_key(&field_id) {
            return Err(CanonicalEncodingError::DuplicateField(field_id));
        }
        self.fields.insert(field_id, bytes);

        Ok(())
    }

    /// Finishes the encoding and returns a deterministic byte vector.
    pub fn finish(self) -> Result<Vec<u8>, CanonicalEncodingError> {
        let field_count = u16::try_from(self.fields.len())
            .map_err(|_| CanonicalEncodingError::TooManyFields(self.fields.len()))?;
        let mut output = Vec::new();
        output.extend_from_slice(&PROTOCOL_MAGIC);
        output.extend_from_slice(&self.type_id.to_le_bytes());
        output.extend_from_slice(&self.version.to_le_bytes());
        output.extend_from_slice(&field_count.to_le_bytes());

        for (field_id, bytes) in self.fields {
            let len = u32::try_from(bytes.len())
                .map_err(|_| CanonicalEncodingError::FieldTooLarge(bytes.len()))?;
            output.extend_from_slice(&field_id.to_le_bytes());
            output.extend_from_slice(&len.to_le_bytes());
            output.extend_from_slice(&bytes);
        }

        Ok(output)
    }
}

/// Encodes a hash algorithm identifier.
pub fn encode_hash_algorithm_id(
    algorithm: HashAlgorithmId,
) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0101, 1);
    canonical.field_u16(1, algorithm.as_u16())?;
    canonical.finish()
}

/// Encodes a hash domain identifier.
pub fn encode_hash_domain(domain: HashDomain) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0102, 1);
    canonical.field_u16(1, domain.as_u16())?;
    canonical.finish()
}

/// Encodes a self-describing digest.
pub fn encode_digest32(digest: &Digest32) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0103, 1);
    canonical.field_u16(1, digest.algorithm().as_u16())?;
    canonical.field_bytes(2, digest.bytes())?;
    canonical.finish()
}

/// Encodes a hash-suite identifier.
pub fn encode_hash_suite(suite: &HashSuite) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0104, 1);
    canonical.field_u16(1, suite.id.get())?;
    canonical.field_u16(2, suite.transaction_hash.as_u16())?;
    canonical.field_u16(3, suite.object_digest.as_u16())?;
    canonical.field_u16(4, suite.effects_hash.as_u16())?;
    canonical.field_u16(5, suite.code_hash.as_u16())?;
    canonical.field_u16(6, suite.config_hash.as_u16())?;
    canonical.field_u16(7, suite.certificate_hash.as_u16())?;
    canonical.finish()
}

/// Encodes a chain identifier.
pub fn encode_chain_id(chain_id: &ChainId) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0105, 1);
    canonical.field_str(1, chain_id.as_str())?;
    canonical.finish()
}

/// Encodes a protocol version.
pub fn encode_protocol_version(
    version: ProtocolVersion,
) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0106, 1);
    canonical.field_u32(1, version.get())?;
    canonical.finish()
}

/// Encodes an epoch value.
pub fn encode_epoch(epoch: Epoch) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0107, 1);
    canonical.field_u64(1, epoch.get())?;
    canonical.finish()
}

/// Encodes a signature-scheme identifier.
pub fn encode_signature_scheme_id(
    scheme: SignatureSchemeId,
) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut canonical = CanonicalStruct::new(0x0108, 1);
    canonical.field_u16(1, scheme.as_u16())?;
    canonical.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashSuiteId, TypeError};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn canonical_encoding_vector_for_hash_algorithm() {
        let bytes = encode_hash_algorithm_id(HashAlgorithmId::Sha2_256).unwrap();
        assert_eq!(hex(&bytes), "534e52450101010001000100020000000100");
    }

    #[test]
    fn hash_domain_vector_is_stable() {
        let bytes = encode_hash_domain(HashDomain::Transaction).unwrap();
        assert_eq!(hex(&bytes), "534e52450201010001000100020000000100");
    }

    #[test]
    fn digest_serialization_includes_algorithm_id() {
        let digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x11; 32]);
        let bytes = encode_digest32(&digest).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "534e5245030101000200",
                "0100020000000200",
                "020020000000",
                "1111111111111111111111111111111111111111111111111111111111111111"
            )
        );
    }

    #[test]
    fn equivalent_structures_have_identical_bytes() {
        let mut left = CanonicalStruct::new(0x0201, 1);
        left.field_u16(2, 9).unwrap();
        left.field_str(1, "alpha").unwrap();

        let mut right = CanonicalStruct::new(0x0201, 1);
        right.field_str(1, "alpha").unwrap();
        right.field_u16(2, 9).unwrap();

        assert_eq!(left.finish().unwrap(), right.finish().unwrap());
    }

    #[test]
    fn ambiguous_payloads_do_not_collapse() {
        let mut first = CanonicalStruct::new(0x0202, 1);
        first.field_bytes(1, b"ab".to_vec()).unwrap();
        first.field_bytes(2, b"c".to_vec()).unwrap();

        let mut second = CanonicalStruct::new(0x0202, 1);
        second.field_bytes(1, b"a".to_vec()).unwrap();
        second.field_bytes(2, b"bc".to_vec()).unwrap();

        assert_ne!(first.finish().unwrap(), second.finish().unwrap());
    }

    #[test]
    fn hash_suite_encoding_is_stable() {
        let suite = HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Sha3_256);
        let bytes = encode_hash_suite(&suite).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "534e5245040101000700",
                "0100020000000900",
                "0200020000000200",
                "0300020000000200",
                "0400020000000200",
                "0500020000000200",
                "0600020000000200",
                "0700020000000200"
            )
        );
    }

    #[test]
    fn chain_id_validation_still_happens_upstream() {
        assert_eq!(ChainId::new("   "), Err(TypeError::EmptyChainId));
    }
}
