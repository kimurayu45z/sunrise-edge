#![forbid(unsafe_code)]

//! Deterministic framed serialization for protocol-critical payloads.

use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashDomain, HashSuite, ProtocolVersion,
    SignatureSchemeId,
};
use std::{collections::BTreeMap, error::Error, fmt};

/// Stable protocol magic prefixed to every canonical payload.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"SNRE";
/// Maximum canonical frame accepted by the shared encoder and decoder.
pub const MAX_CANONICAL_FRAME_BYTES: usize = 32 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 10;
const FIELD_HEADER_BYTES: usize = 6;

/// Errors returned when canonical encoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEncodingError {
    /// The same field identifier was provided twice.
    DuplicateField(u16),
    /// The field count exceeded the current encoding limit.
    TooManyFields(usize),
    /// A field payload exceeded the current encoding limit.
    FieldTooLarge(usize),
    /// The complete frame exceeded the protocol resource bound.
    FrameTooLarge(usize),
}

impl fmt::Display for CanonicalEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateField(id) => write!(f, "duplicate canonical field id: {id}"),
            Self::TooManyFields(count) => write!(f, "too many canonical fields: {count}"),
            Self::FieldTooLarge(len) => write!(f, "canonical field too large: {len} bytes"),
            Self::FrameTooLarge(len) => write!(
                f,
                "canonical frame is {len} bytes, maximum is {MAX_CANONICAL_FRAME_BYTES}"
            ),
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
        let frame_len = self
            .fields
            .values()
            .try_fold(FRAME_HEADER_BYTES, |total, bytes| {
                total
                    .checked_add(FIELD_HEADER_BYTES)
                    .and_then(|value| value.checked_add(bytes.len()))
            });
        let frame_len = frame_len.ok_or(CanonicalEncodingError::FrameTooLarge(usize::MAX))?;
        if frame_len > MAX_CANONICAL_FRAME_BYTES {
            return Err(CanonicalEncodingError::FrameTooLarge(frame_len));
        }

        let mut output = Vec::with_capacity(frame_len);
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

/// Errors returned when canonical decoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalDecodingError {
    /// The frame exceeded the protocol resource bound.
    FrameTooLarge(usize),
    /// The input ended before a complete value could be read.
    Truncated {
        /// Byte offset where the read started.
        offset: usize,
        /// Number of bytes required by the read.
        needed: usize,
        /// Number of bytes remaining in the input.
        remaining: usize,
    },
    /// The protocol magic did not match [`PROTOCOL_MAGIC`].
    InvalidMagic,
    /// Field identifiers were not strictly increasing.
    NonCanonicalFieldOrder {
        /// Previously decoded field identifier.
        previous: u16,
        /// Current field identifier.
        current: u16,
    },
    /// Bytes remained after the declared fields.
    TrailingBytes(usize),
    /// A requested field was absent.
    MissingField(u16),
    /// A schema decoder encountered a field it does not define.
    UnexpectedField(u16),
    /// A typed field had a different byte length.
    InvalidFieldLength {
        /// Field identifier.
        field_id: u16,
        /// Required byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// A string field was not valid UTF-8.
    InvalidUtf8(u16),
    /// A caller expected a different canonical type identifier.
    UnexpectedTypeId {
        /// Required type identifier.
        expected: u16,
        /// Decoded type identifier.
        actual: u16,
    },
    /// A caller expected a different encoding version.
    UnexpectedVersion {
        /// Required encoding version.
        expected: u16,
        /// Decoded encoding version.
        actual: u16,
    },
    /// A self-describing digest named an unknown hash algorithm.
    UnknownHashAlgorithmId(u16),
}

impl fmt::Display for CanonicalDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge(length) => write!(
                f,
                "canonical frame is {length} bytes, maximum is {MAX_CANONICAL_FRAME_BYTES}"
            ),
            Self::Truncated {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "canonical frame truncated at offset {offset}: need {needed} bytes, {remaining} remain"
            ),
            Self::InvalidMagic => f.write_str("invalid canonical protocol magic"),
            Self::NonCanonicalFieldOrder { previous, current } => write!(
                f,
                "canonical field ids must be strictly increasing: {current} follows {previous}"
            ),
            Self::TrailingBytes(length) => {
                write!(f, "canonical frame has {length} trailing bytes")
            }
            Self::MissingField(field_id) => {
                write!(f, "missing canonical field id: {field_id}")
            }
            Self::UnexpectedField(field_id) => {
                write!(f, "unexpected canonical field id: {field_id}")
            }
            Self::InvalidFieldLength {
                field_id,
                expected,
                actual,
            } => write!(
                f,
                "canonical field {field_id} is {actual} bytes, expected {expected}"
            ),
            Self::InvalidUtf8(field_id) => {
                write!(f, "canonical field {field_id} is not valid UTF-8")
            }
            Self::UnexpectedTypeId { expected, actual } => write!(
                f,
                "unexpected canonical type id: expected {expected:#06x}, got {actual:#06x}"
            ),
            Self::UnexpectedVersion { expected, actual } => write!(
                f,
                "unexpected canonical encoding version: expected {expected}, got {actual}"
            ),
            Self::UnknownHashAlgorithmId(id) => {
                write!(f, "unknown canonical digest hash algorithm id: {id:#06x}")
            }
        }
    }
}

impl Error for CanonicalDecodingError {}

/// A validated, zero-copy view over one canonical frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFrame<'a> {
    type_id: u16,
    version: u16,
    fields: Vec<(u16, &'a [u8])>,
}

impl<'a> CanonicalFrame<'a> {
    /// Returns the stable canonical type identifier.
    #[must_use]
    pub const fn type_id(&self) -> u16 {
        self.type_id
    }

    /// Returns the encoding version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the number of decoded fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Checks the decoded type identifier.
    pub fn require_type(&self, expected: u16) -> Result<(), CanonicalDecodingError> {
        if self.type_id != expected {
            return Err(CanonicalDecodingError::UnexpectedTypeId {
                expected,
                actual: self.type_id,
            });
        }
        Ok(())
    }

    /// Checks the decoded encoding version.
    pub fn require_version(&self, expected: u16) -> Result<(), CanonicalDecodingError> {
        if self.version != expected {
            return Err(CanonicalDecodingError::UnexpectedVersion {
                expected,
                actual: self.version,
            });
        }
        Ok(())
    }

    /// Returns an optional raw field.
    #[must_use]
    pub fn field(&self, field_id: u16) -> Option<&'a [u8]> {
        self.fields
            .binary_search_by_key(&field_id, |(id, _)| *id)
            .ok()
            .map(|index| self.fields[index].1)
    }

    /// Returns a required raw field.
    pub fn required_field(&self, field_id: u16) -> Result<&'a [u8], CanonicalDecodingError> {
        self.field(field_id)
            .ok_or(CanonicalDecodingError::MissingField(field_id))
    }

    /// Rejects fields outside a schema's explicit allow-list.
    pub fn require_only_fields(&self, allowed: &[u16]) -> Result<(), CanonicalDecodingError> {
        for (field_id, _) in &self.fields {
            if !allowed.contains(field_id) {
                return Err(CanonicalDecodingError::UnexpectedField(*field_id));
            }
        }
        Ok(())
    }

    /// Decodes a required little-endian `u16` field.
    pub fn required_u16(&self, field_id: u16) -> Result<u16, CanonicalDecodingError> {
        let bytes = self.required_fixed_field::<2>(field_id)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Decodes a required little-endian `u32` field.
    pub fn required_u32(&self, field_id: u16) -> Result<u32, CanonicalDecodingError> {
        let bytes = self.required_fixed_field::<4>(field_id)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Decodes a required little-endian `u64` field.
    pub fn required_u64(&self, field_id: u16) -> Result<u64, CanonicalDecodingError> {
        let bytes = self.required_fixed_field::<8>(field_id)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Decodes a required UTF-8 field.
    pub fn required_str(&self, field_id: u16) -> Result<&'a str, CanonicalDecodingError> {
        let bytes = self.required_field(field_id)?;
        std::str::from_utf8(bytes).map_err(|_| CanonicalDecodingError::InvalidUtf8(field_id))
    }

    fn required_fixed_field<const N: usize>(
        &self,
        field_id: u16,
    ) -> Result<[u8; N], CanonicalDecodingError> {
        let bytes = self.required_field(field_id)?;
        bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id,
                expected: N,
                actual: bytes.len(),
            })
    }
}

/// Decodes and validates one complete canonical frame without copying fields.
pub fn decode_canonical_frame(input: &[u8]) -> Result<CanonicalFrame<'_>, CanonicalDecodingError> {
    if input.len() > MAX_CANONICAL_FRAME_BYTES {
        return Err(CanonicalDecodingError::FrameTooLarge(input.len()));
    }

    let mut offset = 0_usize;
    let magic = take(input, &mut offset, PROTOCOL_MAGIC.len())?;
    if magic != PROTOCOL_MAGIC {
        return Err(CanonicalDecodingError::InvalidMagic);
    }
    let type_id = read_u16(input, &mut offset)?;
    let version = read_u16(input, &mut offset)?;
    let field_count = usize::from(read_u16(input, &mut offset)?);
    let mut fields = Vec::with_capacity(field_count);
    let mut previous = None;

    for _ in 0..field_count {
        let field_id = read_u16(input, &mut offset)?;
        if let Some(previous) = previous
            && field_id <= previous
        {
            return Err(CanonicalDecodingError::NonCanonicalFieldOrder {
                previous,
                current: field_id,
            });
        }
        let field_len = usize::try_from(read_u32(input, &mut offset)?).map_err(|_| {
            CanonicalDecodingError::Truncated {
                offset,
                needed: usize::MAX,
                remaining: input.len().saturating_sub(offset),
            }
        })?;
        let bytes = take(input, &mut offset, field_len)?;
        fields.push((field_id, bytes));
        previous = Some(field_id);
    }

    if offset != input.len() {
        return Err(CanonicalDecodingError::TrailingBytes(input.len() - offset));
    }

    Ok(CanonicalFrame {
        type_id,
        version,
        fields,
    })
}

fn read_u16(input: &[u8], offset: &mut usize) -> Result<u16, CanonicalDecodingError> {
    let start = *offset;
    let bytes: [u8; 2] =
        take(input, offset, 2)?
            .try_into()
            .map_err(|_| CanonicalDecodingError::Truncated {
                offset: start,
                needed: 2,
                remaining: input.len().saturating_sub(start),
            })?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32, CanonicalDecodingError> {
    let start = *offset;
    let bytes: [u8; 4] =
        take(input, offset, 4)?
            .try_into()
            .map_err(|_| CanonicalDecodingError::Truncated {
                offset: start,
                needed: 4,
                remaining: input.len().saturating_sub(start),
            })?;
    Ok(u32::from_le_bytes(bytes))
}

fn take<'a>(
    input: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], CanonicalDecodingError> {
    let start = *offset;
    let remaining = input.len().saturating_sub(start);
    let Some(end) = start.checked_add(length) else {
        return Err(CanonicalDecodingError::Truncated {
            offset: start,
            needed: length,
            remaining,
        });
    };
    if end > input.len() {
        return Err(CanonicalDecodingError::Truncated {
            offset: start,
            needed: length,
            remaining,
        });
    }
    *offset = end;
    Ok(&input[start..end])
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

/// Decodes one self-describing digest without changing its stable encoding.
pub fn decode_digest32(input: &[u8]) -> Result<Digest32, CanonicalDecodingError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(0x0103)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let algorithm_id: u16 = frame.required_u16(1)?;
    let algorithm: HashAlgorithmId = HashAlgorithmId::try_from(algorithm_id)
        .map_err(|_| CanonicalDecodingError::UnknownHashAlgorithmId(algorithm_id))?;
    let encoded_digest: &[u8] = frame.required_field(2)?;
    let digest_bytes: [u8; 32] =
        encoded_digest
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 32,
                actual: encoded_digest.len(),
            })?;
    Ok(Digest32::new(algorithm, digest_bytes))
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

        let node_event = encode_hash_domain(HashDomain::NodeEvent).unwrap();
        assert_eq!(hex(&node_event), "534e52450201010001000100020000000d00");

        let asset_id = encode_hash_domain(HashDomain::AssetId).unwrap();
        assert_eq!(hex(&asset_id), "534e52450201010001000100020000000e00");
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
        assert_eq!(decode_digest32(&bytes), Ok(digest));
    }

    #[test]
    fn digest_decoder_rejects_unknown_algorithms_and_wrong_lengths() {
        let mut unknown = CanonicalStruct::new(0x0103, 1);
        unknown.field_u16(1, 0xffff).unwrap();
        unknown.field_bytes(2, [0x11; 32]).unwrap();
        assert_eq!(
            decode_digest32(&unknown.finish().unwrap()),
            Err(CanonicalDecodingError::UnknownHashAlgorithmId(0xffff))
        );

        let mut short = CanonicalStruct::new(0x0103, 1);
        short
            .field_u16(1, HashAlgorithmId::Sha2_256.as_u16())
            .unwrap();
        short.field_bytes(2, [0x11; 31]).unwrap();
        assert_eq!(
            decode_digest32(&short.finish().unwrap()),
            Err(CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 32,
                actual: 31,
            })
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

    #[test]
    fn decoder_round_trips_fields_without_copying() {
        let mut canonical = CanonicalStruct::new(0x2345, 7);
        canonical.field_str(1, "sunrise").unwrap();
        canonical.field_u16(2, 0x1234).unwrap();
        canonical.field_u32(3, 0x1234_5678).unwrap();
        canonical.field_u64(4, 0x0123_4567_89ab_cdef).unwrap();
        let encoded = canonical.finish().unwrap();

        let decoded = decode_canonical_frame(&encoded).unwrap();
        assert_eq!(decoded.type_id(), 0x2345);
        assert_eq!(decoded.version(), 7);
        assert_eq!(decoded.field_count(), 4);
        assert_eq!(decoded.required_str(1), Ok("sunrise"));
        assert_eq!(decoded.required_u16(2), Ok(0x1234));
        assert_eq!(decoded.required_u32(3), Ok(0x1234_5678));
        assert_eq!(decoded.required_u64(4), Ok(0x0123_4567_89ab_cdef));
        assert_eq!(decoded.field(9), None);
        assert_eq!(decoded.require_type(0x2345), Ok(()));
        assert_eq!(decoded.require_version(7), Ok(()));
    }

    #[test]
    fn every_truncated_prefix_is_rejected() {
        let encoded =
            encode_digest32(&Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32])).unwrap();

        for end in 0..encoded.len() {
            assert!(matches!(
                decode_canonical_frame(&encoded[..end]),
                Err(CanonicalDecodingError::Truncated { .. })
            ));
        }
        assert!(decode_canonical_frame(&encoded).is_ok());
    }

    #[test]
    fn decoder_rejects_magic_trailing_bytes_and_oversized_frames() {
        let mut invalid_magic = encode_hash_algorithm_id(HashAlgorithmId::Sha2_256).unwrap();
        invalid_magic[0] ^= 0xff;
        assert_eq!(
            decode_canonical_frame(&invalid_magic),
            Err(CanonicalDecodingError::InvalidMagic)
        );

        let mut trailing = encode_hash_algorithm_id(HashAlgorithmId::Sha2_256).unwrap();
        trailing.push(0);
        assert_eq!(
            decode_canonical_frame(&trailing),
            Err(CanonicalDecodingError::TrailingBytes(1))
        );

        let oversized = vec![0_u8; MAX_CANONICAL_FRAME_BYTES + 1];
        assert_eq!(
            decode_canonical_frame(&oversized),
            Err(CanonicalDecodingError::FrameTooLarge(
                MAX_CANONICAL_FRAME_BYTES + 1
            ))
        );
    }

    #[test]
    fn decoder_rejects_duplicate_and_out_of_order_fields() {
        let duplicate = concat!("534e5245012001000200", "010001000000aa", "010001000000bb");
        let out_of_order = concat!("534e5245012001000200", "020001000000aa", "010001000000bb");

        assert_eq!(
            decode_canonical_frame(&decode_hex(duplicate)),
            Err(CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 1,
                current: 1,
            })
        );
        assert_eq!(
            decode_canonical_frame(&decode_hex(out_of_order)),
            Err(CanonicalDecodingError::NonCanonicalFieldOrder {
                previous: 2,
                current: 1,
            })
        );
    }

    #[test]
    fn typed_accessors_reject_missing_wrong_length_and_invalid_utf8() {
        let mut canonical = CanonicalStruct::new(0x2002, 1);
        canonical.field_bytes(1, [0xff]).unwrap();
        canonical.field_bytes(2, [1, 2, 3]).unwrap();
        let encoded = canonical.finish().unwrap();
        let decoded = decode_canonical_frame(&encoded).unwrap();

        assert_eq!(
            decoded.required_field(9),
            Err(CanonicalDecodingError::MissingField(9))
        );
        assert_eq!(
            decoded.require_only_fields(&[1]),
            Err(CanonicalDecodingError::UnexpectedField(2))
        );
        assert_eq!(decoded.require_only_fields(&[1, 2]), Ok(()));
        assert_eq!(
            decoded.required_u16(2),
            Err(CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(
            decoded.required_str(1),
            Err(CanonicalDecodingError::InvalidUtf8(1))
        );
        assert_eq!(
            decoded.require_type(0x9999),
            Err(CanonicalDecodingError::UnexpectedTypeId {
                expected: 0x9999,
                actual: 0x2002,
            })
        );
        assert_eq!(
            decoded.require_version(2),
            Err(CanonicalDecodingError::UnexpectedVersion {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn declared_field_length_cannot_escape_input() {
        let mut encoded = encode_hash_algorithm_id(HashAlgorithmId::Sha2_256).unwrap();
        encoded[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode_canonical_frame(&encoded),
            Err(CanonicalDecodingError::Truncated { .. })
        ));
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]);
                let low = hex_nibble(pair[1]);
                (high << 4) | low
            })
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        }
    }
}
