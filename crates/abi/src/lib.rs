#![forbid(unsafe_code)]

//! ABI-driven concurrency protocol for Sunrise Edge.
//!
//! The ABI is not merely a function signature registry – it is a
//! protocol-level manifest that declares:
//!
//! * which objects a transaction touches,
//! * the access mode for each object ([`AccessMode::Read`],
//!   [`AccessMode::Write`], or [`AccessMode::Consume`]),
//! * capability requirements and execution limits.
//!
//! Validators use the [`AccessManifest`] to perform conflict detection and
//! enable fine-grained parallel execution of non-conflicting transactions
//! without global ordering (fast path).

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use objects::{
    AccessMode, ObjectId, ObjectRef, decode_access_mode, decode_object_ref, encode_access_mode,
    encode_object_ref,
};
use std::error::Error;

// ── type-id constants ──────────────────────────────────────────────────────
const ACCESS_ENTRY_TYPE_ID: u16 = 0x5001;
const ACCESS_MANIFEST_TYPE_ID: u16 = 0x5002;
const ENCODING_VERSION: u16 = 1;

// ── error type ────────────────────────────────────────────────────────────

/// Errors produced by the ABI crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// An object encoding or decoding error occurred.
    Object(objects::ObjectError),
    /// The manifest contains more entries than can be encoded, or more
    /// entries than the caller's bound allows while decoding.
    ManifestTooLarge(usize),
    /// The manifest's declared entry count does not match its actual field
    /// layout.
    NonCanonicalManifestLayout {
        /// The entry count declared in field 1.
        declared_count: usize,
        /// The total number of fields actually present in the frame.
        field_count: usize,
    },
    /// The manifest declares the same object more than once.
    DuplicateObjectId(ObjectId),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::CanonicalDecoding(e) => write!(f, "canonical decoding error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
            Self::ManifestTooLarge(n) => write!(f, "manifest has {n} entries, exceeds maximum"),
            Self::NonCanonicalManifestLayout {
                declared_count,
                field_count,
            } => write!(
                f,
                "manifest declares {declared_count} entries but frame has {field_count} fields"
            ),
            Self::DuplicateObjectId(id) => {
                write!(f, "access manifest declares object {id} more than once")
            }
        }
    }
}

impl Error for AbiError {}

impl From<CanonicalEncodingError> for AbiError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for AbiError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<objects::ObjectError> for AbiError {
    fn from(value: objects::ObjectError) -> Self {
        Self::Object(value)
    }
}

// ── AccessEntry ───────────────────────────────────────────────────────────

/// A single entry in an [`AccessManifest`]: one object and the requested
/// access mode.
///
/// Transactions must declare every object they access in their manifest
/// before execution begins.  Contracts that attempt to read or write an
/// object absent from the manifest trigger an execution trap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEntry {
    /// The versioned, digest-authenticated reference to the object.
    pub object_ref: ObjectRef,
    /// The access mode requested for this object.
    pub mode: AccessMode,
}

/// Encodes an [`AccessEntry`] in the canonical wire format.
pub fn encode_access_entry(entry: &AccessEntry) -> Result<Vec<u8>, AbiError> {
    let mut canonical = CanonicalStruct::new(ACCESS_ENTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_ref(&entry.object_ref)?)?;
    canonical.field_bytes(2, encode_access_mode(entry.mode)?)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`AccessEntry`] without changing its stable encoding.
pub fn decode_access_entry(input: &[u8]) -> Result<AccessEntry, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_ENTRY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    Ok(AccessEntry {
        object_ref: decode_object_ref(frame.required_field(1)?)?,
        mode: decode_access_mode(frame.required_field(2)?)?,
    })
}

// ── AccessManifest ────────────────────────────────────────────────────────

/// The complete set of object accesses declared by a transaction.
///
/// The manifest is used by validators to:
///
/// 1. Verify that every object a contract accesses is explicitly declared.
/// 2. Detect write–write and write–consume conflicts between concurrent
///    transactions.
/// 3. Schedule non-conflicting transactions for parallel execution.
///
/// Entry order is preserved so that canonical encoding is deterministic.
/// Construction through [`AccessManifest::push`] does not itself enforce
/// uniqueness; [`decode_access_manifest`] rejects a wire manifest that
/// declares the same [`objects::ObjectId`] more than once, since duplicate
/// entries are a protocol error that validators must reject.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AccessManifest {
    /// Ordered list of object accesses.
    pub entries: Vec<AccessEntry>,
}

impl AccessManifest {
    /// Creates an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry to the manifest.
    pub fn push(&mut self, entry: AccessEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the manifest has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Encodes an [`AccessManifest`] in the canonical wire format.
///
/// Each entry is encoded with [`encode_access_entry`] and stored as a
/// length-prefixed blob under a sequential field id (starting at 1).
pub fn encode_access_manifest(manifest: &AccessManifest) -> Result<Vec<u8>, AbiError> {
    // Field ids for entries start at 2 and go up to u16::MAX, so at most
    // u16::MAX - 1 = 65534 entries are encodable.
    const MAX_ENTRIES: usize = u16::MAX as usize - 1;
    if manifest.entries.len() > MAX_ENTRIES {
        return Err(AbiError::ManifestTooLarge(manifest.entries.len()));
    }
    let mut canonical = CanonicalStruct::new(ACCESS_MANIFEST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, manifest.entries.len() as u32)?;
    for (index, entry) in manifest.entries.iter().enumerate() {
        // field ids 2, 3, 4, … for entries 0, 1, 2, …
        let field_id = (index + 2) as u16;
        canonical.field_bytes(field_id, encode_access_entry(entry)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`AccessManifest`] without changing its stable
/// encoding.
///
/// `max_entries` bounds the declared entry count *before* any entry is
/// decoded or copied, so a caller can apply a tighter, context-specific
/// ceiling than the shared canonical frame bound. The declared count in
/// field 1 must exactly match the number of remaining fields in the frame;
/// any other layout is rejected as non-canonical. The decoded entries must
/// not repeat the same [`objects::ObjectId`].
pub fn decode_access_manifest(
    input: &[u8],
    max_entries: usize,
) -> Result<AccessManifest, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_MANIFEST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let declared_count = frame.required_u32(1)?;
    let declared_count =
        usize::try_from(declared_count).map_err(|_| AbiError::ManifestTooLarge(usize::MAX))?;
    if declared_count > max_entries {
        return Err(AbiError::ManifestTooLarge(declared_count));
    }

    let expected_field_count = declared_count
        .checked_add(1)
        .ok_or(AbiError::ManifestTooLarge(usize::MAX))?;
    if frame.field_count() != expected_field_count {
        return Err(AbiError::NonCanonicalManifestLayout {
            declared_count,
            field_count: frame.field_count(),
        });
    }

    let mut entries = Vec::with_capacity(declared_count);
    for index in 0..declared_count {
        let field_id =
            u16::try_from(index + 2).map_err(|_| AbiError::ManifestTooLarge(declared_count))?;
        entries.push(decode_access_entry(frame.required_field(field_id)?)?);
    }

    let mut object_ids: Vec<ObjectId> = entries.iter().map(|entry| entry.object_ref.id).collect();
    object_ids.sort_unstable();
    if let Some(window) = object_ids.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(AbiError::DuplicateObjectId(window[0]));
    }

    Ok(AccessManifest { entries })
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use objects::{ObjectId, ObjectRef};
    use protocol_types::{Digest32, HashAlgorithmId};

    fn sample_object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
        }
    }

    #[test]
    fn access_entry_encodes_deterministically() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x11, 1, 0x22),
            mode: AccessMode::Read,
        };

        let left = encode_access_entry(&entry).unwrap();
        let right = encode_access_entry(&entry).unwrap();
        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn different_access_modes_produce_different_encodings() {
        let make = |mode| AccessEntry {
            object_ref: sample_object_ref(0xAA, 3, 0xBB),
            mode,
        };

        let read = encode_access_entry(&make(AccessMode::Read)).unwrap();
        let write = encode_access_entry(&make(AccessMode::Write)).unwrap();
        let consume = encode_access_entry(&make(AccessMode::Consume)).unwrap();

        assert_ne!(read, write);
        assert_ne!(write, consume);
        assert_ne!(read, consume);
    }

    #[test]
    fn access_manifest_encodes_deterministically() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x10),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x20),
            mode: AccessMode::Write,
        });

        let left = encode_access_manifest(&manifest).unwrap();
        let right = encode_access_manifest(&manifest).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn empty_manifest_encodes_without_error() {
        let manifest = AccessManifest::new();
        let encoded = encode_access_manifest(&manifest).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn manifest_entry_order_affects_encoding() {
        let e1 = AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x11),
            mode: AccessMode::Read,
        };
        let e2 = AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x22),
            mode: AccessMode::Write,
        };

        let mut m1 = AccessManifest::new();
        m1.push(e1.clone());
        m1.push(e2.clone());

        let mut m2 = AccessManifest::new();
        m2.push(e2.clone());
        m2.push(e1.clone());

        assert_ne!(
            encode_access_manifest(&m1).unwrap(),
            encode_access_manifest(&m2).unwrap()
        );
    }

    #[test]
    fn manifest_len_and_is_empty() {
        let mut manifest = AccessManifest::new();
        assert!(manifest.is_empty());
        assert_eq!(manifest.len(), 0);

        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0xFF, 0, 0xFF),
            mode: AccessMode::Consume,
        });

        assert!(!manifest.is_empty());
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn access_entry_decoder_round_trips_existing_canonical_bytes() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x61, 4, 0x62),
            mode: AccessMode::Consume,
        };
        let canonical: Vec<u8> = encode_access_entry(&entry).unwrap();
        assert_eq!(decode_access_entry(&canonical), Ok(entry));
    }

    #[test]
    fn access_entry_decoder_rejects_wrong_type() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x63, 1, 0x64),
            mode: AccessMode::Read,
        };
        let mut wrong_type: Vec<u8> = encode_access_entry(&entry).unwrap();
        wrong_type[4..6].copy_from_slice(&0x5999_u16.to_le_bytes());
        assert!(matches!(
            decode_access_entry(&wrong_type),
            Err(AbiError::CanonicalDecoding(
                canonical_encoding::CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    #[test]
    fn access_manifest_decoder_round_trips_existing_canonical_bytes() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x10),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x20),
            mode: AccessMode::Write,
        });

        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        assert_eq!(decode_access_manifest(&canonical, 64), Ok(manifest));
    }

    #[test]
    fn access_manifest_decoder_round_trips_empty_manifest() {
        let manifest = AccessManifest::new();
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        assert_eq!(decode_access_manifest(&canonical, 64), Ok(manifest));
    }

    #[test]
    fn access_manifest_decoder_rejects_entries_above_caller_bound() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x71, 1, 0x72),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x73, 2, 0x74),
            mode: AccessMode::Write,
        });
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();

        assert_eq!(
            decode_access_manifest(&canonical, 1),
            Err(AbiError::ManifestTooLarge(2))
        );
    }

    #[test]
    fn access_manifest_decoder_rejects_declared_count_mismatch() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x75, 1, 0x76),
            mode: AccessMode::Read,
        });
        let mut encoded: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        // Field 1 (`declared_count`) is a fixed-width little-endian `u32`
        // located right after the 10-byte frame header and 6-byte field
        // header; overwrite it so it no longer matches the actual field
        // count.
        encoded[16..20].copy_from_slice(&2_u32.to_le_bytes());

        assert_eq!(
            decode_access_manifest(&encoded, 64),
            Err(AbiError::NonCanonicalManifestLayout {
                declared_count: 2,
                field_count: 2,
            })
        );
    }

    #[test]
    fn access_manifest_decoder_rejects_duplicate_object_ids() {
        let object_ref = sample_object_ref(0x77, 1, 0x78);
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        });
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();

        assert_eq!(
            decode_access_manifest(&canonical, 64),
            Err(AbiError::DuplicateObjectId(ObjectId::new([0x77; 32])))
        );
    }

    /// Regression test: a stable hex vector for the canonical encoding of a
    /// one-entry manifest so that accidental encoding changes are caught.
    #[test]
    fn manifest_stable_encoding_vector() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x11, 7, 0x22),
            mode: AccessMode::Write,
        });

        let encoded = encode_access_manifest(&manifest).unwrap();
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();

        // This vector must remain stable across versions.
        assert_eq!(
            hex,
            "534e5245025001000200010004000000010000000200b3000000534e524501500100020001008c000000534e5245044001000300010030000000534e524501400100010001002000000011111111111111111111111111111111111111111111111111111111111111110200080000000700000000000000030038000000534e524503010100020001000200000001000200200000002222222222222222222222222222222222222222222222222222222222222222020011000000534e524506400100010001000100000002"
        );
    }
}
