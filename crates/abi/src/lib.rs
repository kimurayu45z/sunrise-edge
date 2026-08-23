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

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use objects::{AccessMode, ObjectRef, encode_access_mode, encode_object_ref};
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
    /// An object encoding error occurred.
    Object(objects::ObjectError),
    /// The manifest contains more entries than can be encoded.
    ManifestTooLarge(usize),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
            Self::ManifestTooLarge(n) => write!(f, "manifest has {n} entries, exceeds maximum"),
        }
    }
}

impl Error for AbiError {}

impl From<CanonicalEncodingError> for AbiError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
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
/// Callers are responsible for ensuring that the same object does not
/// appear more than once (duplicate entries are a protocol error and will
/// be rejected by validators).
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
