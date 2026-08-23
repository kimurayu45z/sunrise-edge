#![forbid(unsafe_code)]

//! Versioned object identifiers and canonical object references.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32};
use core::fmt;
use protocol_types::Digest32;
use std::error::Error;

const OBJECT_ID_TYPE_ID: u16 = 0x4001;
const ADDRESS_TYPE_ID: u16 = 0x4002;
const OWNER_TYPE_ID: u16 = 0x4003;
const OBJECT_REF_TYPE_ID: u16 = 0x4004;
const OBJECT_TYPE_ID: u16 = 0x4005;
const ACCESS_MODE_TYPE_ID: u16 = 0x4006;
const ENCODING_VERSION: u16 = 1;
const IDENTIFIER_LEN: usize = 32;

/// Errors returned by object model helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// An object identifier had the wrong length.
    InvalidObjectIdLength(usize),
    /// An address had the wrong length.
    InvalidAddressLength(usize),
    /// The access mode identifier is unknown.
    UnknownAccessMode(u8),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObjectIdLength(length) => write!(
                f,
                "object identifiers must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::InvalidAddressLength(length) => {
                write!(f, "addresses must be {IDENTIFIER_LEN} bytes, got {length}")
            }
            Self::UnknownAccessMode(mode) => write!(f, "unknown access mode: {mode}"),
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for ObjectError {}

impl From<CanonicalEncodingError> for ObjectError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// A stable 32-byte object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId {
    bytes: [u8; IDENTIFIER_LEN],
}

impl ObjectId {
    /// Creates an object identifier.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates an object identifier from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self::new(bytes)
    }

    /// Parses an object identifier from a byte slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(ObjectError::InvalidObjectIdLength(bytes.len()));
        }

        let mut array = [0u8; IDENTIFIER_LEN];
        array.copy_from_slice(bytes);
        Ok(Self::new(array))
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.bytes
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A stable 32-byte address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    bytes: [u8; IDENTIFIER_LEN],
}

impl Address {
    /// Creates an address.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates an address from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self::new(bytes)
    }

    /// Parses an address from a byte slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(ObjectError::InvalidAddressLength(bytes.len()));
        }

        let mut array = [0u8; IDENTIFIER_LEN];
        array.copy_from_slice(bytes);
        Ok(Self::new(array))
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.bytes
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Ownership model for objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    /// An address-owned object.
    Address(Address),
    /// A shared object.
    Shared,
    /// An immutable object.
    Immutable,
    /// A system-owned object.
    System,
}

impl Owner {
    const fn tag(&self) -> u16 {
        match self {
            Self::Address(_) => 1,
            Self::Shared => 2,
            Self::Immutable => 3,
            Self::System => 4,
        }
    }
}

/// A versioned protocol object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Monotonic object version.
    pub version: u64,
    /// Current ownership mode.
    pub owner: Owner,
    /// Type fingerprint for the object's schema.
    pub type_hash: Digest32,
    /// Object schema version.
    pub schema_version: u32,
    /// Canonically encoded object bytes.
    pub data: Vec<u8>,
}

/// A transaction-stable object reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Version used for replay protection.
    pub version: u64,
    /// Digest of the referenced object version.
    pub digest: Digest32,
}

/// Access mode requested for an object.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// Read-only access.
    Read = 1,
    /// Mutable access.
    Write = 2,
    /// Consuming access.
    Consume = 3,
}

impl AccessMode {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AccessMode {
    type Error = ObjectError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Consume),
            other => Err(ObjectError::UnknownAccessMode(other)),
        }
    }
}

/// Encodes an object identifier.
pub fn encode_object_id(id: &ObjectId) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OBJECT_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, id.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes an address.
pub fn encode_address(address: &Address) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(ADDRESS_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, address.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes an owner value.
pub fn encode_owner(owner: &Owner) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, owner.tag())?;
    if let Owner::Address(address) = owner {
        canonical.field_bytes(2, encode_address(address)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes an object reference.
pub fn encode_object_ref(object_ref: &ObjectRef) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OBJECT_REF_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_id(&object_ref.id)?)?;
    canonical.field_u64(2, object_ref.version)?;
    canonical.field_bytes(3, encode_digest32(&object_ref.digest)?)?;
    Ok(canonical.finish()?)
}

/// Encodes an object.
pub fn encode_object(object: &Object) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OBJECT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_id(&object.id)?)?;
    canonical.field_u64(2, object.version)?;
    canonical.field_bytes(3, encode_owner(&object.owner)?)?;
    canonical.field_bytes(4, encode_digest32(&object.type_hash)?)?;
    canonical.field_u32(5, object.schema_version)?;
    canonical.field_bytes(6, object.data.clone())?;
    Ok(canonical.finish()?)
}

/// Encodes an access mode.
pub fn encode_access_mode(mode: AccessMode) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(ACCESS_MODE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, [mode.as_u8()])?;
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Digest32, HashAlgorithmId};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn object_id_display_is_hex() {
        let id = ObjectId::new([0xab; IDENTIFIER_LEN]);
        assert_eq!(id.to_string(), "ab".repeat(IDENTIFIER_LEN));
    }

    #[test]
    fn object_ref_encodes_deterministically() {
        let object_ref = ObjectRef {
            id: ObjectId::new([0x11; IDENTIFIER_LEN]),
            version: 7,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; IDENTIFIER_LEN]),
        };

        let left = encode_object_ref(&object_ref).unwrap();
        let right = encode_object_ref(&object_ref).unwrap();

        assert_eq!(left, right);
        assert_eq!(
            hex(&left),
            concat!(
                "534e5245044001000300",
                "010030000000",
                "534e5245014001000100",
                "0100200000001111111111111111111111111111111111111111111111111111111111111111",
                "0200080000000700000000000000",
                "030038000000",
                "534e5245030101000200",
                "0100020000000100",
                "0200200000002222222222222222222222222222222222222222222222222222222222222222"
            )
        );
    }

    #[test]
    fn owner_variants_encode_differently() {
        let address_owner =
            encode_owner(&Owner::Address(Address::new([0x44; IDENTIFIER_LEN]))).unwrap();
        let shared_owner = encode_owner(&Owner::Shared).unwrap();
        let immutable_owner = encode_owner(&Owner::Immutable).unwrap();
        let system_owner = encode_owner(&Owner::System).unwrap();

        assert_ne!(address_owner, shared_owner);
        assert_ne!(shared_owner, immutable_owner);
        assert_ne!(immutable_owner, system_owner);
        assert_ne!(address_owner, system_owner);
    }

    #[test]
    fn short_identifier_slices_are_rejected() {
        assert_eq!(
            ObjectId::try_from_slice(&[0u8; 31]),
            Err(ObjectError::InvalidObjectIdLength(31))
        );
        assert_eq!(
            Address::try_from_slice(&[0u8; 31]),
            Err(ObjectError::InvalidAddressLength(31))
        );
    }
}
