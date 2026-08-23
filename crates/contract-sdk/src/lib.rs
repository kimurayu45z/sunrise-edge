//! # Sunrise Edge Contract SDK
//!
//! Provides the Rust API that smart contracts use to interact with the
//! Sunrise Edge execution environment.  The crate is `no_std`-compatible and
//! allocator-agnostic so the same source can target any WASM toolchain.
//!
//! ## Host ABI
//!
//! The execution engine exposes a set of functions in the `"env"` import
//! module.  Contracts must not call these directly; use the safe wrappers in
//! this crate instead.
//!
//! ## Object indices
//!
//! The `inputs` slice passed to the contract corresponds 1-to-1 with the
//! `AccessManifest` entries in the submitted transaction.  Pass the
//! zero-based index when calling object-level functions.
//!
//! ## Owner tags
//!
//! When creating an object the `owner_tag` parameter encodes the ownership
//! model:
//!
//! | `owner_tag` | [`Owner`] variant | Notes |
//! |-------------|-------------------|-------|
//! | `0`         | `Shared`          |       |
//! | `1`         | `Immutable`       |       |
//! | `2`         | `System`          |       |
//! | `3`         | `Address`         | `owner_addr` must be 32 bytes |
//!
//! ## Type hash encoding
//!
//! The `type_hash` slice passed to [`create_object`] must be exactly 34
//! bytes: 2 big-endian bytes encoding the `HashAlgorithmId` followed by 32
//! hash bytes.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

// ── re-exports ────────────────────────────────────────────────────────────

pub use owner::OWNER_TAG_ADDRESS;
pub use owner::OWNER_TAG_IMMUTABLE;
pub use owner::OWNER_TAG_SHARED;
pub use owner::OWNER_TAG_SYSTEM;
pub use owner::Owner;

// ── raw host bindings ─────────────────────────────────────────────────────

/// Raw bindings to the host functions imported from the `"env"` module.
///
/// All pointer arguments are byte offsets into the contract's linear memory.
/// Prefer the safe wrappers in this crate.
pub mod host {
    /// Number of resolved input objects passed to this invocation.
    pub fn get_object_count() -> i32 {
        unsafe { raw::get_object_count() }
    }

    /// Byte length of `object[index].data`, or `-1` if the index is invalid
    /// or the object has already been consumed.
    pub fn get_object_data_len(index: i32) -> i32 {
        unsafe { raw::get_object_data_len(index) }
    }

    /// Copy `object[index].data[offset..]` into the slice at `buf_ptr`.
    /// Returns the number of bytes written, or `-1` on error.
    ///
    /// # Safety
    ///
    /// `buf_ptr` must point to at least `buf_len` bytes of writable memory
    /// within the WASM linear memory region.
    pub unsafe fn read_object_data(index: i32, offset: i32, buf_ptr: *mut u8, buf_len: i32) -> i32 {
        unsafe { raw::read_object_data(index, offset, buf_ptr, buf_len) }
    }

    /// Overwrite `object[index].data` with the bytes at `data_ptr`.
    /// The object must have been declared with `Write` access.
    /// Returns `0` on success, `-1` on error.
    ///
    /// # Safety
    ///
    /// `data_ptr` must point to at least `data_len` readable bytes within
    /// the WASM linear memory region.
    pub unsafe fn write_object_data(index: i32, data_ptr: *const u8, data_len: i32) -> i32 {
        unsafe { raw::write_object_data(index, data_ptr, data_len) }
    }

    /// Mark `object[index]` as consumed / deleted.
    /// The object must have been declared with `Consume` access.
    /// Returns `0` on success, `-1` on error.
    pub fn consume_object(index: i32) -> i32 {
        unsafe { raw::consume_object(index) }
    }

    /// Create a new object.
    ///
    /// - `data_ptr / data_len` — object data bytes.
    /// - `type_hash_ptr` — 34-byte type hash (2-byte big-endian algo-id +
    ///   32 hash bytes).
    /// - `schema_version` — schema version for the object type.
    /// - `owner_tag` — ownership model (see crate docs).
    /// - `owner_addr_ptr` — 32-byte address, only read when `owner_tag == 3`.
    ///
    /// Returns `0` on success, `-1` on error.
    ///
    /// # Safety
    ///
    /// All pointer arguments must point to valid memory within the WASM
    /// linear memory region for the stated lengths.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn create_object(
        data_ptr: *const u8,
        data_len: i32,
        type_hash_ptr: *const u8,
        schema_version: i32,
        owner_tag: i32,
        owner_addr_ptr: *const u8,
    ) -> i32 {
        unsafe {
            raw::create_object(
                data_ptr,
                data_len,
                type_hash_ptr,
                schema_version,
                owner_tag,
                owner_addr_ptr,
            )
        }
    }

    /// Emit an event.
    ///
    /// - `type_tag_ptr / type_tag_len` — opaque type tag identifying the
    ///   event schema.
    /// - `data_ptr / data_len` — canonically encoded event data.
    ///
    /// Returns `0` on success, `-1` on error.
    ///
    /// # Safety
    ///
    /// All pointer arguments must point to valid memory within the WASM
    /// linear memory region for the stated lengths.
    pub unsafe fn emit_event(
        type_tag_ptr: *const u8,
        type_tag_len: i32,
        data_ptr: *const u8,
        data_len: i32,
    ) -> i32 {
        unsafe { raw::emit_event(type_tag_ptr, type_tag_len, data_ptr, data_len) }
    }

    /// Byte length of the transaction args payload.
    pub fn get_args_len() -> i32 {
        unsafe { raw::get_args_len() }
    }

    /// Copy `args[offset..]` into the slice at `buf_ptr`.
    /// Returns the number of bytes written, or `-1` on error.
    ///
    /// # Safety
    ///
    /// `buf_ptr` must point to at least `buf_len` bytes of writable memory
    /// within the WASM linear memory region.
    pub unsafe fn read_args(offset: i32, buf_ptr: *mut u8, buf_len: i32) -> i32 {
        unsafe { raw::read_args(offset, buf_ptr, buf_len) }
    }

    /// Trap the contract with the given message.  Does not return.
    ///
    /// # Safety
    ///
    /// `msg_ptr` must point to at least `msg_len` readable bytes within
    /// the WASM linear memory region.  The bytes should be valid UTF-8.
    pub unsafe fn abort(msg_ptr: *const u8, msg_len: i32) -> ! {
        unsafe { raw::abort(msg_ptr, msg_len) };
        // SAFETY: abort is declared unreachable by the host.
        core::unreachable!()
    }

    // Raw extern declarations — not pub to enforce use of the wrappers above.
    mod raw {
        // On WASM targets these are resolved by the host at link time.
        // On native targets (e.g. unit test builds) they are replaced by
        // panicking stubs so the tests can link.
        #[cfg(target_arch = "wasm32")]
        #[link(wasm_import_module = "env")]
        unsafe extern "C" {
            pub fn get_object_count() -> i32;
            pub fn get_object_data_len(index: i32) -> i32;
            pub fn read_object_data(index: i32, offset: i32, buf_ptr: *mut u8, buf_len: i32)
            -> i32;
            pub fn write_object_data(index: i32, data_ptr: *const u8, data_len: i32) -> i32;
            pub fn consume_object(index: i32) -> i32;
            pub fn create_object(
                data_ptr: *const u8,
                data_len: i32,
                type_hash_ptr: *const u8,
                schema_version: i32,
                owner_tag: i32,
                owner_addr_ptr: *const u8,
            ) -> i32;
            pub fn emit_event(
                type_tag_ptr: *const u8,
                type_tag_len: i32,
                data_ptr: *const u8,
                data_len: i32,
            ) -> i32;
            pub fn get_args_len() -> i32;
            pub fn read_args(offset: i32, buf_ptr: *mut u8, buf_len: i32) -> i32;
            pub fn abort(msg_ptr: *const u8, msg_len: i32);
        }

        // Panicking stubs used when the crate is built for a native target
        // (e.g. during `cargo test`).  These are never called by tests that
        // exercise only the pure-Rust validation paths.
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn get_object_count() -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn get_object_data_len(_: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn read_object_data(_: i32, _: i32, _: *mut u8, _: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn write_object_data(_: i32, _: *const u8, _: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn consume_object(_: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn create_object(
            _: *const u8,
            _: i32,
            _: *const u8,
            _: i32,
            _: i32,
            _: *const u8,
        ) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn emit_event(_: *const u8, _: i32, _: *const u8, _: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn get_args_len() -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn read_args(_: i32, _: *mut u8, _: i32) -> i32 {
            panic!("host function not available outside WASM")
        }
        #[cfg(not(target_arch = "wasm32"))]
        pub unsafe fn abort(_: *const u8, _: i32) {
            panic!("host function not available outside WASM")
        }
    }
}

// ── error type ────────────────────────────────────────────────────────────

/// Errors returned by the safe SDK wrappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// An object index was out of range or the object was already consumed.
    InvalidObjectIndex(u32),
    /// The object does not have the required access mode for the operation.
    AccessDenied(u32),
    /// A pointer or length argument was out of bounds.
    OutOfBounds,
    /// The type hash slice did not have the required 34-byte length.
    InvalidTypeHashLength(usize),
    /// An unknown owner tag was provided to [`create_object`].
    UnknownOwnerTag(i32),
    /// The address slice for an `Address` owner did not have 32 bytes.
    InvalidAddressLength(usize),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObjectIndex(i) => write!(f, "invalid object index: {i}"),
            Self::AccessDenied(i) => write!(f, "access denied for object index: {i}"),
            Self::OutOfBounds => write!(f, "pointer or length out of bounds"),
            Self::InvalidTypeHashLength(n) => {
                write!(f, "type hash must be 34 bytes, got {n}")
            }
            Self::UnknownOwnerTag(t) => write!(f, "unknown owner tag: {t}"),
            Self::InvalidAddressLength(n) => {
                write!(f, "address must be 32 bytes, got {n}")
            }
        }
    }
}

// ── owner type ────────────────────────────────────────────────────────────

pub mod owner {
    /// Owner tag: shared object.
    pub const OWNER_TAG_SHARED: i32 = 0;
    /// Owner tag: immutable object.
    pub const OWNER_TAG_IMMUTABLE: i32 = 1;
    /// Owner tag: system-owned object.
    pub const OWNER_TAG_SYSTEM: i32 = 2;
    /// Owner tag: address-owned object.  Requires a 32-byte address.
    pub const OWNER_TAG_ADDRESS: i32 = 3;

    /// Ownership specification for a new object.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Owner {
        /// The object is shared and accessible to any transaction.
        Shared,
        /// The object is immutable and cannot be mutated or consumed.
        Immutable,
        /// The object is owned by the protocol system.
        System,
        /// The object is owned by the given 32-byte address.
        Address([u8; 32]),
    }

    impl Owner {
        /// Returns the owner tag used in the host ABI.
        #[must_use]
        pub fn tag(&self) -> i32 {
            match self {
                Self::Shared => OWNER_TAG_SHARED,
                Self::Immutable => OWNER_TAG_IMMUTABLE,
                Self::System => OWNER_TAG_SYSTEM,
                Self::Address(_) => OWNER_TAG_ADDRESS,
            }
        }
    }
}

// ── safe object API ───────────────────────────────────────────────────────

/// Returns the number of resolved input objects for this invocation.
#[must_use]
pub fn object_count() -> u32 {
    host::get_object_count().max(0) as u32
}

/// Returns the byte length of `object[index].data`.
///
/// Returns `None` if the index is out of range or the object has been
/// consumed.
#[must_use]
pub fn object_data_len(index: u32) -> Option<u32> {
    let r = host::get_object_data_len(index as i32);
    if r < 0 { None } else { Some(r as u32) }
}

/// Reads and returns the data bytes of `object[index]`.
///
/// Returns `None` if the index is out of range or the object has been
/// consumed.
pub fn object_data(index: u32) -> Option<Vec<u8>> {
    let len = object_data_len(index)? as usize;
    let mut buf = alloc::vec![0u8; len];
    let written = unsafe { host::read_object_data(index as i32, 0, buf.as_mut_ptr(), len as i32) };
    if written < 0 { None } else { Some(buf) }
}

/// Overwrites `object[index].data` with `data`.
///
/// The object must have been declared with `Write` access in the transaction's
/// `AccessManifest`.
///
/// # Errors
///
/// Returns [`ContractError::AccessDenied`] if the object has read-only or
/// consume-only access, or [`ContractError::InvalidObjectIndex`] if the index
/// is out of range.
pub fn write_object(index: u32, data: &[u8]) -> Result<(), ContractError> {
    if index >= object_count() {
        return Err(ContractError::InvalidObjectIndex(index));
    }
    let rc = unsafe { host::write_object_data(index as i32, data.as_ptr(), data.len() as i32) };
    match rc {
        0 => Ok(()),
        _ => Err(ContractError::AccessDenied(index)),
    }
}

/// Consumes (deletes) `object[index]`.
///
/// The object must have been declared with `Consume` access in the
/// transaction's `AccessManifest`.
///
/// # Errors
///
/// Returns [`ContractError::AccessDenied`] if the object cannot be consumed,
/// or [`ContractError::InvalidObjectIndex`] if the index is out of range.
pub fn consume_object(index: u32) -> Result<(), ContractError> {
    if index >= object_count() {
        return Err(ContractError::InvalidObjectIndex(index));
    }
    let rc = host::consume_object(index as i32);
    match rc {
        0 => Ok(()),
        _ => Err(ContractError::AccessDenied(index)),
    }
}

/// Creates a new object and registers it in the execution effects.
///
/// - `data` — object payload bytes.
/// - `type_hash` — 34-byte type hash (2-byte big-endian `HashAlgorithmId`
///   followed by 32 hash bytes).
/// - `schema_version` — schema version for the object type.
/// - `owner` — ownership model for the new object.
///
/// # Errors
///
/// Returns [`ContractError::InvalidTypeHashLength`] if `type_hash` is not
/// 34 bytes, or [`ContractError::InvalidAddressLength`] if an address owner
/// provides a slice of the wrong length.
pub fn create_object(
    data: &[u8],
    type_hash: &[u8],
    schema_version: u32,
    owner: &Owner,
) -> Result<(), ContractError> {
    if type_hash.len() != 34 {
        return Err(ContractError::InvalidTypeHashLength(type_hash.len()));
    }
    let (owner_tag, addr_bytes) = match owner {
        Owner::Shared => (OWNER_TAG_SHARED, None),
        Owner::Immutable => (OWNER_TAG_IMMUTABLE, None),
        Owner::System => (OWNER_TAG_SYSTEM, None),
        Owner::Address(addr) => (OWNER_TAG_ADDRESS, Some(addr.as_ref())),
    };
    let addr_ptr = addr_bytes.map_or(core::ptr::null(), |a| a.as_ptr());
    let rc = unsafe {
        host::create_object(
            data.as_ptr(),
            data.len() as i32,
            type_hash.as_ptr(),
            schema_version as i32,
            owner_tag,
            addr_ptr,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(ContractError::OutOfBounds),
    }
}

/// Emits an event.
///
/// - `type_tag` — opaque tag identifying the event schema.
/// - `data` — canonically encoded event payload.
///
/// # Errors
///
/// Returns [`ContractError::OutOfBounds`] on failure.
pub fn emit_event(type_tag: &[u8], data: &[u8]) -> Result<(), ContractError> {
    let rc = unsafe {
        host::emit_event(
            type_tag.as_ptr(),
            type_tag.len() as i32,
            data.as_ptr(),
            data.len() as i32,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(ContractError::OutOfBounds),
    }
}

// ── args API ──────────────────────────────────────────────────────────────

/// Returns the byte length of the transaction args payload.
#[must_use]
pub fn args_len() -> u32 {
    host::get_args_len().max(0) as u32
}

/// Reads and returns the full transaction args payload.
pub fn args() -> Vec<u8> {
    let len = args_len() as usize;
    if len == 0 {
        return Vec::new();
    }
    let mut buf = alloc::vec![0u8; len];
    unsafe { host::read_args(0, buf.as_mut_ptr(), len as i32) };
    buf
}

// ── abort helper ─────────────────────────────────────────────────────────

/// Trap the contract with a human-readable message.  Does not return.
///
/// # Example
///
/// ```ignore
/// abort!("insufficient balance");
/// ```
#[macro_export]
macro_rules! abort {
    ($msg:literal) => {
        unsafe { $crate::host::abort($msg.as_ptr(), $msg.len() as i32) }
    };
    ($msg:expr) => {{
        let msg: &str = $msg;
        unsafe { $crate::host::abort(msg.as_ptr(), msg.len() as i32) }
    }};
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_tags_are_distinct() {
        assert_ne!(OWNER_TAG_SHARED, OWNER_TAG_IMMUTABLE);
        assert_ne!(OWNER_TAG_SHARED, OWNER_TAG_SYSTEM);
        assert_ne!(OWNER_TAG_SHARED, OWNER_TAG_ADDRESS);
        assert_ne!(OWNER_TAG_IMMUTABLE, OWNER_TAG_SYSTEM);
    }

    #[test]
    fn owner_tag_values() {
        assert_eq!(Owner::Shared.tag(), OWNER_TAG_SHARED);
        assert_eq!(Owner::Immutable.tag(), OWNER_TAG_IMMUTABLE);
        assert_eq!(Owner::System.tag(), OWNER_TAG_SYSTEM);
        assert_eq!(Owner::Address([0u8; 32]).tag(), OWNER_TAG_ADDRESS);
    }

    #[test]
    fn create_object_rejects_wrong_type_hash_length() {
        // Providing a 33-byte type hash should fail immediately without
        // calling any host function.
        let err = create_object(&[], &[0u8; 33], 1, &Owner::Shared).unwrap_err();
        assert_eq!(err, ContractError::InvalidTypeHashLength(33));
    }

    #[test]
    fn contract_error_display() {
        let e = ContractError::InvalidObjectIndex(7);
        let s = alloc::format!("{e}");
        assert!(s.contains("7"));
    }
}
