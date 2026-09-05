//! Explicit, development-only Ed25519 seed loading from a file path.
//!
//! This is not a keystore. There is no default or home-directory path: the
//! caller must name the seed file explicitly on every invocation
//! (`--seed-file <path>`), the seed is never accepted directly on argv, and
//! it is never printed. The file must be a regular file (not a symlink),
//! and on Unix must grant no permission bits to group or other. Its
//! contents must be exactly 64 lowercase-or-uppercase hexadecimal digits
//! plus at most one trailing `\n`.
//!
//! Validating a path and then opening it are two separate syscalls, which
//! on any POSIX filesystem leaves a time-of-check-to-time-of-use (TOCTOU)
//! window in which the path could be replaced (for example swapped for a
//! symlink to a different file an attacker can read, such as another
//! user's private key material) between the two. On Unix, this loader
//! closes that window by additionally comparing the pre-open path
//! metadata's stable device/inode identity against the metadata of the
//! already-opened file handle (which, once open, cannot itself be replaced
//! by a later filesystem change) and rejecting a mismatch before any byte
//! is read. This does not eliminate every possible race — a replacement
//! landing after the identity check but before the read would need to
//! preserve the same device/inode, which is not possible for a distinct
//! file — but it does close the specific symlink/replacement race described
//! above. On non-Unix platforms (none of which this workspace currently
//! targets; see `docs/architecture/README.md`/`README.md` for the supported Linux/macOS
//! platforms) neither the permission check nor this identity check runs, so
//! this protection is Unix-only.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::hex::{HexError, decode_hex_32};

const SEED_HEX_LEN: usize = 64;
/// One byte more than the longest accepted file body (64 hex digits plus one
/// trailing newline); reading this many bytes is enough to detect a longer
/// file without reading it in full.
const MAX_READ_LEN: usize = SEED_HEX_LEN + 2;

/// Fail-closed errors while loading a development seed file.
#[derive(Debug)]
pub enum SeedFileError {
    /// Reading file metadata or contents failed.
    Io(std::io::Error),
    /// The path is a symlink, which this loader never follows.
    Symlink,
    /// The path exists but is not a regular file.
    NotRegularFile,
    /// On Unix, the file grants a permission bit to group or other.
    InsecurePermissions {
        /// The file's mode bits (lowest 9 bits only).
        mode: u32,
    },
    /// On Unix, the file actually opened has a different device/inode
    /// identity than the path validated immediately beforehand, proving the
    /// path was replaced between validation and opening.
    PathReplacedDuringOpen,
    /// The file body was longer than the exact accepted length.
    TooLong,
    /// The file body was shorter than the exact accepted length.
    WrongLength {
        /// Bytes actually read.
        actual: usize,
    },
    /// The file body was not exactly 64 hexadecimal digits.
    InvalidHex(HexError),
}

impl fmt::Display for SeedFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read seed file: {error}"),
            Self::Symlink => f.write_str("seed file must not be a symlink"),
            Self::NotRegularFile => f.write_str("seed file must be a regular file"),
            Self::InsecurePermissions { mode } => write!(
                f,
                "seed file must grant no group/other permission bits, got mode {mode:03o}"
            ),
            Self::PathReplacedDuringOpen => f.write_str(
                "seed file path was replaced between validation and opening; refusing to read it",
            ),
            Self::TooLong => write!(
                f,
                "seed file must contain exactly {SEED_HEX_LEN} hex digits plus an optional trailing newline"
            ),
            Self::WrongLength { actual } => write!(
                f,
                "seed file must contain exactly {SEED_HEX_LEN} hex digits plus an optional trailing newline, got {actual} bytes"
            ),
            Self::InvalidHex(error) => write!(f, "seed file contents are invalid: {error}"),
        }
    }
}

impl std::error::Error for SeedFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidHex(error) => Some(error),
            _ => None,
        }
    }
}

/// Loads and strictly validates a 32-byte development seed from `path`.
///
/// The returned bytes must never be printed or logged by a caller.
pub fn load_dev_seed(path: &Path) -> Result<[u8; 32], SeedFileError> {
    let pre_open_metadata = fs::symlink_metadata(path).map_err(SeedFileError::Io)?;
    if pre_open_metadata.file_type().is_symlink() {
        return Err(SeedFileError::Symlink);
    }
    if !pre_open_metadata.is_file() {
        return Err(SeedFileError::NotRegularFile);
    }
    check_unix_permissions(&pre_open_metadata)?;
    #[cfg(unix)]
    let pre_open_identity = FileIdentity::from_metadata(&pre_open_metadata);

    let mut file = fs::File::open(path).map_err(SeedFileError::Io)?;

    // Re-validate the already-open handle rather than the path: a handle's
    // metadata cannot be changed by a later filesystem replacement of the
    // path, so this is immune to the same TOCTOU race as the initial check.
    let opened_metadata = file.metadata().map_err(SeedFileError::Io)?;
    if !opened_metadata.is_file() {
        return Err(SeedFileError::NotRegularFile);
    }
    check_unix_permissions(&opened_metadata)?;
    #[cfg(unix)]
    {
        let opened_identity = FileIdentity::from_metadata(&opened_metadata);
        if opened_identity != pre_open_identity {
            return Err(SeedFileError::PathReplacedDuringOpen);
        }
    }

    let mut buffer = Vec::with_capacity(MAX_READ_LEN);
    file.by_ref()
        .take(u64::try_from(MAX_READ_LEN).unwrap_or(u64::MAX))
        .read_to_end(&mut buffer)
        .map_err(SeedFileError::Io)?;

    let text_bytes: &[u8] = match buffer.len() {
        SEED_HEX_LEN => &buffer,
        len if len == SEED_HEX_LEN + 1 && buffer[SEED_HEX_LEN] == b'\n' => &buffer[..SEED_HEX_LEN],
        len if len > SEED_HEX_LEN + 1 => return Err(SeedFileError::TooLong),
        len => return Err(SeedFileError::WrongLength { actual: len }),
    };
    let text = std::str::from_utf8(text_bytes)
        .map_err(|_| SeedFileError::InvalidHex(HexError::InvalidDigit { field: "seed file" }))?;
    decode_hex_32("seed file", text).map_err(SeedFileError::InvalidHex)
}

#[cfg(unix)]
fn check_unix_permissions(metadata: &fs::Metadata) -> Result<(), SeedFileError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SeedFileError::InsecurePermissions { mode });
    }
    Ok(())
}

#[cfg(not(unix))]
const fn check_unix_permissions(_metadata: &fs::Metadata) -> Result<(), SeedFileError> {
    Ok(())
}

/// A file's stable identity on a POSIX filesystem: the device it resides on
/// plus its inode number. Two metadata snapshots of the same still-existing
/// file always report the same identity; two distinct files (even if one
/// replaced the other at the same path) essentially never share one, which
/// is exactly the property [`load_dev_seed`] relies on to detect a
/// path replaced between validation and opening.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(contents: &[u8]) -> Self {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-cli-seed-test-{}-{sequence}",
                std::process::id()
            ));
            let mut file = fs::File::create(&path).unwrap();
            file.write_all(contents).unwrap();
            drop(file);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ignored = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn loads_a_valid_seed_without_trailing_newline() {
        let hex = "a5".repeat(32);
        let file = TempFile::new(hex.as_bytes());
        assert_eq!(load_dev_seed(&file.0).unwrap(), [0xA5_u8; 32]);
    }

    #[test]
    fn loads_a_valid_seed_with_exactly_one_trailing_newline() {
        let mut contents = "a5".repeat(32);
        contents.push('\n');
        let file = TempFile::new(contents.as_bytes());
        assert_eq!(load_dev_seed(&file.0).unwrap(), [0xA5_u8; 32]);
    }

    #[test]
    fn rejects_two_trailing_newlines() {
        let mut contents = "a5".repeat(32);
        contents.push_str("\n\n");
        let file = TempFile::new(contents.as_bytes());
        assert!(matches!(
            load_dev_seed(&file.0),
            Err(SeedFileError::TooLong)
        ));
    }

    #[test]
    fn rejects_short_contents() {
        let file = TempFile::new(b"ab");
        assert!(matches!(
            load_dev_seed(&file.0),
            Err(SeedFileError::WrongLength { actual: 2 })
        ));
    }

    #[test]
    fn rejects_non_hex_contents() {
        let contents = "g".repeat(64);
        let file = TempFile::new(contents.as_bytes());
        assert!(matches!(
            load_dev_seed(&file.0),
            Err(SeedFileError::InvalidHex(_))
        ));
    }

    #[test]
    fn rejects_a_missing_file() {
        let path = std::env::temp_dir().join("sunrise-edge-cli-seed-test-missing-file");
        assert!(matches!(load_dev_seed(&path), Err(SeedFileError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_readable_permissions() {
        let hex = "a5".repeat(32);
        let file = TempFile::new(hex.as_bytes());
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file.0, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            load_dev_seed(&file.0),
            Err(SeedFileError::InsecurePermissions { mode: 0o640 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink() {
        let hex = "a5".repeat(32);
        let target = TempFile::new(hex.as_bytes());
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let link_path = std::env::temp_dir().join(format!(
            "sunrise-edge-cli-seed-test-symlink-{}-{sequence}",
            std::process::id()
        ));
        std::os::unix::fs::symlink(&target.0, &link_path).unwrap();
        let result = load_dev_seed(&link_path);
        let _ignored = fs::remove_file(&link_path);
        assert!(matches!(result, Err(SeedFileError::Symlink)));
    }

    #[cfg(unix)]
    #[test]
    fn file_identity_is_stable_for_the_same_file_and_distinct_across_files() {
        let file_a = TempFile::new(b"a");
        let file_b = TempFile::new(b"b");

        // Two independent metadata snapshots of the same file (one via the
        // path, one via an already-open handle) must report identical
        // identity — this is the property `load_dev_seed` relies on to
        // prove nothing was swapped between its own two metadata reads.
        let path_metadata = fs::symlink_metadata(&file_a.0).unwrap();
        let handle_metadata = fs::File::open(&file_a.0).unwrap().metadata().unwrap();
        let identity_a_via_path = FileIdentity::from_metadata(&path_metadata);
        let identity_a_via_handle = FileIdentity::from_metadata(&handle_metadata);
        assert_eq!(identity_a_via_path, identity_a_via_handle);

        // Two distinct files must not share an identity.
        let metadata_b = fs::symlink_metadata(&file_b.0).unwrap();
        let identity_b = FileIdentity::from_metadata(&metadata_b);
        assert_ne!(identity_a_via_path, identity_b);
    }

    #[cfg(unix)]
    #[test]
    fn load_dev_seed_rejects_a_path_replaced_with_a_different_regular_file_after_validation() {
        // This does not reproduce the real TOCTOU race (which requires a
        // concurrent replacement between two syscalls inside
        // `load_dev_seed` itself); it instead proves the identity check's
        // conclusion deterministically: metadata captured for one file
        // never matches an already-open handle to a different file, which
        // is exactly the condition `load_dev_seed` tests for internally.
        let original = TempFile::new(b"a5".repeat(32).as_slice());
        let replacement = TempFile::new(b"b6".repeat(32).as_slice());

        let original_identity =
            FileIdentity::from_metadata(&fs::symlink_metadata(&original.0).unwrap());
        let replacement_handle_identity = FileIdentity::from_metadata(
            &fs::File::open(&replacement.0).unwrap().metadata().unwrap(),
        );

        assert_ne!(original_identity, replacement_handle_identity);
    }
}
