//! Exact-match clear-signing policy for one preinstalled module's arguments.

use crate::transaction::TransactionSignable;
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use objects::{AccessMode, ObjectRef};
use protocol_types::HashAlgorithmId;

/// Exact reason a signed transaction did not match a clear-signing policy.
///
/// There is deliberately no generic-display fallback. A basic transfer is
/// either recognized in full or rejected before any signer is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClearSigningPolicyError {
    /// The signed chain identifier was not allowlisted.
    ChainId,
    /// The signed protocol version was not allowlisted.
    ProtocolVersion,
    /// The signed epoch was not allowlisted.
    Epoch,
    /// The module object identifier was not allowlisted.
    ModuleId,
    /// The module version was not allowlisted.
    ModuleVersion,
    /// The module digest algorithm was not allowlisted.
    ModuleDigestAlgorithm,
    /// The module digest bytes were not allowlisted.
    ModuleDigest,
    /// The entrypoint was not allowlisted.
    Entrypoint,
    /// The declared object-access shape was not the exact transfer shape.
    AccessShape,
    /// The transfer profile requires a fee authorization.
    FeeRequired,
    /// The fee object was not the exact source reference at manifest index 0.
    FeeObjectMismatch,
    /// The signed fee asset was not allowlisted.
    FeeAsset,
    /// The argument bytes were not one complete canonical frame.
    ArgumentsEncoding(canonical_encoding::CanonicalDecodingError),
    /// The argument type identifier was not allowlisted.
    ArgumentsTypeId(u16),
    /// The argument encoding version was not allowlisted.
    ArgumentsVersion(u16),
    /// The argument fields were not the exact allowlisted shape.
    ArgumentsShape(canonical_encoding::CanonicalDecodingError),
    /// The amount was zero.
    ZeroAmount,
    /// Re-encoding the decoded arguments did not reproduce the signed bytes.
    NonCanonicalArguments,
}

impl core::fmt::Display for ClearSigningPolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChainId => formatter.write_str("unrecognized chain id"),
            Self::ProtocolVersion => formatter.write_str("unrecognized protocol version"),
            Self::Epoch => formatter.write_str("unrecognized epoch"),
            Self::ModuleId => formatter.write_str("unrecognized module object id"),
            Self::ModuleVersion => formatter.write_str("unrecognized module version"),
            Self::ModuleDigestAlgorithm => {
                formatter.write_str("unrecognized module digest algorithm")
            }
            Self::ModuleDigest => formatter.write_str("unrecognized module digest"),
            Self::Entrypoint => formatter.write_str("unrecognized module entrypoint"),
            Self::AccessShape => formatter.write_str("unrecognized transfer access shape"),
            Self::FeeRequired => formatter.write_str("recognized transfer requires fee payment"),
            Self::FeeObjectMismatch => formatter.write_str("fee object is not the transfer source"),
            Self::FeeAsset => formatter.write_str("unrecognized fee asset"),
            Self::ArgumentsEncoding(error) => write!(formatter, "argument encoding error: {error}"),
            Self::ArgumentsTypeId(actual) => {
                write!(formatter, "unrecognized argument type id: {actual:#06x}")
            }
            Self::ArgumentsVersion(actual) => {
                write!(
                    formatter,
                    "unrecognized argument encoding version: {actual}"
                )
            }
            Self::ArgumentsShape(error) => write!(formatter, "argument shape error: {error}"),
            Self::ZeroAmount => formatter.write_str("transfer amount must be non-zero"),
            Self::NonCanonicalArguments => {
                formatter.write_str("transfer arguments are not canonically encoded")
            }
        }
    }
}

impl std::error::Error for ClearSigningPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ArgumentsEncoding(error) | Self::ArgumentsShape(error) => Some(error),
            _ => None,
        }
    }
}

/// An exact-match clear-signing policy: recognizes one specific preinstalled
/// module version/entrypoint/argument shape and gives its sole argument a
/// human-meaningful label.
///
/// Recognition ([`ClearSigningPolicy::recognize`]) requires byte-exact
/// equality of every field below against a
/// [`crate::transaction::TransactionSignable`]'s `module_ref`, `entrypoint`,
/// and `args` — there is no fuzzy, prefix, or best-effort match. This is
/// deliberate: unlike a module *name* (never part of the signed bytes, and
/// therefore untrusted host metadata this crate must never display as
/// though it were signed — see `docs/signing/hardware-signing.md`, "Clear-signing policy"), a
/// policy keyed to the exact immutable module identity and code digest is
/// safe to compile into device firmware, because recognition can only
/// succeed against the exact bytecode this policy was written against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearSigningPolicy {
    /// Exact signed chain identifier this policy recognizes.
    chain_id: &'static str,
    /// Exact signed protocol version this policy recognizes.
    protocol_version: u32,
    /// Exact signed epoch this reference policy recognizes.
    epoch: u64,
    /// Exact `ObjectId` bytes the module reference must carry.
    module_id: [u8; 32],
    /// Exact module version the module reference must carry.
    module_version: u64,
    /// Exact code-digest hash algorithm the module reference must carry.
    code_digest_algorithm: HashAlgorithmId,
    /// Exact code-digest bytes the module reference must carry.
    code_digest_bytes: [u8; 32],
    /// Exact entrypoint name the transaction must invoke.
    entrypoint: &'static str,
    /// Exact canonical type id the argument frame must carry.
    args_type_id: u16,
    /// Exact canonical encoding version the argument frame must carry.
    args_version: u16,
    /// Exact field id of the sole recognized argument (a non-zero `u64`).
    args_field_id: u16,
    /// Deterministic ASCII label used for the recognized argument in a
    /// rendered [`crate::view::ClearSigningView`].
    args_label: &'static str,
    /// Exact signed fee asset this policy recognizes.
    fee_asset_id: [u8; 32],
}

impl ClearSigningPolicy {
    /// Exact module object identifier recognized by this policy.
    #[must_use]
    pub const fn module_id(self) -> [u8; 32] {
        self.module_id
    }

    /// Exact module version recognized by this policy.
    #[must_use]
    pub const fn module_version(self) -> u64 {
        self.module_version
    }

    /// Exact module digest algorithm recognized by this policy.
    #[must_use]
    pub const fn code_digest_algorithm(self) -> HashAlgorithmId {
        self.code_digest_algorithm
    }

    /// Exact module digest bytes recognized by this policy.
    #[must_use]
    pub const fn code_digest_bytes(self) -> [u8; 32] {
        self.code_digest_bytes
    }

    /// Exact entrypoint recognized by this policy.
    #[must_use]
    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    /// Exact argument canonical type id recognized by this policy.
    #[must_use]
    pub const fn args_type_id(self) -> u16 {
        self.args_type_id
    }

    /// Exact argument encoding version recognized by this policy.
    #[must_use]
    pub const fn args_version(self) -> u16 {
        self.args_version
    }

    /// Exact argument field id recognized by this policy.
    #[must_use]
    pub const fn args_field_id(self) -> u16 {
        self.args_field_id
    }

    /// Deterministic display label for the recognized argument.
    #[must_use]
    pub const fn args_label(self) -> &'static str {
        self.args_label
    }

    /// Exact signed fee asset recognized by this policy.
    #[must_use]
    pub const fn fee_asset_id(self) -> [u8; 32] {
        self.fee_asset_id
    }

    /// Recognizes one signed transaction in full and returns its non-zero
    /// transfer amount. Every mismatch is a typed rejection; this API has no
    /// raw-argument or blind-signing fallback.
    pub fn recognize(
        &self,
        transaction: &TransactionSignable,
    ) -> Result<u64, ClearSigningPolicyError> {
        if transaction.chain_id.as_str() != self.chain_id {
            return Err(ClearSigningPolicyError::ChainId);
        }
        if transaction.protocol_version.get() != self.protocol_version {
            return Err(ClearSigningPolicyError::ProtocolVersion);
        }
        if transaction.epoch.get() != self.epoch {
            return Err(ClearSigningPolicyError::Epoch);
        }
        let module_ref: &ObjectRef = &transaction.module_ref;
        if module_ref.id.as_bytes() != &self.module_id {
            return Err(ClearSigningPolicyError::ModuleId);
        }
        if module_ref.version != self.module_version {
            return Err(ClearSigningPolicyError::ModuleVersion);
        }
        if module_ref.digest.algorithm() != self.code_digest_algorithm {
            return Err(ClearSigningPolicyError::ModuleDigestAlgorithm);
        }
        if module_ref.digest.bytes() != self.code_digest_bytes {
            return Err(ClearSigningPolicyError::ModuleDigest);
        }
        if transaction.entrypoint != self.entrypoint {
            return Err(ClearSigningPolicyError::Entrypoint);
        }

        let entries = transaction.access_manifest.entries.as_slice();
        if entries.len() != 3 || entries.iter().any(|entry| entry.mode != AccessMode::Write) {
            return Err(ClearSigningPolicyError::AccessShape);
        }
        let fee_payment = transaction
            .fee_payment
            .as_ref()
            .ok_or(ClearSigningPolicyError::FeeRequired)?;
        if fee_payment.fee_object != entries[0].object_ref {
            return Err(ClearSigningPolicyError::FeeObjectMismatch);
        }
        if fee_payment.asset_id.as_bytes() != &self.fee_asset_id {
            return Err(ClearSigningPolicyError::FeeAsset);
        }

        let args: &[u8] = transaction.args.as_slice();
        let frame =
            decode_canonical_frame(args).map_err(ClearSigningPolicyError::ArgumentsEncoding)?;
        if frame.type_id() != self.args_type_id {
            return Err(ClearSigningPolicyError::ArgumentsTypeId(frame.type_id()));
        }
        if frame.version() != self.args_version {
            return Err(ClearSigningPolicyError::ArgumentsVersion(frame.version()));
        }
        frame
            .require_only_fields(&[self.args_field_id])
            .map_err(ClearSigningPolicyError::ArgumentsShape)?;
        let value = frame
            .required_u64(self.args_field_id)
            .map_err(ClearSigningPolicyError::ArgumentsShape)?;
        if value == 0 {
            return Err(ClearSigningPolicyError::ZeroAmount);
        }

        // Byte-identity re-encoding check: an alternate canonical encoding
        // of the same logical value (there should be none, but this is
        // defense in depth matching every other decoder in this workspace)
        // is never treated as recognized.
        let mut canonical = CanonicalStruct::new(self.args_type_id, self.args_version);
        if canonical.field_u64(self.args_field_id, value).is_err() {
            return Err(ClearSigningPolicyError::NonCanonicalArguments);
        }
        let encoded = canonical
            .finish()
            .map_err(|_| ClearSigningPolicyError::NonCanonicalArguments)?;
        if encoded.as_slice() != args {
            return Err(ClearSigningPolicyError::NonCanonicalArguments);
        }

        Ok(value)
    }
}

/// The current local-devnet asset-account transfer module (see
/// `apps/devnet/src/catalog.rs`'s `ASSET_ACCOUNT_MODULE_ID` /
/// `ASSET_ACCOUNT_MODULE_VERSION`, and `apps/devnet/src/asset_account.rs`'s
/// `TRANSFER_ENTRYPOINT` / `TRANSFER_ARGS_TYPE_ID`).
///
/// This is a provisional, narrow reference-build recognition entry, not a
/// general module-registration mechanism (see `docs/signing/hardware-signing.md`,
/// "Clear-signing policy"). It duplicates those values as data rather
/// than adding a dependency on `apps/devnet` — an application crate this
/// protocol/device-view crate must not depend on. The exact code digest
/// below is valid only for one reference build documented in `docs/signing/hardware-signing.md`:
/// `chain_id = "sunrise-local-devnet"` (the exact value used by
/// `docs/guides/devnet.md`'s local devnet walkthrough),
/// `protocol_version = 3`, hashing the exact committed
/// `apps/devnet/src/modules/asset_account.wasm` bytes through the genesis
/// SHA-256 hash suite. Any other devnet deployment (a different
/// `--chain-id`, protocol version, or WASM build) produces a different
/// digest and is correctly rejected rather than guessed or rendered through
/// a generic fallback.
pub const DEVNET_ASSET_TRANSFER_POLICY: ClearSigningPolicy = ClearSigningPolicy {
    chain_id: "sunrise-local-devnet",
    protocol_version: 3,
    epoch: 0,
    module_id: [
        0x0D, 0x5D, 0xD1, 0x0A, 0xEC, 0x2C, 0x31, 0x5B, 0x1D, 0xC5, 0x64, 0xC6, 0x94, 0x43, 0x9E,
        0x46, 0xBA, 0xC4, 0xB6, 0x14, 0x26, 0xD2, 0x2E, 0x0D, 0x7D, 0xDB, 0x76, 0x4C, 0x49, 0x19,
        0x7F, 0xE7,
    ],
    module_version: 3,
    code_digest_algorithm: HashAlgorithmId::Sha2_256,
    code_digest_bytes: [
        0x01, 0x53, 0x41, 0x28, 0xF1, 0x2E, 0xB4, 0xCF, 0x46, 0x9B, 0xFA, 0x29, 0x67, 0x7B, 0xBC,
        0xED, 0x13, 0x44, 0x87, 0x9D, 0xE2, 0x87, 0x03, 0x15, 0x84, 0x7C, 0xBB, 0x7F, 0xAE, 0xC2,
        0x16, 0x19,
    ],
    entrypoint: "transfer",
    args_type_id: 0xF002,
    args_version: 1,
    args_field_id: 1,
    args_label: "amount",
    fee_asset_id: [
        0xCC, 0xAD, 0x27, 0xF6, 0x87, 0x33, 0x8B, 0x99, 0x95, 0x31, 0x83, 0x72, 0x86, 0x47, 0xBC,
        0x11, 0x77, 0x38, 0x8E, 0xB4, 0x5A, 0x37, 0xAF, 0xD9, 0x81, 0x2C, 0x0D, 0x28, 0x6B, 0x43,
        0x3E, 0xA8,
    ],
};
