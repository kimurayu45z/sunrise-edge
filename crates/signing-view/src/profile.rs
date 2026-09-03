//! Strictly bounded device parsing/display limits.

/// Strictly bounded parsing and display limits for one hardware signing
/// device profile.
///
/// See `SIGNING.md`, "Hardware Signing Profile v1", for the normative
/// specification these bounds implement. [`crate::view::build_clear_signing_view`]
/// fails closed — it never truncates, wraps, or partially renders a
/// value — if any signed field exceeds its bound here; a transaction that
/// does not fit this profile is a transaction this profile cannot safely
/// sign, not one it silently approximates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceSigningProfile {
    version: u16,
    /// Maximum byte length of the complete outer signature frame.
    max_framed_message_bytes: usize,
    /// Maximum byte length of the inner `TransactionSignable` payload.
    max_transaction_payload_bytes: usize,
    /// Maximum byte length of the outer signature frame's `chain_id`
    /// (field 1).
    max_chain_id_bytes: usize,
    /// Maximum byte length of the outer signature frame's `message_type`
    /// (field 4).
    max_message_type_bytes: usize,
    /// Maximum byte length of a `TransactionSignable` `entrypoint`
    /// (field 8).
    max_entrypoint_bytes: usize,
    /// Maximum byte length of a `TransactionSignable` `args` payload
    /// (field 9).
    max_args_bytes: usize,
    /// Maximum number of `AccessManifest` entries (field 6).
    max_manifest_entries: usize,
    /// Maximum number of deterministic ASCII display lines one
    /// [`crate::view::ClearSigningView`] may contain.
    max_display_lines: usize,
    /// Maximum byte length of one deterministic ASCII display line.
    max_line_bytes: usize,
}

impl DeviceSigningProfile {
    /// Hardware Signing Profile v1 (see `SIGNING.md`).
    ///
    /// These bounds are sized so every line this crate renders — including
    /// a full 32-byte `ObjectId`/`Address`/`AssetId` or an algorithm-
    /// prefixed `Digest32` in a `field=value` line — fits within
    /// [`Self::max_line_bytes`] with headroom. `max_args_bytes` admits the
    /// exact recognized transfer frame while remaining far below the host
    /// transaction bound; unrecognized arguments are rejected, never dumped
    /// or blind-signed.
    pub const V1: Self = Self {
        version: 1,
        max_framed_message_bytes: 4 * 1024,
        max_transaction_payload_bytes: 3 * 1024,
        max_chain_id_bytes: 64,
        max_message_type_bytes: 32,
        max_entrypoint_bytes: 64,
        max_args_bytes: 40,
        max_manifest_entries: 8,
        max_display_lines: 64,
        max_line_bytes: 96,
    };

    /// Stable hardware-signing profile version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Maximum complete signature-frame bytes.
    #[must_use]
    pub const fn max_framed_message_bytes(self) -> usize {
        self.max_framed_message_bytes
    }

    /// Maximum inner transaction-signable bytes.
    #[must_use]
    pub const fn max_transaction_payload_bytes(self) -> usize {
        self.max_transaction_payload_bytes
    }

    /// Maximum chain-id bytes.
    #[must_use]
    pub const fn max_chain_id_bytes(self) -> usize {
        self.max_chain_id_bytes
    }

    /// Maximum signature message-type bytes.
    #[must_use]
    pub const fn max_message_type_bytes(self) -> usize {
        self.max_message_type_bytes
    }

    /// Maximum entrypoint bytes.
    #[must_use]
    pub const fn max_entrypoint_bytes(self) -> usize {
        self.max_entrypoint_bytes
    }

    /// Maximum canonical argument bytes.
    #[must_use]
    pub const fn max_args_bytes(self) -> usize {
        self.max_args_bytes
    }

    /// Maximum access-manifest entries.
    #[must_use]
    pub const fn max_manifest_entries(self) -> usize {
        self.max_manifest_entries
    }

    /// Maximum rendered display lines.
    #[must_use]
    pub const fn max_display_lines(self) -> usize {
        self.max_display_lines
    }

    /// Maximum bytes in one rendered display line.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }
}
