//! Deterministic, bounded, ASCII-only clear-signing display.

use crate::{
    SigningViewError,
    policy::ClearSigningPolicy,
    profile::DeviceSigningProfile,
    transaction::{TransactionSignable, decode_transaction_signable},
};
use crypto::{SignatureFrameView, decode_signature_frame};
use objects::AccessMode;
use protocol_types::SignatureSchemeId;

/// The exact Transaction v1 signature message-type family this crate
/// recognizes.
///
/// Duplicated here as data from `node_core::TRANSACTION_V1_MESSAGE_TYPE`
/// (`"transaction-v1"`) for the same "no dependency on execution/node-core"
/// reason documented on [`crate::transaction::TRANSACTION_TYPE_ID`].
pub const TRANSACTION_V1_MESSAGE_TYPE: &str = "transaction-v1";

/// A deterministic, bounded, ASCII-only rendering of exactly what one framed
/// signature payload authenticates.
///
/// Every line is derived only from bytes the wrapping
/// [`crypto::SignatureFrameView`] and its decoded [`TransactionSignable`]
/// payload actually carry — see `docs/signing/hardware-signing.md`, "Clear-signing policy", for
/// the normative rule: never an unsigned request id, a queried destination
/// owner, an asset symbol, or a module display name. Lines are exposed as an
/// ordered slice, not a single joined string, so a caller (a real device's
/// firmware, or a test) can page, scroll, or compare them without
/// re-parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearSigningView {
    lines: Vec<String>,
}

impl ClearSigningView {
    /// Returns the deterministic, ordered `field=value` display lines.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// Builds a [`ClearSigningView`] from the exact bytes an external signer is
/// asked to produce a raw signature over (a
/// [`crypto::frame_signature_message`] output, exactly what
/// `clients/rust`'s `PreparedTransaction::signable_frame` returns).
///
/// `policy` is applied only after every signed field has been decoded and
/// bounded. A mismatch rejects the transaction; Hardware Signing Profile v1
/// has no generic raw-argument or blind-signing fallback.
pub fn build_clear_signing_view(
    framed_message: &[u8],
    profile: &DeviceSigningProfile,
    policy: &ClearSigningPolicy,
) -> Result<ClearSigningView, SigningViewError> {
    if framed_message.len() > profile.max_framed_message_bytes() {
        return Err(SigningViewError::FramedMessageTooLarge {
            actual: framed_message.len(),
            maximum: profile.max_framed_message_bytes(),
        });
    }
    let frame: SignatureFrameView<'_> = decode_signature_frame(framed_message)?;

    if frame.payload.len() > profile.max_transaction_payload_bytes() {
        return Err(SigningViewError::TransactionPayloadTooLarge {
            actual: frame.payload.len(),
            maximum: profile.max_transaction_payload_bytes(),
        });
    }

    if frame.chain_id.len() > profile.max_chain_id_bytes() {
        return Err(SigningViewError::FieldTooLarge {
            field: "chain_id",
            actual: frame.chain_id.len(),
            maximum: profile.max_chain_id_bytes(),
        });
    }
    if frame.message_type.len() > profile.max_message_type_bytes() {
        return Err(SigningViewError::FieldTooLarge {
            field: "message_type",
            actual: frame.message_type.len(),
            maximum: profile.max_message_type_bytes(),
        });
    }
    if frame.message_type != TRANSACTION_V1_MESSAGE_TYPE {
        return Err(SigningViewError::UnsupportedMessageType(
            frame.message_type.to_string(),
        ));
    }
    if frame.signature_scheme_id != SignatureSchemeId::Ed25519 {
        return Err(SigningViewError::UnsupportedSignatureScheme(
            frame.signature_scheme_id,
        ));
    }

    let tx: TransactionSignable = decode_transaction_signable(frame.payload, profile)?;

    // The outer signature frame and the inner transaction payload each
    // independently carry chain_id/protocol_version/epoch (see
    // `SigningViewError::SignedContextMismatch`'s doc comment). Both are
    // signed; require them identical rather than displaying — or silently
    // preferring — only one.
    if tx.chain_id.as_str() != frame.chain_id {
        return Err(SigningViewError::SignedContextMismatch { field: "chain_id" });
    }
    if tx.protocol_version != frame.protocol_version {
        return Err(SigningViewError::SignedContextMismatch {
            field: "protocol_version",
        });
    }
    if tx.epoch != frame.epoch {
        return Err(SigningViewError::SignedContextMismatch { field: "epoch" });
    }

    let mut lines: Vec<String> = Vec::new();
    push_line(
        &mut lines,
        profile,
        "chain_id",
        format!("chain_id={}", frame.chain_id),
    )?;
    push_line(
        &mut lines,
        profile,
        "protocol_version",
        format!("protocol_version={}", frame.protocol_version.get()),
    )?;
    push_line(
        &mut lines,
        profile,
        "epoch",
        format!("epoch={}", frame.epoch.get()),
    )?;
    push_line(
        &mut lines,
        profile,
        "message_type",
        format!("message_type={}", frame.message_type),
    )?;
    push_line(
        &mut lines,
        profile,
        "scheme",
        format!("scheme={}", scheme_label(frame.signature_scheme_id)),
    )?;
    push_line(
        &mut lines,
        profile,
        "sender",
        format!("sender={}", tx.sender),
    )?;
    push_line(&mut lines, profile, "nonce", format!("nonce={}", tx.nonce))?;
    push_line(
        &mut lines,
        profile,
        "module_id",
        format!("module_id={}", tx.module_ref.id),
    )?;
    push_line(
        &mut lines,
        profile,
        "module_version",
        format!("module_version={}", tx.module_ref.version),
    )?;
    push_line(
        &mut lines,
        profile,
        "module_digest",
        format!("module_digest={}", tx.module_ref.digest),
    )?;
    push_line(
        &mut lines,
        profile,
        "entrypoint",
        format!("entrypoint={}", tx.entrypoint),
    )?;

    let value: u64 = policy.recognize(&tx)?;
    push_line(
        &mut lines,
        profile,
        "args",
        format!("{}={value}", policy.args_label()),
    )?;

    push_line(
        &mut lines,
        profile,
        "gas_limit",
        format!("gas_limit={}", tx.gas_limit),
    )?;
    push_line(
        &mut lines,
        profile,
        "manifest_count",
        format!("manifest_count={}", tx.access_manifest.entries.len()),
    )?;

    for (index, entry) in tx.access_manifest.entries.iter().enumerate() {
        push_line(
            &mut lines,
            profile,
            "access.mode",
            format!("access[{index}].mode={}", access_mode_label(entry.mode)),
        )?;
        push_line(
            &mut lines,
            profile,
            "access.object_id",
            format!("access[{index}].object_id={}", entry.object_ref.id),
        )?;
        push_line(
            &mut lines,
            profile,
            "access.version",
            format!("access[{index}].version={}", entry.object_ref.version),
        )?;
        push_line(
            &mut lines,
            profile,
            "access.digest",
            format!("access[{index}].digest={}", entry.object_ref.digest),
        )?;
    }

    match &tx.fee_payment {
        Some(fee) => {
            push_line(
                &mut lines,
                profile,
                "fee_payment",
                "fee_payment=present".to_string(),
            )?;
            push_line(
                &mut lines,
                profile,
                "fee_asset",
                format!("fee_asset={}", fee.asset_id),
            )?;
            push_line(
                &mut lines,
                profile,
                "fee_max",
                format!("fee_max={}", fee.max_fee),
            )?;
            push_line(
                &mut lines,
                profile,
                "fee_object_id",
                format!("fee_object_id={}", fee.fee_object.id),
            )?;
            push_line(
                &mut lines,
                profile,
                "fee_object_version",
                format!("fee_object_version={}", fee.fee_object.version),
            )?;
            push_line(
                &mut lines,
                profile,
                "fee_object_digest",
                format!("fee_object_digest={}", fee.fee_object.digest),
            )?;
        }
        None => {
            push_line(
                &mut lines,
                profile,
                "fee_payment",
                "fee_payment=none".to_string(),
            )?;
        }
    }

    Ok(ClearSigningView { lines })
}

fn push_line(
    lines: &mut Vec<String>,
    profile: &DeviceSigningProfile,
    field: &'static str,
    line: String,
) -> Result<(), SigningViewError> {
    if !line.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
        return Err(SigningViewError::NonAsciiField(field));
    }
    if line.len() > profile.max_line_bytes() {
        return Err(SigningViewError::DisplayLineTooLong {
            field,
            actual: line.len(),
            maximum: profile.max_line_bytes(),
        });
    }
    if lines.len() >= profile.max_display_lines() {
        return Err(SigningViewError::TooManyDisplayLines {
            actual: lines.len() + 1,
            maximum: profile.max_display_lines(),
        });
    }
    lines.push(line);
    Ok(())
}

const fn scheme_label(scheme: SignatureSchemeId) -> &'static str {
    match scheme {
        SignatureSchemeId::Ed25519 => "ed25519",
        SignatureSchemeId::Secp256k1 => "secp256k1",
    }
}

const fn access_mode_label(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::Consume => "consume",
    }
}
