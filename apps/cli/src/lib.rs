#![forbid(unsafe_code)]

//! Sunrise Edge Developer MVP Rust CLI (`apps/cli`, docs/architecture/README.md §44,
//! DR-0084, and DR-0092).
//!
//! Rust-only, with exactly two non-development/runtime dependencies:
//! `sunrise-edge-client` and, as of S4c (DR-0092, amending DR-0084's
//! original one-dependency invariant), `sunrise-edge-ledger` — the crate
//! that owns every Ledger/APDU/USB/HID dependency in this workspace. (A
//! handful of crates are declared under `[dev-dependencies]` only, to
//! compose a real local devnet and build test fixtures directly in this
//! crate's own test suite; none of them are reachable from `main`, `lib`,
//! or any non-test build.) There is no Node/browser runtime, no
//! argument-parsing crate, and no independent canonical encode/decode,
//! signing, or RPC path — every protocol interaction goes through
//! `sunrise-edge-client`, and every Ledger interaction goes through
//! `sunrise-edge-ledger`.
//!
//! Commands: `address`, `context`, `object`, `receipt`, `next-nonce`, and
//! `transfer` (the devnet asset transfer with an explicit destination-owner
//! expectation). `address` and `transfer` each require an explicit,
//! all-or-none signer selection (see `signer::parse_signer_selection`):
//! `--seed-file` (the development-only, non-keystore local signer) or all
//! three of `--ledger-hid-path`, `--ledger-account`, and
//! `--ledger-expected-firmware-version` (a Ledger hardware signer). A Ledger
//! selection runs a staged identity check before any signing: the device's
//! dashboard/firmware identity is verified against
//! `--ledger-expected-firmware-version`, the Sunrise application is opened
//! and its own reported app/version identity verified, and only then are the
//! device-reported configuration and on-device-confirmed public key/address
//! checked. The real USB/HID transport (`--ledger-hid-path`) requires this
//! binary to be built with the `usb-hid` Cargo feature; without it, a Ledger
//! selection fails closed with a typed, actionable error rather than
//! silently falling back to the local signer. Output is deterministic,
//! line-oriented `key=value` text; every error is typed and actionable, and
//! every error exits the process non-zero.

mod args;
mod commands;
mod error;
mod hex;
mod net;
mod output;
mod parse;
mod seed;
mod signer;
#[cfg(test)]
mod test_support;

use std::ffi::OsString;

pub use error::CliError;

/// Renders `error` as the single deterministic `error=...` line this
/// binary's `main` prints on stderr.
///
/// The message is sanitized (control characters, including newlines,
/// Unicode bidirectional/format characters, and Unicode line/paragraph
/// separators, collapsed to spaces — see `output::sanitize_line`) so
/// untrusted, server-derived text embedded in an error — for example an
/// HTTP error response body echoed back verbatim in
/// [`sunrise_edge_client::ClientError::UnexpectedStatus`] — cannot inject
/// additional terminal lines or visually reorder/hide output. The sanitized
/// message is also bounded to `output::MAX_ERROR_MESSAGE_CHARS`; a
/// truncated message is explicitly marked so it is never mistaken for the
/// complete message.
#[must_use]
pub fn render_error_line(error: &CliError) -> String {
    let (sanitized, truncated) = output::bounded_sanitized_line(&error.to_string());
    if truncated {
        format!("error={sanitized}...(truncated)")
    } else {
        format!("error={sanitized}")
    }
}

/// Runs the CLI against `args` (excluding the program name), dispatching to
/// exactly one subcommand.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iterator = args.into_iter();
    let command_os = iterator.next().ok_or(CliError::MissingCommand)?;
    let command = command_os
        .to_str()
        .ok_or(args::ArgsError::NonUtf8Token)?
        .to_string();

    match command.as_str() {
        "address" => commands::address::run(iterator),
        "context" => commands::context::run(iterator),
        "object" => commands::object::run(iterator),
        "receipt" => commands::receipt::run(iterator),
        "next-nonce" => commands::next_nonce::run(iterator),
        "transfer" => commands::transfer::run(iterator),
        other => Err(CliError::UnknownCommand(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_command_is_reported() {
        let error = run(Vec::<OsString>::new()).unwrap_err();
        assert!(matches!(error, CliError::MissingCommand));
    }

    #[test]
    fn unknown_command_is_reported() {
        let error = run(vec![OsString::from("bogus")]).unwrap_err();
        assert!(matches!(error, CliError::UnknownCommand(name) if name == "bogus"));
    }

    #[test]
    fn address_command_requires_a_signer_selection() {
        let error = run(vec![OsString::from("address")]).unwrap_err();
        assert!(matches!(error, CliError::MissingSignerSelection));
    }

    #[test]
    fn render_error_line_sanitizes_server_derived_text_into_one_line() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "line one\nFAKE-LOG-LINE=injected\r\nline three".to_string(),
            },
        ));

        let rendered = render_error_line(&error);

        assert!(rendered.starts_with("error="));
        assert_eq!(rendered.lines().count(), 1);
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
    }

    #[test]
    fn render_error_line_neutralizes_a_bidi_override_in_server_derived_text() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "prefix\u{202E}reversed-looking-suffix".to_string(),
            },
        ));

        let rendered = render_error_line(&error);

        assert_eq!(rendered.lines().count(), 1);
        assert!(!rendered.contains('\u{202E}'));
    }

    #[test]
    fn render_error_line_bounds_a_long_server_derived_body_and_marks_truncation() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "x".repeat(output::MAX_ERROR_MESSAGE_CHARS + 1_000),
            },
        ));

        let rendered = render_error_line(&error);

        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.ends_with("...(truncated)"));
        assert!(rendered.len() < output::MAX_ERROR_MESSAGE_CHARS + 1_000);
    }
}
