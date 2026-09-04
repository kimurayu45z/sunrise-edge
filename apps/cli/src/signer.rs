//! Explicit, all-or-none CLI signer selection between the development-only
//! local seed signer and a Ledger hardware signer (S4c; see `SIGNING.md`
//! and `ARCHITECTURE.md`'s Hardware Signing Profile v1 decision records).
//!
//! Exactly one signer must be selected: `--seed-file` alone (development-
//! only, in-memory, never a keystore), or both `--ledger-hid-path` and
//! `--ledger-account` together (a real Ledger device, verified by its
//! device-reported configuration and on-device-confirmed public key/address
//! before any signing — see [`connect_ledger_with`] and
//! `sunrise_edge_ledger::LedgerExternalSigner`). Any other combination —
//! neither, both groups at once, or exactly one of the two Ledger flags — is
//! a typed rejection before any network dispatch or device connection.

use sunrise_edge_ledger::{DerivationPath, LedgerExternalSigner, Transport};

use crate::args::{FlagSpec, ParsedArgs, scalar};
use crate::error::CliError;
use crate::parse::parse_u32;

/// Development-only local seed file flag.
pub const SEED_FILE: &str = "--seed-file";
/// Ledger device HID path flag.
pub const LEDGER_HID_PATH: &str = "--ledger-hid-path";
/// Ledger provisional derivation account flag.
pub const LEDGER_ACCOUNT: &str = "--ledger-account";

/// The signer-selection flags every signer-capable subcommand accepts, in
/// addition to its own flags.
#[must_use]
pub fn signer_flag_specs() -> Vec<FlagSpec> {
    vec![
        scalar(SEED_FILE),
        scalar(LEDGER_HID_PATH),
        scalar(LEDGER_ACCOUNT),
    ]
}

/// One fully validated, mutually exclusive signer choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerSelection {
    /// The development-only local in-memory seed signer.
    Local {
        /// Path to the development seed file (see `crate::seed`).
        seed_file: String,
    },
    /// A Ledger hardware signer, addressed by an explicit HID device path
    /// and provisional derivation account.
    Ledger {
        /// Platform HID device path (see
        /// `sunrise_edge_ledger::HidTransport::list_devices`, behind
        /// the `usb-hid` feature).
        hid_path: String,
        /// Non-hardened `account` component of the provisional derivation
        /// path `m/44'/21333'/account'/0'/0'`.
        account: u32,
    },
}

/// Parses the required, explicit, all-or-none signer selection.
pub fn parse_signer_selection(parsed: &ParsedArgs) -> Result<SignerSelection, CliError> {
    let local = parsed.is_present(SEED_FILE);
    let ledger_hid = parsed.is_present(LEDGER_HID_PATH);
    let ledger_account = parsed.is_present(LEDGER_ACCOUNT);

    match (local, ledger_hid, ledger_account) {
        (true, false, false) => Ok(SignerSelection::Local {
            seed_file: parsed.require(SEED_FILE)?.to_string(),
        }),
        (false, true, true) => Ok(SignerSelection::Ledger {
            hid_path: parsed.require(LEDGER_HID_PATH)?.to_string(),
            account: parse_u32(LEDGER_ACCOUNT, parsed.require(LEDGER_ACCOUNT)?)?,
        }),
        (false, false, false) => Err(CliError::MissingSignerSelection),
        (true, _, _) => Err(CliError::ConflictingSignerSelection),
        (false, true, false) => Err(CliError::PartialLedgerSignerConfiguration {
            missing: LEDGER_ACCOUNT,
        }),
        (false, false, true) => Err(CliError::PartialLedgerSignerConfiguration {
            missing: LEDGER_HID_PATH,
        }),
    }
}

/// Connects a [`LedgerExternalSigner`] over an already-constructed
/// `transport`: checks the device-reported configuration, then fetches and
/// confirms its public key/address at `account`'s provisional derivation
/// path — both *before* returning — matching this crate's "device-reported
/// configuration/public key/address checks before signing" requirement.
///
/// Generic over [`Transport`] so this exact connect-then-verify sequence is
/// unit-testable with `sunrise_edge_ledger::FakeTransport`, independent of
/// the `usb-hid` feature and any real USB/HID hardware. Its only non-test
/// caller is behind `#[cfg(feature = "usb-hid")]`
/// (`commands::transfer::run_with_ledger`, `commands::address::run_with_ledger`),
/// so a default (non-test, non-`usb-hid`) build sees no call site at all.
#[allow(dead_code, reason = "used by usb-hid-gated callers and by tests")]
pub fn connect_ledger_with<T: Transport>(
    transport: T,
    account: u32,
) -> Result<LedgerExternalSigner<T>, CliError> {
    let path = DerivationPath::provisional(account)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
    LedgerExternalSigner::connect(transport, path)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_flags;
    use std::ffi::OsString;

    fn parsed(pairs: &[(&'static str, &str)]) -> ParsedArgs {
        let specs = signer_flag_specs();
        let args: Vec<OsString> = pairs
            .iter()
            .flat_map(|(name, value)| [OsString::from(*name), OsString::from(*value)])
            .collect();
        parse_flags(args, &specs).unwrap()
    }

    #[test]
    fn selects_local_when_only_seed_file_is_present() {
        let selection = parse_signer_selection(&parsed(&[(SEED_FILE, "seed.hex")])).unwrap();
        assert_eq!(
            selection,
            SignerSelection::Local {
                seed_file: "seed.hex".to_string()
            }
        );
    }

    #[test]
    fn selects_ledger_when_both_ledger_flags_are_present() {
        let selection = parse_signer_selection(&parsed(&[
            (LEDGER_HID_PATH, "/dev/hidraw0"),
            (LEDGER_ACCOUNT, "3"),
        ]))
        .unwrap();
        assert_eq!(
            selection,
            SignerSelection::Ledger {
                hid_path: "/dev/hidraw0".to_string(),
                account: 3,
            }
        );
    }

    #[test]
    fn rejects_no_signer_selected() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[])),
            Err(CliError::MissingSignerSelection)
        ));
    }

    #[test]
    fn rejects_local_combined_with_either_ledger_flag() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (SEED_FILE, "seed.hex"),
                (LEDGER_HID_PATH, "/dev/hidraw0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[(SEED_FILE, "seed.hex"), (LEDGER_ACCOUNT, "0"),])),
            Err(CliError::ConflictingSignerSelection)
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (SEED_FILE, "seed.hex"),
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
    }

    #[test]
    fn rejects_exactly_one_of_the_two_ledger_flags() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[(LEDGER_HID_PATH, "/dev/hidraw0")])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_ACCOUNT
            })
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[(LEDGER_ACCOUNT, "0")])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_HID_PATH
            })
        ));
    }

    #[test]
    fn rejects_a_malformed_ledger_account() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "not-a-number"),
            ])),
            Err(CliError::InvalidInteger {
                flag: LEDGER_ACCOUNT,
                ..
            })
        ));
    }

    #[test]
    fn connect_ledger_with_checks_configuration_before_the_public_key() {
        use sunrise_edge_client::ExternalSigner;
        use sunrise_edge_ledger::{ApduResponse, FakeTransport};

        let key = [0x11_u8; 32];
        let transport = FakeTransport::new(vec![
            ApduResponse {
                data: vec![0x00, 0x01, 1, 0, 0, 0x00],
                status_word: 0x9000,
            },
            ApduResponse {
                data: key.to_vec(),
                status_word: 0x9000,
            },
        ]);

        let signer = connect_ledger_with(transport, 0).unwrap();
        assert_eq!(signer.address(), sunrise_edge_client::Address::new(key));
    }

    #[test]
    fn connect_ledger_with_rejects_an_account_that_already_has_the_hardened_bit_set() {
        use sunrise_edge_ledger::FakeTransport;

        let error = connect_ledger_with(FakeTransport::new(vec![]), 0x8000_0000).unwrap_err();
        assert!(matches!(error, CliError::LedgerConnect(_)));
    }
}
