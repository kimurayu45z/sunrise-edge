//! `address`: derive and print the address bound to an explicitly selected
//! signer — the development-only local seed file, or a Ledger hardware
//! signer (see `crate::signer`).

use std::ffi::OsString;
use std::path::PathBuf;

use sunrise_edge_client::LocalSigner;

use crate::args::parse_flags;
use crate::error::CliError;
use crate::seed::load_dev_seed;
use crate::signer::{SignerSelection, parse_signer_selection, signer_flag_specs};

/// Runs `address --seed-file <path>` or
/// `address --ledger-hid-path <path> --ledger-account <n>`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let parsed = parse_flags(args, &signer_flag_specs())?;

    match parse_signer_selection(&parsed)? {
        SignerSelection::Local { seed_file } => {
            let seed = load_dev_seed(&PathBuf::from(seed_file))?;
            let signer = LocalSigner::from_seed(seed);
            println!("address={}", signer.address());
            Ok(())
        }
        SignerSelection::Ledger { hid_path, account } => run_with_ledger(&hid_path, account),
    }
}

/// Connects a real Ledger device, confirms its address, and prints it.
#[cfg(feature = "usb-hid")]
fn run_with_ledger(hid_path: &str, account: u32) -> Result<(), CliError> {
    use sunrise_edge_client::ExternalSigner;

    let transport = sunrise_edge_ledger::HidTransport::open(hid_path)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
    let signer = crate::signer::connect_ledger_with(transport, account)?;
    println!("address={}", signer.address());
    Ok(())
}

/// This binary was not built with the `usb-hid` feature: fail closed with
/// an actionable error before any device connection is even attempted.
#[cfg(not(feature = "usb-hid"))]
fn run_with_ledger(_hid_path: &str, _account: u32) -> Result<(), CliError> {
    Err(CliError::LedgerTransportFeatureDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::ArgsError;

    #[test]
    fn requires_a_signer_selection() {
        let error = run(Vec::<OsString>::new()).unwrap_err();
        assert!(matches!(error, CliError::MissingSignerSelection));
    }

    #[test]
    fn rejects_an_unknown_flag() {
        let error = run(vec![OsString::from("--bogus"), OsString::from("x")]).unwrap_err();
        assert!(matches!(error, CliError::Args(ArgsError::UnknownFlag(flag)) if flag == "--bogus"));
    }

    #[test]
    fn rejects_combining_local_and_ledger_selection() {
        let error = run(vec![
            OsString::from("--seed-file"),
            OsString::from("seed.hex"),
            OsString::from("--ledger-hid-path"),
            OsString::from("/dev/hidraw0"),
            OsString::from("--ledger-account"),
            OsString::from("0"),
        ])
        .unwrap_err();
        assert!(matches!(error, CliError::ConflictingSignerSelection));
    }

    #[cfg(not(feature = "usb-hid"))]
    #[test]
    fn a_ledger_selection_without_the_usb_hid_feature_fails_closed() {
        let error = run(vec![
            OsString::from("--ledger-hid-path"),
            OsString::from("/dev/hidraw0"),
            OsString::from("--ledger-account"),
            OsString::from("0"),
        ])
        .unwrap_err();
        assert!(matches!(error, CliError::LedgerTransportFeatureDisabled));
    }
}
