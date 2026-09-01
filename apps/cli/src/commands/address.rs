//! `address`: derive and print the `AddressIsPublicKey` address bound to an
//! explicitly named development seed file.

use std::ffi::OsString;
use std::path::PathBuf;

use sunrise_edge_client::LocalSigner;

use crate::args::{parse_flags, scalar};
use crate::error::CliError;
use crate::seed::load_dev_seed;

const SEED_FILE: &str = "--seed-file";

/// Runs `address --seed-file <path>`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let parsed = parse_flags(args, &[scalar(SEED_FILE)])?;
    let seed_file = PathBuf::from(parsed.require(SEED_FILE)?);

    let seed = load_dev_seed(&seed_file)?;
    let signer = LocalSigner::from_seed(seed);

    println!("address={}", signer.address());
    Ok(())
}
