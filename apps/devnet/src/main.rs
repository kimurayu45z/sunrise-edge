#![forbid(unsafe_code)]

use std::{error::Error, process::ExitCode};
use sunrise_edge_devnet::{DevnetConfig, boot_local_store};

fn run() -> Result<(), Box<dyn Error>> {
    let config: DevnetConfig = DevnetConfig::parse_from(std::env::args_os().skip(1))?;
    let boot = boot_local_store(&config)?;
    println!("Sunrise Edge local devnet foundation initialized.");
    println!("chain_id={}", config.chain_id());
    println!("epoch={}", config.epoch().get());
    println!("listen={} (reserved; not serving)", config.listen());
    println!("database={}", boot.database_path().display());
    println!("boot_generation={}", boot.boot_generation().get());
    println!("dev_owners={}", config.dev_owners().len());
    println!("max_concurrent={}", config.max_concurrent());
    println!("Native request composition is not wired; this process is not serving HTTP.");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sunrise-edge-devnet failed: {error}");
            ExitCode::FAILURE
        }
    }
}
