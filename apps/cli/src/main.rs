#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match sunrise_edge_cli::run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", sunrise_edge_cli::render_error_line(&error));
            ExitCode::FAILURE
        }
    }
}
