use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use grdr_interface_gen::{RunMode, run};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-interface-gen",
    about = "Generate typed Rust and Web interface artifacts from contracts/interface/"
)]
struct Cli {
    /// Repository root containing contracts/interface/
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Verify checked-in generated files match contracts/interface/ without writing
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mode = if cli.check {
        RunMode::Check
    } else {
        RunMode::Write
    };
    match run(&cli.root, mode) {
        Ok(paths) => {
            let verb = if cli.check { "Verified" } else { "Generated" };
            println!("{verb} {} interface artifact(s).", paths.len());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
