// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
use clap::{Parser, Subcommand};
use openari_core::{DEFAULT_MAX_INPUT_BYTES, Verifier, capabilities};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "openari",
    version,
    about = "OpenARI pre-spec tooling. No Apple ARI revision is verified yet."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print supported format revisions and available providers as JSON.
    Capabilities,
    /// Report a preliminary container hint. Does not validate the file.
    Inspect { file: PathBuf },
    /// Emit an indeterminate report and exit 3. Verification is not implemented.
    Verify { file: PathBuf },
}

fn read_bounded(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("input must be a regular file".into());
    }
    let mut input = Vec::new();
    file.take(DEFAULT_MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)?;
    if input.len() > DEFAULT_MAX_INPUT_BYTES {
        return Err("input exceeds the 64 MiB limit".into());
    }
    Ok(input)
}

fn run(args: Args) -> Result<u8, Box<dyn std::error::Error>> {
    let (output, status) = match args.command {
        Command::Capabilities => (serde_json::to_vec_pretty(&capabilities())?, 0),
        Command::Inspect { file } => (
            serde_json::to_vec_pretty(&Verifier::default().inspect(&read_bounded(&file)?)?)?,
            0,
        ),
        Command::Verify { file } => (
            serde_json::to_vec_pretty(&Verifier::default().verify(&read_bounded(&file)?)?)?,
            3,
        ),
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.write_all(b"\n")?;
    Ok(status)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("openari: {error}");
            ExitCode::from(2)
        }
    }
}
