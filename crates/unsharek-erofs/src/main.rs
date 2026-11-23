//! unsharek-erofs: a directory tree (one Nix store path) to an erofs image whose ELF files map in
//! place. See the library for the image's layout.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Print where each regular file's data is: `offset slot size elf|data path` per line.
    #[arg(long)]
    layout: bool,
    /// The tree to store, e.g. /nix/store/…-bash-5.3.
    source: PathBuf,
    /// The image to write.
    image: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match unsharek_erofs::build(&cli.source, &cli.image) {
        Ok(layout) => {
            if cli.layout && std::io::stdout().write_all(&layout.to_text()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("unsharek-erofs: {e}");
            ExitCode::FAILURE
        }
    }
}
