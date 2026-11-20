//! The exobox CLI: arguments to an [`exobox::Config`], then [`exobox::run`].

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a program in a sandbox; exits with the program's status.
    Run {
        #[arg(long, value_enum, default_value_t = Mode::Coroutine)]
        mode: Mode,
        /// More the program may see and map: a store path (with its closure) or a host path
        /// (read-only). Repeatable.
        #[arg(long = "allow-path", value_name = "PATH")]
        allow_paths: Vec<PathBuf>,
        /// Map an erofs image as /dev/exobox/NAME, and mount it at MOUNTPOINT if given.
        /// Repeatable.
        #[arg(long = "image", value_name = "NAME=PATH[:MOUNTPOINT]")]
        images: Vec<exobox::ImageArg>,
        /// Fork mode: the most processes alive at once.
        #[arg(long)]
        max_procs: Option<u32>,
        /// The program and its arguments.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<OsString>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Coroutine,
    Threaded,
    Fork,
}

fn main() -> ExitCode {
    let Command::Run { mode, allow_paths, images, max_procs, argv } = Cli::parse().command;
    let config = exobox::Config {
        mode: match mode {
            Mode::Coroutine => exobox::Mode::Coroutine,
            Mode::Threaded => exobox::Mode::Threaded,
            Mode::Fork => exobox::Mode::Fork,
        },
        allow_paths,
        images,
        max_procs,
        argv,
        // As env(1): the program gets this process's environment.
        env: std::env::vars_os()
            .map(|(k, v)| {
                let mut kv = k;
                kv.push("=");
                kv.push(v);
                kv
            })
            .collect(),
        image_cache: None,
    };
    let Err(e) = exobox::run(config);
    eprintln!("exobox: {e}");
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}
