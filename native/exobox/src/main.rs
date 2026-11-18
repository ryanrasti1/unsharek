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
        /// What a disallowed host syscall gets.
        #[arg(long, value_enum, default_value_t = Deny::Kill)]
        deny: Deny,
        /// Allow one more host syscall: name[:argN=V|argN=LO..HI,...]. Repeatable.
        #[arg(long = "allow", value_name = "RULE")]
        rules: Vec<exobox::Rule>,
        /// More the program may see and map: a store path (with its closure) or a host path
        /// (read-only). Repeatable.
        #[arg(long = "allow-path", value_name = "PATH")]
        allow_paths: Vec<PathBuf>,
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

#[derive(Clone, Copy, ValueEnum)]
enum Deny {
    Kill,
    Errno,
}

fn main() -> ExitCode {
    let Command::Run { mode, deny, rules, allow_paths, max_procs, argv } = Cli::parse().command;
    let config = exobox::Config {
        mode: match mode {
            Mode::Coroutine => exobox::Mode::Coroutine,
            Mode::Threaded => exobox::Mode::Threaded,
            Mode::Fork => exobox::Mode::Fork,
        },
        deny: match deny {
            Deny::Kill => exobox::Deny::Kill,
            Deny::Errno => exobox::Deny::Errno,
        },
        rules,
        allow_paths,
        max_procs,
        argv,
        image_cache: None,
    };
    let Err(e) = exobox::run(config);
    eprintln!("exobox: {e}");
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}
