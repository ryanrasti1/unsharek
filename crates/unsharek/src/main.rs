//! The unsharek CLI: arguments to an [`unsharek::Config`], then [`unsharek::run`].

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

/// Run a program in a sandbox of its own kernel; exits with the program's status.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Coroutine)]
    mode: Mode,
    /// More the program may see and map, read-only: a store path (with its closure) or a host
    /// path. Repeatable.
    #[arg(long = "ro", value_name = "PATH")]
    ro: Vec<PathBuf>,
    /// Map an erofs image as /dev/unsharek/NAME, and mount it at MOUNTPOINT if given.
    /// Repeatable.
    #[arg(long = "image", value_name = "NAME=PATH[:MOUNTPOINT]")]
    images: Vec<unsharek::ImageArg>,
    /// Fork mode: the most processes alive at once.
    #[arg(long)]
    max_procs: Option<u32>,
    /// Set a variable in the program's environment, which is otherwise empty. Repeatable.
    #[arg(long = "setenv", value_name = "NAME=VALUE")]
    setenv: Vec<OsString>,
    /// Pass this process's variable NAME to the program, if set. Repeatable.
    #[arg(long = "keep-env", value_name = "NAME")]
    keep_env: Vec<OsString>,
    /// The program and its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Coroutine,
    Threaded,
    Fork,
}

fn main() -> ExitCode {
    let Cli { mode, ro, images, max_procs, setenv, keep_env, argv } = Cli::parse();
    // An empty environment, but what was asked for: the host's variables (tokens, keys) stay out
    // unless kept by name. `--setenv` first: getenv(3) takes a name's first entry.
    let mut env = setenv;
    env.extend(keep_env.iter().filter_map(|k| {
        let v = std::env::var_os(k)?;
        let mut kv = k.clone();
        kv.push("=");
        kv.push(v);
        Some(kv)
    }));
    let config = unsharek::Config {
        mode: match mode {
            Mode::Coroutine => unsharek::Mode::Coroutine,
            Mode::Threaded => unsharek::Mode::Threaded,
            Mode::Fork => unsharek::Mode::Fork,
        },
        allow_paths: ro,
        images,
        max_procs,
        argv,
        env,
        image_cache: None,
    };
    let Err(e) = unsharek::run(config);
    eprintln!("unsharek: {e}");
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}
