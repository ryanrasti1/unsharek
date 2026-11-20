//! The unsharek CLI: arguments to an [`unsharek::Config`], then [`unsharek::run`].

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

#[path = "cli/fs.rs"]
mod fs;

/// Run a program in a sandbox of its own kernel; exits with the program's status.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Coroutine)]
    mode: Mode,
    /// More the program may see, read-only: a store path (with its closure, as an image), a host
    /// file, or a host directory, served live (at AT, default its own path). Repeatable.
    #[arg(long = "ro", value_name = "PATH[:AT]")]
    ro: Vec<fs::Arg>,
    /// A host directory the program may read and write, served live (at AT, default its own
    /// path). Repeatable.
    #[arg(long = "rw", value_name = "DIR[:AT]")]
    rw: Vec<fs::Arg>,
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
    /// For trying things out: the host's system directories, read-only and live (`/nix/store`,
    /// `/run/current-system`, `/etc`, `/bin`, `/usr`, `/lib`, `/lib64`, `/opt`, `/sbin`, those that
    /// exist; never home or /tmp), and the host's PATH, TERM and LANG. Anything world-readable
    /// there, `/etc` included, is the program's to read.
    #[arg(long)]
    system: bool,
    /// The program and its arguments: a bare name is looked up on this process's PATH.
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
    let Cli { mode, mut ro, rw, images, max_procs, setenv, mut keep_env, system, mut argv } = Cli::parse();
    if system {
        ro.extend(fs::SYSTEM.iter().filter(|d| std::path::Path::new(d).is_dir()).map(|d| fs::Arg { host: d.into(), at: None, live: true }));
        keep_env.extend(["PATH", "TERM", "LANG"].map(OsString::from));
    }
    // The program as the host resolves it: a bare name on PATH, then any symlinks (a profile's
    // bin/ into the store), so its closure is found and its path exists in the guest.
    match fs::resolve(&argv[0]) {
        Ok(p) => argv[0] = p.into_os_string(),
        Err(e) => {
            eprintln!("unsharek: {}: {e}", argv[0].to_string_lossy());
            return ExitCode::from(127);
        }
    }
    // Plugin: host directories, live (cli/fs.rs).
    let (live, images_ro): (Vec<fs::Arg>, Vec<fs::Arg>) = ro.into_iter().partition(|a| a.live || fs::live(&a.host));
    let host_dirs = match fs::spawn(&live, &rw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("unsharek: a host directory's server: {e}");
            return ExitCode::from(125);
        }
    };
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
        allow_paths: images_ro.into_iter().map(|a| a.host).collect(),
        images,
        max_procs,
        argv,
        env,
        image_cache: None,
        host_dirs,
    };
    let Err(e) = unsharek::run(config);
    eprintln!("unsharek: {e}");
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}
