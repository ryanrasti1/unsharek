//! The unsharek CLI: arguments to an [`unsharek::Config`], then [`unsharek::run`].

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

#[path = "cli/fs.rs"]
mod fs;
#[path = "cli/net.rs"]
mod net;
#[path = "cli/tty.rs"]
mod tty;

/// Run a program in a sandbox of its own kernel; exits with the program's status.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Coroutine)]
    mode: Mode,
    /// A store path the program may see, with everything it references, read-only, each at its
    /// own path (the program's code maps in place from them). A host directory: the store paths
    /// its files reference (show the directory itself with --ro). Nothing is shown unless given:
    /// not even the program's own. At most 256 store paths. Repeatable.
    #[arg(long = "closure", value_name = "PATH")]
    closure: Vec<std::path::PathBuf>,
    /// A host directory the program may read, served live (at AT, default its own path).
    /// Repeatable.
    #[arg(long = "ro", value_name = "DIR[:AT]")]
    ro: Vec<fs::Arg>,
    /// A host directory the program may read and write, served live (at AT, default its own
    /// path). Repeatable.
    #[arg(long = "rw", value_name = "DIR[:AT]")]
    rw: Vec<fs::Arg>,
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
    /// The network beyond loopback (plugin, experimental): `none`, `public` (public addresses
    /// only) or `all`, dialled by a provider process under that policy.
    #[arg(long, value_enum, default_value_t = Net::None)]
    net: Net,
    /// Publish a port: connections to HOST_PORT on the host (127.0.0.1 unless IP is given) reach
    /// the program's listener on GUEST_PORT, as docker's -p. Repeatable.
    #[arg(long, value_name = "[IP:]HOST_PORT:GUEST_PORT")]
    publish: Vec<unsharek::provider::Publish>,
    /// The program and its arguments: a bare name is looked up on this process's PATH.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Net {
    None,
    Public,
    All,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Coroutine,
    Threaded,
    Fork,
}

fn main() -> ExitCode {
    // The image builder holds each file of a store path open until it writes the image (tzdata:
    // thousands), past the usual soft limit of 1024 ("Too many open files"). The hard limit is
    // ours to take; lockdown closes every fd it doesn't keep anyway.
    if let Ok(l) = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum.ok_or(()) {
        let _ = rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit { current: Some(l), maximum: Some(l) },
        );
    }
    let Cli { mode, closure, mut ro, rw, max_procs, setenv, mut keep_env, system, net, publish, mut argv } = Cli::parse();
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
    // An interactive terminal (cli/tty.rs): fork mode, stdin a terminal. This process becomes the
    // terminal's supervisor, outside the sandbox; its child goes on.
    let tty = if matches!(mode, Mode::Fork) && tty::is_tty() { Some(tty::supervise()) } else { None };
    // Plugin: host directories, live (cli/fs.rs). A store path's place is --closure.
    if let Some(a) = ro.iter().find(|a| !a.live && !fs::live(&a.host)) {
        let p = a.host.display();
        let why = if a.host.is_dir() { "a store path: use --closure" } else { "not a directory" };
        eprintln!("unsharek: --ro {p}: {why}");
        return ExitCode::from(125);
    }
    let host_dirs = match fs::spawn(&ro, &rw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("unsharek: a host directory's server: {e}");
            return ExitCode::from(125);
        }
    };
    // Plugin: the network, through a provider (cli/net.rs).
    let policy = match net {
        Net::None => None,
        Net::Public => Some(unsharek::provider::Policy::Public),
        Net::All => Some(unsharek::provider::Policy::All),
    };
    let net = match net::spawn(&net::Args { policy, publish }) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("unsharek: the network provider: {e}");
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
        closures: closure,
        max_procs,
        argv,
        env,
        image_cache: None,
        host_dirs: host_dirs.clone(),
        tty,
    };
    let prepare = |g: &mut unsharek::Guest| {
        if let Some(n) = &net {
            n.install(g)?;
        }
        Ok(())
    };
    let grants = |c: unsharek::SandboxConfig| {
        let c = fs::grant(&host_dirs, c);
        match &net {
            Some(n) => n.grant(c),
            None => c,
        }
    };
    let Err(e) = unsharek::run_with(config, prepare, grants);
    eprintln!("unsharek: {e}");
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}
