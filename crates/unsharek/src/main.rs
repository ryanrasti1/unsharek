//! The unsharek CLI: arguments to an [`unsharek::Config`], then [`unsharek::run_with`].

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

#[path = "cli/fs.rs"]
mod fs;
#[path = "cli/tty.rs"]
mod tty;

use fs::{Mount, Type};

/// Run a program in a sandbox of its own kernel; exits with the program's status.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Coroutine)]
    mode: Mode,
    /// Show the program SRC at DST (default: SRC's own path). TYPE is required:
    /// `map`: read-only, its files mapped in place, not copied (SRC must not change while the
    /// program runs); `closure`: a store path and everything it references, each at its own
    /// path (at most 256 store paths); `ro`, `rw` (experimental): live, read-only or
    /// read-write, through the host's own file calls, confined by Landlock to the sources.
    /// Nothing is shown unless mounted, not even the program's own files. Repeatable.
    #[arg(long = "mount", value_name = "SRC[:DST]:TYPE")]
    mounts: Vec<Mount>,
    /// The network beyond loopback (experimental): `none`, or `host`, the host's own: the
    /// program's sockets are host sockets, any address, any port (isolate it with a network
    /// namespace).
    #[arg(long, value_enum, default_value_t = Net::None)]
    net: Net,
    /// `ro` and `rw` mounts without Landlock: their paths confined by nothing but where this
    /// process runs. Only where file access is already scoped (a container's filesystem).
    #[arg(long)]
    no_landlock: bool,
    /// NAME=VALUE: set it in the program's environment, which is otherwise empty. NAME alone:
    /// pass this process's NAME, if set. Repeatable; the first of a name wins.
    #[arg(long = "env", value_name = "NAME[=VALUE]")]
    env: Vec<OsString>,
    /// For trying things out: the host's system directories as `ro` mounts (`/nix/store`,
    /// `/run/current-system`, `/etc`, `/bin`, `/usr`, `/lib`, `/lib64`, `/opt`, `/sbin`, those
    /// that exist; never home or /tmp), and the host's PATH, TERM and LANG. Anything
    /// world-readable there, `/etc` included, is the program's to read.
    #[arg(long)]
    system: bool,
    /// Fork mode: the most processes alive at once.
    #[arg(long)]
    max_procs: Option<u32>,
    /// The program and its arguments: a bare name is looked up on this process's PATH. (An
    /// unknown flag before it is an error, not the program's name; its own flags are its.)
    #[arg(required = true, trailing_var_arg = true)]
    argv: Vec<OsString>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Net {
    None,
    Host,
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
    let Cli { mode, mut mounts, net, no_landlock, mut env, system, max_procs, mut argv } = Cli::parse();
    if system {
        let dirs = fs::SYSTEM.iter().filter(|d| std::path::Path::new(d).is_dir());
        mounts.extend(dirs.map(|d| Mount { src: d.into(), dst: d.into(), ty: Type::Ro }));
        env.extend(["PATH", "TERM", "LANG"].map(OsString::from));
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
    let mut closures = vec![];
    let mut immutable = vec![];
    let mut host_dirs = vec![];
    // Plugin: host directories, live (unsharek-tcb's `Files`, its roots the sources).
    let mut files = unsharek::plugin::Files::new().no_landlock(no_landlock);
    for m in &mounts {
        match m.ty {
            Type::Closure => closures.push(m.src.clone()),
            Type::Map => immutable.push(unsharek::Immutable { dir: m.src.clone(), at: m.dst.clone() }),
            Type::Ro | Type::Rw => {
                // The served root is the directory itself, not a symlink to it
                // (`/run/current-system`), mounted at the path as given.
                let dir = match std::fs::canonicalize(&m.src) {
                    Ok(d) if d.is_dir() => d,
                    Ok(_) => return usage(format!("{}: not a directory", m.src.display())),
                    Err(e) => return usage(format!("{}: {e}", m.src.display())),
                };
                let writable = m.ty == Type::Rw;
                let access = if writable { unsharek::plugin::Fs::ReadWrite } else { unsharek::plugin::Fs::ReadOnly };
                files = files.root(&dir, access);
                host_dirs.push(unsharek::HostDir { dir, at: m.dst.clone(), writable });
            }
        }
    }
    if no_landlock && !host_dirs.is_empty() {
        eprintln!("unsharek: --no-landlock: the ro and rw mounts' paths are confined only by where unsharek runs");
    }
    // An interactive terminal (cli/tty.rs): fork mode, stdin a terminal. This process becomes the
    // terminal's supervisor, outside the sandbox; its child goes on.
    let tty = if matches!(mode, Mode::Fork) && tty::is_tty() { Some(tty::supervise()) } else { None };
    // An empty environment, but what was asked for: the host's variables (tokens, keys) stay out
    // unless kept by name. In order: getenv(3) takes a name's first entry.
    let env = env
        .into_iter()
        .filter_map(|e| {
            if e.as_encoded_bytes().contains(&b'=') {
                return Some(e);
            }
            let v = std::env::var_os(&e)?;
            let mut kv = e;
            kv.push("=");
            kv.push(v);
            Some(kv)
        })
        .collect();
    let config = unsharek::Config {
        mode: match mode {
            Mode::Coroutine => unsharek::Mode::Coroutine,
            Mode::Threaded => unsharek::Mode::Threaded,
            Mode::Fork => unsharek::Mode::Fork,
        },
        closures,
        max_procs,
        argv,
        env,
        immutable,
        image_cache: None,
        host_dirs: host_dirs.clone(),
        tty,
    };
    // Plugins (experimental): unsharek-tcb's, each behind its flag.
    let sockets = (net == Net::Host).then_some(unsharek::plugin::Net);
    let mut plugins: Vec<&dyn unsharek::Plugin> = vec![];
    if !host_dirs.is_empty() {
        plugins.push(&files);
    }
    if let Some(n) = &sockets {
        plugins.push(n);
    }
    let prepare = |g: &mut unsharek::Guest| if net == Net::Host { unsharek::hostnet::install(g) } else { Ok(()) };
    let Err(e) = unsharek::run_with(config, prepare, |c| c, &plugins);
    eprintln!("unsharek: {e}");
    if e.to_string().contains("landlock") {
        // The library's words are its API's (`Files::no_landlock`); the CLI's are flags.
        eprintln!("unsharek: for the CLI: --no-landlock (where file access is already scoped), or a `map` mount instead of `ro`");
    }
    // As env(1) and container runtimes: the sandbox itself failed, not the program.
    ExitCode::from(125)
}

fn usage(msg: String) -> ExitCode {
    eprintln!("unsharek: --mount {msg}");
    ExitCode::from(125)
}
