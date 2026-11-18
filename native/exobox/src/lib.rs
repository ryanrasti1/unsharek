//! exobox: run an unmodified Linux program on an in-process Linux kernel (LKL), behind a seccomp
//! filter that leaves the host a handful of syscalls.
//!
//! [`Config`] says what to run and how; [`run`] turns the calling process into the sandbox. The
//! `exobox` binary is a thin CLI over the two.

pub mod store;

use std::convert::Infallible;
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub use syscalls::Sysno;

/// How the sandbox runs the program's threads and processes. Each mode's host allowlist is a
/// superset of the one before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The guest kernel's threads and the program's on one host thread, as coroutines.
    #[default]
    Coroutine,
    /// A host thread per program thread, made through the filter by one exact `clone`.
    Threaded,
    /// Threaded, and a guest `fork` is a host fork: processes share one guest kernel.
    Fork,
}

/// What the filter does to a host syscall it doesn't allow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deny {
    /// Kill the sandbox (SIGSYS).
    #[default]
    Kill,
    /// Fail the syscall with EPERM (for probing the filter).
    Errno,
}

/// One more host syscall the filter allows, on top of the mode's own: a syscall and conditions on
/// its arguments, all of which must hold. Written `name[:argN=V|argN=LO..HI,...]` (`HI`
/// inclusive), e.g. `getppid`, `write:arg0=3`, `madvise:arg2=4..4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub sysno: Sysno,
    pub args: Vec<ArgRange>,
}

/// Argument `index` (0-5) within `lo..=hi`, compared as 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgRange {
    pub index: u8,
    pub lo: u64,
    pub hi: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid rule {rule:?}: {why}")]
    Rule { rule: String, why: String },
    #[error("no program to run (argv is empty)")]
    NoProgram,
    #[error(transparent)]
    Store(#[from] store::Error),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = |why: &str| Error::Rule { rule: s.to_owned(), why: why.to_owned() };
        let (name, conds) = s.split_once(':').unwrap_or((s, ""));
        let sysno = Sysno::from_str(name).map_err(|_| bad("no such x86-64 syscall"))?;
        let mut args = Vec::new();
        for cond in conds.split(',').filter(|c| !c.is_empty()) {
            let (arg, range) = cond.split_once('=').ok_or_else(|| bad("a condition is argN=..."))?;
            let index = arg
                .strip_prefix("arg")
                .and_then(|i| i.parse::<u8>().ok())
                .filter(|&i| i < 6)
                .ok_or_else(|| bad("arguments are arg0..arg5"))?;
            let (lo, hi) = match range.split_once("..") {
                Some((lo, hi)) => (parse_u64(lo), parse_u64(hi)),
                None => (parse_u64(range), parse_u64(range)),
            };
            let (Some(lo), Some(hi)) = (lo, hi) else { return Err(bad("values are integers")) };
            if lo > hi {
                return Err(bad("an empty range"));
            }
            args.push(ArgRange { index, lo, hi });
        }
        Ok(Rule { sysno, args })
    }
}

/// Decimal or 0x-prefixed hexadecimal.
fn parse_u64(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Everything a sandbox needs to start.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub mode: Mode,
    pub deny: Deny,
    /// Host syscalls allowed on top of the mode's own.
    pub rules: Vec<Rule>,
    /// More host paths the program may see and map, besides its own closure: a store path
    /// brings its closure; a path outside the store is shown as is, read-only.
    pub allow_paths: Vec<PathBuf>,
    /// Writable and executable memory (JITs). Off: W^X.
    pub jit: bool,
    /// Fork mode: the most processes alive at once, the first one included.
    pub max_procs: Option<u32>,
    /// The program and its arguments; `argv[0]` is the program's path.
    pub argv: Vec<OsString>,
    /// Where store images are cached; None: [`store::Cache::default_dir`].
    pub image_cache: Option<PathBuf>,
}

/// The images the guest mounts for `config`'s program and allowed paths, built where the cache
/// lacks them. Host-side, before lockdown; nothing is opened or mapped yet.
pub fn store(config: &Config) -> Result<store::Store, Error> {
    let program = config.argv.first().ok_or(Error::NoProgram)?;
    let closure = store::closure(Path::new(program), &config.allow_paths)?;
    let dir = match &config.image_cache {
        Some(dir) => dir.clone(),
        None => store::Cache::default_dir()?,
    };
    Ok(store::Cache::new(&dir).images(&closure)?)
}

/// Become the sandbox: boot the guest kernel in this process, load `config`'s program, lock down
/// and run it. Returns only on failure before the program starts; the process ends with the
/// program's status.
pub fn run(config: Config) -> Result<Infallible, Error> {
    let _ = config;
    Err(Error::NotImplemented("the sandbox"))
}

/// A booted kernel with no program, forked once per sandbox: each child loads its own program,
/// sharing the template's booted kernel copy-on-write. Starting a sandbox skips the boot, and the
/// kernel's pages are paid for once.
pub struct Template {
    _config: Config,
}

impl Template {
    /// Boot a template in a process of its own. `config.argv` is ignored: each [`spawn`] names
    /// its program.
    ///
    /// [`spawn`]: Template::spawn
    pub fn start(config: Config) -> Result<Template, Error> {
        let _ = config;
        Err(Error::NotImplemented("templates"))
    }

    /// Fork a sandbox running `argv` with these stdin, stdout and stderr. Returns its host pid
    /// (a child of the template's process, not of this one).
    pub fn spawn(&self, argv: &[OsString], stdio: [OwnedFd; 3]) -> Result<u32, Error> {
        let _ = (argv, stdio);
        Err(Error::NotImplemented("templates"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_parse() {
        assert_eq!("getppid".parse::<Rule>().unwrap(), Rule { sysno: Sysno::getppid, args: vec![] });
        assert_eq!(
            "madvise:arg0=0x1000..0x2000,arg2=4".parse::<Rule>().unwrap(),
            Rule {
                sysno: Sysno::madvise,
                args: vec![
                    ArgRange { index: 0, lo: 0x1000, hi: 0x2000 },
                    ArgRange { index: 2, lo: 4, hi: 4 }
                ],
            }
        );
    }

    #[test]
    fn rules_refuse_nonsense() {
        for bad in ["nosuchcall", "write:fd=3", "write:arg6=1", "write:arg0=x", "write:arg0=5..4"] {
            assert!(bad.parse::<Rule>().is_err(), "{bad} parsed");
        }
    }
}
