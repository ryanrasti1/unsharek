//! **Plugin (experimental): host directories, live.** `--ro DIR[:AT]` and `--rw DIR[:AT]`: each
//! directory served by a process of its own (unsharek-fs-server: virtiofsd's passthrough file
//! system, confined by Landlock to the directory, read-only or read-write, and its own proven
//! filter), to a virtio-fs device mounted at AT (default: DIR's own path). The sandbox gains a
//! granted socket per directory, and nothing in its filter.
//!
//! A store path given to `--ro` stays an erofs image of the closure (immutable, its ELF files
//! mapped in place), as does a file; only directories outside the store are served live.

use std::path::{Path, PathBuf};

/// One `--ro` or `--rw` argument: `DIR[:AT]`.
#[derive(Clone, Debug)]
pub struct Arg {
    pub host: PathBuf,
    pub at: Option<PathBuf>,
    /// Served live even if it is the store (`--system`'s `/nix/store`).
    pub live: bool,
}

/// `--system`'s directories (those of them that exist): the host's system, read-only.
pub const SYSTEM: &[&str] = &["/nix/store", "/run/current-system", "/etc", "/bin", "/usr", "/lib", "/lib64", "/opt", "/sbin"];

/// `prog` as the host finds it: a bare name looked up on PATH, then canonical (symlinks, such as a
/// profile's `bin/` into the store, resolved).
pub fn resolve(prog: &std::ffi::OsStr) -> std::io::Result<PathBuf> {
    let p = Path::new(prog);
    if p.components().count() > 1 || p.is_absolute() {
        return std::fs::canonicalize(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(p))
        .find(|c| c.is_file())
        .map(std::fs::canonicalize)
        .unwrap_or_else(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found on PATH")))
}

impl std::str::FromStr for Arg {
    type Err = String;
    fn from_str(s: &str) -> Result<Arg, String> {
        let (host, at) = match s.split_once(':') {
            Some((h, a)) if !a.is_empty() => (h, Some(PathBuf::from(a))),
            Some(_) => return Err(format!("{s}: empty mount point")),
            None => (s, None),
        };
        if host.is_empty() {
            return Err("an empty path".into());
        }
        Ok(Arg { host: host.into(), at, live: false })
    }
}

/// Whether `--ro PATH` is served live (a directory outside the store) rather than as an image.
pub fn live(p: &Path) -> bool {
    p.is_dir() && !std::path::absolute(p).is_ok_and(|a| a.starts_with("/nix/store"))
}

/// Spawn a server for each directory (before the sandbox boots: this process has one thread):
/// the sandbox's `host_dirs`.
pub fn spawn(ro: &[Arg], rw: &[Arg]) -> std::io::Result<Vec<unsharek::HostDir>> {
    let mut out = vec![];
    for (a, writable) in ro.iter().map(|a| (a, false)).chain(rw.iter().map(|a| (a, true))) {
        let host = std::path::absolute(&a.host)?;
        // The server's root is the directory itself, not a symlink to it (`/run/current-system`):
        // it opens its root without following one. Mounted at the path as given.
        let real = std::fs::canonicalize(&host)?;
        let fd = unsharek_fs_server::spawn(&unsharek_fs_server::Dir { host: real, writable, ..Default::default() })?;
        // Open for the sandbox's life: the process ends with the program.
        out.push(unsharek::HostDir { fd: std::os::fd::IntoRawFd::into_raw_fd(fd), at: a.at.clone().unwrap_or(host) });
    }
    Ok(out)
}
