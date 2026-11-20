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
        Ok(Arg { host: host.into(), at })
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
        let fd = unsharek_fs_server::spawn(&unsharek_fs_server::Dir { host: host.clone(), writable, ..Default::default() })?;
        // Open for the sandbox's life: the process ends with the program.
        out.push(unsharek::HostDir { fd: std::os::fd::IntoRawFd::into_raw_fd(fd), at: a.at.clone().unwrap_or(host) });
    }
    Ok(out)
}
