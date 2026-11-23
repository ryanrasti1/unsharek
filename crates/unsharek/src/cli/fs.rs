//! The CLI's mounts: `--mount SRC:DST:TYPE` (or `SRC:TYPE`, at SRC's own path), TYPE one of
//!
//! - `map`: SRC shown read-only, its files mapped in place from the host's (not copied): it must
//!   not change while the program runs. No host call is added to the filter.
//! - `closure`: SRC a store path (or a directory whose files reference some), shown with
//!   everything it references, each store path at its own path. No host call is added.
//! - `ro`, `rw` (plugin, experimental): SRC served live through virtio-fs, by the host's file
//!   calls (unsharek-tcb's fs plugin's rows), every path confined by Landlock to the mounts'
//!   sources (`--no-landlock`: by nothing but the process's own environment, a container's).

use std::path::{Path, PathBuf};

/// `--system`'s directories (those of them that exist): the host's system, read-only.
pub const SYSTEM: &[&str] = &["/nix/store", "/run/current-system", "/etc", "/bin", "/usr", "/lib", "/lib64", "/opt", "/sbin"];

/// `prog` as the host finds it: a bare name looked up on PATH, then canonical (symlinks, such as a
/// profile's `bin/` into the store, resolved).
pub fn resolve(prog: &std::ffi::OsStr) -> std::io::Result<PathBuf> {
    let p = Path::new(prog);
    if p.components().count() > 1 || p.is_absolute() {
        return follow(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(p))
        .find(|c| c.is_file())
        .map(|c| follow(&c))
        .unwrap_or_else(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found on PATH")))
}

/// `p`'s symlinks followed while each keeps its name: a profile's `bin/true` to the store's, but
/// not on to `coreutils`, a multi-call program that tells what to be by the name it was run by.
fn follow(p: &Path) -> std::io::Result<PathBuf> {
    let mut p = std::path::absolute(p)?;
    for _ in 0..40 {
        let Ok(t) = std::fs::read_link(&p) else { break };
        let next = p.parent().unwrap_or(Path::new("/")).join(t);
        if next.file_name() != p.file_name() {
            break;
        }
        p = next;
    }
    // The directories' symlinks too (`/run/current-system`), the name kept.
    let dir = std::fs::canonicalize(p.parent().unwrap_or(Path::new("/")))?;
    Ok(dir.join(p.file_name().unwrap_or_default()))
}

/// A mount's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Map,
    Closure,
    Ro,
    Rw,
}

/// One `--mount`: `SRC:DST:TYPE`, or `SRC:TYPE` (DST is SRC).
#[derive(Clone, Debug)]
pub struct Mount {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub ty: Type,
}

impl std::str::FromStr for Mount {
    type Err = String;
    fn from_str(s: &str) -> Result<Mount, String> {
        let (rest, ty) = s.rsplit_once(':').ok_or("SRC:DST:TYPE (TYPE: map, closure, ro or rw)")?;
        let ty = match ty {
            "map" => Type::Map,
            "closure" => Type::Closure,
            "ro" => Type::Ro,
            "rw" => Type::Rw,
            t => return Err(format!("{t}: not a mount type (map, closure, ro or rw)")),
        };
        let (src, dst) = match rest.split_once(':') {
            Some((s, d)) => (s, Some(d)),
            None => (rest, None),
        };
        if src.is_empty() {
            return Err("an empty source".into());
        }
        let src = std::path::absolute(src).map_err(|e| e.to_string())?;
        let dst = match dst {
            None | Some("") => src.clone(),
            Some(d) if Path::new(d).is_absolute() => PathBuf::from(d),
            Some(d) => return Err(format!("{d}: the mount point must be absolute")),
        };
        if ty == Type::Closure && dst != src {
            return Err("a closure is shown at its own paths: no mount point".into());
        }
        Ok(Mount { src, dst, ty })
    }
}
