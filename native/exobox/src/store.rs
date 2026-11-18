//! What the guest sees of the host's files: the Nix store paths the program needs and the host
//! directories the user allowed, each as a read-only erofs image (exobox-erofs) built once and
//! cached on disk. Runs on the host before lockdown, so std is fine here.
//!
//! Two steps, separately usable:
//! - [`closure`]: which store paths and host directories, from the program and `--allow-path`s.
//!   Nix's own tooling (`nix-store --query --requisites`) computes store closures; for files
//!   outside the store, references are found the way Nix finds them, by scanning bytes for store
//!   paths.
//! - [`Cache::images`]: an image per entry, built if the cache doesn't have it, and where it is.
//!   Nothing is opened or mapped here: how images are mapped before lockdown is decided later.
//!
//! The cache, under its directory (`$XDG_CACHE_HOME/exobox/images` by default):
//! ```text
//! v<FORMAT>/store/<hash>-<name>.erofs    one per store path; a store path is immutable, so its
//! v<FORMAT>/store/<hash>-<name>.layout   name is the key
//! v<FORMAT>/host/<dirname>-<key>.erofs   one per allowed host directory; <key> hashes the tree's
//! v<FORMAT>/host/<dirname>-<key>.layout  metadata, so an edit makes a new key and a rebuild
//! ```
//! `<FORMAT>` is [`exobox_erofs::FORMAT_VERSION`]: a builder that writes differently doesn't read
//! old images. Each image is written to a temporary file and renamed into place, its layout
//! before it, so an image that exists is complete and has its layout; racing builders write the
//! same bytes (the builder is deterministic) and the last rename wins.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, process, thread};

/// Where the guest sees the store. Fixed: store paths' contents refer to it by this name.
pub const STORE_DIR: &str = "/nix/store";

/// Names the image cache's directory, over `$XDG_CACHE_HOME/exobox/images` (and under
/// [`Config::image_cache`](crate::Config::image_cache)): for tests, and for a cache shared
/// between users.
pub const CACHE_ENV: &str = "EXOBOX_IMAGE_CACHE";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0}: an allowed path outside the store must be a directory")]
    NotDir(PathBuf),
    #[error("{0}: allowing it would show the whole store; allow store paths instead")]
    WholeStore(PathBuf),
    #[error("{0}: the program is outside the store and outside every allowed path")]
    ProgramNotAllowed(PathBuf),
    #[error("nix-store --query --requisites: {0}")]
    Query(String),
    #[error("{path}: building its image: {source}")]
    Image { path: PathBuf, source: exobox_erofs::Error },
    #[error("{0}: kept changing while its image was built")]
    Unstable(PathBuf),
    #[error("no cache directory: set {CACHE_ENV}, XDG_CACHE_HOME or HOME")]
    NoCacheDir,
}

pub type Result<T> = std::result::Result<T, Error>;

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::Io { path: path.to_owned(), source }
}

/// Everything the guest sees of the host's files, each entry mounted at its own path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Closure {
    /// Store paths (`/nix/store/<hash>-<name>`), closed under references.
    pub store: BTreeSet<PathBuf>,
    /// Allowed directories outside the store, canonical; none inside another.
    pub host: BTreeSet<PathBuf>,
}

/// The store paths and host directories the guest sees when running `program` with
/// `allow_paths`:
/// - a store path, or a path inside one (the program or an allowed path): that store path's
///   closure;
/// - an allowed path outside the store: a directory, shown as is, plus the closure of every store
///   path its files and symlinks mention. A host path that resolves into the store (a `result`
///   link) is that store path;
/// - a program outside the store: must be inside an allowed directory (its references come with
///   that directory's).
///
/// Paths that don't exist are errors, as is a store path that Nix doesn't know. Relative paths
/// are from the current directory. Needs `nix-store` on `PATH` (one query for all roots).
pub fn closure(program: &Path, allow_paths: &[PathBuf]) -> Result<Closure> {
    let mut roots = BTreeSet::new();
    let mut host = BTreeSet::new();
    for path in allow_paths {
        match locate(path)? {
            Place::Store(p) => {
                roots.insert(p);
            }
            Place::Host(dir) => {
                if !fs::metadata(&dir).map_err(io_err(&dir))?.is_dir() {
                    return Err(Error::NotDir(dir));
                }
                host.insert(dir);
            }
        }
    }
    // An allowed directory inside another is already in the outer one's image.
    let outer: BTreeSet<PathBuf> =
        host.iter().filter(|d| !host.iter().any(|o| o != *d && d.starts_with(o))).cloned().collect();
    match locate(program)? {
        Place::Store(p) => {
            roots.insert(p);
        }
        Place::Host(p) => {
            if !outer.iter().any(|d| p.starts_with(d)) {
                return Err(Error::ProgramNotAllowed(p));
            }
        }
    }
    let mut refs = BTreeMap::new();
    for dir in &outer {
        scan_tree(dir, &mut refs)?;
    }
    roots.extend(resolve(refs));
    Ok(Closure { store: requisites(&roots)?, host: outer })
}

enum Place {
    /// The store path containing it.
    Store(PathBuf),
    /// Outside the store, canonical.
    Host(PathBuf),
}

fn locate(path: &Path) -> Result<Place> {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir().map_err(io_err(path))?.join(path)
    };
    // Lexically first: a path inside a store path names that store path even if it's a symlink
    // into another (`bin/sh -> bash`), and the closure covers the target anyway.
    if let Some(sp) = store_path_of(&abs) {
        fs::metadata(&abs).map_err(io_err(&abs))?;
        return Ok(Place::Store(sp));
    }
    let canon = fs::canonicalize(&abs).map_err(io_err(&abs))?;
    if let Some(sp) = store_path_of(&canon) {
        return Ok(Place::Store(sp));
    }
    if Path::new(STORE_DIR).starts_with(&canon) {
        return Err(Error::WholeStore(canon));
    }
    Ok(Place::Host(canon))
}

/// `/nix/store/<name>` if `path` is it or is inside it, lexically (no `..`, which a symlink could
/// make mean anything).
fn store_path_of(path: &Path) -> Option<PathBuf> {
    let rest = path.strip_prefix(STORE_DIR).ok()?;
    let mut parts = rest.components();
    let Some(Component::Normal(name)) = parts.next() else { return None };
    if parts.any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(Path::new(STORE_DIR).join(name))
}

/// `nix-store --query --requisites`: the roots and everything they reference, transitively.
fn requisites(roots: &BTreeSet<PathBuf>) -> Result<BTreeSet<PathBuf>> {
    if roots.is_empty() {
        return Ok(BTreeSet::new());
    }
    let out = Command::new("nix-store")
        .args(["--query", "--requisites", "--"])
        .args(roots)
        .output()
        .map_err(io_err(Path::new("nix-store")))?;
    if !out.status.success() {
        return Err(Error::Query(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(out
        .stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| PathBuf::from(OsStr::from_bytes(l)))
        .collect())
}

/// Store paths mentioned, by hash: the longest name seen after each (see [`resolve`]).
type Refs = BTreeMap<[u8; HASH_LEN], Vec<u8>>;

const HASH_LEN: usize = 32;
/// The longest name after a store path's hash (Nix's limit).
const NAME_MAX: usize = 211;
const PREFIX: &[u8] = b"/nix/store/";
/// A reference's most bytes: the prefix, hash, `-` and name. Chunks overlap by this much so none
/// is split.
const REF_MAX: usize = PREFIX.len() + HASH_LEN + 1 + NAME_MAX;

/// Every regular file's bytes and every symlink's target under `dir`, without following links.
fn scan_tree(dir: &Path, refs: &mut Refs) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        let path = entry.map_err(io_err(dir))?.path();
        let md = fs::symlink_metadata(&path).map_err(io_err(&path))?;
        if md.is_dir() {
            scan_tree(&path, refs)?;
        } else if md.is_symlink() {
            let target = fs::read_link(&path).map_err(io_err(&path))?;
            scan_bytes(target.as_os_str().as_bytes(), refs);
        } else if md.is_file() {
            scan_file(&path, refs)?;
        }
    }
    Ok(())
}

fn scan_file(path: &Path, refs: &mut Refs) -> Result<()> {
    const CHUNK: usize = 1 << 20;
    let mut f = File::open(path).map_err(io_err(path))?;
    let mut buf = vec![0u8; REF_MAX + CHUNK];
    let mut kept = 0;
    loop {
        let n = f.read(&mut buf[kept..]).map_err(io_err(path))?;
        if n == 0 {
            return Ok(());
        }
        let end = kept + n;
        // A reference cut at the end is seen shorter (or not at all) now and whole next time,
        // from the kept tail; `resolve` takes the longest.
        scan_bytes(&buf[..end], refs);
        kept = end.min(REF_MAX);
        buf.copy_within(end - kept..end, 0);
    }
}

/// Finds `/nix/store/<hash>-<name>` in `bytes`: a hash of Nix's base-32 digits, then as many
/// name characters as follow (which may run past the name, as in `…-glibc-2.44.so`; `resolve`
/// trims them).
fn scan_bytes(bytes: &[u8], refs: &mut Refs) {
    let hash_char = |b: &u8| b"0123456789abcdfghijklmnpqrsvwxyz".contains(b);
    let name_char = |b: &&u8| b.is_ascii_alphanumeric() || b"+-._?=".contains(b);
    let mut at = 0;
    while let Some(i) = bytes[at..].iter().position(|&b| b == b'/') {
        let rest = &bytes[at + i..];
        at += i + 1;
        let Some(rest) = rest.strip_prefix(PREFIX) else { continue };
        if rest.len() <= HASH_LEN || !rest[..HASH_LEN].iter().all(hash_char) || rest[HASH_LEN] != b'-' {
            continue;
        }
        let name: Vec<u8> = rest[HASH_LEN + 1..].iter().take(NAME_MAX).take_while(name_char).copied().collect();
        let longest = refs.entry(rest[..HASH_LEN].try_into().unwrap()).or_default();
        if name.len() > longest.len() {
            *longest = name;
        }
    }
}

/// Each mentioned hash's store path: the longest prefix of the name seen that exists (a hash
/// names one store path, so the first that exists is it). A hash with none is dropped: the path
/// isn't on this host, natively the program wouldn't find it either.
fn resolve(refs: Refs) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    for (hash, name) in refs {
        for len in (1..=name.len()).rev() {
            let mut base = hash.to_vec();
            base.push(b'-');
            base.extend_from_slice(&name[..len]);
            let path = Path::new(STORE_DIR).join(OsStr::from_bytes(&base));
            if fs::symlink_metadata(&path).is_ok() {
                found.insert(path);
                break;
            }
        }
    }
    found
}

/// One image the guest mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Where the guest sees it: the store path, or the host directory's own path.
    pub guest: PathBuf,
    /// The erofs image.
    pub image: PathBuf,
    /// Its layout, as [`exobox_erofs::Layout::to_text`] writes it: each file's offset in the image.
    pub layout: PathBuf,
}

/// Everything the runtime mounts: store paths first (sorted), then host directories.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Store {
    pub mounts: Vec<Mount>,
}

/// The on-disk image cache (see the module's comment).
pub struct Cache {
    /// `<dir>/v<FORMAT>`.
    root: PathBuf,
    builds: AtomicUsize,
}

/// Distinguishes this process's temporary files from each other (the pid, from other processes').
static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);

impl Cache {
    pub fn new(dir: &Path) -> Cache {
        let root = dir.join(format!("v{}", exobox_erofs::FORMAT_VERSION));
        Cache { root, builds: AtomicUsize::new(0) }
    }

    /// `$EXOBOX_IMAGE_CACHE`, else `$XDG_CACHE_HOME/exobox/images`, else
    /// `$HOME/.cache/exobox/images`.
    pub fn default_dir() -> Result<PathBuf> {
        let var = |name| env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        if let Some(dir) = var(CACHE_ENV) {
            return Ok(dir);
        }
        let cache = var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache")));
        Ok(cache.ok_or(Error::NoCacheDir)?.join("exobox/images"))
    }

    /// How many images this `Cache` has built (rather than found).
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::Relaxed)
    }

    /// An image for every entry of `closure`, built in parallel where missing.
    pub fn images(&self, closure: &Closure) -> Result<Store> {
        let jobs: Vec<(&Path, bool)> = closure
            .store
            .iter()
            .map(|p| (p.as_path(), true))
            .chain(closure.host.iter().map(|p| (p.as_path(), false)))
            .collect();
        let next = AtomicUsize::new(0);
        let done = Mutex::new(Vec::with_capacity(jobs.len()));
        let workers = thread::available_parallelism().map_or(1, |n| n.get()).min(jobs.len());
        thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(path, store)) = jobs.get(i) else { break };
                        let got = if store { self.store_image(path) } else { self.host_image(path) };
                        done.lock().unwrap().push((i, got));
                    }
                });
            }
        });
        let mut done = done.into_inner().unwrap();
        done.sort_by_key(|(i, _)| *i);
        Ok(Store { mounts: done.into_iter().map(|(_, m)| m).collect::<Result<_>>()? })
    }

    /// The image of store path `path` (`/nix/store/<hash>-<name>`).
    pub fn store_image(&self, path: &Path) -> Result<Mount> {
        let name = path.file_name().ok_or_else(|| Error::NotDir(path.to_owned()))?;
        let mount = self.mount(path, "store", name);
        if !exists(&mount.image)? {
            self.build(path, &mount, || Ok(()))?;
        }
        Ok(mount)
    }

    /// The image of host directory `dir` (canonical), current as of now.
    pub fn host_image(&self, dir: &Path) -> Result<Mount> {
        // A tree edited between the key's walk and the build's would be cached under a key that
        // doesn't describe it; walking again after the build catches that (to the metadata's
        // resolution), and the build is retried a few times before giving up.
        for _ in 0..3 {
            let key = tree_key(dir)?;
            let mount = self.mount(dir, "host", &host_name(dir, key));
            if exists(&mount.image)? {
                return Ok(mount);
            }
            match self.build(dir, &mount, || {
                if tree_key(dir)? == key { Ok(()) } else { Err(Error::Unstable(dir.to_owned())) }
            }) {
                Err(Error::Unstable(_)) => continue,
                got => return got.map(|()| mount),
            }
        }
        Err(Error::Unstable(dir.to_owned()))
    }

    fn mount(&self, guest: &Path, kind: &str, name: &OsStr) -> Mount {
        let base = self.root.join(kind).join(name);
        Mount {
            guest: guest.to_owned(),
            image: with_suffix(&base, ".erofs"),
            layout: with_suffix(&base, ".layout"),
        }
    }

    /// Builds `src`'s image into temporary files beside `mount`'s, and renames them into place
    /// if `check` (run after the build) agrees.
    fn build(&self, src: &Path, mount: &Mount, check: impl FnOnce() -> Result<()>) -> Result<()> {
        let dir = mount.image.parent().unwrap();
        fs::create_dir_all(dir).map_err(io_err(dir))?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = |p: &Path| with_suffix(p, &format!(".{}-{seq}.tmp", process::id()));
        let (image, layout) = (tmp(&mount.image), tmp(&mount.layout));
        let built = (|| {
            let lay = exobox_erofs::build(src, &image)
                .map_err(|source| Error::Image { path: src.to_owned(), source })?;
            fs::write(&layout, lay.to_text()).map_err(io_err(&layout))?;
            // On disk before the renames: after a crash, a cached image is whole or absent, never
            // a renamed file whose data never made it.
            for p in [&image, &layout] {
                File::open(p).and_then(|f| f.sync_all()).map_err(io_err(p))?;
            }
            check()?;
            fs::rename(&layout, &mount.layout).map_err(io_err(&mount.layout))?;
            fs::rename(&image, &mount.image).map_err(io_err(&mount.image))
        })();
        if built.is_err() {
            let _ = fs::remove_file(&image);
            let _ = fs::remove_file(&layout);
        } else {
            self.builds.fetch_add(1, Ordering::Relaxed);
        }
        built
    }
}

/// `path` with `suffix` appended to its last component (store names have dots of their own, so
/// not an extension).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io { path: path.to_owned(), source: e }),
    }
}

/// `<dirname>-<key>`, the name only to tell images apart by eye.
fn host_name(dir: &Path, key: u64) -> std::ffi::OsString {
    let base = dir.file_name().map_or(b"root".as_slice(), |n| n.as_bytes());
    let mut name: String = base
        .iter()
        .take(64)
        .map(|&b| if b.is_ascii_alphanumeric() || b"+-._".contains(&b) { b as char } else { '_' })
        .collect();
    name.push_str(&format!("-{key:016x}"));
    name.into()
}

/// A hash of everything about the tree under `dir` that its image depends on, or that changes
/// when a file's contents do: each entry's path, type and mode, size, mtime, inode and link count,
/// and each symlink's target. Contents aren't read: an edit changes the mtime (or the inode, for
/// a replacement), which is what make and cargo trust too.
///
/// std's SipHash, 64 bits: not stable across Rust versions (a new toolchain rebuilds the images,
/// nothing worse), and a collision needs two states of one tree with equal keys.
fn tree_key(dir: &Path) -> Result<u64> {
    fn walk(dir: &Path, rel: &Path, h: &mut DefaultHasher) -> Result<()> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(io_err(dir))? {
            names.push(entry.map_err(io_err(dir))?.file_name());
        }
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let rel = rel.join(&name);
            let md = fs::symlink_metadata(&path).map_err(io_err(&path))?;
            // Lengths before variable-length fields, so no two trees hash the same bytes.
            let rel_bytes = rel.as_os_str().as_bytes();
            h.write_usize(rel_bytes.len());
            h.write(rel_bytes);
            for v in [md.mode() as u64, md.len(), md.mtime() as u64, md.mtime_nsec() as u64, md.ino(), md.nlink()] {
                h.write_u64(v);
            }
            if md.is_symlink() {
                let target = fs::read_link(&path).map_err(io_err(&path))?;
                h.write_usize(target.as_os_str().len());
                h.write(target.as_os_str().as_bytes());
            } else if md.is_dir() {
                walk(&path, &rel, h)?;
            }
        }
        // Ends the directory, so moving an entry out of it changes the key.
        h.write_usize(usize::MAX);
        Ok(())
    }
    let mut h = DefaultHasher::new();
    h.write_u32(exobox_erofs::FORMAT_VERSION);
    let md = fs::metadata(dir).map_err(io_err(dir))?;
    h.write_u64(md.mode() as u64);
    walk(dir, Path::new(""), &mut h)?;
    Ok(h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "r3hvhzl5fxhrgn0rfy5g7rda17702pj4";

    #[test]
    fn scan_finds_references_and_their_longest_name() {
        let mut refs = Refs::new();
        // Not references: a short hash, one with an 'o' (not a base-32 digit), one with no name.
        let text = format!(
            "x/nix/store/{HASH}-glibc-2.44/lib/ld.so\0/nix/store/{HASH}-glibc:/nix/store/short-x \
             /nix/store/{}-nope /nix/store/{}",
            "o".repeat(32),
            HASH.replace('r', "0"),
        );
        scan_bytes(text.as_bytes(), &mut refs);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[HASH.as_bytes()], b"glibc-2.44");
    }

    #[test]
    fn scan_file_sees_a_reference_across_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        // Puts the reference across the first 1 MiB read's end.
        let mut data = vec![b'x'; (1 << 20) + REF_MAX - 20];
        data.extend_from_slice(format!("/nix/store/{HASH}-glibc-2.44-57\0").as_bytes());
        fs::write(&path, &data).unwrap();
        let mut refs = Refs::new();
        scan_file(&path, &mut refs).unwrap();
        assert_eq!(refs[HASH.as_bytes()], b"glibc-2.44-57");
    }

    #[test]
    fn store_paths_lexically() {
        let sp = |p: &str| store_path_of(Path::new(p));
        assert_eq!(sp(&format!("/nix/store/{HASH}-x/bin/sh")), Some(format!("/nix/store/{HASH}-x").into()));
        assert_eq!(sp(&format!("/nix/store/{HASH}-x")), Some(format!("/nix/store/{HASH}-x").into()));
        assert_eq!(sp("/nix/store"), None);
        assert_eq!(sp(&format!("/nix/store/{HASH}-x/../y")), None);
        assert_eq!(sp("/home/nix/store/x"), None);
    }
}
