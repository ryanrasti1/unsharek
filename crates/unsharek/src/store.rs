//! What the guest sees of the host's files: the Nix store paths the program needs and the host
//! directories the user allowed, each as a read-only erofs image (unsharek-erofs) built once and
//! cached on disk. Runs on the host before lockdown, so std is fine here.
//!
//! Two steps, separately usable:
//! - [`closure`]: which store paths and host directories, from the program and `--ro`s.
//!   Nix's own tooling (`nix-store --query --requisites`) computes store closures; for files
//!   outside the store, references are found the way Nix finds them, by scanning bytes for store
//!   paths. [`Cache::closure`] is the same with both cached: a store path's closure is immutable
//!   (the query was ~19 ms of a 30 ms start), and a host tree's scan is keyed like its image.
//! - [`Cache::images`]: an image per entry, built if the cache doesn't have it, and where it is.
//!   Nothing is opened or mapped here: how images are mapped before lockdown is decided later.
//!
//! The cache, under its directory (`$XDG_CACHE_HOME/unsharek/images` by default):
//! ```text
//! v<FORMAT>/store/<hash>-<name>.erofs    one per store path; a store path is immutable, so its
//! v<FORMAT>/store/<hash>-<name>.layout   name is the key
//! v<FORMAT>/entry/<hash>-<name>.erofs    one per store path that is a file or a symlink: its
//! v<FORMAT>/entry/<hash>-<name>.layout   root directory holds it, by its name (`Kind::Entry`)
//! v<FORMAT>/host/<dirname>-<key>.erofs  one per allowed host directory; <key> hashes the tree's
//! v<FORMAT>/host/<dirname>-<key>.layout  metadata, so an edit makes a new key and a rebuild
//! v<FORMAT>/host/<dirname>-<key>.refs    the store paths the tree mentions (its scan), same key
//! v<FORMAT>/requisites/<key>             the closure of a set of store paths; <key> hashes their
//!                                        names, which the file repeats (checked on reading)
//! ```
//! `<FORMAT>` is [`unsharek_erofs::FORMAT_VERSION`]: a builder that writes differently doesn't read
//! old images. Each image is written to a temporary file and renamed into place, its layout
//! before it, so an image that exists is complete and has its layout; racing builders write the
//! same bytes (the builder is deterministic) and the last rename wins. The `.refs` and
//! `requisites` files are written the same way and carry their own version ([`LIST_VERSION`]) and
//! an end line, so a file of another version, or cut short, is ignored and made again.

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

/// Names the image cache's directory, over `$XDG_CACHE_HOME/unsharek/images` (and under
/// `unsharek::Config::image_cache`): for tests, and for a cache shared
/// between users.
pub const CACHE_ENV: &str = "UNSHAREK_IMAGE_CACHE";

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
    Image { path: PathBuf, source: unsharek_erofs::Error },
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
    closure_in(Some(program), allow_paths, &[], None)
}

fn closure_in(program: Option<&Path>, allow_paths: &[PathBuf], live: &[PathBuf], cache: Option<&Cache>) -> Result<Closure> {
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
    // A directory served live (virtiofs: the CLI's `--ro DIR`, `--rw DIR`) isn't imaged; one the
    // program is in is still scanned for its references, so its libraries are in the closure (a
    // program built against the store). Others aren't: a big tree's walk at every run, for
    // nothing the program needs.
    let mut scan: Vec<PathBuf> = outer.iter().cloned().collect();
    match program.map(locate).transpose()? {
        None => {}
        Some(Place::Store(p)) => {
            roots.insert(p);
        }
        Some(Place::Host(p)) => {
            if !outer.iter().any(|d| p.starts_with(d)) {
                let canon: Vec<PathBuf> = live.iter().filter_map(|d| fs::canonicalize(d).ok()).collect();
                match canon.into_iter().find(|d| p.starts_with(d)) {
                    Some(d) => scan.push(d),
                    None => return Err(Error::ProgramNotAllowed(p)),
                }
            }
        }
    }
    let mut refs = BTreeMap::new();
    for dir in &scan {
        match cache {
            Some(c) => merge(&mut refs, c.host_refs(dir)?),
            None => scan_tree(dir, &mut refs)?,
        }
    }
    roots.extend(resolve(refs));
    let store = match cache {
        Some(c) => c.requisites(&roots)?,
        None => requisites(&roots)?,
    };
    Ok(Closure { store, host: outer })
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

/// `from`'s references added to `into`'s, the longer name kept where both have a hash.
fn merge(into: &mut Refs, from: Refs) {
    for (hash, name) in from {
        let longest = into.entry(hash).or_default();
        if name.len() > longest.len() {
            *longest = name;
        }
    }
}

/// Every regular file's bytes and every symlink's target under `dir`, without following links.
fn scan_tree(dir: &Path, refs: &mut Refs) -> Result<()> {
    let mut buf = vec![0u8; REF_MAX + SCAN_CHUNK];
    scan_dir(dir, refs, &mut buf)
}

fn scan_dir(dir: &Path, refs: &mut Refs, buf: &mut [u8]) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        let path = entry.map_err(io_err(dir))?.path();
        let md = fs::symlink_metadata(&path).map_err(io_err(&path))?;
        if md.is_dir() {
            scan_dir(&path, refs, buf)?;
        } else if md.is_symlink() {
            let target = fs::read_link(&path).map_err(io_err(&path))?;
            scan_bytes(target.as_os_str().as_bytes(), refs);
        } else if md.is_file() {
            scan_file(&path, refs, buf)?;
        }
    }
    Ok(())
}

/// Files are read this much at a time, into one buffer for the whole walk. (A megabyte buffer
/// per file, allocated and freed 34 times for the fixtures, grew glibc's heap by a megabyte that
/// every sandbox kept.)
const SCAN_CHUNK: usize = 256 << 10;

/// `buf` is `REF_MAX + SCAN_CHUNK` bytes, its contents don't matter.
fn scan_file(path: &Path, refs: &mut Refs, buf: &mut [u8]) -> Result<()> {
    let mut f = File::open(path).map_err(io_err(path))?;
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
    /// Its layout, as [`unsharek_erofs::Layout::to_text`] writes it: each file's offset in the image.
    pub layout: PathBuf,
    /// What the image's root is.
    pub kind: Kind,
}

/// What a [`Mount`]'s image holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The image's root is the directory: mounted at `guest`.
    Dir,
    /// A store path that is a file or a symlink (a setup hook's script, a source tarball): the
    /// image's root directory holds it under its own name (`<hash>-<name>`), and
    /// [`setup::mount_closure`](crate::setup::mount_closure) shows it at `guest` as it is, the
    /// file bind-mounted from the image (no copy), the symlink made.
    Entry,
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
        let root = dir.join(format!("v{}", unsharek_erofs::FORMAT_VERSION));
        Cache { root, builds: AtomicUsize::new(0) }
    }

    /// `$UNSHAREK_IMAGE_CACHE`, else `$XDG_CACHE_HOME/unsharek/images`, else
    /// `$HOME/.cache/unsharek/images`.
    pub fn default_dir() -> Result<PathBuf> {
        let var = |name| env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        if let Some(dir) = var(CACHE_ENV) {
            return Ok(dir);
        }
        let cache = var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache")));
        Ok(cache.ok_or(Error::NoCacheDir)?.join("unsharek/images"))
    }

    /// The cache at [`Cache::default_dir`].
    pub fn open_default() -> Result<Cache> {
        Ok(Cache::new(&Cache::default_dir()?))
    }

    /// `program`'s closure (plus `allow_paths`, each with its own) as images: [`Cache::closure`]
    /// then [`Cache::images`], each built where the cache lacks it.
    pub fn store(&self, program: &Path, allow_paths: &[PathBuf]) -> Result<Store> {
        self.store_live(program, allow_paths, &[])
    }

    /// The closures of `paths` alone (store paths, or paths inside them, or host directories as
    /// [`closure`] takes them), as images: no program's.
    pub fn closures(&self, paths: &[PathBuf]) -> Result<Store> {
        self.images(&closure_in(None, paths, &[], Some(self))?)
    }

    /// [`Cache::store`], with host directories served live (`live`: not imaged) besides: the
    /// program may be in one.
    pub fn store_live(&self, program: &Path, allow_paths: &[PathBuf], live: &[PathBuf]) -> Result<Store> {
        self.images(&closure_in(Some(program), allow_paths, live, Some(self))?)
    }

    /// How many images this `Cache` has built (rather than found).
    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::Relaxed)
    }

    /// [`closure`], from the cache where it can be: each set of store roots' requisites (a store
    /// path's closure never changes, so their names are the key), and each host directory's
    /// references (keyed by its tree, as its image; resolved again on every call, since a store
    /// path it mentions may have appeared since).
    pub fn closure(&self, program: &Path, allow_paths: &[PathBuf]) -> Result<Closure> {
        closure_in(Some(program), allow_paths, &[], Some(self))
    }

    fn requisites(&self, roots: &BTreeSet<PathBuf>) -> Result<BTreeSet<PathBuf>> {
        if roots.is_empty() {
            return Ok(BTreeSet::new());
        }
        let names: Vec<&[u8]> = roots.iter().map(|r| r.as_os_str().as_bytes()).collect();
        let mut h = DefaultHasher::new();
        for n in &names {
            h.write_usize(n.len());
            h.write(n);
        }
        let file = self.root.join("requisites").join(format!("{:016x}", h.finish()));
        // The roots, an empty line, their closure.
        if let Some(lines) = read_list(&file)
            && let Some(split) = lines.iter().position(|l| l.is_empty())
            && lines[..split] == names[..]
        {
            return Ok(lines[split + 1..].iter().map(|l| PathBuf::from(OsStr::from_bytes(l))).collect());
        }
        let got = requisites(roots)?;
        let lines = names.iter().copied().chain([&b""[..]]).chain(got.iter().map(|p| p.as_os_str().as_bytes()));
        write_list(&file, lines)?;
        Ok(got)
    }

    /// The references in host directory `dir` (canonical), as of now.
    fn host_refs(&self, dir: &Path) -> Result<Refs> {
        let key = tree_key(dir)?;
        let file = with_suffix(&self.root.join("host").join(host_name(dir, key)), ".refs");
        // `<hash>-<name>` each.
        if let Some(lines) = read_list(&file) {
            let parse = |l: &[u8]| -> Option<([u8; HASH_LEN], Vec<u8>)> {
                let (hash, name) = (l.get(..HASH_LEN)?, l.get(HASH_LEN + 1..)?);
                (l[HASH_LEN] == b'-').then(|| (hash.try_into().unwrap(), name.to_vec()))
            };
            if let Some(refs) = lines.iter().map(|l| parse(l)).collect::<Option<Refs>>() {
                return Ok(refs);
            }
        }
        let mut refs = Refs::new();
        scan_tree(dir, &mut refs)?;
        // Cached only if the tree didn't change while it was read (as `host_image` checks).
        if tree_key(dir)? == key {
            let lines: Vec<Vec<u8>> = refs.iter().map(|(h, n)| [&h[..], b"-", n].concat()).collect();
            write_list(&file, lines.iter().map(Vec::as_slice))?;
        }
        Ok(refs)
    }

    /// An image for every entry of `closure`, built in parallel where missing.
    pub fn images(&self, closure: &Closure) -> Result<Store> {
        let jobs: Vec<(&Path, bool)> = closure
            .store
            .iter()
            .map(|p| (p.as_path(), true))
            .chain(closure.host.iter().map(|p| (p.as_path(), false)))
            .collect();
        // What the cache has is found here, on this thread (a stat, or a host tree's walk): the
        // usual start builds nothing, and a thread per CPU to find that out cost a malloc arena
        // each, which every sandbox kept.
        let mut found = Vec::with_capacity(jobs.len());
        let mut missing = Vec::new();
        for (i, &(path, store)) in jobs.iter().enumerate() {
            let mount = if store {
                self.store_mount(path)?
            } else {
                self.mount(path, "host", Kind::Dir, &host_name(path, tree_key(path)?))
            };
            if exists(&mount.image)? {
                found.push((i, Ok(mount)));
            } else {
                missing.push(i);
            }
        }
        let next = AtomicUsize::new(0);
        let done = Mutex::new(found);
        let workers = thread::available_parallelism().map_or(1, |n| n.get()).min(missing.len());
        thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    loop {
                        let Some(&i) = missing.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                        let (path, store) = jobs[i];
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
        let mount = self.store_mount(path)?;
        if !exists(&mount.image)? {
            self.build(path, &mount, || Ok(()))?;
        }
        Ok(mount)
    }

    /// Store path `path`'s mount: a directory's image, or a file's or symlink's ([`Kind::Entry`]),
    /// which are cached apart (`entry/`, the module's comment), so a symlink to a directory imaged
    /// before as the directory isn't taken for one.
    fn store_mount(&self, path: &Path) -> Result<Mount> {
        let name = path.file_name().ok_or_else(|| Error::NotDir(path.to_owned()))?;
        let dir = fs::symlink_metadata(path).map_err(io_err(path))?.is_dir();
        Ok(if dir { self.mount(path, "store", Kind::Dir, name) } else { self.mount(path, "entry", Kind::Entry, name) })
    }

    /// The image of host directory `dir` (canonical), current as of now.
    pub fn host_image(&self, dir: &Path) -> Result<Mount> {
        // A tree edited between the key's walk and the build's would be cached under a key that
        // doesn't describe it; walking again after the build catches that (to the metadata's
        // resolution), and the build is retried a few times before giving up.
        for _ in 0..3 {
            let key = tree_key(dir)?;
            let mount = self.mount(dir, "host", Kind::Dir, &host_name(dir, key));
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

    /// `guest`'s mount, its image `<dir>/<name>` in the cache.
    fn mount(&self, guest: &Path, dir: &str, kind: Kind, name: &OsStr) -> Mount {
        let base = self.root.join(dir).join(name);
        Mount { guest: guest.to_owned(), image: with_suffix(&base, ".erofs"), layout: with_suffix(&base, ".layout"), kind }
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
            let err = |source| Error::Image { path: src.to_owned(), source };
            let lay = match mount.kind {
                Kind::Dir => unsharek_erofs::build(src, &image).map_err(err)?,
                // A file or a symlink, under its own name in the image's root.
                Kind::Entry => {
                    let at = Path::new("/").join(src.file_name().unwrap());
                    let img = unsharek_erofs::Image::scan_roots(&[(src.to_owned(), at)]).map_err(err)?;
                    img.write(&image).map_err(err)?;
                    img.layout().clone()
                }
            };
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

/// The version of the cache's lists (`.refs`, `requisites/`): what they hold and how. A change
/// to either, or to what `scan_bytes` finds, bumps it.
const LIST_VERSION: u32 = 1;

fn list_header() -> String {
    format!("unsharek list v{LIST_VERSION}")
}

/// A list the cache wrote: its lines, if the file is there, of this version and whole (it ends
/// with `end`). Anything else is as good as missing: the caller makes it again.
fn read_list(path: &Path) -> Option<Vec<Vec<u8>>> {
    let data = fs::read(path).ok()?;
    let mut lines: Vec<&[u8]> = data.strip_suffix(b"\n")?.split(|&b| b == b'\n').collect();
    if lines.first()? != &list_header().as_bytes() || lines.pop()? != b"end" {
        return None;
    }
    Some(lines[1..].iter().map(|l| l.to_vec()).collect())
}

/// Writes a list for [`read_list`], atomically (a temporary file renamed into place: readers see
/// the old file or the whole new one). Store paths and references hold no newlines.
fn write_list<'a>(path: &Path, lines: impl IntoIterator<Item = &'a [u8]>) -> Result<()> {
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).map_err(io_err(dir))?;
    let mut data = list_header().into_bytes();
    data.push(b'\n');
    for l in lines {
        debug_assert!(!l.contains(&b'\n'));
        data.extend_from_slice(l);
        data.push(b'\n');
    }
    data.extend_from_slice(b"end\n");
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = with_suffix(path, &format!(".{}-{seq}.tmp", process::id()));
    let written = fs::write(&tmp, &data).and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.map_err(io_err(path))
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io { path: path.to_owned(), source: e }),
    }
}

/// `<dirname>-<key>`, the name only to tell images apart by eye. Leading dots go: the name is also
/// the guest's device name (`/dev/unsharek/<name>`), which mustn't be hidden or `.`/`..` (a
/// `tempfile` directory is `.tmpXXXXXX`).
fn host_name(dir: &Path, key: u64) -> std::ffi::OsString {
    let base = dir.file_name().map_or(b"root".as_slice(), |n| n.as_bytes());
    let base = match base.iter().position(|&b| b != b'.') {
        Some(i) => &base[i..],
        None => b"root".as_slice(),
    };
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
    h.write_u32(unsharek_erofs::FORMAT_VERSION);
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
        // Puts the reference across the fourth read's end (the first reads `REF_MAX` more).
        let mut data = vec![b'x'; 4 * SCAN_CHUNK + REF_MAX - 20];
        data.extend_from_slice(format!("/nix/store/{HASH}-glibc-2.44-57\0").as_bytes());
        fs::write(&path, &data).unwrap();
        let mut refs = Refs::new();
        scan_file(&path, &mut refs, &mut vec![0; REF_MAX + SCAN_CHUNK]).unwrap();
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
