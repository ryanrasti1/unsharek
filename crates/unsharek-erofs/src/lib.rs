//! Builds an erofs image of a directory tree (one Nix store path) in which every ELF file can be
//! mapped in place by a loader, or synthesizes one over host directories without copying any
//! file's data.
//!
//! The guest sees each store path as a read-only erofs image, mapped into the host process before
//! lockdown. ld.so reserves a library's whole memory image with one mmap, which the runtime
//! answers with the address of the file's data inside the image mapping; then it maps each
//! segment `MAP_FIXED` over that reservation (see `elf.rs`). For that to work the file's data must
//! start on a block (= page) boundary, and the image must leave unused blocks after it until its
//! memory image ends: the writable segment and .bss land there. So each ELF gets a *slot*: its
//! data, then zero blocks nothing in the image refers to, as long as its memory image.
//!
//! Everything else is plain erofs that Linux's driver mounts unmodified (no compression, xattrs,
//! fragments or chunks; 4 KiB blocks):
//! - Block 0 holds the superblock (at 1024). The metadata area starts at block 1: inodes, each in
//!   the extended format (64 bytes). Extended rather than compact (32 bytes) because it carries
//!   its own mtime, a 64-bit size and a 32-bit nlink, so there's one inode format and no field
//!   that can overflow; the cost is 32 bytes per inode.
//! - Directories and symlinks whose data fits after their inode in the inode's block are stored
//!   inline there (FLAT_INLINE); larger ones get blocks right after the inodes (FLAT_PLAIN).
//! - Regular files are never inlined: all of them (ELF or not) start on a block of their own after
//!   the metadata, in walk order, so any file can be mapped from the image, and there's one path.
//!   An empty file has no blocks.
//! - Owners are root, every mtime is 1 (as in the store), entries are sorted: the image depends
//!   only on the tree's names, contents, modes and links. Hard links (an optimised store) share
//!   one inode.
//!
//! So an image is its metadata (blocks 0 to the first file's), then each file's data and its
//! slot's zeros, in walk order: a list of [`Extent`]s. [`synthesize`] makes that list in memory
//! from a walk of the trees (stat, readdir, readlink, and each ELF's headers), each file's data
//! named by the host file it is in, never read: a guest disk is then the metadata bytes, each
//! file's own host mapping and zeros (memblk's extents), and nothing is copied. [`build`] is the
//! same list written out to one file. One layout, so the two are byte for byte the same image.
//!
//! The prior art is capnix's `runtime/tier-a/src/store.c`, which synthesizes the same metadata
//! over host file mappings (and is proven to mount in LKL); this adds the ELF slots.

mod elf;
mod format;

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use format::{BLOCK, INODE_SIZE, NID_UNIT};

/// The image's block size, also the loader's page size: a block-aligned offset maps page-aligned.
pub const BLOCK_SIZE: u64 = BLOCK;

/// The version of what [`build`] writes (the image and [`Layout::to_text`]). Images are cached on
/// disk keyed by their source (unsharek's `store.rs`), so a change to either output must bump this,
/// or a cache keeps serving images in the old layout.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0}: not a directory (an image's root is one)")]
    NotDir(PathBuf),
    #[error(
        "{path}: a {kind} can't be stored (a Nix store path holds only files, directories and symlinks)"
    )]
    Unsupported { path: PathBuf, kind: &'static str },
    #[error("{0}: name longer than 255 bytes")]
    NameTooLong(PathBuf),
    #[error("{0}: changed while the image was built")]
    Changed(PathBuf),
    #[error("the image would need {0} blocks; erofs addresses at most 2^32")]
    TooLarge(u64),
    #[error("{0}: not a place for a root in the image (one under /, without `..`)")]
    BadRoot(PathBuf),
    #[error("{0}: two roots of the image there, or one inside another")]
    RootsOverlap(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.to_owned(),
        source,
    }
}

/// Where one regular file's data is. A hard-linked file has one entry per path, all alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLayout {
    /// Relative to the image's root, e.g. `lib/libc.so.6`.
    pub path: PathBuf,
    /// The inode's number in the image (its `st_ino` once mounted).
    pub nid: u64,
    /// The data's offset in the image, in bytes; block-aligned. 0 for an empty file.
    pub offset: u64,
    /// The file's size.
    pub size: u64,
    /// The bytes from `offset` that belong to this file: its data rounded up to a block, and for
    /// an ELF at least its memory image (`elf.rs`). Nothing else in the image is there.
    pub slot: u64,
    /// The file starts with the ELF magic.
    pub elf: bool,
}

/// Where everything is, for the runtime: guest path → image offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The image's size in bytes (a whole number of blocks; the last slot included).
    pub size: u64,
    /// Every regular file, sorted by path.
    pub files: Vec<FileLayout>,
}

impl Layout {
    /// One line per file: `offset slot size elf|data path`, numbers in decimal. The path is the
    /// rest of the line, with `\` and newline written as `\\` and `\n`.
    pub fn to_text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.files {
            let kind = if f.elf { "elf" } else { "data" };
            write!(out, "{} {} {} {kind} ", f.offset, f.slot, f.size).unwrap();
            for &b in f.path.as_os_str().as_bytes() {
                match b {
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b => out.push(b),
                }
            }
            out.push(b'\n');
        }
        out
    }
}

/// A host file whose data is in the image: opened once by the walk (a hard-linked file once for
/// all its names), and kept open, so that what is mapped is the file whose ELF headers were read
/// (no path is looked up again). Empty files have no data and aren't here.
///
/// So a closure holds thousands of descriptors open at once (python's 7741) until the caller has
/// mapped them and drops these. The fd table grows as they're opened, by doubling, and in a
/// process of several threads each growth waits for an RCU grace period (`expand_fdtable`'s
/// `synchronize_rcu`): measured, ~0.1 s the first time a process synthesizes such a closure, none
/// after (the table stays grown). A caller that minds can grow it once beforehand (one `dup2` to
/// a high descriptor is one grace period).
#[derive(Debug)]
pub struct HostFile {
    /// Where the walk found it (its first name, for a hard-linked file).
    pub path: PathBuf,
    pub file: File,
    /// Its size when it was opened (`fstat`).
    pub size: u64,
}

/// A run of the image, in order: their lengths add up to [`Layout::size`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extent {
    /// Bytes made in memory: the superblock, inodes, directories, symlinks (whole blocks).
    Metadata(Vec<u8>),
    /// `len` bytes (whole blocks) of `files[file]` from its byte `offset` (block-aligned): its
    /// data, and past the file's end zeros to the block's end, as a mapping of the file has
    /// (`mmap` of `len` from `offset`, `MAP_PRIVATE`, gives exactly these bytes).
    File { file: usize, offset: u64, len: u64 },
    /// `len` zero bytes (whole blocks): an ELF slot's tail.
    Zeros(u64),
}

impl Extent {
    /// Its length in the image: a whole number of blocks.
    pub fn len(&self) -> u64 {
        match self {
            Extent::Metadata(b) => b.len() as u64,
            Extent::File { len, .. } | Extent::Zeros(len) => *len,
        }
    }

    /// Never: an extent has at least one block.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An image as extents over host files ([`synthesize`]).
#[derive(Debug)]
pub struct Synthesized {
    pub extents: Vec<Extent>,
    pub layout: Layout,
    /// What [`Extent::File`] refers to, in the image's order.
    pub files: Vec<HostFile>,
}

impl Synthesized {
    /// Writes the image to `image`, reading each file's data. Zeros are holes (the file is
    /// extended, not written), so they cost no disk. [`Error::Changed`]: a file isn't the size it
    /// was when the image was laid out.
    pub fn write(&self, image: &Path) -> Result<()> {
        write_extents(&self.extents, &self.files, self.layout.size, image, true)
    }
}

/// Lays out an image of `roots` (`(host path, its path in the image)`): each host tree at its own
/// place (`/` for the image's root itself, then the only root, a directory, followed if it's a
/// symlink; directories that lead to the places, 0755, are made). A root elsewhere is taken as it
/// is, not followed: a directory, a file or a symlink, as a store path may be any of them. Say a
/// closure's store paths, each at `/<hash>-<name>`.
/// The trees are walked (stat, readdir, readlink), each regular file opened once and, if it's an
/// ELF, its headers read for its slot; nothing else of any file is read. The result is
/// deterministic: it depends only on the trees (not on `roots`' order).
pub fn synthesize(roots: &[(PathBuf, PathBuf)]) -> Result<Synthesized> {
    Ok(Image::scan_roots(roots)?.synthesized())
}

/// Scans `source`, writes the image to `image`, and returns where every file is: [`synthesize`]
/// with `source` as the root, written out.
pub fn build(source: &Path, image: &Path) -> Result<Layout> {
    let img = Image::scan(source)?;
    img.write(image)?;
    Ok(img.layout)
}

/// [`build`] without the files' data: the metadata written, every file's blocks left a hole
/// (the image file is its metadata on disk, sparse to its full size). Whoever mounts it maps each
/// file's own host data over its blocks ([`Layout`] says where), as [`synthesize`]'s extents
/// would. No file's data is read.
pub fn build_metadata(source: &Path, image: &Path) -> Result<Layout> {
    let img = Image::scan(source)?;
    write_extents(&img.extents(), &img.files, img.layout.size, image, false)?;
    Ok(img.layout)
}

enum Kind {
    /// Children by name (sorted), and the parent's node.
    Dir {
        entries: Vec<(Vec<u8>, usize)>,
        parent: usize,
    },
    File {
        /// Its [`HostFile`], or None when it's empty.
        file: Option<usize>,
        paths: Vec<PathBuf>,
        elf: bool,
        slot: u64,
    },
    Symlink(Vec<u8>),
}

struct Node {
    kind: Kind,
    perms: u16,
    nlink: u32,
    size: u64,
    nid: u64,
    inline: bool,
    blkaddr: u32,
}

impl Node {
    fn mode(&self) -> u16 {
        self.perms
            | match self.kind {
                Kind::Dir { .. } => format::S_IFDIR,
                Kind::File { .. } => format::S_IFREG,
                Kind::Symlink(_) => format::S_IFLNK,
            }
    }

    fn ftype(&self) -> u8 {
        match self.kind {
            Kind::Dir { .. } => format::FT_DIR,
            Kind::File { .. } => format::FT_REG_FILE,
            Kind::Symlink(_) => format::FT_SYMLINK,
        }
    }
}

/// A tree scanned and laid out: every node's nid and blocks assigned, the files open.
pub struct Image {
    /// In walk order (depth-first, sorted): the root is node 0, at nid 0.
    nodes: Vec<Node>,
    /// The blocks before the first file's data: superblock, inodes, directory and symlink data.
    meta_blocks: u64,
    blocks: u64,
    layout: Layout,
    files: Vec<HostFile>,
}

/// Where the roots go in the image: a host tree, or a directory made to lead to them.
enum Mount<'a> {
    Host(&'a Path),
    Dir(BTreeMap<Vec<u8>, Mount<'a>>),
}

impl<'a> Mount<'a> {
    fn of(roots: &'a [(PathBuf, PathBuf)]) -> Result<Mount<'a>> {
        let mut top = Mount::Dir(BTreeMap::new());
        for (host, at) in roots {
            let mut names = Vec::new();
            for c in at.components() {
                match c {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(n) => names.push(n.as_bytes().to_vec()),
                    _ => return Err(Error::BadRoot(at.clone())),
                }
            }
            let Some((last, dirs)) = names.split_last() else {
                // The image's root: then the only root.
                if roots.len() > 1 {
                    return Err(Error::RootsOverlap(at.clone()));
                }
                return Ok(Mount::Host(host));
            };
            let mut m = &mut top;
            for name in dirs {
                let Mount::Dir(d) = m else {
                    return Err(Error::RootsOverlap(at.clone()));
                };
                m = d
                    .entry(name.clone())
                    .or_insert_with(|| Mount::Dir(BTreeMap::new()));
            }
            let Mount::Dir(d) = m else {
                return Err(Error::RootsOverlap(at.clone()));
            };
            if d.insert(last.clone(), Mount::Host(host)).is_some() {
                return Err(Error::RootsOverlap(at.clone()));
            }
        }
        Ok(top)
    }
}

impl Image {
    /// Reads the tree under `source` (a directory; followed if it's a symlink, as a `result` link
    /// would be) and lays the image out. Files' contents are read only for ELF headers here.
    pub fn scan(source: &Path) -> Result<Image> {
        Image::scan_roots(&[(source.to_owned(), PathBuf::from("/"))])
    }

    /// [`synthesize`]'s walk and layout.
    pub fn scan_roots(roots: &[(PathBuf, PathBuf)]) -> Result<Image> {
        let mut scan = Scan {
            nodes: Vec::new(),
            links: HashMap::new(),
            files: Vec::new(),
        };
        match Mount::of(roots)? {
            Mount::Host(source) => {
                let perms = dir_perms(source)?;
                scan.push(
                    Kind::Dir {
                        entries: Vec::new(),
                        parent: 0,
                    },
                    perms,
                    2,
                    0,
                );
                scan.walk(source, Path::new(""), 0)?;
            }
            Mount::Dir(dirs) => {
                scan.push(
                    Kind::Dir {
                        entries: Vec::new(),
                        parent: 0,
                    },
                    0o755,
                    2,
                    0,
                );
                scan.mount(&dirs, Path::new(""), 0)?;
            }
        }
        Image::plan(scan.nodes, scan.files)
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The image as extents: its metadata, then each file's data and slot, in block order.
    pub fn synthesized(self) -> Synthesized {
        let extents = self.extents();
        Synthesized {
            extents,
            layout: self.layout,
            files: self.files,
        }
    }

    /// Writes the image (see [`Synthesized::write`]).
    pub fn write(&self, image: &Path) -> Result<()> {
        write_extents(&self.extents(), &self.files, self.layout.size, image, true)
    }

    /// Assigns nids and blocks.
    fn plan(mut nodes: Vec<Node>, files: Vec<HostFile>) -> Result<Image> {
        // Sizes first: a directory's size depends on its names only, not on the nids in it.
        for i in 0..nodes.len() {
            nodes[i].size = match &nodes[i].kind {
                Kind::Dir { .. } => dir_data(&nodes, i).len() as u64,
                Kind::Symlink(target) => target.len() as u64,
                Kind::File { .. } => nodes[i].size,
            };
        }
        // Inodes, 32-byte aligned (nids count 32-byte units). An inline tail must share its
        // inode's block (the kernel refuses one that crosses), so a node that doesn't fit in what
        // is left of a block starts the next one; inodes never cross a block either.
        let mut pos = 0u64;
        for n in &mut nodes {
            n.inline = !matches!(n.kind, Kind::File { .. }) && n.size <= BLOCK - INODE_SIZE;
            let len = INODE_SIZE + if n.inline { n.size } else { 0 };
            if pos % BLOCK + len > BLOCK {
                pos = pos.next_multiple_of(BLOCK);
            }
            n.nid = pos / NID_UNIT;
            pos = (pos + len).next_multiple_of(NID_UNIT);
        }
        // The superblock's root_nid is 16 bits; the root is the first inode, at 0.
        debug_assert_eq!(nodes[0].nid, 0);
        let mut next = 1 + pos.div_ceil(BLOCK); // block 0 is the superblock's, then the inodes
        let block_of = |n: u64| u32::try_from(n).map_err(|_| Error::TooLarge(n));
        for n in &mut nodes {
            if !n.inline && !matches!(n.kind, Kind::File { .. }) {
                n.blkaddr = block_of(next)?;
                next += n.size.div_ceil(BLOCK);
            }
        }
        let meta_blocks = next;
        let mut layout = Vec::new();
        for n in &mut nodes {
            if let Kind::File {
                paths, elf, slot, ..
            } = &n.kind
            {
                if n.size > 0 {
                    n.blkaddr = block_of(next)?;
                    next += slot / BLOCK;
                }
                for path in paths {
                    layout.push(FileLayout {
                        path: path.clone(),
                        nid: n.nid,
                        offset: n.blkaddr as u64 * BLOCK,
                        size: n.size,
                        slot: *slot,
                        elf: *elf,
                    });
                }
            }
        }
        block_of(next)?;
        layout.sort_by(|a, b| a.path.cmp(&b.path));
        let layout = Layout {
            size: next * BLOCK,
            files: layout,
        };
        Ok(Image {
            nodes,
            meta_blocks,
            blocks: next,
            layout,
            files,
        })
    }

    /// The metadata blocks: superblock, inodes, inline and block-sized directory and symlink data.
    fn metadata(&self) -> Vec<u8> {
        let mut meta = vec![0u8; (self.meta_blocks * BLOCK) as usize];
        format::Super {
            root_nid: 0,
            inos: self.nodes.len() as u64,
            blocks: self.blocks as u32,
            meta_blkaddr: 1,
        }
        .write(&mut meta);
        for (i, n) in self.nodes.iter().enumerate() {
            let at = (BLOCK + n.nid * NID_UNIT) as usize;
            format::Inode {
                mode: n.mode(),
                layout: if n.inline {
                    format::FLAT_INLINE
                } else {
                    format::FLAT_PLAIN
                },
                size: n.size,
                blkaddr: n.blkaddr,
                ino: n.nid as u32,
                nlink: n.nlink,
            }
            .write(&mut meta[at..at + INODE_SIZE as usize]);
            let data = match &n.kind {
                Kind::Dir { .. } => dir_data(&self.nodes, i),
                Kind::Symlink(target) => target.clone(),
                Kind::File { .. } => continue,
            };
            let at = if n.inline {
                at + INODE_SIZE as usize
            } else {
                (n.blkaddr as u64 * BLOCK) as usize
            };
            meta[at..at + data.len()].copy_from_slice(&data);
        }
        meta
    }

    /// The metadata, then each file in the nodes' order, which is the order of their blocks.
    fn extents(&self) -> Vec<Extent> {
        let mut out = vec![Extent::Metadata(self.metadata())];
        let mut at = self.meta_blocks * BLOCK;
        for n in &self.nodes {
            let Kind::File {
                file: Some(file),
                slot,
                ..
            } = n.kind
            else {
                continue;
            };
            debug_assert_eq!(at, n.blkaddr as u64 * BLOCK);
            let data = n.size.next_multiple_of(BLOCK);
            out.push(Extent::File {
                file,
                offset: 0,
                len: data,
            });
            if slot > data {
                out.push(Extent::Zeros(slot - data));
            }
            at += slot;
        }
        debug_assert_eq!(at, self.layout.size);
        out
    }
}

/// Writes `extents` to `image`: what each is, zeros as holes; `size` is their total. Without
/// `data`, files' extents are holes too ([`build_metadata`]).
fn write_extents(
    extents: &[Extent],
    files: &[HostFile],
    size: u64,
    image: &Path,
    data: bool,
) -> Result<()> {
    let mut out = File::create(image).map_err(io_err(image))?;
    let mut at = 0;
    for e in extents {
        match e {
            Extent::Metadata(bytes) => {
                out.seek(SeekFrom::Start(at)).map_err(io_err(image))?;
                out.write_all(bytes).map_err(io_err(image))?;
            }
            Extent::File { .. } if !data => {}
            &Extent::File { file, offset, len } => {
                let f = &files[file];
                // The file's bytes the extent holds, and whether it runs to the file's end: then
                // one byte more is asked for, to notice a file that grew.
                let want = len.min(f.size.saturating_sub(offset));
                let to_end = offset + want == f.size;
                let mut src = &f.file;
                src.seek(SeekFrom::Start(offset)).map_err(io_err(&f.path))?;
                out.seek(SeekFrom::Start(at)).map_err(io_err(image))?;
                let copied = io::copy(&mut src.take(want + to_end as u64), &mut out)
                    .map_err(io_err(&f.path))?;
                if copied != want {
                    return Err(Error::Changed(f.path.clone()));
                }
            }
            Extent::Zeros(_) => {}
        }
        at += e.len();
    }
    debug_assert_eq!(at, size);
    out.set_len(size).map_err(io_err(image))?;
    Ok(())
}

/// A directory node's data, with "." and ".." (the kernel doesn't need them, but readdir and fsck
/// expect them).
fn dir_data(nodes: &[Node], i: usize) -> Vec<u8> {
    let Kind::Dir { entries, parent } = &nodes[i].kind else {
        unreachable!()
    };
    let mut all: Vec<(&[u8], u64, u8)> = vec![
        (b".", nodes[i].nid, format::FT_DIR),
        (b"..", nodes[*parent].nid, format::FT_DIR),
    ];
    all.extend(
        entries
            .iter()
            .map(|(name, c)| (name.as_slice(), nodes[*c].nid, nodes[*c].ftype())),
    );
    all.sort_by(|a, b| a.0.cmp(b.0));
    format::dir_data(&all)
}

/// A root's permission bits; it must be a directory (followed if it's a symlink).
fn dir_perms(source: &Path) -> Result<u16> {
    let md = fs::metadata(source).map_err(io_err(source))?;
    if !md.is_dir() {
        return Err(Error::NotDir(source.to_owned()));
    }
    Ok((md.mode() & 0o7777) as u16)
}

struct Scan {
    nodes: Vec<Node>,
    /// Regular files with more than one link, by (device, inode): their node.
    links: HashMap<(u64, u64), usize>,
    files: Vec<HostFile>,
}

impl Scan {
    /// Adds the directories `dirs` lead to (node `idx`, at `rel` in the image), and the roots in
    /// them, in name order as `walk` adds a directory's entries.
    fn mount(&mut self, dirs: &BTreeMap<Vec<u8>, Mount>, rel: &Path, idx: usize) -> Result<()> {
        let mut entries = Vec::with_capacity(dirs.len());
        let mut subdirs = 0;
        for (name, m) in dirs {
            let rel = rel.join(OsStr::from_bytes(name));
            if name.len() > format::NAME_MAX {
                return Err(Error::NameTooLong(rel));
            }
            let child = match m {
                // As it is (not followed): a directory walked, a file or a symlink stored, as a
                // store path may be either (a script, a source tarball, a link).
                Mount::Host(source) => {
                    let (child, dir) = self.entry(source.to_path_buf(), rel, idx)?;
                    subdirs += dir as u32;
                    child
                }
                Mount::Dir(dirs) => {
                    subdirs += 1;
                    let child = self.push(
                        Kind::Dir {
                            entries: Vec::new(),
                            parent: idx,
                        },
                        0o755,
                        2,
                        0,
                    );
                    self.mount(dirs, &rel, child)?;
                    child
                }
            };
            entries.push((name.clone(), child));
        }
        let Kind::Dir { entries: e, .. } = &mut self.nodes[idx].kind else {
            unreachable!()
        };
        *e = entries;
        self.nodes[idx].nlink = 2 + subdirs;
        Ok(())
    }

    /// Adds the children of `dir` (node `idx`, at `rel` in the image), depth-first.
    fn walk(&mut self, dir: &Path, rel: &Path, idx: usize) -> Result<()> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(io_err(dir))? {
            names.push(entry.map_err(io_err(dir))?.file_name());
        }
        // Bytewise, as the kernel's bisection compares names; also makes the walk deterministic.
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut entries = Vec::with_capacity(names.len());
        let mut subdirs = 0;
        for name in names {
            let path = dir.join(&name);
            if name.len() > format::NAME_MAX {
                return Err(Error::NameTooLong(path));
            }
            let (child, dir) = self.entry(path, rel.join(&name), idx)?;
            subdirs += dir as u32;
            entries.push((name.into_vec(), child));
        }
        let Kind::Dir { entries: e, .. } = &mut self.nodes[idx].kind else {
            unreachable!()
        };
        *e = entries;
        self.nodes[idx].nlink = 2 + subdirs;
        Ok(())
    }

    /// Adds host `path` (at `rel` in the image, a child of node `parent`), not followed if it's a
    /// symlink, and what is under it if it's a directory: its node, and whether it's a directory.
    fn entry(&mut self, path: PathBuf, rel: PathBuf, parent: usize) -> Result<(usize, bool)> {
        let md = fs::symlink_metadata(&path).map_err(io_err(&path))?;
        let ft = md.file_type();
        let perms = (md.mode() & 0o7777) as u16;
        let child = if ft.is_dir() {
            let child = self.push(
                Kind::Dir {
                    entries: Vec::new(),
                    parent,
                },
                perms,
                2,
                0,
            );
            self.walk(&path, &rel, child)?;
            child
        } else if ft.is_symlink() {
            let target = fs::read_link(&path).map_err(io_err(&path))?;
            self.push(
                Kind::Symlink(target.into_os_string().into_vec()),
                0o777,
                1,
                0,
            )
        } else if ft.is_file() {
            self.file(path, rel, &md, perms)?
        } else {
            let kind = if ft.is_block_device() {
                "block device"
            } else if ft.is_char_device() {
                "character device"
            } else if ft.is_fifo() {
                "fifo"
            } else if ft.is_socket() {
                "socket"
            } else {
                "file of unknown type"
            };
            return Err(Error::Unsupported { path, kind });
        };
        Ok((child, ft.is_dir()))
    }

    fn file(
        &mut self,
        path: PathBuf,
        rel: PathBuf,
        md: &fs::Metadata,
        perms: u16,
    ) -> Result<usize> {
        let key = (md.dev(), md.ino());
        if md.nlink() > 1
            && let Some(&node) = self.links.get(&key)
        {
            let n = &mut self.nodes[node];
            n.nlink += 1;
            let Kind::File { paths, .. } = &mut n.kind else {
                unreachable!()
            };
            paths.push(rel);
            return Ok(node);
        }
        let f = File::open(&path).map_err(io_err(&path))?;
        // The file opened is the one the directory listed (not another put there since), and
        // its size is the open file's.
        let fmd = f.metadata().map_err(io_err(&path))?;
        if (fmd.dev(), fmd.ino()) != key || !fmd.is_file() {
            return Err(Error::Changed(path));
        }
        let size = fmd.len();
        let kind = elf::classify(&f).map_err(io_err(&path))?;
        let data = elf::round_up(size, BLOCK).ok_or(Error::TooLarge(u64::MAX))?;
        let (elf, slot) = match kind {
            elf::Kind::Data => (false, data),
            elf::Kind::Elf { mapped } => (true, data.max(mapped.unwrap_or(0))),
        };
        let file = (size > 0).then(|| {
            self.files.push(HostFile {
                path: path.clone(),
                file: f,
                size,
            });
            self.files.len() - 1
        });
        let node = self.push(
            Kind::File {
                file,
                paths: vec![rel],
                elf,
                slot,
            },
            perms,
            1,
            size,
        );
        if md.nlink() > 1 {
            self.links.insert(key, node);
        }
        Ok(node)
    }

    fn push(&mut self, kind: Kind, perms: u16, nlink: u32, size: u64) -> usize {
        self.nodes.push(Node {
            kind,
            perms,
            nlink,
            size,
            nid: 0,
            inline: false,
            blkaddr: 0,
        });
        self.nodes.len() - 1
    }
}

#[cfg(test)]
mod tests;
