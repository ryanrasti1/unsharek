//! STOPGAP(kernel item 12, memblk): an image's files copied into the guest's ramfs.
//!
//! Until the guest kernel has a block device over host memory, it can't mount an erofs image,
//! so `setup::mount_erofs` reads the image here, from its host mapping, and writes its tree into
//! the guest with ordinary file calls (from the setup closure, so they are the guest's):
//! directories and symlinks as they are, regular files with their size and no contents, which the
//! runtime writes in on the first open that finds one (`exobox_rt::guest::LazyFile`). A Nix
//! closure is easily hundreds of MB (hello's has gcc, which its binaries name); copying it all at
//! every start would take seconds and that much kernel memory, while a program opens a few files.
//! Only what exobox-erofs writes is read: 4 KiB blocks, extended inodes, no xattrs, flat plain or
//! inline data. Delete this module when memblk lands.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

const BLOCK: usize = 4096;
const MAGIC: u32 = 0xE0F5_E1E2;
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;
const S_IFDIR: u16 = 0o040000;
const S_IFLNK: u16 = 0o120000;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("erofs image: {what}"))
}

fn u16_at(b: &[u8], at: usize) -> io::Result<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| bad("truncated"))
}
fn u32_at(b: &[u8], at: usize) -> io::Result<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| bad("truncated"))
}
fn u64_at(b: &[u8], at: usize) -> io::Result<u64> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| bad("truncated"))
}

struct Inode<'a> {
    mode: u16,
    /// The data: its whole blocks, then the inline tail (empty when there's none).
    blocks: &'a [u8],
    tail: &'a [u8],
}

impl Inode<'_> {
    fn data(&self) -> Vec<u8> {
        [self.blocks, self.tail].concat()
    }
}

struct Image<'a> {
    b: &'a [u8],
    meta: usize,
}

impl<'a> Image<'a> {
    fn inode(&self, nid: u64) -> io::Result<Inode<'a>> {
        let at = self.meta + nid as usize * 32;
        let format = u16_at(self.b, at)?;
        if format & 1 == 0 || u16_at(self.b, at + 2)? != 0 {
            return Err(bad("a compact inode or xattrs (not exobox-erofs's)"));
        }
        let layout = (format >> 1) & 7;
        let mode = u16_at(self.b, at + 4)?;
        let size = u64_at(self.b, at + 8)? as usize;
        let blkaddr = u32_at(self.b, at + 16)? as usize;
        let (nblocks, tail_len) = match layout {
            0 => (size, 0),                          // FLAT_PLAIN
            2 => (size / BLOCK * BLOCK, size % BLOCK), // FLAT_INLINE
            _ => return Err(bad("a compressed or chunked inode")),
        };
        let blocks = if nblocks == 0 { &[][..] } else { self.b.get(blkaddr * BLOCK..blkaddr * BLOCK + nblocks).ok_or_else(|| bad("data past the end"))? };
        let tail = self.b.get(at + 64..at + 64 + tail_len).ok_or_else(|| bad("inline data past the end"))?;
        Ok(Inode { mode, blocks, tail })
    }

    /// A directory's entries but `.` and `..`: (name, nid).
    fn entries(&self, dir: &Inode) -> io::Result<Vec<(Vec<u8>, u64)>> {
        let data = dir.data();
        let mut out = vec![];
        for blk in data.chunks(BLOCK) {
            let n = u16_at(blk, 8)? as usize / 12;
            for i in 0..n {
                let nid = u64_at(blk, i * 12)?;
                let start = u16_at(blk, i * 12 + 8)? as usize;
                let end = if i + 1 < n { u16_at(blk, (i + 1) * 12 + 8)? as usize } else { blk.len() };
                let name = blk.get(start..end).ok_or_else(|| bad("a name past its block"))?;
                let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
                if name != b"." && name != b".." {
                    out.push((name.to_vec(), nid));
                }
            }
        }
        Ok(out)
    }
}

/// A regular file left empty, to fill on its first open: its inode number and contents.
pub type Lazy = (u64, &'static [u8]);

/// Write the tree of the erofs image `b` under `dest` (made if missing). With `lazy`, regular
/// files stored in whole blocks are left empty at their size and listed in `out`.
pub fn unpack(b: &'static [u8], dest: &Path, lazy: bool, out: &mut Vec<Lazy>) -> io::Result<()> {
    if u32_at(b, 1024)? != MAGIC || b[1024 + 12] != 12 {
        return Err(bad("not an erofs image with 4 KiB blocks"));
    }
    let img = Image { b, meta: u32_at(b, 1024 + 40)? as usize * BLOCK };
    let root = u16_at(b, 1024 + 14)? as u64;
    fs::create_dir_all(dest)?;
    let mut seen = HashMap::new();
    walk(&img, root, dest, &mut seen, lazy, out)
}

fn walk(
    img: &Image<'static>,
    nid: u64,
    dir: &Path,
    seen: &mut HashMap<u64, std::path::PathBuf>,
    lazy: bool,
    out: &mut Vec<Lazy>,
) -> io::Result<()> {
    let d = img.inode(nid)?;
    for (name, child) in img.entries(&d)? {
        let path = dir.join(OsStr::from_bytes(&name));
        let ino = img.inode(child)?;
        match ino.mode & S_IFMT {
            S_IFDIR => {
                fs::create_dir(&path)?;
                walk(img, child, &path, seen, lazy, out)?;
                fs::set_permissions(&path, fs::Permissions::from_mode((ino.mode & 0o7777) as u32))?;
            }
            S_IFLNK => symlink(OsStr::from_bytes(&ino.data()), &path)?,
            S_IFREG => {
                // A hard link (an optimised store) shares the inode: link, don't copy again.
                if let Some(first) = seen.get(&child) {
                    fs::hard_link(first, &path)?;
                    continue;
                }
                let mut f = fs::File::create(&path)?;
                if lazy && ino.tail.is_empty() && !ino.blocks.is_empty() {
                    // Left at size 0: the kernel has no MMU, and its ramfs allocates a file's
                    // whole size, contiguously, when a truncate grows it from empty
                    // (ramfs_nommu_expand_for_mapping: EFBIG past 4 MiB). The runtime reports
                    // the size from stat calls until the first open fills it.
                    out.push((std::os::unix::fs::MetadataExt::ino(&f.metadata()?), ino.blocks));
                } else {
                    f.write_all(ino.blocks)?;
                    f.write_all(ino.tail)?;
                }
                f.set_permissions(fs::Permissions::from_mode((ino.mode & 0o7777) as u32))?;
                seen.insert(child, path);
            }
            _ => return Err(bad("an inode that is no file, directory or symlink")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    /// An image of a small tree unpacks to the same tree (on the host, here).
    #[test]
    fn round_trip() {
        let src = tempfile::tempdir().unwrap();
        let s = src.path();
        fs_tree(s);
        let img = tempfile::NamedTempFile::new().unwrap();
        exobox_erofs::build(s, img.path()).unwrap();
        let bytes: &'static [u8] = Vec::leak(std::fs::read(img.path()).unwrap());
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("t");
        let mut lazy = vec![];
        super::unpack(bytes, &dest, false, &mut lazy).unwrap();
        assert!(lazy.is_empty());
        // Lazy: sizes right, contents listed by inode.
        let dest2 = out.path().join("lazy");
        super::unpack(bytes, &dest2, true, &mut lazy).unwrap();
        let big = std::fs::metadata(dest2.join("a/big")).unwrap();
        assert_eq!(big.len(), 0);
        let (_, data) = lazy.iter().find(|(i, _)| *i == big.ino()).unwrap();
        assert_eq!(*data, &vec![7u8; 10_000][..]);
        assert_eq!(std::fs::read(dest.join("a/big")).unwrap(), vec![7u8; 10_000]);
        assert_eq!(std::fs::read(dest.join("small")).unwrap(), b"hi");
        assert_eq!(std::fs::read_link(dest.join("a/link")).unwrap().to_str(), Some("../small"));
        assert_eq!(std::fs::metadata(dest.join("a/x")).unwrap().mode() & 0o777, 0o755);
        assert_eq!(std::fs::read(dest.join("empty")).unwrap(), b"");
        // A directory of many entries spans blocks.
        assert_eq!(std::fs::read_dir(dest.join("many")).unwrap().count(), 400);
    }

    fn fs_tree(s: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(s.join("a")).unwrap();
        std::fs::create_dir_all(s.join("many")).unwrap();
        std::fs::write(s.join("a/big"), vec![7u8; 10_000]).unwrap();
        std::fs::write(s.join("small"), b"hi").unwrap();
        std::fs::write(s.join("empty"), b"").unwrap();
        std::fs::write(s.join("a/x"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(s.join("a/x"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("../small", s.join("a/link")).unwrap();
        for i in 0..400 {
            std::fs::write(s.join(format!("many/file-with-a-longish-name-{i}")), b"").unwrap();
        }
    }
}
