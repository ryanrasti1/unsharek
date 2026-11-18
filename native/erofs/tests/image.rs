//! Images checked against erofs-utils, the reference implementation: `fsck.erofs` must accept
//! each one, and its extraction must match the source tree file by file (contents, modes, symlink
//! targets, hard-link identity). Generated trees cover the format's corners; real store paths
//! from the devshell (bash and its glibc) cover real ELFs.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use exobox_erofs::{BLOCK_SIZE, Layout};
use object::read::elf::{FileHeader, ProgramHeader};

/// Runs an erofs-utils tool, bounded (AGENTS.md: everything run has a timeout of seconds).
fn tool(args: &[&OsStr]) {
    let out = Command::new("timeout")
        .arg("10")
        .args(args)
        .output()
        .expect("timeout(1)");
    assert!(
        out.status.success(),
        "{args:?}: {}\n{}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A scratch directory whose read-only trees (0555 directories, like the store's) are made
/// writable again before removal, which would otherwise fail on them.
struct Scratch(tempfile::TempDir);

impl Scratch {
    fn new() -> Scratch {
        Scratch(tempfile::tempdir().unwrap())
    }
    fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fn writable(p: &Path) {
            let Ok(md) = fs::symlink_metadata(p) else {
                return;
            };
            if md.is_dir() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                for e in fs::read_dir(p).into_iter().flatten().flatten() {
                    writable(&e.path());
                }
            }
        }
        writable(self.0.path());
    }
}

/// Builds `src` into an image, checks it with fsck.erofs, extracts it, and compares.
fn roundtrip(src: &Path) -> Layout {
    let scratch = Scratch::new();
    let img = scratch.path().join("img");
    let layout = exobox_erofs::build(src, &img).unwrap();
    check_layout(&layout);
    tool(&["fsck.erofs".as_ref(), img.as_os_str()]);
    let out = scratch.path().join("out");
    let extract = format!("--extract={}", out.display());
    tool(&[
        "fsck.erofs".as_ref(),
        extract.as_ref(),
        "--preserve-perms".as_ref(),
        img.as_os_str(),
    ]);
    let mut pairs = HashMap::new();
    compare(src, &out, Path::new(""), &mut pairs, &layout);
    // Image bytes: each file's data at its offset, as the runtime will map it.
    let image = fs::read(&img).unwrap();
    assert_eq!(image.len() as u64, layout.size);
    for f in &layout.files {
        let data = fs::read(src.join(&f.path)).unwrap();
        assert_eq!(
            &image[f.offset as usize..][..data.len()],
            &data[..],
            "{}",
            f.path.display()
        );
    }
    layout
}

/// Data block-aligned, slots at least the data, distinct inodes' slots disjoint.
fn check_layout(layout: &Layout) {
    let mut files: Vec<_> = layout.files.iter().filter(|f| f.size > 0).collect();
    files.sort_by_key(|f| (f.offset, f.nid));
    files.dedup_by_key(|f| f.nid);
    for w in files.windows(2) {
        assert!(
            w[0].offset + w[0].slot <= w[1].offset,
            "{:?} overlaps {:?}",
            w[0],
            w[1]
        );
    }
    for f in &files {
        assert_eq!(f.offset % BLOCK_SIZE, 0, "{f:?}");
        assert!(
            f.slot >= f.size && f.offset + f.slot <= layout.size,
            "{f:?}"
        );
    }
}

/// (device, inode).
type Ino = (u64, u64);

/// Compares the trees under `a` (source) and `b` (extracted) at `rel`. `pairs` maps a source
/// inode to the extracted one and its nid in the image, so hard links must agree on both sides.
fn compare(a: &Path, b: &Path, rel: &Path, pairs: &mut HashMap<Ino, (Ino, u64)>, layout: &Layout) {
    let (pa, pb) = (a.join(rel), b.join(rel));
    let (ma, mb) = (
        fs::symlink_metadata(&pa).unwrap(),
        fs::symlink_metadata(&pb).unwrap(),
    );
    let what = rel.display();
    assert_eq!(ma.file_type(), mb.file_type(), "{what}");
    if ma.is_symlink() {
        assert_eq!(
            fs::read_link(&pa).unwrap(),
            fs::read_link(&pb).unwrap(),
            "{what}"
        );
        return;
    }
    assert_eq!(ma.mode() & 0o7777, mb.mode() & 0o7777, "{what}: mode");
    if ma.is_dir() {
        let names = |p: &Path| {
            let mut v: Vec<_> = fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            v.sort();
            v
        };
        let names_a = names(&pa);
        assert_eq!(names_a, names(&pb), "{what}");
        for n in names_a {
            compare(a, b, &rel.join(n), pairs, layout);
        }
        return;
    }
    assert_eq!(
        fs::read(&pa).unwrap(),
        fs::read(&pb).unwrap(),
        "{what}: contents"
    );
    let nid = layout
        .files
        .iter()
        .find(|f| f.path == rel)
        .unwrap_or_else(|| panic!("{what}: no layout"))
        .nid;
    let seen = pairs
        .entry((ma.dev(), ma.ino()))
        .or_insert(((mb.dev(), mb.ino()), nid));
    assert_eq!(
        *seen,
        ((mb.dev(), mb.ino()), nid),
        "{what}: hard links differ"
    );
    assert_eq!(ma.nlink(), mb.nlink(), "{what}: link count");
}

#[test]
fn generated_tree() {
    let scratch = Scratch::new();
    let s = scratch.path();
    let file = |rel: &str, bytes: &[u8], mode: u32| {
        let p = s.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    };
    file("bin/tool", b"#!/bin/sh\necho hi\n", 0o555);
    file("share/doc/readme", b"hello", 0o444);
    file("share/empty", b"", 0o444);
    file("share/one-block", &[7; BLOCK_SIZE as usize], 0o644);
    let big: Vec<u8> = (0..3_000_123u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    file("share/big", &big, 0o644);
    // Names that sort unlike their UTF-8 or locale order, and one that isn't UTF-8.
    for name in ["+x", "-a", ".hidden", "A", "a", "a-b", "a.b", "ab", "é"] {
        file(&format!("names/{name}"), name.as_bytes(), 0o644);
    }
    fs::write(
        s.join("names").join(OsStr::from_bytes(b"\xffbin")),
        b"latin1",
    )
    .unwrap();
    // Enough entries, with long names, for the directory to span several blocks.
    for i in 0..700 {
        file(
            &format!("many/{}-{i:04}", "x".repeat(i % 40)),
            &i.to_le_bytes(),
            0o644,
        );
    }
    fs::create_dir_all(s.join("deep/a/b/c/d/e")).unwrap();
    fs::create_dir(s.join("emptydir")).unwrap();
    // Hard links: three names for one inode, across directories.
    fs::hard_link(s.join("share/doc/readme"), s.join("bin/readme-link")).unwrap();
    fs::hard_link(s.join("share/doc/readme"), s.join("deep/a/readme")).unwrap();
    // Symlinks: short (inline), long enough to need its own block, and in between.
    symlink("../share/doc/readme", s.join("bin/short")).unwrap();
    symlink("x".repeat(4000), s.join("bin/long-inline")).unwrap();
    symlink("y".repeat(4090), s.join("bin/long-block")).unwrap();
    symlink("/nix/store/does-not-exist", s.join("dangling")).unwrap();
    // A read-only directory, as everything in the store is.
    fs::set_permissions(s.join("deep/a/b"), fs::Permissions::from_mode(0o555)).unwrap();

    let layout = roundtrip(s);
    let nid = |p: &str| {
        layout
            .files
            .iter()
            .find(|f| f.path == Path::new(p))
            .unwrap()
            .nid
    };
    assert_eq!(nid("share/doc/readme"), nid("bin/readme-link"));
    assert_eq!(nid("share/doc/readme"), nid("deep/a/readme"));
    assert_ne!(nid("share/doc/readme"), nid("bin/tool"));
}

#[test]
fn empty_root() {
    let scratch = Scratch::new();
    let layout = roundtrip(scratch.path());
    assert!(layout.files.is_empty());
}

#[test]
fn cli_layout() {
    let scratch = Scratch::new();
    let src = scratch.path().join("src");
    fs::create_dir_all(src.join("lib")).unwrap();
    fs::write(src.join("lib/data"), vec![1; 5000]).unwrap();
    fs::write(src.join("odd\\name\nhere"), b"x").unwrap();
    let img = scratch.path().join("img");
    let out = Command::new("timeout")
        .args(["10", env!("CARGO_BIN_EXE_exobox-erofs"), "--layout"])
        .args([&src, &img])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let layout = exobox_erofs::Image::scan(&src).unwrap();
    assert_eq!(out.stdout, layout.layout().to_text());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(" 5000 data lib/data\n"), "{text}");
    assert!(text.contains(" 1 data odd\\\\name\\nhere\n"), "{text}");
    tool(&["fsck.erofs".as_ref(), img.as_os_str()]);

    let bad = Command::new("timeout")
        .args(["10", env!("CARGO_BIN_EXE_exobox-erofs")])
        .args([&src.join("lib/data"), &img])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not a directory"));
}

/// `/nix/store/<name>` of a path inside it.
fn store_path(p: &Path) -> PathBuf {
    p.components().take(4).collect()
}

/// The memory image an ELF's PT_LOADs span, from the first one's page-aligned offset (as
/// `elf.rs`, recomputed here from the headers, independently of the image's code).
fn memory_image(data: &[u8]) -> Option<u64> {
    let h = object::elf::FileHeader64::<object::Endianness>::parse(data).ok()?;
    let e = h.endian().ok()?;
    let loads: Vec<_> = h
        .program_headers(e, data)
        .ok()?
        .iter()
        .filter(|p| p.p_type(e) == object::elf::PT_LOAD)
        .collect();
    let first = loads.iter().min_by_key(|p| p.p_vaddr(e))?;
    let hi = loads.iter().map(|p| p.p_vaddr(e) + p.p_memsz(e)).max()?;
    Some((first.p_offset(e) & !4095) + hi - (first.p_vaddr(e) & !4095))
}

fn interp(elf: &Path) -> PathBuf {
    let data = fs::read(elf).unwrap();
    let h = object::elf::FileHeader64::<object::Endianness>::parse(&*data).unwrap();
    let e = h.endian().unwrap();
    let ph = h
        .program_headers(e, &*data)
        .unwrap()
        .iter()
        .find(|p| p.p_type(e) == object::elf::PT_INTERP)
        .unwrap();
    let bytes = ph.data(e, &*data).unwrap();
    PathBuf::from(OsStr::from_bytes(
        bytes.strip_suffix(b"\0").unwrap_or(bytes),
    ))
}

#[test]
fn store_paths() {
    let Some(bash) = std::env::var_os("EXOBOX_TEST_BASH") else {
        eprintln!("skipped: EXOBOX_TEST_BASH is unset (run in the devshell)");
        return;
    };
    let bash = PathBuf::from(bash);
    let glibc = store_path(&interp(&bash));
    for path in [store_path(&bash), glibc] {
        let layout = roundtrip(&path);
        let mut elves = 0;
        for f in layout.files.iter().filter(|f| f.elf) {
            let data = fs::read(path.join(&f.path)).unwrap();
            if let Some(mem) = memory_image(&data) {
                assert!(
                    f.slot >= mem,
                    "{}: slot {} < memory image {mem}",
                    f.path.display(),
                    f.slot
                );
                elves += 1;
            }
        }
        assert!(elves > 0, "{}: no ELF files", path.display());
    }
}
