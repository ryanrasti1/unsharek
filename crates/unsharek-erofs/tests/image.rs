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

use std::os::unix::fs::FileExt;
use std::time::Instant;

use unsharek_erofs::{BLOCK_SIZE, Extent, FileLayout, Layout, Synthesized};
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

/// The image `synthesize` describes, assembled here from its extents as a guest's disk is: the
/// metadata's bytes, each file's bytes read from the open host file (`read_at`, not through the
/// crate's writer) up to the extent's end, zeros past the file's end and for zero extents.
fn assemble(s: &Synthesized) -> Vec<u8> {
    let mut image = Vec::with_capacity(s.layout.size as usize);
    for e in &s.extents {
        let start = image.len();
        assert_eq!(start as u64 % BLOCK_SIZE, 0);
        assert_eq!(e.len() % BLOCK_SIZE, 0, "{e:?}");
        assert!(!e.is_empty());
        match e {
            Extent::Metadata(b) => image.extend_from_slice(b),
            &Extent::File { file, offset, len } => {
                let f = &s.files[file];
                assert_eq!(offset % BLOCK_SIZE, 0);
                assert!(f.size > offset && f.size - offset <= len, "{f:?} {e:?}");
                image.resize(start + len as usize, 0);
                f.file
                    .read_exact_at(&mut image[start..][..(f.size - offset) as usize], offset)
                    .unwrap();
            }
            &Extent::Zeros(len) => image.resize(start + len as usize, 0),
        }
    }
    assert_eq!(image.len() as u64, s.layout.size);
    image
}

/// Checks an image file with fsck.erofs and extracts it into `out`.
fn fsck_extract(img: &Path, out: &Path) {
    tool(&["fsck.erofs".as_ref(), img.as_os_str()]);
    let extract = format!("--extract={}", out.display());
    tool(&[
        "fsck.erofs".as_ref(),
        extract.as_ref(),
        "--preserve-perms".as_ref(),
        img.as_os_str(),
    ]);
}

/// Builds `src` into an image, checks it with fsck.erofs, extracts it, and compares. The same
/// tree synthesized is the same image, written by the crate or assembled from its extents.
fn roundtrip(src: &Path) -> Layout {
    let scratch = Scratch::new();
    let img = scratch.path().join("img");
    let layout = unsharek_erofs::build(src, &img).unwrap();
    check_layout(&layout);
    let out = scratch.path().join("out");
    fsck_extract(&img, &out);
    let mut pairs = HashMap::new();
    compare(src, &out, Path::new(""), &mut pairs, &layout);
    let synth = unsharek_erofs::synthesize(&[(src.to_owned(), "/".into())]).unwrap();
    assert_eq!(synth.layout, layout);
    let built = fs::read(&img).unwrap();
    assert!(assemble(&synth) == built, "synthesized != built");
    let written = scratch.path().join("written");
    synth.write(&written).unwrap();
    assert!(
        fs::read(&written).unwrap() == built,
        "synthesized and written != built"
    );
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
        .args(["10", env!("CARGO_BIN_EXE_unsharek-erofs"), "--layout"])
        .args([&src, &img])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let layout = unsharek_erofs::Image::scan(&src).unwrap();
    assert_eq!(out.stdout, layout.layout().to_text());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(" 5000 data lib/data\n"), "{text}");
    assert!(text.contains(" 1 data odd\\\\name\\nhere\n"), "{text}");
    tool(&["fsck.erofs".as_ref(), img.as_os_str()]);

    let bad = Command::new("timeout")
        .args(["10", env!("CARGO_BIN_EXE_unsharek-erofs")])
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
    let Some(bash) = std::env::var_os("UNSHAREK_TEST_BASH") else {
        eprintln!("skipped: UNSHAREK_TEST_BASH is unset (run in the devshell)");
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

/// The files of `layout` under `at` (a root's place), with paths from there: what `compare` takes
/// for that root's tree.
fn under(layout: &Layout, at: &Path) -> Layout {
    let at = at.strip_prefix("/").unwrap_or(at);
    Layout {
        size: layout.size,
        files: layout
            .files
            .iter()
            .filter_map(|f| {
                let path = f.path.strip_prefix(at).ok()?.to_owned();
                Some(FileLayout { path, ..f.clone() })
            })
            .collect(),
    }
}

/// A synthesized image of several roots, each at its own place: assembled from its extents, fsck
/// accepts it, and each place extracts as its tree. Hard links across roots share an inode and
/// a host file; the directories leading to the places are made.
#[test]
fn synthesized_roots() {
    let scratch = Scratch::new();
    let s = scratch.path();
    let file = |rel: &str, bytes: &[u8]| {
        let p = s.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
    };
    file("one/bin/tool", b"#!/bin/sh\n");
    file("one/lib/data", &[3; 9000]);
    file("two/share/readme", b"two");
    file("two/empty", b"");
    fs::create_dir(s.join("three")).unwrap();
    symlink("../one/bin/tool", s.join("two/tool")).unwrap();
    fs::hard_link(s.join("one/lib/data"), s.join("two/data-link")).unwrap();
    fs::set_permissions(s.join("two"), fs::Permissions::from_mode(0o555)).unwrap();
    // Store paths that are a file and a symlink, stored as they are.
    file("four", b"a store path that is a file");
    fs::set_permissions(s.join("four"), fs::Permissions::from_mode(0o444)).unwrap();
    symlink("aaa-one/bin/tool", s.join("five")).unwrap();
    let roots = [
        (s.join("two"), PathBuf::from("/nix/store/bbb-two")),
        (s.join("one"), PathBuf::from("/nix/store/aaa-one")),
        (s.join("three"), PathBuf::from("/x")),
        (s.join("four"), PathBuf::from("/nix/store/ccc-four")),
        (s.join("five"), PathBuf::from("/nix/store/ddd-five")),
    ];
    let synth = unsharek_erofs::synthesize(&roots).unwrap();
    check_layout(&synth.layout);
    // Each file with data once, in the image's order: one's, then two's own, then four.
    let names: Vec<_> = synth
        .files
        .iter()
        .map(|f| f.path.strip_prefix(s).unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        ["one/bin/tool", "one/lib/data", "two/share/readme", "four"].map(PathBuf::from)
    );
    let nid = |p: &str| {
        synth
            .layout
            .files
            .iter()
            .find(|f| f.path == Path::new(p))
            .unwrap()
            .nid
    };
    assert_eq!(
        nid("nix/store/aaa-one/lib/data"),
        nid("nix/store/bbb-two/data-link")
    );
    // Deterministic, whatever the roots' order.
    let mut reversed = roots.clone();
    reversed.reverse();
    let again = unsharek_erofs::synthesize(&reversed).unwrap();
    assert_eq!(
        (&again.extents, &again.layout),
        (&synth.extents, &synth.layout)
    );

    let img = scratch.path().join("img");
    fs::write(&img, assemble(&synth)).unwrap();
    let out = scratch.path().join("out");
    fsck_extract(&img, &out);
    let names = |p: &Path| {
        let mut v: Vec<_> = fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
    };
    assert_eq!(names(&out), ["nix", "x"]);
    assert_eq!(
        names(&out.join("nix/store")),
        ["aaa-one", "bbb-two", "ccc-four", "ddd-five"]
    );
    assert_eq!(
        fs::metadata(out.join("nix")).unwrap().mode() & 0o7777,
        0o755
    );
    let four = out.join("nix/store/ccc-four");
    assert_eq!(fs::read(&four).unwrap(), b"a store path that is a file");
    assert_eq!(fs::symlink_metadata(&four).unwrap().mode(), 0o100444);
    assert_eq!(
        fs::read_link(out.join("nix/store/ddd-five")).unwrap(),
        Path::new("aaa-one/bin/tool")
    );
    let mut pairs = HashMap::new();
    for (host, at) in roots.iter().filter(|(h, _)| h.is_dir()) {
        let mounted = out.join(at.strip_prefix("/").unwrap());
        compare(
            host,
            &mounted,
            Path::new(""),
            &mut pairs,
            &under(&synth.layout, at),
        );
    }

    // Places that aren't one: outside the image, taken twice, inside another root, the image's
    // root and another; and an image's root that isn't a directory.
    let root = |host: &str, at: &str| (s.join(host), PathBuf::from(at));
    for bad in [
        vec![root("one", "/a/../b")],
        vec![root("one", "/a"), root("two", "/a")],
        vec![root("one", "/a"), root("two", "/a/b")],
        vec![root("one", "/a/b"), root("two", "a")],
        vec![root("one", "/"), root("two", "/b")],
        vec![root("one/lib/data", "/")],
        vec![root("four", "/a"), root("two", "/a/b")],
    ] {
        assert!(unsharek_erofs::synthesize(&bad).is_err(), "{bad:?}");
    }
    assert!(unsharek_erofs::synthesize(&[]).unwrap().files.is_empty());
}

/// A store path's closure (`nix-store -qR`), or None without nix.
fn closure(path: &Path) -> Option<Vec<PathBuf>> {
    let out = Command::new("timeout")
        .args(["10", "nix-store", "-qR"])
        .arg(path)
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .collect()
    })
}

/// A closure synthesized as one image, each store path at its own place: what it takes (time,
/// files to map, extents), and for bash's, fsck's extraction compared with the store.
#[test]
fn synthesized_closures() {
    for (var, extract) in [("UNSHAREK_TEST_BASH", true), ("UNSHAREK_TEST_PYTHON", false)] {
        let Some(bin) = std::env::var_os(var) else {
            eprintln!("skipped: {var} is unset (run in the devshell)");
            continue;
        };
        let Some(paths) = closure(&store_path(Path::new(&bin))) else {
            eprintln!("skipped: no nix-store");
            return;
        };
        let roots: Vec<_> = paths
            .iter()
            .map(|p| (p.clone(), Path::new("/").join(p.file_name().unwrap())))
            .collect();
        // (The first in a process is ~0.1 s slower with thousands of files: see `HostFile`.)
        let t = Instant::now();
        let synth = unsharek_erofs::synthesize(&roots).unwrap();
        let took = t.elapsed();
        check_layout(&synth.layout);
        let count = |f: fn(&Extent) -> bool| synth.extents.iter().filter(|e| f(e)).count();
        let meta: u64 = synth
            .extents
            .iter()
            .filter_map(|e| match e {
                Extent::Metadata(b) => Some(b.len() as u64),
                _ => None,
            })
            .sum();
        eprintln!(
            "{var}: {} store paths, {} files to map ({} names), synthesized in {took:?}: {} extents \
             ({} file mappings, {} zeros), metadata {meta} bytes, image {} bytes",
            roots.len(),
            synth.files.len(),
            synth.layout.files.len(),
            synth.extents.len(),
            count(|e| matches!(e, Extent::File { .. })),
            count(|e| matches!(e, Extent::Zeros(_))),
            synth.layout.size,
        );
        if !extract {
            continue;
        }
        let scratch = Scratch::new();
        let img = scratch.path().join("img");
        synth.write(&img).unwrap();
        let out = scratch.path().join("out");
        fsck_extract(&img, &out);
        let mut pairs = HashMap::new();
        for (host, at) in &roots {
            let mounted = out.join(at.strip_prefix("/").unwrap());
            compare(
                host,
                &mounted,
                Path::new(""),
                &mut pairs,
                &under(&synth.layout, at),
            );
        }
    }
}
