//! The layout's invariant: every file's data is block-aligned, an ELF's slot covers its memory
//! image, and no slot overlaps the metadata or another file's data.

use super::*;
use crate::elf::PAGE;
use crate::elf::tests::elf64;

/// Checks the invariant on a laid-out image.
fn check(img: &Image) {
    let layout = img.layout();
    let mut by_nid: Vec<&FileLayout> = layout.files.iter().collect();
    by_nid.sort_by_key(|f| (f.offset, f.nid));
    by_nid.dedup_by_key(|f| f.nid);
    let meta_end = img.meta_blocks * BLOCK;
    let mut end = meta_end;
    for f in by_nid.iter().filter(|f| f.size > 0) {
        assert_eq!(f.offset % BLOCK, 0, "{f:?}: not block-aligned");
        assert!(
            f.offset >= end,
            "{f:?}: overlaps the metadata or the previous slot (ends {end})"
        );
        assert!(
            f.slot >= f.size.next_multiple_of(BLOCK),
            "{f:?}: slot shorter than the data"
        );
        assert_eq!(f.slot % BLOCK, 0, "{f:?}");
        end = f.offset + f.slot;
    }
    assert!(end <= layout.size, "the last slot runs past the image");
    // Hard links share one inode and so one place.
    for f in &layout.files {
        for g in layout.files.iter().filter(|g| g.nid == f.nid) {
            assert_eq!((f.offset, f.slot, f.size), (g.offset, g.slot, g.size));
        }
    }
}

fn tree(files: &[(&str, Vec<u8>)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in files {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    dir
}

fn file<'a>(img: &'a Image, path: &str) -> &'a FileLayout {
    img.layout()
        .files
        .iter()
        .find(|f| f.path == Path::new(path))
        .unwrap()
}

#[test]
fn elf_slots_cover_their_memory_images() {
    let lib = [(0, 0, 0x1800, 0x1800), (0x1e00, 0x2e00, 0x300, 0x5000)]; // .bss to 0x7e00
    let exec = [
        (0, 0x400000, 0x1000, 0x1000),
        (0x1000, 0x401000, 0x10, 0x200000),
    ];
    let small_bss = [(0, 0, 0x1000, 0x1000), (0x1000, 0x2000, 0x100, 0x100)];
    let src = tree(&[
        ("a/libfoo.so", elf64(3, &lib, 0x2100)),
        ("a/notes.txt", b"not an elf".to_vec()),
        ("b/exec", elf64(2, &exec, 0x1010)),
        ("b/odd", b"\x7fELF garbage".to_vec()),
        ("b/small", elf64(3, &small_bss, 0x1100)),
        // A file larger than its memory image (debug info past the segments): the data wins.
        ("c/big", elf64(3, &small_bss, 5 * PAGE as usize + 7)),
        ("c/empty", Vec::new()),
        ("c/z", vec![1; 3 * PAGE as usize]),
    ]);
    let img = Image::scan(src.path()).unwrap();
    check(&img);
    assert_eq!(file(&img, "a/libfoo.so").slot, 0x8000);
    assert_eq!(file(&img, "a/notes.txt").slot, PAGE);
    assert_eq!(file(&img, "b/exec").slot, 0x201000);
    assert!(file(&img, "b/odd").elf);
    assert_eq!(file(&img, "b/odd").slot, PAGE);
    assert_eq!(file(&img, "b/small").slot, 0x3000);
    assert_eq!(file(&img, "c/big").slot, 6 * PAGE);
    assert_eq!(
        (file(&img, "c/empty").size, file(&img, "c/empty").slot),
        (0, 0)
    );
    assert_eq!(file(&img, "c/z").slot, 3 * PAGE);

    // Written: each file's bytes at its offset, zeros for the rest of its slot.
    let out = tempfile::NamedTempFile::new().unwrap();
    img.write(out.path()).unwrap();
    let bytes = fs::read(out.path()).unwrap();
    assert_eq!(bytes.len() as u64, img.layout().size);
    for f in &img.layout().files {
        let data = fs::read(src.path().join(&f.path)).unwrap();
        let at = f.offset as usize;
        assert_eq!(&bytes[at..at + data.len()], &data[..], "{f:?}");
        assert!(
            bytes[at + data.len()..at + f.slot as usize]
                .iter()
                .all(|&b| b == 0),
            "{f:?}"
        );
    }
}

#[test]
fn hard_links_share_a_slot() {
    let src = tree(&[("x/lib.so", elf64(3, &[(0, 0, 0x100, 0x3000)], 0x100))]);
    fs::hard_link(src.path().join("x/lib.so"), src.path().join("y")).unwrap();
    let img = Image::scan(src.path()).unwrap();
    check(&img);
    assert_eq!(file(&img, "x/lib.so").nid, file(&img, "y").nid);
    assert_eq!(file(&img, "y").slot, 0x3000);
    assert_eq!(img.layout().files.len(), 2);
}

#[test]
fn deterministic() {
    let src = tree(&[
        ("b", vec![2; 5000]),
        ("a/c", b"c".to_vec()),
        ("l.so", elf64(3, &[(0, 0, 9, 0x9000)], 9)),
    ]);
    std::os::unix::fs::symlink("a/c", src.path().join("s")).unwrap();
    let (one, two) = (
        tempfile::NamedTempFile::new().unwrap(),
        tempfile::NamedTempFile::new().unwrap(),
    );
    let l1 = build(src.path(), one.path()).unwrap();
    let l2 = build(src.path(), two.path()).unwrap();
    assert_eq!(l1, l2);
    assert_eq!(fs::read(one.path()).unwrap(), fs::read(two.path()).unwrap());
}

#[test]
fn rejects_what_a_store_path_cannot_hold() {
    let src = tempfile::tempdir().unwrap();
    let _sock = std::os::unix::net::UnixListener::bind(src.path().join("sock")).unwrap();
    let err = Image::scan(src.path()).err().unwrap();
    assert!(
        matches!(err, Error::Unsupported { kind: "socket", .. }),
        "{err}"
    );
    let file = src.path().join("f");
    fs::write(&file, b"").unwrap();
    assert!(matches!(
        Image::scan(&file).err().unwrap(),
        Error::NotDir(_)
    ));
}

#[test]
fn directory_blocks() {
    // A directory's entries never straddle a block, and its last block is cut short.
    let names: Vec<Vec<u8>> = (0..500)
        .map(|i| format!("entry-{i:04}").into_bytes())
        .collect();
    let entries: Vec<(&[u8], u64, u8)> = names
        .iter()
        .map(|n| (n.as_slice(), 7, format::FT_REG_FILE))
        .collect();
    let data = format::dir_data(&entries);
    let per_block = BLOCK as usize / (format::DIRENT_SIZE + 10);
    let blocks = 500usize.div_ceil(per_block);
    assert_eq!(
        data.len(),
        (blocks - 1) * BLOCK as usize + (500 - (blocks - 1) * per_block) * 22
    );
    let nameoff = u16::from_le_bytes([data[BLOCK as usize + 8], data[BLOCK as usize + 9]]);
    assert_eq!(
        nameoff as usize,
        per_block * format::DIRENT_SIZE,
        "block 1 starts with its own dirents"
    );
}
