//! Files and directories (hello.c's file part, shmap.c).

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

use crate::tmp;

pub fn file_rw() {
    let p = tmp("file_rw");
    let mut f = fs::OpenOptions::new().create(true).read(true).write(true).truncate(true).open(&p).unwrap();
    f.write_all(b"abc").unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    assert_eq!(s, "abc");
    assert_eq!(f.metadata().unwrap().len(), 3);
    fs::remove_file(&p).unwrap();
    assert!(!p.exists());
}

pub fn dirs() {
    let d = tmp("dirs");
    fs::create_dir_all(d.join("a/b/c")).unwrap();
    for i in 0..10 {
        fs::write(d.join(format!("a/b/f{i}")), format!("{i}")).unwrap();
    }
    let mut names: Vec<_> = fs::read_dir(d.join("a/b")).unwrap().map(|e| e.unwrap().file_name()).collect();
    names.sort();
    assert_eq!(names.len(), 11, "{names:?}");
    fs::rename(d.join("a/b/f3"), d.join("a/moved")).unwrap();
    assert_eq!(fs::read_to_string(d.join("a/moved")).unwrap(), "3");
    std::os::unix::fs::symlink("b/f4", d.join("a/link")).unwrap();
    assert_eq!(fs::read_to_string(d.join("a/link")).unwrap(), "4");
    assert_eq!(fs::read_link(d.join("a/link")).unwrap().to_str(), Some("b/f4"));
    fs::remove_dir_all(&d).unwrap();
    assert!(!d.exists());
}

/// A writable MAP_SHARED file mapping: its writes reach the file at msync and at munmap.
pub fn shmap() {
    let p = tmp("shmap");
    let f = fs::OpenOptions::new().create(true).read(true).write(true).truncate(true).open(&p).unwrap();
    f.set_len(4096).unwrap();
    // SAFETY: a fresh shared mapping of the file's one page, used only here.
    unsafe {
        let m = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, f.as_raw_fd(), 0);
        assert_ne!(m, libc::MAP_FAILED, "mmap: {}", crate::errno());
        let page = std::slice::from_raw_parts_mut(m as *mut u8, 4096);
        page[..11].copy_from_slice(b"after-msync");
        assert_eq!(libc::msync(m, 4096, libc::MS_SYNC), 0);
        let mut b = [0u8; 12];
        f.read_exact_at(&mut b[..11], 0).unwrap();
        assert_eq!(&b[..11], b"after-msync");
        page[..12].copy_from_slice(b"after-munmap");
        assert_eq!(libc::munmap(m, 4096), 0);
        f.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(&b, b"after-munmap");
    }
    fs::remove_file(&p).unwrap();
}
