//! Files and directories, statx's pointers, /dev's nodes.

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

fn statx(dfd: i32, path: *const libc::c_char, flags: i32, mask: u32, buf: *mut libc::statx) -> i32 {
    // SAFETY: the kernel checks every pointer (that is the test).
    let r = unsafe { libc::syscall(libc::SYS_statx, dfd, path, flags, mask, buf) };
    if r < 0 { -crate::raw_errno() } else { r as i32 }
}

/// statx with bad pointers is EFAULT, not a crash. Rust's std probes for statx at its first failed
/// one (library/std/src/sys/fs/unix.rs, try_statx) with `statx(0, NULL, 0, STATX_ALL, NULL)` and
/// expects EFAULT; the call went to LKL as is, whose getname() reads the path with no MMU to fault
/// in (asm-generic access_ok is true everywhere), so it dereferenced NULL and the sandbox died of
/// SIGSEGV. cargo did that at startup, looking for `/.cargo/config.toml`: every cargo in every
/// mode; and every libtest binary (its terminfo lookup), these tests among them.
pub fn statx_probe() {
    use std::ptr::{null, null_mut};
    // SAFETY: a zeroed out-struct.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    let missing = c"/statx_probe_missing".as_ptr();
    // Rust's probe, exactly.
    assert_eq!(statx(0, null(), 0, libc::STATX_ALL, null_mut()), -libc::EFAULT, "the probe");
    // What std does after a failed statx with EFAULT: its own path missing, ENOENT.
    assert_eq!(statx(libc::AT_FDCWD, missing, libc::AT_STATX_SYNC_AS_STAT, libc::STATX_ALL, &mut st), -libc::ENOENT);
    // A path the program doesn't have. (NULL with AT_EMPTY_PATH at AT_FDCWD depends on the kernel:
    // EFAULT in the guest's 6.12, the cwd's stat in newer hosts'.)
    assert_eq!(statx(libc::AT_FDCWD, 8 as *const _, 0, libc::STATX_ALL, &mut st), -libc::EFAULT, "a bad path");
    // A bad buffer: the lookup's own error first, else EFAULT.
    assert_eq!(statx(libc::AT_FDCWD, c"/".as_ptr(), 0, libc::STATX_ALL, null_mut()), -libc::EFAULT, "a NULL buffer");
    assert_eq!(statx(libc::AT_FDCWD, missing, 0, libc::STATX_ALL, null_mut()), -libc::ENOENT, "missing, a NULL buffer");
    // What works: a path, and an fd with a NULL or empty path (Linux 6.11's NULL form).
    let is_dir = |st: &libc::statx| st.stx_mode as u32 & libc::S_IFMT == libc::S_IFDIR;
    assert_eq!(statx(libc::AT_FDCWD, c"/".as_ptr(), 0, libc::STATX_BASIC_STATS, &mut st), 0);
    assert!(is_dir(&st) && st.stx_mask & libc::STATX_TYPE != 0, "/: mode {:o}", st.stx_mode);
    let dir = fs::File::open("/").unwrap();
    for path in [c"".as_ptr(), null()] {
        // SAFETY: as above.
        st = unsafe { std::mem::zeroed() };
        assert_eq!(statx(dir.as_raw_fd(), path, libc::AT_EMPTY_PATH, libc::STATX_BASIC_STATS, &mut st), 0, "fd, {path:?}");
        assert!(is_dir(&st), "fd, {path:?}: mode {:o}", st.stx_mode);
    }
}

/// The guest's device nodes are usable by a user that isn't root, as on any Linux: setup made
/// them with mknod, whose mode goes through the umask, so they were 0644 (crw-r--r--) and a build
/// user (capnix's, after setresuid in a guard) couldn't write /dev/null. In the sandbox the program
/// is root, so it drops to uid/gid 1000 first (for good: the process is this test's alone);
/// natively it runs as whoever runs the tests.
pub fn devnodes() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    // SAFETY: id calls.
    unsafe {
        if libc::geteuid() == 0 {
            assert!(libc::setresgid(1000, 1000, 1000) == 0 && libc::setresuid(1000, 1000, 1000) == 0, "dropping to 1000");
        }
    }
    for node in ["/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx"] {
        let md = fs::metadata(node).unwrap_or_else(|e| panic!("stat {node}: {e}"));
        assert!(md.file_type().is_char_device() && md.permissions().mode() & 0o777 == 0o666, "{node}: mode {:o}", md.permissions().mode());
    }
    fs::OpenOptions::new().write(true).open("/dev/null").and_then(|mut f| f.write_all(b"x")).expect("writing /dev/null");
    let full = fs::OpenOptions::new().write(true).open("/dev/full").unwrap().write(b"x");
    assert_eq!(full.map_err(|e| e.raw_os_error()), Err(Some(libc::ENOSPC)), "writing /dev/full");
    for dev in ["/dev/zero", "/dev/urandom", "/dev/random"] {
        let mut b = [0u8; 16];
        fs::File::open(dev).and_then(|mut f| f.read_exact(&mut b)).unwrap_or_else(|e| panic!("reading {dev}: {e}"));
    }
}
