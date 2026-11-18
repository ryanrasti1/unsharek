//! Helpers for setup closures ([`crate::Guest::run`]'s `before_exec`), written as ordinary Rust:
//! inside the closure every syscall is the guest's, so `std::fs` and friends work on the guest's
//! files. And the guest's basics, which [`crate::Guest::boot`] makes itself ([`defaults`]).

use std::ffi::CStr;
use std::io;
use std::path::{Path, PathBuf};

use exobox_rt::guest;
use lkl_sys as l;

use crate::{Error, Image};

/// Mount `image` (its block device, [`Image::device`]) at `path`, made if missing, read-only.
/// From a setup closure: `mkdir` and `mount(2)` are the guest's there.
pub fn mount_erofs(image: &Image, path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    let what = || format!("mounting {} at {}", image.device().display(), path.display());
    std::fs::create_dir_all(path).map_err(Error::io(what()))?;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let (dev, at) = (c(&image.device()), c(path));
    // SAFETY: NUL-terminated strings, live for the call.
    let r = unsafe { libc::mount(dev.as_ptr(), at.as_ptr(), c"erofs".as_ptr(), libc::MS_RDONLY, std::ptr::null()) };
    if r != 0 {
        return Err(Error::io(what())(io::Error::last_os_error()));
    }
    Ok(())
}

/// `image`'s disk in the guest (memblk over its host mapping) and its node, `/dev/exobox/<name>`.
/// Host code before `run` ([`crate::Guest::map_image`]).
/// `in_zone`: where it is mapped in the arena's image zone too.
pub(crate) fn block_device(image: &Image, in_zone: Option<usize>) -> io::Result<()> {
    let b = image.bytes();
    // SAFETY: an image's mappings are never unmapped, the read-only one never written
    // (`map_image`), which runs on the guest's one thread.
    let dev = unsafe { exobox_rt::memblk::add(guest::syscall, b.as_ptr(), b.len(), in_zone) }
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    mkdir(c"/dev/exobox", 0o755)?;
    let node = std::ffi::CString::new(image.device().into_os_string().into_encoded_bytes()).unwrap();
    sys(l::__lkl__NR_mknodat, [AT_FDCWD, p(&node), libc::S_IFBLK as usize | 0o400, dev, 0, 0]).map(|_| ())
}

/// A Nix closure: each image mounted at its store path (or allowed host directory), as
/// `store.rs` lists them.
pub fn mount_closure(images: &[(Image, PathBuf)]) -> Result<(), Error> {
    for (image, at) in images {
        mount_erofs(image, at)?;
    }
    Ok(())
}

/// A guest syscall from host code before `run` (generic numbers; the routing filter isn't in, so
/// a plain `std::fs` call would still be the host's).
fn sys(nr: std::ffi::c_long, a: [usize; 6]) -> io::Result<usize> {
    let r = guest::syscall(nr, a);
    if r < 0 { Err(io::Error::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

const AT_FDCWD: usize = -100isize as usize;

fn p(s: &CStr) -> usize {
    s.as_ptr() as usize
}

fn mkdir(path: &CStr, mode: usize) -> io::Result<()> {
    match sys(l::__lkl__NR_mkdirat, [AT_FDCWD, p(path), mode, 0, 0, 0]) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r.map(|_| ()),
    }
}

fn mknod(path: &CStr, major: u32, minor: u32) -> io::Result<()> {
    let dev = libc::makedev(major, minor) as usize;
    match sys(l::__lkl__NR_mknodat, [AT_FDCWD, p(path), libc::S_IFCHR as usize | 0o666, dev, 0, 0]) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r.map(|_| ()),
    }
}

fn symlink(target: &CStr, path: &CStr) -> io::Result<()> {
    match sys(l::__lkl__NR_symlinkat, [p(target), AT_FDCWD, p(path), 0, 0, 0]) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r.map(|_| ()),
    }
}

fn mount(src: &CStr, at: &CStr, fstype: &CStr, flags: usize, data: usize) -> io::Result<()> {
    sys(l::__lkl__NR_mount, [p(src), p(at), p(fstype), flags, data, 0]).map(|_| ())
}

fn open(path: &CStr, flags: usize) -> io::Result<usize> {
    sys(l::__lkl__NR_openat, [AT_FDCWD, p(path), flags, 0, 0, 0])
}

fn close(fd: usize) {
    let _ = sys(l::__lkl__NR_close, [fd, 0, 0, 0, 0, 0]);
}

/// The guest's basics, as init's: `/proc`, `/dev` (null, zero, full, random, urandom, tty, devpts,
/// the fd links), `/tmp`, `/dev/shm`, the RNG seeded with `entropy` from the host (else the
/// guest's `getrandom` would wait for entropy a cooperative kernel can't gather), loopback up,
/// and fds 0-2.
///
/// fds 0-2 are the host's (`host_fd`, the kernel series' item 11): guest files whose reads and
/// writes the runtime does on the host's 0-2 (`exobox_rt::host`'s `hostfd_rw`), so `dup2`, pipes
/// and inheritance treat them as any file.
pub fn defaults(entropy: &[u8]) -> io::Result<()> {
    mkdir(c"/proc", 0o555)?;
    mount(c"proc", c"/proc", c"proc", 0, 0)?;
    mkdir(c"/dev", 0o755)?;
    for (path, major, minor) in
        [(c"/dev/null", 1, 3), (c"/dev/zero", 1, 5), (c"/dev/full", 1, 7), (c"/dev/random", 1, 8), (c"/dev/urandom", 1, 9), (c"/dev/tty", 5, 0)]
    {
        mknod(path, major, minor)?;
    }
    mkdir(c"/dev/pts", 0o755)?;
    mount(c"devpts", c"/dev/pts", c"devpts", 0, p(c"mode=620,ptmxmode=666"))?;
    symlink(c"pts/ptmx", c"/dev/ptmx")?;
    symlink(c"/proc/self/fd", c"/dev/fd")?;
    symlink(c"/proc/self/fd/0", c"/dev/stdin")?;
    symlink(c"/proc/self/fd/1", c"/dev/stdout")?;
    symlink(c"/proc/self/fd/2", c"/dev/stderr")?;
    mkdir(c"/dev/shm", 0o1777)?;
    mkdir(c"/tmp", 0o1777)?;
    // mkdir's mode passes through the umask; the sticky, world-writable bits are wanted.
    for d in [c"/tmp", c"/dev/shm"] {
        sys(l::__lkl__NR_fchmodat, [AT_FDCWD, p(d), 0o1777, 0, 0, 0])?;
    }

    // The RNG: RNDADDENTROPY with the host's bytes, credited in full.
    let fd = open(c"/dev/urandom", libc::O_RDWR as usize)?;
    let mut req = vec![0u8; 8 + entropy.len()];
    req[..4].copy_from_slice(&((entropy.len() * 8) as i32).to_ne_bytes());
    req[4..8].copy_from_slice(&(entropy.len() as i32).to_ne_bytes());
    req[8..].copy_from_slice(entropy);
    const RNDADDENTROPY: usize = 0x4008_5203;
    let r = sys(l::__lkl__NR_ioctl, [fd, RNDADDENTROPY, req.as_ptr() as usize, 0, 0, 0]);
    close(fd);
    r?;

    // Loopback up: SIOCGIFFLAGS, then SIOCSIFFLAGS with IFF_UP | IFF_RUNNING.
    let s = sys(l::__lkl__NR_socket, [libc::AF_INET as usize, libc::SOCK_DGRAM as usize, 0, 0, 0, 0])?;
    let mut ifr = [0u8; 40];
    ifr[..2].copy_from_slice(b"lo");
    let r = sys(l::__lkl__NR_ioctl, [s, libc::SIOCGIFFLAGS as usize, ifr.as_mut_ptr() as usize, 0, 0, 0]).and_then(|_| {
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]) | (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        sys(l::__lkl__NR_ioctl, [s, libc::SIOCSIFFLAGS as usize, ifr.as_mut_ptr() as usize, 0, 0, 0])
    });
    close(s);
    r?;

    // fds 0-2: host_fd takes the lowest free fd, and init has none yet (no console).
    for k in 0..3 {
        let fd = sys(l::__lkl__NR_host_fd, [k, libc::O_RDWR as usize, 0, 0, 0, 0])?;
        if fd != k {
            return Err(io::Error::other(format!("host_fd({k}) made fd {fd}")));
        }
    }
    Ok(())
}
