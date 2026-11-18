//! Helpers for setup closures ([`crate::Guest::run`]'s `before_exec`), written as ordinary Rust:
//! inside the closure every syscall is the guest's, so `std::fs` and friends work on the guest's
//! files. And the guest's basics, which [`crate::Guest::boot`] makes itself ([`defaults`]).

use std::ffi::CStr;
use std::io;
use std::path::{Path, PathBuf};

use exobox_rt::guest;
use lkl_sys as l;

use crate::{Error, Image};

/// Mount `image` at `path` (made if missing), read-only.
///
/// STOPGAP(kernel item 12, memblk): the kernel can't mount the image's block device yet
/// ([`Image::device`]), so its tree is made in the guest's ramfs under `path` (writable), each
/// file's contents copied in from the host mapping when it is first opened (and then paid for in
/// the kernel's memory). When memblk lands this becomes
/// `mount(image.device(), path, "erofs", MS_RDONLY)`.
pub fn mount_erofs(image: &Image, path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    let mut lazy = vec![];
    crate::unpack::unpack(image.bytes(), path, true, &mut lazy)
        .map_err(Error::io(format!("{} at {}", image.name(), path.display())))?;
    lazy.sort_by_key(|l| l.0);
    let files: Vec<guest::LazyFile> = lazy.into_iter().map(|(ino, data)| guest::LazyFile::new(ino, data)).collect();
    guest::lazy_files(Vec::leak(files))?;
    Ok(())
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
/// STOPGAP(kernel item 11): fds 0-2 are `/dev/null` placeholders that the runtime serves from the
/// host's stdio (`exobox_rt::guest`), so they have a file type but aren't the host's files.
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

    // fds 0-2: the lowest free fds, so opening until 2 is taken fills exactly the missing ones.
    const F_GETFD: usize = 1;
    while sys(l::__lkl__NR_fcntl, [2, F_GETFD, 0, 0, 0, 0]).is_err() {
        let fd = open(c"/dev/null", libc::O_RDWR as usize)?;
        if fd > 2 {
            close(fd);
            break;
        }
    }
    Ok(())
}
