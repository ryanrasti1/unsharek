//! Helpers for setup inside an intercept guard ([`crate::Sandbox::intercept`]), written as
//! ordinary Rust: inside one every syscall of the thread is the guest's, so `std::fs` and friends
//! work on the guest's files. Anything else the guest kernel does is a syscall away there too
//! (`setresuid`, `sethostname`, an `/etc/passwd` written with `std::fs::write`): exobox doesn't
//! wrap them. And the guest's basics, which [`crate::Guest::boot`] makes itself ([`defaults`]).

use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use exobox_rt::guest;
use lkl_sys as l;

use crate::{Error, Image};

/// Mount `image` (its block device, [`Image::device`]) at `path`, made if missing, read-only.
/// Inside a guard: `mkdir` and `mount(2)` are the guest's there.
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

/// An image mapped for [`mount_closure`] ([`crate::Guest::map_store`]): where the guest sees it,
/// and what its root is.
#[derive(Clone, Debug)]
pub struct Mount {
    pub image: Image,
    /// A store path, or an allowed host directory, or an image's mount point.
    pub at: PathBuf,
    pub kind: crate::store::Kind,
}

/// A Nix closure: each image mounted at its store path (or allowed host directory), as
/// `store.rs` lists them. A store path that is a file or a symlink ([`Kind::Entry`]) is shown as
/// it is: its image is mounted at a mount point of its own (`/dev/exobox/<name>.d`), the file
/// bind-mounted from there onto the store path (a file onto a file: nothing is copied) or the
/// symlink made, and the image's own mount detached again. Inside a guard.
///
/// [`Kind::Entry`]: crate::store::Kind::Entry
pub fn mount_closure(images: &[Mount]) -> Result<(), Error> {
    for m in images {
        match m.kind {
            crate::store::Kind::Dir => mount_erofs(&m.image, &m.at)?,
            crate::store::Kind::Entry => mount_entry(&m.image, &m.at)?,
        }
    }
    Ok(())
}

/// [`mount_closure`]'s store path that is a file or a symlink, `at`.
fn mount_entry(image: &Image, at: &Path) -> Result<(), Error> {
    let what = || format!("showing {} at {}", image.device().display(), at.display());
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let (Some(name), Some(parent)) = (at.file_name(), at.parent()) else {
        return Err(Error::io(what())(io::Error::from(io::ErrorKind::InvalidInput)));
    };
    let dir = PathBuf::from(format!("{}.d", image.device().display()));
    mount_erofs(image, &dir)?;
    let shown = (|| {
        let inner = dir.join(name);
        std::fs::create_dir_all(parent)?;
        let md = std::fs::symlink_metadata(&inner)?;
        if md.is_symlink() {
            return std::os::unix::fs::symlink(std::fs::read_link(&inner)?, at);
        }
        // The bind mount's point: an empty file, the bind's file over it.
        drop(std::fs::OpenOptions::new().write(true).create_new(true).open(at)?);
        let (from, to) = (c(&inner), c(at));
        // SAFETY: NUL-terminated strings, live for the call.
        if unsafe { libc::mount(from.as_ptr(), to.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    // The image's own mount goes (a bind of its file holds the image's filesystem on its own).
    let d = c(&dir);
    // SAFETY: as above.
    unsafe {
        libc::umount2(d.as_ptr(), libc::MNT_DETACH);
        libc::rmdir(d.as_ptr());
    }
    shown.map_err(Error::io(what()))
}

/// A guest syscall from host code outside a guard (generic numbers, made on the guest directly: a
/// plain `std::fs` call there is the host's).
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

/// The nameserver the guest's libc asks: an address of no one, as the kernel sends every datagram
/// to a non-loopback address to the runtime, which answers DNS on port 53 from the `on_resolve`
/// hook (`net`). 10.0.2.3, slirp's (QEMU's user network) resolver.
pub const NAMESERVER: &str = "10.0.2.3";

/// The guest's `/etc/resolv.conf` (naming [`NAMESERVER`]) and `/etc/hosts` (localhost: no query
/// for it), root's, 0644. Written by [`Builder::build`](crate::Builder::build) when names resolve
/// (an `on_resolve` or `on_connect` hook), as init at boot, before any guard: a guard may then
/// change them or chown them, and nothing is written for them after the guards, whose
/// credentials (a `setresuid` to a build user) it would have had (it failed with EACCES).
/// Direct guest calls: outside a guard or in one.
pub fn resolver() -> io::Result<()> {
    mkdir(c"/etc", 0o755)?;
    // One attempt, two seconds: the answer is local, a lost one isn't coming.
    write_file(c"/etc/resolv.conf", format!("nameserver {NAMESERVER}\noptions timeout:2 attempts:1\n").as_bytes())?;
    write_file(c"/etc/hosts", b"127.0.0.1 localhost\n::1 localhost\n")
}

/// `data` as the guest's file `path`, made or truncated.
fn write_file(path: &CStr, mut data: &[u8]) -> io::Result<()> {
    let flags = (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC) as usize;
    let fd = sys(l::__lkl__NR_openat, [AT_FDCWD, p(path), flags, 0o644, 0, 0])?;
    let mut r = Ok(());
    while !data.is_empty() {
        match sys(l::__lkl__NR_write, [fd, data.as_ptr() as usize, data.len(), 0, 0, 0]) {
            Ok(n) => data = &data[n..],
            Err(e) => {
                r = Err(e);
                break;
            }
        }
    }
    close(fd);
    r
}

/// Host fd `host` as guest fd `guest`: a guest file whose reads and writes the runtime does on
/// the host's fd (`host_fd`, the kernel series' item 11), as fds 0-2 are. Host code (it calls the
/// guest directly); under a [`Sandbox`](crate::Sandbox),
/// [`Sandbox::pass_fd`](crate::Sandbox::pass_fd) does this and widens the filter to the host fd,
/// which calling this alone doesn't.
pub fn host_fd(host: RawFd, guest: RawFd) -> io::Result<()> {
    let fd = sys(l::__lkl__NR_host_fd, [host as usize, libc::O_RDWR as usize, 0, 0, 0, 0])?;
    if fd != guest as usize {
        let r = sys(l::__lkl__NR_dup3, [fd, guest as usize, 0, 0, 0, 0]);
        close(fd);
        r?;
    }
    Ok(())
}

/// The guest's RNG given `entropy` from the host (RNDADDENTROPY, credited in full), and with
/// `reseed`, its CRNG reseeded from it at once (RNDRESEEDCRNG): a fork's child would otherwise
/// keep drawing from the key it copied until the kernel's next periodic reseed.
fn add_entropy(entropy: &[u8], reseed: bool) -> io::Result<()> {
    let fd = open(c"/dev/urandom", libc::O_RDWR as usize)?;
    let mut req = vec![0u8; 8 + entropy.len()];
    req[..4].copy_from_slice(&((entropy.len() * 8) as i32).to_ne_bytes());
    req[4..8].copy_from_slice(&(entropy.len() as i32).to_ne_bytes());
    req[8..].copy_from_slice(entropy);
    const RNDADDENTROPY: usize = 0x4008_5203;
    const RNDRESEEDCRNG: usize = 0x5207;
    let mut r = sys(l::__lkl__NR_ioctl, [fd, RNDADDENTROPY, req.as_ptr() as usize, 0, 0, 0]);
    if r.is_ok() && reseed {
        r = sys(l::__lkl__NR_ioctl, [fd, RNDRESEEDCRNG, 0, 0, 0, 0]);
    }
    close(fd);
    r.map(|_| ())
}

/// A fork's child's guest RNG made its own: `entropy` from the host, and the CRNG reseeded from
/// it (`Guest`'s takeover after a fork).
pub(crate) fn reseed(entropy: &[u8]) -> io::Result<()> {
    add_entropy(entropy, true)
}

/// The guest kernel's CLOCK_REALTIME set to the host's, now (host code, before any filter).
///
/// The guest kernel's clock is the host's CLOCK_MONOTONIC (the runtime's `time` hook), and LKL
/// reads its "persistent clock" from that too, so its realtime started at the host's uptime: files
/// got 1970 mtimes while the program's `clock_gettime` (the host's vDSO) said today, and autoconf
/// stopped ("newly created file is older than distributed files"). Set once: from here on the
/// guest's realtime is this instant plus the host's monotonic time since, which runs at the host
/// realtime's rate (NTP's frequency corrections slew both clocks alike); it departs from the
/// host's realtime only by what the host steps its realtime clock by later (a `settimeofday`, an
/// NTP step) and by the time the host spends suspended (CLOCK_MONOTONIC doesn't count it). A
/// template's children and fork mode's processes share the kernel's clock, so this holds there too.
fn set_clock() -> io::Result<()> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: fills a local.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    sys(l::__lkl__NR_clock_settime, [libc::CLOCK_REALTIME as usize, (&raw const ts) as usize, 0, 0, 0, 0]).map(|_| ())
}

/// The guest's basics, as init's: its realtime clock the host's (`set_clock`), `/proc`, `/dev`
/// (null, zero, full, random, urandom, tty, devpts, the fd links), `/tmp`, `/dev/shm`, the RNG seeded with `entropy` from the host (else the
/// guest's `getrandom` would wait for entropy a cooperative kernel can't gather), loopback up,
/// and fds 0-2.
///
/// fds 0-2 are the host's (`host_fd`, the kernel series' item 11): guest files whose reads and
/// writes the runtime does on the host's 0-2 (`exobox_rt::host`'s `hostfd_rw`), so `dup2`, pipes
/// and inheritance treat them as any file.
pub fn defaults(entropy: &[u8]) -> io::Result<()> {
    set_clock()?;
    mkdir(c"/proc", 0o555)?;
    mount(c"proc", c"/proc", c"proc", 0, 0)?;
    mkdir(c"/dev", 0o755)?;
    for (path, major, minor) in
        [(c"/dev/null", 1, 3), (c"/dev/zero", 1, 5), (c"/dev/full", 1, 7), (c"/dev/random", 1, 8), (c"/dev/urandom", 1, 9), (c"/dev/tty", 5, 0)]
    {
        mknod(path, major, minor)?;
        // mknod's mode passes through the umask too (0644, root's): anyone may use these, as on
        // any Linux (capnix's build user couldn't write /dev/null).
        sys(l::__lkl__NR_fchmodat, [AT_FDCWD, p(path), 0o666, 0, 0, 0])?;
    }
    mkdir(c"/dev/pts", 0o755)?;
    // /dev/ptmx is devpts' own node, 0666 by `ptmxmode`.
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

    add_entropy(entropy, false)?;

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
