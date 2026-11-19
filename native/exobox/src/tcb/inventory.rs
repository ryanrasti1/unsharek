//! The authority inventory: every host resource the sandbox keeps past lockdown, made here and
//! recorded here. The runtime is given these resources; it produces nothing the filter trusts.
//!
//! After lockdown the program shares the address space with everything in the process, so what
//! it can reach on the host is exactly:
//! - **its fds**: the ones [`Inventory::fds`] lists, and no others ([`super::lockdown`] closes the
//!   rest). The security filter lets `read` and `write` reach stdio and the [`Fd::Passed`],
//!   [`Fd::Held`] and [`Fd::Token`] ones, each pinned; init's pidfd ([`Fd::InitPidfd`], fork mode)
//!   is only ever polled (ppoll moves no data).
//! - **its memory**: everything mapped. [`Inventory::maps`] records what exobox maps; all of it
//!   private (the process's own copy) but fork mode's [`Map::shared`] kernel memory, which is
//!   shared only with the sandbox's own processes (each a host fork that inherits the filters).
//!   A template must hold no shared mapping: its children would share memory with the template,
//!   which is not locked down ([`Inventory::has_shared`]). Private file mappings (the images)
//!   show the program those files' bytes, which is what they are for.
//! - **its threads**: [`Inventory::threads`] host threads, each under the security filter (TSYNC).
//!
//! Every call here is a raw syscall through the gate (`exobox_rt::trap::gate`): before the
//! routing filter it is an ordinary syscall, after it the one place host calls are allowed from,
//! so the inventory works in a template's child too. None of it allocates after lockdown.

use std::io;
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};

/// A host fd the sandbox keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fd {
    /// 0-2: the program's stdin (read), stdout and stderr (write).
    Stdio,
    /// `Sandbox::pass_fd`: a guest file over it; read and write.
    Passed,
    /// `Sandbox::hold_fd`: for the network hooks; read and write.
    Held,
    /// A CPU token's eventfd (threaded and fork mode); read and write.
    Token,
    /// Fork mode: init's process's pidfd, which the others poll to see it gone.
    InitPidfd,
}

/// What a mapping is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MapKind {
    /// The program's memory and the image zone at its top: read, write, execute.
    Arena,
    /// The guest kernel's memory (`mem=`).
    KernelHeap,
    /// The coroutines' stacks.
    Stacks,
    /// The kernel's and the runtime's statics, remapped shared (fork mode).
    SharedSection,
    /// An image, mapped read-only (the guest's block device).
    Image,
    /// An image mapped again into the arena's image zone (inside [`MapKind::Arena`]).
    ImageInZone,
}

/// A mapping exobox made. The record is for the reviewer and for `Sandbox`'s `Debug`; the
/// lockdown decision it feeds is [`Inventory::has_shared`].
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct Map {
    pub lo: usize,
    pub len: usize,
    pub kind: MapKind,
    /// `MAP_SHARED` (else private).
    pub shared: bool,
}

#[derive(Debug)]
pub(crate) struct Inventory {
    fds: Vec<(RawFd, Fd)>,
    maps: Vec<Map>,
    /// The token eventfds, an inclusive range.
    tokens: Option<(RawFd, RawFd)>,
    /// Host threads: the boot thread, and threaded mode's kernel idler.
    threads: usize,
}

// Syscall numbers (x86-64).
const NR_CLOSE: usize = 3;
const NR_MMAP: usize = 9;
const NR_MUNMAP: usize = 11;
const NR_MREMAP: usize = 25;
const NR_DUP2: usize = 33;
const NR_GETPID: usize = 39;
const NR_FCNTL: usize = 72;
const NR_EVENTFD2: usize = 290;
const NR_PIDFD_OPEN: usize = 434;
const PAGE: usize = 4096;

/// A raw syscall through the gate, its result as `io::Result`.
pub(crate) fn sys(nr: usize, a: [usize; 6]) -> io::Result<usize> {
    // SAFETY: each caller's call is a plain syscall on its own arguments (said at each).
    let r = unsafe { exobox_rt::trap::gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    if (-4095..0).contains(&r) { Err(io::Error::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

/// This process's host pid.
pub(crate) fn getpid() -> u32 {
    sys(NR_GETPID, [0; 6]).expect("getpid") as u32
}

fn is_open(fd: RawFd) -> bool {
    sys(NR_FCNTL, [fd as usize, libc::F_GETFD as usize, 0, 0, 0, 0]).is_ok()
}

impl Inventory {
    /// Stdio, and the boot thread.
    pub fn new() -> Inventory {
        Inventory { fds: (0..3).map(|fd| (fd, Fd::Stdio)).collect(), maps: vec![], tokens: None, threads: 1 }
    }

    pub fn fds(&self) -> &[(RawFd, Fd)] {
        &self.fds
    }

    pub fn maps(&self) -> &[Map] {
        &self.maps
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Whether anything is mapped shared (fork mode's kernel memory).
    pub fn has_shared(&self) -> bool {
        self.maps.iter().any(|m| m.shared)
    }

    /// One more host thread of the sandbox's (threaded mode's kernel idler).
    pub fn add_thread(&mut self) {
        self.threads += 1;
    }

    /// The authority the security filter pins: this process's pid, the token range, and each
    /// passed and held fd.
    pub fn pins(&self) -> super::filter::Pins {
        let fds = self.fds.iter().filter(|(_, k)| matches!(k, Fd::Passed | Fd::Held)).map(|&(fd, _)| fd).collect();
        super::filter::Pins { pid: getpid(), tokens: self.tokens, fds }
    }

    /// Anonymous memory, `MAP_NORESERVE` (it costs what is touched): at `at` if it's free (0:
    /// anywhere), else anywhere.
    pub fn reserve(&mut self, at: usize, len: usize, prot: i32, shared: bool, kind: MapKind) -> io::Result<usize> {
        let share = if shared { libc::MAP_SHARED } else { libc::MAP_PRIVATE };
        let flags = share | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        // A fresh anonymous mapping; FIXED_NOREPLACE never replaces one.
        let fixed = if at != 0 { libc::MAP_FIXED_NOREPLACE } else { 0 };
        let p = match sys(NR_MMAP, [at, len, prot as usize, (flags | fixed) as usize, usize::MAX, 0]) {
            Err(_) if at != 0 => sys(NR_MMAP, [0, len, prot as usize, flags as usize, usize::MAX, 0]),
            r => r,
        }?;
        self.maps.push(Map { lo: p, len, kind, shared });
        Ok(p)
    }

    /// `fd`'s first `len` bytes mapped read-only and private, for the process's life: an image.
    pub fn map_image(&mut self, fd: RawFd, len: usize) -> io::Result<&'static [u8]> {
        let p = sys(NR_MMAP, [0, len, libc::PROT_READ as usize, libc::MAP_PRIVATE as usize, fd as usize, 0])?;
        self.maps.push(Map { lo: p, len, kind: MapKind::Image, shared: false });
        // SAFETY: mapped above, readable, never unmapped.
        Ok(unsafe { std::slice::from_raw_parts(p as *const u8, len) })
    }

    /// `fd`'s first `len` bytes mapped again, private, readable and executable, over `at` in the
    /// arena's image zone. On failure the zone's range is anonymous memory again, as reserved.
    pub fn map_image_at(&mut self, at: usize, fd: RawFd, len: usize) -> io::Result<()> {
        let rx = (libc::PROT_READ | libc::PROT_EXEC) as usize;
        // Over the arena's own reservation, where nothing is mapped yet.
        if let Err(e) = sys(NR_MMAP, [at, len, rx, (libc::MAP_PRIVATE | libc::MAP_FIXED) as usize, fd as usize, 0]) {
            // A failed MAP_FIXED may have unmapped the range: the reservation's zeros back.
            let rwx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as usize;
            let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED) as usize;
            sys(NR_MMAP, [at, len.next_multiple_of(PAGE), rwx, flags, usize::MAX, 0]).expect("the image zone lost a range");
            return Err(e);
        }
        self.maps.push(Map { lo: at, len, kind: MapKind::ImageInZone, shared: false });
        Ok(())
    }

    /// Fork mode: the kernel's and the runtime's statics (`exobox_rt::share::section`, whole pages)
    /// mapped shared, their contents kept, so a host fork from now on shares them. All-zero pages
    /// aren't copied (they cost nothing until written).
    ///
    /// # Safety
    /// Before the runtime is used, on the only thread (nothing writes the section meanwhile).
    pub unsafe fn share_section(&mut self) -> io::Result<()> {
        let (lo, hi) = exobox_rt::share::section();
        if !lo.is_multiple_of(PAGE) || !hi.is_multiple_of(PAGE) || hi <= lo {
            // The link didn't make it whole pages: sharing would take in its neighbours.
            return Err(io::Error::from_raw_os_error(libc::ENOEXEC));
        }
        let len = hi - lo;
        let flags = (libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE) as usize;
        let tmp = sys(NR_MMAP, [0, len, (libc::PROT_READ | libc::PROT_WRITE) as usize, flags, usize::MAX, 0])?;
        for p in (lo..hi).step_by(PAGE) {
            // SAFETY: the section is mapped and readable; `tmp` is its size.
            unsafe {
                let page = std::slice::from_raw_parts(p as *const u64, PAGE / 8);
                if page.iter().any(|&w| w != 0) {
                    std::ptr::copy_nonoverlapping(p as *const u8, (tmp + (p - lo)) as *mut u8, PAGE);
                }
            }
        }
        // Over the section, atomically: nothing runs in between that could see it unmapped.
        let moved = (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as usize;
        if let Err(e) = sys(NR_MREMAP, [tmp, len, len, moved, lo, 0]) {
            let _ = sys(NR_MUNMAP, [tmp, len, 0, 0, 0, 0]);
            return Err(e);
        }
        self.maps.push(Map { lo, len, kind: MapKind::SharedSection, shared: true });
        Ok(())
    }

    /// The CPU tokens' eventfds, one at each of `base..base + n` (where the runtime looks for
    /// them: `exobox_rt::par`). Each fd must be free: one of the caller's there would otherwise be
    /// closed and its number become a token's.
    pub fn token_eventfds(&mut self, base: RawFd, n: usize) -> io::Result<(RawFd, RawFd)> {
        let range = (base, base + n as RawFd - 1);
        if let Some(fd) = (range.0..=range.1).find(|&fd| is_open(fd)) {
            return Err(io::Error::other(format!("fd {fd} is open: the CPU tokens' eventfds go at {}..={}", range.0, range.1)));
        }
        self.tokens = Some(range);
        self.remake_tokens()?;
        self.fds.extend((range.0..=range.1).map(|fd| (fd, Fd::Token)));
        Ok(range)
    }

    /// A host fork's child: each token eventfd made again at its fd (the fork shares the
    /// parent's: every hand-off would wake the other's threads).
    pub fn remake_tokens(&mut self) -> io::Result<()> {
        let Some((lo, hi)) = self.tokens else { return Ok(()) };
        for fd in lo..=hi {
            let efd = sys(NR_EVENTFD2, [0; 6])?;
            let r = sys(NR_DUP2, [efd, fd as usize, 0, 0, 0, 0]);
            let _ = sys(NR_CLOSE, [efd, 0, 0, 0, 0, 0]);
            r?;
        }
        Ok(())
    }

    /// Fork mode: a pidfd of this process (init's), for the others to poll.
    pub fn init_pidfd(&mut self) -> io::Result<RawFd> {
        let fd = sys(NR_PIDFD_OPEN, [getpid() as usize, 0, 0, 0, 0, 0])? as RawFd;
        self.fds.push((fd, Fd::InitPidfd));
        Ok(fd)
    }

    /// `fd`, kept open for the sandbox's life, as a passed or held fd.
    pub fn keep(&mut self, fd: OwnedFd, kind: Fd) -> io::Result<RawFd> {
        let fd = fd.into_raw_fd();
        if let Some(range) = self.tokens
            && (range.0..=range.1).contains(&fd)
        {
            // Can't be: the tokens hold those fds. (A wrong `OwnedFd` of the caller's.)
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if !is_open(fd) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        self.fds.push((fd, kind));
        Ok(fd)
    }
}
