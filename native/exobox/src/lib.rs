//! exobox: run an unmodified Linux program on an in-process Linux kernel (LKL), behind a seccomp
//! filter that leaves the host a handful of syscalls.
//!
//! Three layers (README.md, "The library"), each built only from the one below:
//! 1. [`Guest`]: the kernel booted in this process ([`Guest::boot`]), host data given to it
//!    ([`Guest::map_image`]), and a program routed into it ([`Guest::run`]): the routing filter,
//!    a closure run as the guest's init, then the program's exec. No security policy.
//! 2. Security is a closure on top of that: the mode's filter, installed before the exec.
//! 3. [`Sandbox`]: a `Guest` whose closure runs the caller's setup and then installs the mode's
//!    filter. [`run`] (the CLI's path) is a `Sandbox` for a [`Config`].
//!
//! What runs in the guest is given as [`Hooks`]: `pre_exec` (setup, as init, before the program)
//! and the network's ([`net`]: connects, listens and name lookups beyond loopback).
//!
//! The process becomes the sandbox: one guest per process, booted from the thread that will run
//! it, and setup is single-threaded (the closure's threads would be host threads the guest can't
//! route). In fork mode the sandbox is this process and the host processes its guest forks make.

pub mod alloc;
pub mod net;
pub mod setup;
pub mod store;

pub use net::{Cx, GuestSocket, HeldFd, Hooks, NetError, OnConnect, OnListen, OnResolve, PreExec};

use std::convert::Infallible;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use exobox_rt::{filter, guest, sched};
pub use syscalls::Sysno;

/// How the sandbox runs the program's threads and processes. Each mode's host allowlist is a
/// superset of the one before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The guest kernel's threads and the program's on one host thread, as coroutines.
    #[default]
    Coroutine,
    /// A host thread per program thread, made through the filter by one exact `clone`.
    Threaded,
    /// Threaded, and a guest `fork` is a host fork: processes share one guest kernel.
    Fork,
}

/// What the filter does to a host syscall it doesn't allow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deny {
    /// Kill the sandbox (SIGSYS).
    #[default]
    Kill,
    /// Fail the syscall with EPERM (for probing the filter).
    Errno,
}

/// One more host syscall the filter allows, on top of the mode's own: a syscall and conditions on
/// its arguments, all of which must hold. Written `name[:argN=V|argN=LO..HI,...]` (`HI`
/// inclusive), e.g. `getppid`, `write:arg0=3`, `madvise:arg2=4..4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub sysno: Sysno,
    pub args: Vec<ArgRange>,
}

/// Argument `index` (0-5) within `lo..=hi`, compared as 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgRange {
    pub index: u8,
    pub lo: u64,
    pub hi: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid rule {rule:?}: {why}")]
    Rule { rule: String, why: String },
    #[error("invalid image {0:?}: NAME=PATH[:MOUNTPOINT]")]
    ImageArg(String),
    #[error("no program to run (argv is empty)")]
    NoProgram,
    #[error(transparent)]
    Store(#[from] store::Error),
    #[error("{what}: {source}")]
    Io { what: String, source: std::io::Error },
    #[error("the guest: {0}")]
    Guest(guest::Error),
    #[error("{}: {errno}", .path.display())]
    Exec { path: PathBuf, errno: std::io::Error },
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl Error {
    fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> Error {
        let what = what.into();
        move |source| Error::Io { what, source }
    }
}

/// For setup closures: `std::fs` and friends' errors, with `?`.
impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::Io { what: "setup".into(), source }
    }
}

impl From<guest::Error> for Error {
    fn from(e: guest::Error) -> Self {
        Error::Guest(e)
    }
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = |why: &str| Error::Rule { rule: s.to_owned(), why: why.to_owned() };
        let (name, conds) = s.split_once(':').unwrap_or((s, ""));
        let sysno = Sysno::from_str(name).map_err(|_| bad("no such x86-64 syscall"))?;
        let mut args = Vec::new();
        for cond in conds.split(',').filter(|c| !c.is_empty()) {
            let (arg, range) = cond.split_once('=').ok_or_else(|| bad("a condition is argN=..."))?;
            let index = arg
                .strip_prefix("arg")
                .and_then(|i| i.parse::<u8>().ok())
                .filter(|&i| i < 6)
                .ok_or_else(|| bad("arguments are arg0..arg5"))?;
            let (lo, hi) = match range.split_once("..") {
                Some((lo, hi)) => (parse_u64(lo), parse_u64(hi)),
                None => (parse_u64(range), parse_u64(range)),
            };
            let (Some(lo), Some(hi)) = (lo, hi) else { return Err(bad("values are integers")) };
            if lo > hi {
                return Err(bad("an empty range"));
            }
            args.push(ArgRange { index, lo, hi });
        }
        Ok(Rule { sysno, args })
    }
}

/// Decimal or 0x-prefixed hexadecimal.
fn parse_u64(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

// ------------------------------------------------------------------------------------------------
// Layer 1: the guest.

/// What [`Guest::boot`] reserves.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    /// The program's memory (the arena), in bytes. Reserved, not committed: it costs what the
    /// program touches. What `sysinfo` reports as the machine's memory.
    pub memory: usize,
    /// The guest kernel's own memory (`mem=`), in bytes: its slab, page cache and ramfs.
    pub kernel_memory: usize,
    /// Address space for the images ([`Guest::map_image`]), in bytes: each is mapped there too,
    /// in the arena, so the program's code and data files are mapped in place from it (the
    /// host's page cache, shared by every sandbox) instead of copied. Reserved, not committed;
    /// images past it are copied from.
    pub image_space: usize,
}

impl Default for GuestConfig {
    fn default() -> Self {
        // The kernel's memory holds its slab, the page cache of what the program reads from its
        // images (evictable) and its ramfs files (/tmp). 32 MiB: each MiB costs 16 KiB of struct
        // pages, all written at boot (64 MiB was 1 MiB of every sandbox).
        GuestConfig { memory: 4 << 30, kernel_memory: 32 << 20, image_space: 64 << 30 }
    }
}

/// The guest kernel, booted in this process: [`Guest::boot`], then [`Guest::map_image`] any
/// number of times, then [`Guest::run`], which never returns on success.
#[derive(Debug)]
pub struct Guest {
    aux: guest::Aux,
    /// The image zone's unused part, `[next, end)`.
    zone: (usize, usize),
}

/// A host image (erofs) mapped by [`Guest::map_image`], read-only. The guest sees it as the
/// block device [`Image::device`]; [`setup::mount_erofs`] mounts it.
#[derive(Clone, Copy, Debug)]
pub struct Image {
    name: &'static str,
    /// The host mapping (read-only, alive for the process's life): the disk's bytes, which the
    /// runtime also copies files from.
    data: &'static [u8],
}

impl Image {
    /// Its name: `/dev/exobox/<name>`.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The guest's block device for it (a memblk disk, the kernel series' item 12).
    pub fn device(&self) -> PathBuf {
        Path::new("/dev/exobox").join(self.name)
    }

    /// The image's bytes (the host mapping).
    pub fn bytes(&self) -> &'static [u8] {
        self.data
    }
}

/// A host path or an open file, for [`Guest::map_image`].
pub enum ImageSource<'a> {
    Path(&'a Path),
    Fd(OwnedFd),
}

impl<'a> From<&'a Path> for ImageSource<'a> {
    fn from(p: &'a Path) -> Self {
        ImageSource::Path(p)
    }
}
impl<'a> From<&'a str> for ImageSource<'a> {
    fn from(p: &'a str) -> Self {
        ImageSource::Path(Path::new(p))
    }
}
impl<'a> From<&'a PathBuf> for ImageSource<'a> {
    fn from(p: &'a PathBuf) -> Self {
        ImageSource::Path(p)
    }
}
impl From<OwnedFd> for ImageSource<'_> {
    fn from(f: OwnedFd) -> Self {
        ImageSource::Fd(f)
    }
}
impl From<File> for ImageSource<'_> {
    fn from(f: File) -> Self {
        ImageSource::Fd(f.into())
    }
}

/// Coroutines: the kernel's few dozen threads and the program's.
const COROUTINES: usize = 256;
/// Each coroutine's stack, its guard page included: kernel code and the dispatcher run on them.
const COROUTINE_STACK: usize = 128 << 10;
/// Where the arena is placed if it can be: low enough to hold non-PIE programs (x86-64's linkers
/// put them at 0x400000).
const ARENA_AT: usize = 0x20_0000;

fn reserve(at: usize, len: usize, prot: i32) -> Result<*mut u8, Error> {
    reserve_as(at, len, prot, libc::MAP_PRIVATE)
}

/// `reserve`, `MAP_SHARED` or `MAP_PRIVATE`: fork mode's kernel memory is shared by the
/// processes' host forks (`exobox_rt::share`).
fn reserve_as(at: usize, len: usize, prot: i32, share: i32) -> Result<*mut u8, Error> {
    let flags = share | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
    let fixed = if at != 0 { libc::MAP_FIXED_NOREPLACE } else { 0 };
    // SAFETY: a fresh anonymous mapping; FIXED_NOREPLACE never replaces one.
    let p = unsafe { libc::mmap(at as *mut _, len, prot, flags | fixed, -1, 0) };
    if p == libc::MAP_FAILED {
        if at != 0 {
            return reserve_as(0, len, prot, share);
        }
        return Err(Error::Io { what: format!("reserving {len} bytes"), source: std::io::Error::last_os_error() });
    }
    Ok(p as *mut u8)
}

static BOOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Guest {
    /// Reserve the program's memory and the kernel's, boot the kernel on this thread, and set up
    /// the guest's basics ([`setup::defaults`]: `/proc`, `/dev`, `/tmp`, stdio, loopback,
    /// entropy). Host code, no filter. Once per process.
    pub fn boot(config: GuestConfig) -> Result<Guest, Error> {
        Guest::boot_as(config, false)
    }

    /// [`Guest::boot`]; with `shared`, the kernel's memory (its pool, the coroutine stacks, the
    /// runtime's shared section) is mapped shared, for fork mode's host forks.
    fn boot_as(config: GuestConfig, shared: bool) -> Result<Guest, Error> {
        if BOOTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::NotImplemented("a second guest in one process"));
        }
        const PAGE: usize = 4096;
        // No core dumps: the sandbox killed by its filter (SIGSYS) would dump GiBs of reserved
        // memory (the suite's escape_kill took longer than its 5 s timeout writing it), and the
        // dump of a sandbox is the host's business only by accident. RLIMIT_CORE 0, not
        // PR_SET_DUMPABLE 0, which would also hide /proc/<pid>/smaps_rollup (perf.rs's PSS) from
        // its owner. A piped core_pattern (systemd-coredump) is still started, sees the limit and
        // stops reading.
        // The allocator's region for after lockdown (`alloc`): reserved now, while mmap is the host's.
        alloc::reserve().map_err(Error::io("the allocator's region"))?;
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: sets a limit of this process.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
        let memory = config.memory.next_multiple_of(PAGE);
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        // The filter's madvise bound: an arena address plus a chunk stays inside the reservation.
        let zone = config.image_space.next_multiple_of(PAGE);
        let arena = reserve(ARENA_AT, memory + zone + filter::MADV_CHUNK as usize, rwx)?;
        let mem_mb = config.kernel_memory.div_ceil(1 << 20).max(16);
        let heap_len = (mem_mb << 20) + PAGE;
        let share = if shared {
            // The kernel's and the runtime's statics, before anything of them is used. Before
            // any other thread exists.
            // SAFETY: this thread is the process's only one.
            unsafe { exobox_rt::share::remap() }.map_err(|e| Error::Io {
                what: "sharing the kernel's data (fork mode)".into(),
                source: std::io::Error::from_raw_os_error(e.raw_os_error()),
            })?;
            libc::MAP_SHARED
        } else {
            libc::MAP_PRIVATE
        };
        let heap = reserve_as(0, heap_len, rw, share)?;
        let stacks_len = COROUTINES * COROUTINE_STACK;
        let stacks = reserve_as(0, stacks_len, rw, share)?;
        let loglevel = std::env::var("EXOBOX_KERNEL_LOGLEVEL").unwrap_or_else(|_| "1".into());
        // program_mem: what sysinfo and /proc/meminfo report (the kernel series' item 13): the
        // program's memory is the arena, not the kernel's pool (V8 sizes its heap from it).
        let cmdline = CString::new(format!("mem={mem_mb}M program_mem={memory} loglevel={loglevel}")).unwrap();
        // SAFETY: fresh reservations, the guest's from now on; this thread runs it.
        unsafe {
            guest::boot(guest::Boot {
                arena: (arena as usize, memory + zone),
                image_zone: zone,
                heap: (heap, heap_len),
                stacks: sched::Stacks { base: stacks, len: stacks_len, size: COROUTINE_STACK, guard: true },
                cmdline: &cmdline,
            })?;
        }
        // SAFETY: getauxval reads the process's auxiliary vector.
        let aux = |t| unsafe { libc::getauxval(t) };
        let mut entropy = [0u8; 64];
        // SAFETY: fills the buffer.
        if unsafe { libc::getrandom(entropy.as_mut_ptr().cast(), entropy.len(), 0) } != entropy.len() as isize {
            return Err(Error::io("host entropy")(std::io::Error::last_os_error()));
        }
        setup::defaults(&entropy).map_err(Error::io("the guest's basics"))?;
        Ok(Guest {
            aux: guest::Aux {
                hwcap: aux(libc::AT_HWCAP),
                hwcap2: aux(libc::AT_HWCAP2),
                sysinfo_ehdr: aux(libc::AT_SYSINFO_EHDR),
                minsigstksz: aux(libc::AT_MINSIGSTKSZ),
            },
            zone: (arena as usize + memory, arena as usize + memory + zone),
        })
    }

    /// Map an erofs image read-only (a host `mmap`, before lockdown): the guest's read-only block
    /// device `/dev/exobox/<name>` (a memblk disk over the mapping), the name being the file's
    /// without `.erofs` (for an fd, `image<N>`). Mapped a second time, privately, in the arena's
    /// image zone ([`GuestConfig::image_space`]): the program's mappings of its files are made
    /// there in place. Host code.
    pub fn map_image<'a>(&mut self, source: impl Into<ImageSource<'a>>) -> Result<Image, Error> {
        self.map_image_named(source.into(), None)
    }

    fn map_image_named(&mut self, source: ImageSource, name: Option<&str>) -> Result<Image, Error> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (file, name_default): (File, String) = match source {
            ImageSource::Path(p) => {
                let f = File::open(p).map_err(Error::io(p.display().to_string()))?;
                let base = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let stem = base.strip_suffix(".erofs").unwrap_or(&base).to_owned();
                (f, if stem.is_empty() { format!("image{n}") } else { stem })
            }
            ImageSource::Fd(fd) => (File::from(fd), format!("image{n}")),
        };
        let name = name.map_or(name_default, str::to_owned);
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(Error::ImageArg(name));
        }
        let len = file.metadata().map_err(Error::io(name.clone()))?.len() as usize;
        // memblk serves whole 512-byte sectors; an erofs image is whole 4 KiB blocks.
        if len == 0 || !len.is_multiple_of(512) {
            return Err(Error::io(name)(std::io::Error::new(std::io::ErrorKind::InvalidData, "not an image of whole blocks")));
        }
        let data: &'static [u8] = {
            // SAFETY: a read-only private mapping of the whole file, never unmapped.
            let p = unsafe {
                libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0)
            };
            if p == libc::MAP_FAILED {
                return Err(Error::io(format!("mapping {name}"))(std::io::Error::last_os_error()));
            }
            // SAFETY: mapped above for the process's life.
            unsafe { std::slice::from_raw_parts(p as *const u8, len) }
        };
        let image = Image { name: Box::leak(name.into_boxed_str()), data };
        let in_zone = self.map_in_zone(&file, len);
        setup::block_device(&image, in_zone).map_err(Error::io(format!("the guest's {}", image.device().display())))?;
        Ok(image)
    }

    /// The image mapped again, privately, in the arena's image zone (`exobox_rt::memblk`): what
    /// the program maps from it is mapped there in place. None when it doesn't fit, or can't be
    /// mapped executable (a `noexec` mount): its files are copied instead.
    fn map_in_zone(&mut self, file: &File, len: usize) -> Option<usize> {
        let (at, end) = self.zone;
        let size = len.next_multiple_of(4096);
        if end - at < size {
            return None;
        }
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        // SAFETY: over the arena's own reservation, in the zone's unused part: nothing is there.
        let p = unsafe { libc::mmap(at as *mut _, len, rwx, libc::MAP_PRIVATE | libc::MAP_FIXED, file.as_raw_fd(), 0) };
        if p == libc::MAP_FAILED {
            // A failed MAP_FIXED may have unmapped the range: the reservation's zeros back.
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED;
            // SAFETY: as above.
            let back = unsafe { libc::mmap(at as *mut _, size, rwx, flags, -1, 0) };
            assert_ne!(back, libc::MAP_FAILED, "the image zone lost a range");
            return None;
        }
        self.zone.0 = at + size;
        Some(at)
    }

    /// Hold host fd `fd` for the hooks (a provider's connection, made before `run`): made
    /// nonblocking and kept open for the sandbox's life. Under a [`Sandbox`] the filter allows
    /// `read` and `write` on exactly it ([`Sandbox::hold_fd`]).
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        use std::os::fd::IntoRawFd;
        let fd = fd.into_raw_fd();
        // SAFETY: fcntl on our own fd.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: as above.
        if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(Error::io("holding an fd")(std::io::Error::last_os_error()));
        }
        Ok(HeldFd { fd })
    }

    /// Install the routing filter and the network hooks, run `hooks.pre_exec` as the guest's init
    /// (every syscall it makes is the guest's: host data must be read before), then exec
    /// `argv[0]` inside the guest with `argv` and `env` (each `NAME=value`). With an `on_resolve`
    /// hook, the guest's `/etc/resolv.conf` and `/etc/hosts` are written first (`pre_exec` may
    /// replace them). Never returns on success; on failure the routing filter is in, so the
    /// caller can only report the error and exit (both work: through the guest, to the host's
    /// stderr and exit).
    pub fn run(self, hooks: Hooks, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        let path = argv.first().ok_or(Error::NoProgram)?;
        let args: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
        let envs: Vec<&[u8]> = env.iter().map(|a| a.as_bytes()).collect();
        let (pre_exec, resolves) = hooks.install();
        guest::route()?;
        if resolves {
            setup::resolver().map_err(Error::io("the guest's resolver"))?;
        }
        if let Some(f) = pre_exec.0 {
            f()?;
        }
        // From here on the program's memory is the arena's: allocations are the region's.
        alloc::lockdown();
        let errno = guest::exec(path.as_bytes(), &args, &envs, self.aux);
        Err(Error::Exec { path: PathBuf::from(path), errno: std::io::Error::from_raw_os_error(errno.raw_os_error()) })
    }
}

// ------------------------------------------------------------------------------------------------
// Layer 3: the sandbox (layer 2, the filter, is its closure).

/// A [`Guest`] with a security profile: [`Sandbox::run`]'s closure runs the caller's setup, then
/// installs the mode's filter (stacked on the routing one) before the program's exec.
#[derive(Debug)]
pub struct Sandbox {
    guest: Guest,
    mode: Mode,
    deny: Deny,
    rules: Vec<Rule>,
    /// Host fds given to the guest ([`Sandbox::pass_fd`]): (host, guest).
    fds: Vec<(i32, i32)>,
    /// Threaded mode: the CPU-token eventfds' inclusive fd range (coroutine: `(0, 0)`).
    token_fds: (u32, u32),
}

impl Sandbox {
    /// Boot a guest for `mode`. Fork mode's processes share the kernel's memory, mapped shared
    /// here; a fork has no bound but the runtime's host-thread slots until
    /// [`Sandbox::max_procs`].
    pub fn boot(mode: Mode, config: GuestConfig) -> Result<Sandbox, Error> {
        let guest = Guest::boot_as(config, mode == Mode::Fork)?;
        let token_fds = if mode != Mode::Coroutine {
            // Make the CPU-token eventfds and switch the runtime to threaded (before lockdown),
            // then start the kernel idler host thread and wait for it to install its signal stack
            // (the routing filter is synced to it).
            let range = guest::enable_threaded()?;
            std::thread::Builder::new()
                .stack_size(256 * 1024)
                .name("exobox-kernel".into())
                .spawn(|| guest::threaded_kernel_main())
                .map_err(Error::io("the kernel idler thread"))?;
            guest::threaded_wait_ready();
            if mode == Mode::Fork {
                guest::enable_fork(0)?;
            }
            range
        } else {
            (0, 0)
        };
        Ok(Sandbox { guest, mode, deny: Deny::Kill, rules: vec![], fds: vec![], token_fds })
    }

    /// Fork mode: at most `n` processes alive at once, the first one included; a fork past it
    /// fails with EAGAIN. Ignored in the other modes.
    pub fn max_procs(&mut self, n: u32) -> &mut Self {
        if self.mode == Mode::Fork {
            exobox_rt::par::set_max_procs(n);
        }
        self
    }

    /// What a refused host syscall gets (default: kill).
    pub fn deny(&mut self, deny: Deny) -> &mut Self {
        self.deny = deny;
        self
    }

    /// Allow one more host syscall on top of the mode's list.
    pub fn allow(&mut self, rule: Rule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    /// Give the guest host fd `fd` as its fd `guest` (e.g. a channel to the orchestrator at 1000):
    /// a guest file whose reads and writes the runtime does on `fd` (as fds 0-2 are), installed
    /// before the setup closure runs; the filter is widened to `read` and `write` on exactly that
    /// host fd. A guest read waits for the host fd without holding the guest's CPU, and the
    /// guest's `poll`/`epoll` on it see the host fd's readiness (the kernel asks the runtime,
    /// whose idle wait watches the fd). `fd` stays open for the sandbox's life.
    pub fn pass_fd(&mut self, fd: OwnedFd, guest: i32) -> &mut Self {
        use std::os::fd::IntoRawFd;
        let host = fd.into_raw_fd();
        for sysno in [Sysno::read, Sysno::write] {
            self.rules.push(Rule { sysno, args: vec![ArgRange { index: 0, lo: host as u64, hi: host as u64 }] });
        }
        self.fds.push((host, guest));
        self
    }

    /// [`Guest::hold_fd`], and the filter widened to `read` and `write` on exactly that fd.
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        let held = self.guest.hold_fd(fd)?;
        for sysno in [Sysno::read, Sysno::write] {
            self.rules.push(Rule { sysno, args: vec![ArgRange { index: 0, lo: held.fd as u64, hi: held.fd as u64 }] });
        }
        Ok(held)
    }

    /// [`Guest::map_image`].
    pub fn map_image<'a>(&mut self, source: impl Into<ImageSource<'a>>) -> Result<Image, Error> {
        self.guest.map_image(source)
    }

    /// [`Guest::run`], its `pre_exec` the caller's and then the mode's filter.
    pub fn run(self, mut hooks: Hooks, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        // Compiled now, on the host: the closure must not allocate after the filter goes in.
        let prog = Box::leak(Box::new(filter::Program::new()));
        let conds: Vec<Vec<filter::Cond>> = self
            .rules
            .iter()
            .map(|r| r.args.iter().map(|a| filter::Cond { arg: a.index, lo: a.lo, hi: a.hi }).collect())
            .collect();
        let extra: Vec<filter::Rule> =
            self.rules.iter().zip(&conds).map(|(r, c)| filter::Rule { nr: r.sysno.id() as u32, conds: c }).collect();
        let arena = [guest::arena_range()];
        let params = filter::Params {
            policy: filter::Policy::Mode(match self.mode {
                Mode::Coroutine => filter::Mode::Coroutine,
                Mode::Threaded => filter::Mode::Threaded,
                Mode::Fork => filter::Mode::Fork,
            }),
            deny: match self.deny {
                Deny::Kill => filter::Deny::Kill,
                Deny::Errno => filter::Deny::Errno,
            },
            gate_ip: exobox_rt::trap::gate_ip(),
            arena: &arena,
            token_fds: self.token_fds,
            pid: std::process::id(),
            extra: &extra,
        };
        filter::compile(&params, prog).map_err(|e| Error::Io {
            what: "the filter".into(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
        })?;
        let prog: &'static filter::Program = prog;
        let fds = self.fds.clone();
        // Threaded mode: sync the mode filter to every host thread (the kernel idler, and the
        // program's threads made lazily inherit it). SECCOMP_FILTER_FLAG_TSYNC = 1.
        let flags: u32 = if self.mode == Mode::Coroutine { 0 } else { 1 };
        let setup = hooks.pre_exec.0.take();
        hooks.pre_exec = PreExec::new(move || {
            for (host, guest) in fds {
                setup::host_fd(host, guest).map_err(Error::io("passing a host fd"))?;
            }
            if let Some(f) = setup {
                f()?;
            }
            // The mode's filter allows no host memory call: allocations are the region's.
            alloc::lockdown();
            // The mode's list allows no host memory calls: setup code that still makes one gets
            // ENOMEM (mmap) or nothing done, not the filter's verdict.
            guest::host_memory(false);
            filter::install(prog, flags)
                .map_err(|e| Error::io("installing the filter")(std::io::Error::from_raw_os_error(e.raw_os_error())))
        });
        self.guest.run(hooks, argv, env)
    }
}

// ------------------------------------------------------------------------------------------------
// The CLI's path.

/// An image given on the command line: `NAME=PATH[:MOUNTPOINT]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageArg {
    pub name: String,
    pub path: PathBuf,
    pub mount: Option<PathBuf>,
}

impl FromStr for ImageArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::ImageArg(s.to_owned());
        let (name, rest) = s.split_once('=').ok_or_else(bad)?;
        if name.is_empty() || name.contains('/') || rest.is_empty() {
            return Err(bad());
        }
        let (path, mount) = match rest.split_once(':') {
            Some((p, m)) if !m.is_empty() => (p, Some(PathBuf::from(m))),
            Some(_) => return Err(bad()),
            None => (rest, None),
        };
        Ok(ImageArg { name: name.to_owned(), path: path.into(), mount })
    }
}

/// Everything a sandbox needs to start.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub mode: Mode,
    pub deny: Deny,
    /// Host syscalls allowed on top of the mode's own.
    pub rules: Vec<Rule>,
    /// More host paths the program may see and map, besides its own closure: a store path
    /// brings its closure; a path outside the store is shown as is, read-only.
    pub allow_paths: Vec<PathBuf>,
    /// More images to map (and mount, where a mount point is given).
    pub images: Vec<ImageArg>,
    /// Fork mode: the most processes alive at once, the first one included.
    pub max_procs: Option<u32>,
    /// The program and its arguments; `argv[0]` is the program's path.
    pub argv: Vec<OsString>,
    /// The program's environment, `NAME=value` each.
    pub env: Vec<OsString>,
    /// Where store images are cached; None: [`store::Cache::default_dir`].
    pub image_cache: Option<PathBuf>,
}

/// The images the guest mounts for `config`'s program and allowed paths, built where the cache
/// lacks them (the closure too is cached there: [`store::Cache::closure`]). Host-side, before
/// lockdown; nothing is opened or mapped yet.
pub fn store(config: &Config) -> Result<store::Store, Error> {
    let program = config.argv.first().ok_or(Error::NoProgram)?;
    let dir = match &config.image_cache {
        Some(dir) => dir.clone(),
        None => store::Cache::default_dir()?,
    };
    let cache = store::Cache::new(&dir);
    let closure = cache.closure(Path::new(program), &config.allow_paths)?;
    Ok(cache.images(&closure)?)
}

/// Become the sandbox: [`Sandbox::boot`], the closure's images (and `config.images`) mapped,
/// [`Sandbox::run`] with [`setup::mount_closure`]. Returns only on failure before the program
/// starts; the process ends with the program's status.
pub fn run(config: Config) -> Result<Infallible, Error> {
    let store = store(&config)?;
    let guest = GuestConfig::default();
    let mut sb = Sandbox::boot(config.mode, guest)?;
    sb.deny(config.deny);
    if let Some(n) = config.max_procs {
        sb.max_procs(n);
    }
    for r in &config.rules {
        sb.allow(r.clone());
    }
    let mut mounts = Vec::new();
    for m in &store.mounts {
        mounts.push((sb.map_image(&m.image)?, m.guest.clone()));
    }
    for i in &config.images {
        let img = sb.guest.map_image_named(ImageSource::Path(&i.path), Some(&i.name))?;
        if let Some(at) = &i.mount {
            mounts.push((img, at.clone()));
        }
    }
    // The program's path as the host resolves it: the guest's working directory is `/`.
    let mut argv = config.argv.clone();
    argv[0] = std::path::absolute(&argv[0]).map_err(Error::io("the program's path"))?.into_os_string();
    let hooks = Hooks { pre_exec: PreExec::new(move || setup::mount_closure(&mounts)), ..Default::default() };
    sb.run(hooks, &argv, &config.env)
}

/// A booted kernel with no program, forked once per sandbox: each child loads its own program,
/// sharing the template's booted kernel copy-on-write. Starting a sandbox skips the boot, and the
/// kernel's pages are paid for once.
pub struct Template {
    _config: Config,
}

impl Template {
    /// Boot a template in a process of its own. `config.argv` is ignored: each [`spawn`] names
    /// its program.
    ///
    /// [`spawn`]: Template::spawn
    pub fn start(config: Config) -> Result<Template, Error> {
        let _ = config;
        Err(Error::NotImplemented("templates"))
    }

    /// Fork a sandbox running `argv` with these stdin, stdout and stderr. Returns its host pid
    /// (a child of the template's process, not of this one).
    pub fn spawn(&self, argv: &[OsString], stdio: [OwnedFd; 3]) -> Result<u32, Error> {
        let _ = (argv, stdio);
        Err(Error::NotImplemented("templates"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_parse() {
        assert_eq!("getppid".parse::<Rule>().unwrap(), Rule { sysno: Sysno::getppid, args: vec![] });
        assert_eq!(
            "madvise:arg0=0x1000..0x2000,arg2=4".parse::<Rule>().unwrap(),
            Rule {
                sysno: Sysno::madvise,
                args: vec![
                    ArgRange { index: 0, lo: 0x1000, hi: 0x2000 },
                    ArgRange { index: 2, lo: 4, hi: 4 }
                ],
            }
        );
    }

    #[test]
    fn rules_refuse_nonsense() {
        for bad in ["nosuchcall", "write:fd=3", "write:arg6=1", "write:arg0=x", "write:arg0=5..4"] {
            assert!(bad.parse::<Rule>().is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn image_args() {
        assert_eq!(
            "store=/x/s.erofs:/nix/store".parse::<ImageArg>().unwrap(),
            ImageArg { name: "store".into(), path: "/x/s.erofs".into(), mount: Some("/nix/store".into()) }
        );
        assert_eq!("a=/p".parse::<ImageArg>().unwrap().mount, None);
        for bad in ["a", "=p", "a=", "a/b=p", "a=p:"] {
            assert!(bad.parse::<ImageArg>().is_err(), "{bad} parsed");
        }
    }
}
