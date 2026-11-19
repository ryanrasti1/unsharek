//! exobox: run an unmodified Linux program on an in-process Linux kernel (LKL), behind a seccomp
//! filter that leaves the host a handful of syscalls.
//!
//! ```no_run
//! # fn main() -> Result<(), exobox::Error> {
//! # let (program, argv, env): (std::path::PathBuf, Vec<std::ffi::OsString>, Vec<std::ffi::OsString>) = Default::default();
//! use exobox::{Mode, Sandbox};
//! let mut sb = Sandbox::builder().mode(Mode::Coroutine).build()?; // boots the guest kernel
//! let mounts = sb.map_closure(&program, &[])?;                    // host work: images mapped
//! {
//!     let _g = sb.intercept()?;                  // this thread's syscalls are the guest's now
//!     exobox::setup::mount_closure(&mounts)?;    // ordinary Rust, in the guest
//!     std::fs::write("/etc/motd", "hi\n")?;
//! }                                              // the host's again
//! let Err(e) = sb.run(&argv, &env);              // lockdown, exec; never returns on success
//! # Err(e) }
//! ```
//!
//! Three layers (README.md, "The library"), each built only from the one below:
//! 1. [`Guest`]: the kernel booted in this process ([`Guest::boot`]), host data given to it
//!    ([`Guest::map_image`]), setup run in it ([`Guest::intercept`]) and a program exec'd in it
//!    ([`Guest::run`]). Routing only, no security policy.
//! 2. Security: the mode's filter, stacked on the routing one at lockdown, with the caller's
//!    restrictions ([`Builder::restrict`]).
//! 3. [`Sandbox`]: a `Guest` with a mode, its filter, the network's hooks ([`net`]) and
//!    templates ([`Sandbox::fork`]). [`run`] (the CLI's path) is a `Sandbox` for a [`Config`].
//!
//! The process becomes the sandbox: one guest per process, used from the thread that built it
//! (a `Sandbox` is `!Send`). A template forks it ([`Sandbox::fork`], [`Sandbox::spawn`]): each
//! child is a sandbox of its own, sharing the template's booted kernel copy-on-write.

pub mod alloc;
pub mod net;
pub mod setup;
pub mod store;

pub use net::{Cx, GuestSocket, HeldFd, NetError, OnConnect, OnListen, OnResolve};

/// One classic-BPF instruction (`struct sock_filter`), for [`Builder::restrict`].
pub use exobox_rt::filter::SockFilter;
/// The auxiliary-vector tag under which a sandboxed program finds the gate's address (what the
/// escape tests call, as a compromised program that found the gate would).
pub use exobox_rt::exec::AT_EXOBOX_GATE;

use std::convert::Infallible;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use exobox_rt::{filter, guest, sched};

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

/// What the filter does to a host syscall it doesn't allow. A debugging knob for the escape
/// tests: a sandbox kills (the default), always.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deny {
    /// Kill the sandbox (SIGSYS).
    #[default]
    Kill,
    /// Fail the syscall with EPERM (for probing the filter).
    Errno,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid image {0:?}: NAME=PATH[:MOUNTPOINT]")]
    ImageArg(String),
    #[error("no program to run (argv is empty)")]
    NoProgram,
    #[error(transparent)]
    Store(#[from] store::Error),
    #[error(transparent)]
    Erofs(#[from] exobox_erofs::Error),
    #[error("{what}: {source}")]
    Io { what: String, source: std::io::Error },
    /// An I/O error of the caller's (inside a guard, say), as it came: `?` on `std::fs` and
    /// friends.
    #[error(transparent)]
    Os(#[from] std::io::Error),
    #[error("the guest: {0}")]
    Guest(guest::Error),
    #[error("{}: {errno}", .path.display())]
    Exec { path: PathBuf, errno: std::io::Error },
    #[error("{0} host threads at lockdown, {1} expected: the mode's filter would leave the others unfiltered or misrouted")]
    Threads(usize, usize),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl Error {
    fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> Error {
        let what = what.into();
        move |source| Error::Io { what, source }
    }
}

impl From<guest::Error> for Error {
    fn from(e: guest::Error) -> Self {
        Error::Guest(e)
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

/// The guest kernel, booted in this process: [`Guest::boot`], then host work and setup in any
/// order ([`Guest::map_image`], [`Guest::intercept`]), then [`Guest::run`], which never returns
/// on success. `!Send`: the thread that booted it is the one that uses it.
#[derive(Debug)]
pub struct Guest {
    aux: guest::Aux,
    /// The image zone's unused part, `[next, end)`.
    zone: (usize, usize),
    _thread: PhantomData<*const ()>,
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
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
    let fixed = if at != 0 { libc::MAP_FIXED_NOREPLACE } else { 0 };
    // SAFETY: a fresh anonymous mapping; FIXED_NOREPLACE never replaces one.
    let p = unsafe { libc::mmap(at as *mut _, len, prot, flags | fixed, -1, 0) };
    if p == libc::MAP_FAILED {
        if at != 0 {
            return reserve(0, len, prot);
        }
        return Err(Error::Io { what: format!("reserving {len} bytes"), source: std::io::Error::last_os_error() });
    }
    Ok(p as *mut u8)
}

static BOOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 64 bytes of the host's entropy.
fn host_entropy() -> Result<[u8; 64], Error> {
    let mut entropy = [0u8; 64];
    // SAFETY: fills the buffer.
    if unsafe { libc::getrandom(entropy.as_mut_ptr().cast(), entropy.len(), 0) } != entropy.len() as isize {
        return Err(Error::io("host entropy")(std::io::Error::last_os_error()));
    }
    Ok(entropy)
}

/// Threaded mode's kernel idler host thread, started (at boot, and in a fork's child, which the
/// fork didn't copy it to).
fn spawn_idler() -> std::io::Result<()> {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .name("exobox-kernel".into())
        .spawn(|| guest::threaded_kernel_main())
        .map(drop)
}

impl Guest {
    /// Reserve the program's memory and the kernel's, boot the kernel on this thread, and set up
    /// the guest's basics ([`setup::defaults`]: `/proc`, `/dev`, `/tmp`, stdio, loopback,
    /// entropy). Host code, no filter. Once per process.
    pub fn boot(config: GuestConfig) -> Result<Guest, Error> {
        if BOOTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::NotImplemented("a second guest in one process"));
        }
        const PAGE: usize = 4096;
        // The allocator's region for after lockdown (`alloc`): reserved now, while mmap is the host's.
        alloc::reserve().map_err(Error::io("the allocator's region"))?;
        // No core dumps: the sandbox killed by its filter (SIGSYS) would dump GiBs of reserved
        // memory (the suite's escape_kill took longer than its 5 s timeout writing it), and the
        // dump of a sandbox is the host's business only by accident. RLIMIT_CORE 0, not
        // PR_SET_DUMPABLE 0, which would also hide /proc/<pid>/smaps_rollup (perf.rs's PSS) from
        // its owner. A piped core_pattern (systemd-coredump) is still started, sees the limit and
        // stops reading.
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
        let heap = reserve(0, heap_len, rw)?;
        let stacks_len = COROUTINES * COROUTINE_STACK;
        let stacks = reserve(0, stacks_len, rw)?;
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
        setup::defaults(&host_entropy()?).map_err(Error::io("the guest's basics"))?;
        Ok(Guest {
            aux: guest::Aux {
                hwcap: aux(libc::AT_HWCAP),
                hwcap2: aux(libc::AT_HWCAP2),
                sysinfo_ehdr: aux(libc::AT_SYSINFO_EHDR),
                minsigstksz: aux(libc::AT_MINSIGSTKSZ),
            },
            zone: (arena as usize + memory, arena as usize + memory + zone),
            _thread: PhantomData,
        })
    }

    /// A host fork's child (a template's instance: [`Sandbox::fork`], or a plain `fork()` of the
    /// process) takes the guest over before its first use: the guest's pid is its own, threaded
    /// mode's host threads are made again (`guest::fork_child`), and the guest's RNG gets fresh
    /// host entropy and is reseeded (the fork copied its state: without it, every child of one
    /// template would draw the same random bytes). Nothing in the process that booted it.
    fn own(&mut self, token: Option<u16>) -> Result<(), Error> {
        if token.is_none() && !guest::forked() {
            return Ok(());
        }
        guest::fork_child(token, || spawn_idler().expect("the kernel idler thread"))?;
        setup::reseed(&host_entropy()?).map_err(Error::io("reseeding the guest's RNG"))
    }

    /// Map an erofs image read-only (a host `mmap`, before lockdown): the guest's read-only block
    /// device `/dev/exobox/<name>` (a memblk disk over the mapping), the name being the file's
    /// without `.erofs` (for an fd, `image<N>`). Mapped a second time, privately, in the arena's
    /// image zone ([`GuestConfig::image_space`]): the program's mappings of its files are made
    /// there in place. Host code (outside a guard).
    pub fn map_image<'a>(&mut self, source: impl Into<ImageSource<'a>>) -> Result<Image, Error> {
        self.map_image_named(source.into(), None)
    }

    /// [`Guest::map_image`] as `/dev/exobox/<name>` (no `/`, not starting with `.`).
    pub fn map_image_as<'a>(&mut self, source: impl Into<ImageSource<'a>>, name: &str) -> Result<Image, Error> {
        self.map_image_named(source.into(), Some(name))
    }

    fn map_image_named(&mut self, source: ImageSource, name: Option<&str>) -> Result<Image, Error> {
        self.own(None)?;
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

    /// `program`'s Nix closure (plus `allow_paths`, each a store path with its closure or a
    /// host directory, read-only) as images from the default cache ([`store::Cache::open_default`],
    /// built where missing), mapped, each with where [`setup::mount_closure`] mounts it.
    pub fn map_closure(&mut self, program: &Path, allow_paths: &[PathBuf]) -> Result<Vec<(Image, PathBuf)>, Error> {
        let store = store::Cache::open_default()?.store(program, allow_paths)?;
        self.map_store(&store)
    }

    /// Each of `store`'s images mapped, with where [`setup::mount_closure`] mounts it.
    pub fn map_store(&mut self, store: &store::Store) -> Result<Vec<(Image, PathBuf)>, Error> {
        store.mounts.iter().map(|m| Ok((self.map_image(&m.image)?, m.guest.clone()))).collect()
    }

    /// Hold host fd `fd` for the hooks (a provider's connection, made before `run`): made
    /// nonblocking and kept open for the sandbox's life. Under a [`Sandbox`] the filter allows
    /// `read` and `write` on exactly it ([`Sandbox::hold_fd`]).
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        let fd = fd.into_raw_fd();
        // SAFETY: fcntl on our own fd.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: as above.
        if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(Error::io("holding an fd")(std::io::Error::last_os_error()));
        }
        Ok(HeldFd { fd })
    }

    /// Route this thread's syscalls to the guest while the guard lives: from here on, until the
    /// guard drops, every syscall the calling thread makes is served by the guest kernel, as its
    /// init (PID 1, root). Anything the guest kernel can do, a guard can: mounts, files, ids
    /// (`setresuid`: the program is exec'd with init's credentials as they are then), the
    /// hostname. The first guard installs the routing filter (permanent: seccomp filters can't
    /// be removed); after the guard's drop, the runtime passes the trapped syscalls through to the
    /// host (`exobox_rt::passthrough`), so host code behaves as before, until [`Guest::run`].
    /// Guards may come and go any number of times, interleaved with host work.
    ///
    /// What runs where while a guard lives:
    /// - **Only this thread.** Other host threads' syscalls stay the host's (passthrough, if they
    ///   were made after the first guard and inherited the filter). The guard is `!Send`, and
    ///   only the thread that booted the guest may take one.
    /// - **Memory stays the host's.** `mmap`, `munmap`, `mremap`, `mprotect`, `madvise`, `brk`
    ///   and friends pass through to the host, so the allocator (the system's, until lockdown) works
    ///   as ever: what is allocated inside a guard is ordinary host memory, valid after it.
    /// - **Everything else is the guest's**: files, fds, sockets, `getpid` (1), `getrandom`
    ///   (the guest's RNG). An fd opened inside is a guest fd: don't keep it for after the guard
    ///   (there it would name some host fd), and don't use a host fd inside. The guest's fds 0-2
    ///   write and read the host's 0-2, so printing works. Host data is read before the guard and
    ///   moved in (a `Vec`, a string): a host path means nothing inside.
    /// - **std's lazy state** that makes no syscall (environment, thread-locals, the stdout
    ///   buffer) is unaffected. State that caches an fd or a syscall's answer on first use would
    ///   cache the guest's: first use it outside (`std::io::stdout()` is fine either way: it
    ///   writes fd 1).
    /// - **No threads**: a `clone` inside fails with ENOSYS (setup is single-threaded; the
    ///   program makes its threads after exec).
    /// - **A panic** unwinds as usual and drops the guard on its way (back to the host's
    ///   syscalls), its message printed through the guest's stderr, the host's. With
    ///   `panic = "abort"`, the abort's signal is the guest's, which ends init and the process
    ///   with SIGABRT.
    ///
    /// Fails if the routing filter can't be installed (no seccomp).
    pub fn intercept(&mut self) -> Result<Intercept<'_>, Error> {
        self.own(None)?;
        guest::route()?;
        guest::intercept_begin()?;
        Ok(Intercept { _guest: PhantomData })
    }

    /// Exec `argv[0]` inside the guest with `argv` and `env` (each `NAME=value`): the routing
    /// filter (if no guard has installed it), then the exec, no security filter (layer 1: a
    /// [`Sandbox`] adds it). Never returns on success; on failure the error is the caller's to
    /// report (its syscalls are the guest's by then, and printing and exiting work through it).
    pub fn run(self, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        self.launch(net::Hooks::default(), argv, env, || {
            alloc::lockdown();
            Ok(())
        })
    }

    /// Install the network hooks, begin setup (the routing filter in, if it isn't), write the
    /// resolver's files if a hook resolves, run `lockdown` (the security filter), start the
    /// hooks' `on_start` task, exec.
    fn launch(
        mut self,
        hooks: net::Hooks,
        argv: &[OsString],
        env: &[OsString],
        lockdown: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Infallible, Error> {
        let path = argv.first().ok_or(Error::NoProgram)?;
        self.own(None)?;
        let args: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
        let envs: Vec<&[u8]> = env.iter().map(|a| a.as_bytes()).collect();
        let (resolves, on_start) = hooks.install();
        guest::route()?;
        guest::intercept_begin()?;
        let r = (|| {
            if resolves {
                setup::resolver().map_err(Error::io("the guest's resolver"))?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            guest::intercept_end();
            return Err(e);
        }
        lockdown()?;
        if let Some(f) = on_start {
            exobox_rt::executor::spawn(f(Cx));
        }
        let errno = guest::exec(path.as_bytes(), &args, &envs, self.aux);
        Err(Error::Exec { path: PathBuf::from(path), errno: std::io::Error::from_raw_os_error(errno.raw_os_error()) })
    }
}

/// While it lives, the calling thread's syscalls are the guest's ([`Guest::intercept`]); dropped,
/// they pass through to the host again.
#[must_use = "the guest's routing ends when the guard is dropped"]
pub struct Intercept<'a> {
    _guest: PhantomData<(&'a mut Guest, *const ())>,
}

impl Drop for Intercept<'_> {
    fn drop(&mut self) {
        guest::intercept_end();
    }
}

impl std::fmt::Debug for Intercept<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Intercept")
    }
}

// ------------------------------------------------------------------------------------------------
// Layers 2 and 3: the sandbox.

/// A sandbox's configuration, before boot: [`Sandbox::builder`].
pub struct Builder {
    mode: Mode,
    config: GuestConfig,
    deny: Deny,
    restrictions: Vec<Vec<SockFilter>>,
    hooks: net::Hooks,
}

impl Builder {
    /// The mode (default: coroutine).
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// The memory the guest reserves (default: [`GuestConfig::default`]).
    pub fn config(mut self, config: GuestConfig) -> Self {
        self.config = config;
        self
    }

    /// The program's connects beyond loopback ([`net`]).
    pub fn on_connect(mut self, hook: OnConnect) -> Self {
        self.hooks.on_connect = hook;
        self
    }

    /// The program's listens beyond loopback ([`net`]).
    pub fn on_listen(mut self, hook: OnListen) -> Self {
        self.hooks.on_listen = hook;
        self
    }

    /// The program's name lookups ([`net`]). Without one, but with an `on_connect`, every name
    /// resolves to an address of its own (see [`Cx::name_of`]).
    pub fn on_resolve(mut self, hook: OnResolve) -> Self {
        self.hooks.on_resolve = hook;
        self
    }

    /// A task started on the hooks' executor at lockdown, before the program: a provider's
    /// session over a held fd ([`Cx::held`]), ready before the first connect.
    pub fn on_start<F, Fut>(mut self, f: F) -> Self
    where
        F: FnOnce(Cx) -> Fut + 'static,
        Fut: std::future::Future<Output = ()> + 'static,
    {
        self.hooks.on_start = Some(Box::new(move |cx| Box::pin(f(cx))));
        self
    }

    /// One more seccomp program, stacked at lockdown with the mode's filter: the kernel runs
    /// every filter and takes the strictest answer, so a restriction can only take away (a call
    /// the mode allows fails as the restriction says; one it refuses stays refused), never add.
    /// Repeatable. A classic-BPF program over `struct seccomp_data`, as seccompiler and libseccomp
    /// make them. It sees exobox's own syscalls (from the gate: the ones the mode allows, which it
    /// can refuse with any verdict) and the program's too, but those are traps of the routing
    /// filter's, and of the kernel's precedence (KILL > TRAP > ERRNO > ALLOW) only a kill outranks a
    /// trap: an ERRNO leaves the program's call to the guest.
    /// exobox installs the mode's filter after it, so its `prctl` and `seccomp` from the gate get
    /// through (the mode's filter refuses both after).
    ///
    /// With seccompiler (a dependency of yours, not exobox's), forbidding `write` to fd 2:
    ///
    /// ```ignore
    /// use seccompiler::{BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule};
    /// let filter = SeccompFilter::new(
    ///     [(libc::SYS_write, vec![SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 2)?])?])].into(),
    ///     SeccompAction::Allow,       // what isn't matched
    ///     SeccompAction::KillProcess, // what is
    ///     std::env::consts::ARCH.try_into()?,
    /// )?;
    /// let bpf: BpfProgram = filter.try_into()?;
    /// let sb = exobox::Sandbox::builder()
    ///     .restrict(bpf.iter().map(|f| exobox::SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }))
    ///     .build()?;
    /// ```
    pub fn restrict(mut self, prog: impl IntoIterator<Item = SockFilter>) -> Self {
        self.restrictions.push(prog.into_iter().collect());
        self
    }

    /// What a refused host syscall gets (default: kill). For the escape tests.
    #[doc(hidden)]
    pub fn deny(mut self, deny: Deny) -> Self {
        self.deny = deny;
        self
    }

    /// Boot the guest for the mode (coroutine and threaded; fork mode is not implemented yet).
    pub fn build(self) -> Result<Sandbox, Error> {
        if self.mode == Mode::Fork {
            return Err(Error::NotImplemented("fork mode"));
        }
        let guest = Guest::boot(self.config)?;
        let token_fds = if self.mode == Mode::Threaded {
            // Make the CPU-token eventfds and switch the runtime to threaded (before lockdown),
            // then start the kernel idler host thread and wait for it to install its signal stack.
            let range = guest::enable_threaded()?;
            spawn_idler().map_err(Error::io("the kernel idler thread"))?;
            guest::threaded_wait_ready();
            range
        } else {
            (0, 0)
        };
        Ok(Sandbox {
            guest,
            mode: self.mode,
            deny: self.deny,
            restrictions: self.restrictions,
            hooks: self.hooks,
            host_fds: vec![],
            token_fds,
        })
    }
}

/// A [`Guest`] with a mode, its security filter, the network's hooks, and templates: built by
/// [`Sandbox::builder`], given host data ([`Sandbox::map_image`], [`Sandbox::pass_fd`],
/// [`Sandbox::hold_fd`]), set up through [`Sandbox::intercept`], forked per instance as a
/// template ([`Sandbox::fork`]), and started by [`Sandbox::run`].
pub struct Sandbox {
    guest: Guest,
    mode: Mode,
    deny: Deny,
    restrictions: Vec<Vec<SockFilter>>,
    hooks: net::Hooks,
    /// Host fds the filter allows `read` and `write` on (passed and held fds).
    host_fds: Vec<RawFd>,
    /// Threaded mode: the CPU-token eventfds' inclusive fd range (coroutine: `(0, 0)`).
    token_fds: (u32, u32),
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox").field("mode", &self.mode).field("host_fds", &self.host_fds).finish_non_exhaustive()
    }
}

/// Which side of [`Sandbox::fork`] this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fork {
    /// The new process: a sandbox of its own, to set up and run.
    Child,
    /// The template, with the child's host pid.
    Parent(u32),
}

/// A sandbox started by [`Sandbox::spawn`]: a child process of the caller's.
#[derive(Debug)]
pub struct Child {
    pid: u32,
}

impl Child {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for it to end: its status is the program's (a signal's death included).
    pub fn wait(self) -> std::io::Result<std::process::ExitStatus> {
        wait(self.pid)
    }
}

/// Wait for child process `pid` (a sandbox [`Sandbox::fork`] made): `waitpid`.
pub fn wait(pid: u32) -> std::io::Result<std::process::ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    let mut st = 0;
    loop {
        // SAFETY: waitpid into a local.
        let r = unsafe { libc::waitpid(pid as i32, &mut st, 0) };
        if r == pid as i32 {
            return Ok(std::process::ExitStatus::from_raw(st));
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

impl Sandbox {
    /// A sandbox to configure, then [`Builder::build`].
    pub fn builder() -> Builder {
        Builder { mode: Mode::default(), config: GuestConfig::default(), deny: Deny::Kill, restrictions: vec![], hooks: net::Hooks::default() }
    }

    /// Its mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// [`Guest::map_image`].
    pub fn map_image<'a>(&mut self, source: impl Into<ImageSource<'a>>) -> Result<Image, Error> {
        self.guest.map_image(source)
    }

    /// [`Guest::map_image_as`].
    pub fn map_image_as<'a>(&mut self, source: impl Into<ImageSource<'a>>, name: &str) -> Result<Image, Error> {
        self.guest.map_image_as(source, name)
    }

    /// [`Guest::map_closure`].
    pub fn map_closure(&mut self, program: &Path, allow_paths: &[PathBuf]) -> Result<Vec<(Image, PathBuf)>, Error> {
        self.guest.map_closure(program, allow_paths)
    }

    /// [`Guest::map_store`].
    pub fn map_store(&mut self, store: &store::Store) -> Result<Vec<(Image, PathBuf)>, Error> {
        self.guest.map_store(store)
    }

    /// Give the guest host fd `fd` as its fd `guest` (e.g. a channel to the orchestrator at 1000),
    /// now: a guest file whose reads and writes the runtime does on `fd` (as fds 0-2 are); the
    /// filter is widened to `read` and `write` on exactly that host fd. A guest read waits for
    /// the host fd without holding the guest's CPU, and the guest's `poll`/`epoll` on it see the
    /// host fd's readiness (the kernel asks the runtime, whose idle wait watches the fd). `fd`
    /// stays open for the sandbox's life. Host code (outside a guard); fails if `fd` isn't open.
    pub fn pass_fd(&mut self, fd: OwnedFd, guest: i32) -> Result<(), Error> {
        self.guest.own(None)?;
        let host = fd.into_raw_fd();
        // SAFETY: fcntl on the fd just taken.
        if unsafe { libc::fcntl(host, libc::F_GETFD) } < 0 {
            return Err(Error::io("passing an fd")(std::io::Error::last_os_error()));
        }
        setup::host_fd(host, guest).map_err(Error::io(format!("the guest's fd {guest}")))?;
        self.host_fds.push(host);
        Ok(())
    }

    /// [`Guest::hold_fd`], and the filter widened to `read` and `write` on exactly that fd.
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        let held = self.guest.hold_fd(fd)?;
        self.host_fds.push(held.fd);
        Ok(held)
    }

    /// [`Sandbox::hold_fd`] under `name`, for the hooks to find with [`Cx::held`]: a template's
    /// hooks are given at build, each child holds its own provider's fd.
    pub fn hold_fd_as(&mut self, name: &str, fd: OwnedFd) -> Result<HeldFd, Error> {
        let held = self.hold_fd(fd)?;
        net::name_held(name, held);
        Ok(held)
    }

    /// [`Guest::intercept`].
    pub fn intercept(&mut self) -> Result<Intercept<'_>, Error> {
        self.guest.intercept()
    }

    /// A host fork of the sandbox's process: a template's instance. The child is a sandbox of its
    /// own, a copy of this one as it is now (its guest kernel, its mounts and files, what it has
    /// mapped, passed and held), to set up further and [`Sandbox::run`]; the parent goes on, a
    /// template for more. The fork is made right (`guest::fork_prepare`/`fork_child`): the
    /// child's guest RNG is reseeded with fresh host entropy, and in threaded mode the kernel is
    /// copied at rest (the CPU token held) and the child's host threads and CPU token made again.
    /// The child's status, once it runs, is its program's. Usable in a loop (a long-lived
    /// template forking per request); outside a guard. The parent waits for its children itself
    /// ([`wait`], or `waitpid`).
    ///
    /// Fork mode: not yet (its processes share the guest kernel's memory, which each instance
    /// needs a copy of).
    pub fn fork(&mut self) -> Result<Fork, Error> {
        if self.mode == Mode::Fork {
            return Err(Error::NotImplemented("a fork-mode template: its kernel's shared memory needs a copy per child"));
        }
        self.guest.own(None)?;
        let token = guest::fork_prepare();
        // SAFETY: fork; the child is single-threaded and takes the guest over before using it.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            guest::fork_parent(token);
            return Err(Error::io("fork")(std::io::Error::last_os_error()));
        }
        if pid == 0 {
            self.guest.own(Some(token.unwrap_or(0)))?;
            return Ok(Fork::Child);
        }
        guest::fork_parent(token);
        Ok(Fork::Parent(pid as u32))
    }

    /// [`Sandbox::fork`], the child running `f` (its setup, then `run`) and ending with its
    /// program (or, if `f` fails or panics, reporting it and exiting 125 or 101). Returns the
    /// child to the parent.
    pub fn spawn(&mut self, f: impl FnOnce(Sandbox) -> Result<Infallible, Error>) -> Result<Child, Error> {
        match self.fork()? {
            Fork::Parent(pid) => Ok(Child { pid }),
            Fork::Child => {
                // SAFETY: this process's copy of the sandbox, moved into `f`; the original is
                // never used or dropped (the process ends here).
                let sb = unsafe { std::ptr::read(self) };
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(sb)));
                match r {
                    Ok(Err(e)) => {
                        eprintln!("exobox: {e}");
                        std::process::exit(125)
                    }
                    _ => std::process::exit(101),
                }
            }
        }
    }

    /// Lockdown and exec: the routing filter (if no guard installed it), the network hooks, the
    /// guest's resolver files when names resolve, then the security filter (the mode's, and the
    /// restrictions) and the exec of `argv[0]` inside the guest with `argv` and `env` (each
    /// `NAME=value`). Never returns on success: the process's status is the program's. On failure
    /// the error is the caller's to report and exit with (after lockdown its syscalls are the
    /// guest's, and printing and exiting work through it).
    ///
    /// The sandbox's process must have no host threads but the mode's own (the caller's would be
    /// left unfiltered, or routed into the guest): `Error::Threads`.
    pub fn run(mut self, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        self.guest.own(None)?;
        let expected = if self.mode == Mode::Coroutine { 1 } else { 2 };
        // A thread just joined (the image cache's builders: `std::thread::scope`) is still listed
        // while it finishes exiting (a join returns when its tid word is cleared, before the
        // kernel has reaped it): a few milliseconds' grace.
        let mut threads = 0;
        for _ in 0..100 {
            threads = std::fs::read_dir("/proc/self/task").map_err(Error::io("/proc/self/task"))?.count();
            if threads <= expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if threads != expected {
            return Err(Error::Threads(threads, expected));
        }
        // Compiled now, on the host: lockdown must not allocate after the filter goes in.
        let prog = Box::leak(Box::new(filter::Program::new()));
        let conds: Vec<[filter::Cond; 1]> =
            self.host_fds.iter().map(|&fd| [filter::Cond { arg: 0, lo: fd as u64, hi: fd as u64 }]).collect();
        let extra: Vec<filter::Rule> = conds
            .iter()
            .flat_map(|c| [filter::Rule { nr: filter::NR_READ, conds: c }, filter::Rule { nr: filter::NR_WRITE, conds: c }])
            .collect();
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
        let restrictions: Vec<Vec<SockFilter>> =
            std::mem::take(&mut self.restrictions).iter().map(|r| restriction(r, params.gate_ip)).collect();
        // Threaded mode: sync the filters to every host thread (the kernel idler, and the
        // program's threads made lazily inherit them). SECCOMP_FILTER_FLAG_TSYNC = 1.
        let flags: u32 = if self.mode == Mode::Coroutine { 0 } else { 1 };
        let hooks = std::mem::take(&mut self.hooks);
        let install = |insns: &[SockFilter]| {
            filter::install_insns(insns, flags)
                .map_err(|e| Error::io("installing the filter")(std::io::Error::from_raw_os_error(e.raw_os_error())))
        };
        self.guest.launch(hooks, argv, env, move || {
            // The mode's filter allows no host memory call: allocations are the region's.
            alloc::lockdown();
            // Setup code that still makes one gets ENOMEM (mmap) or nothing done, not the
            // filter's verdict.
            guest::host_memory(false);
            for r in &restrictions {
                install(r)?;
            }
            install(prog.as_slice())
        })
    }
}

/// A restriction as installed: the caller's program after a prologue that lets exobox's own
/// `prctl` and `seccomp` from the gate through (it installs the mode's filter after the
/// restrictions; the mode's filter then refuses both). Classic BPF jumps are relative and
/// forward, so the caller's program is unchanged after it.
fn restriction(insns: &[SockFilter], gate_ip: u64) -> Vec<SockFilter> {
    const LD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET: u16 = 0x06;
    const ALLOW: u32 = filter::SECCOMP_RET_ALLOW;
    let i = |code, jt, jf, k| SockFilter { code, jt, jf, k };
    let mut p = vec![
        i(LD, 0, 0, 0),                        // nr
        i(JEQ, 1, 0, libc::SYS_prctl as u32),  // -> 3
        i(JEQ, 0, 5, libc::SYS_seccomp as u32), // else -> 8
        i(LD, 0, 0, 8),                        // instruction_pointer, low half
        i(JEQ, 0, 3, gate_ip as u32),          // else -> 8
        i(LD, 0, 0, 12),                       // high half
        i(JEQ, 0, 1, (gate_ip >> 32) as u32),  // else -> 8
        i(RET, 0, 0, ALLOW),
    ];
    p.extend_from_slice(insns);
    p
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
    #[doc(hidden)]
    pub deny: Deny,
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
    let cache = match &config.image_cache {
        Some(dir) => store::Cache::new(dir),
        None => store::Cache::open_default()?,
    };
    Ok(cache.store(Path::new(program), &config.allow_paths)?)
}

/// Become the sandbox: [`Sandbox::builder`] for the mode, the closure's images (and
/// `config.images`) mapped and mounted in a guard, [`Sandbox::run`]. Returns only on failure
/// before the program starts; the process ends with the program's status.
pub fn run(config: Config) -> Result<Infallible, Error> {
    let store = store(&config)?;
    let mut sb = Sandbox::builder().mode(config.mode).deny(config.deny).build()?;
    let mut mounts = sb.map_store(&store)?;
    for i in &config.images {
        let img = sb.map_image_as(&i.path, &i.name)?;
        if let Some(at) = &i.mount {
            mounts.push((img, at.clone()));
        }
    }
    // The program's path as the host resolves it: the guest's working directory is `/`.
    let mut argv = config.argv.clone();
    argv[0] = std::path::absolute(&argv[0]).map_err(Error::io("the program's path"))?.into_os_string();
    {
        let _g = sb.intercept()?;
        setup::mount_closure(&mounts)?;
    }
    sb.run(&argv, &config.env)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn restriction_prologue_jumps_to_the_program() {
        let user = [SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
        let p = restriction(&user, 0x1234_5678_9abc);
        // Every not-taken branch of the prologue lands on the caller's first instruction.
        let start = p.len() - 1;
        assert_eq!(2 + 1 + p[2].jf as usize, start);
        assert_eq!(4 + 1 + p[4].jf as usize, start);
        assert_eq!(6 + 1 + p[6].jf as usize, start);
        assert_eq!(1 + 1 + p[1].jt as usize, 3);
    }
}
