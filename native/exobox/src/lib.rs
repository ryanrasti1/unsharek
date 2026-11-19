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
mod tcb;

pub use net::{Cx, GuestSocket, HeldFd, NetError, OnConnect, OnListen, OnResolve};

/// One classic-BPF instruction (`struct sock_filter`), for [`Builder::restrict`].
pub use tcb::filter::SockFilter;
/// The auxiliary-vector tag under which a sandboxed program finds the gate's address (what the
/// escape tests call, as a compromised program that found the gate would).
pub use exobox_rt::exec::AT_EXOBOX_GATE;

use std::convert::Infallible;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use exobox_rt::{guest, sched};
use tcb::inventory::{Fd, Inventory, MapKind};

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
    /// Every host resource the sandbox keeps past lockdown (`tcb::inventory`).
    inv: Inventory,
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
        Guest::boot_as(config, false)
    }

    /// [`Guest::boot`]; with `shared`, the kernel's memory (its pool, the coroutine stacks, the
    /// runtime's shared section) is mapped shared, for fork mode's host forks.
    fn boot_as(config: GuestConfig, shared: bool) -> Result<Guest, Error> {
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
        let mut inv = Inventory::new();
        let memory = config.memory.next_multiple_of(PAGE);
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        let zone = config.image_space.next_multiple_of(PAGE);
        let reserving = |len| Error::io(format!("reserving {len} bytes"));
        let arena = inv.reserve(ARENA_AT, memory + zone, rwx, false, MapKind::Arena).map_err(reserving(memory + zone))?;
        let mem_mb = config.kernel_memory.div_ceil(1 << 20).max(16);
        let heap_len = (mem_mb << 20) + PAGE;
        if shared {
            // The kernel's and the runtime's statics, before anything of them is used.
            // SAFETY: nothing else uses the runtime yet; this is the only thread.
            unsafe { inv.share_section() }.map_err(Error::io("sharing the kernel's data (fork mode)"))?;
        }
        let heap = inv.reserve(0, heap_len, rw, shared, MapKind::KernelHeap).map_err(reserving(heap_len))? as *mut u8;
        let stacks_len = COROUTINES * COROUTINE_STACK;
        let stacks = inv.reserve(0, stacks_len, rw, shared, MapKind::Stacks).map_err(reserving(stacks_len))? as *mut u8;
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
            inv,
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
        self.inv.remake_tokens().map_err(Error::io("the CPU tokens' eventfds, after a fork"))?;
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
        // The layout exobox-erofs wrote beside it (`X.layout` for `X.erofs`): where its ELFs are.
        let (file, name_default, layout): (File, String, Option<PathBuf>) = match source {
            ImageSource::Path(p) => {
                let f = File::open(p).map_err(Error::io(p.display().to_string()))?;
                let base = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let stem = base.strip_suffix(".erofs").unwrap_or(&base).to_owned();
                let layout = base.strip_suffix(".erofs").map(|s| p.with_file_name(format!("{s}.layout")));
                (f, if stem.is_empty() { format!("image{n}") } else { stem }, layout)
            }
            ImageSource::Fd(fd) => (File::from(fd), format!("image{n}"), None),
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
        let data = self.inv.map_image(file.as_raw_fd(), len).map_err(Error::io(format!("mapping {name}")))?;
        let image = Image { name: Box::leak(name.into_boxed_str()), data };
        let in_zone = match layout.and_then(|l| std::fs::read(l).ok()) {
            Some(layout) => self.map_in_zone(&file, len, &layout)?,
            // No layout, no known slots: its files are copied when mapped.
            None => None,
        };
        setup::block_device(&image, in_zone).map_err(Error::io(format!("the guest's {}", image.device().display())))?;
        Ok(image)
    }

    /// The image mapped again, privately, in the arena's image zone (`exobox_rt::memblk`): what
    /// the program maps from it is mapped there in place. None when it doesn't fit, or can't be
    /// mapped executable (a `noexec` mount): its files are copied instead.
    ///
    /// Read-only and executable, but for each ELF's writable segments in its slot (from the
    /// image's `layout` and the ELFs' own program headers), which are made writable here and
    /// told to the arena: so every other page of the zone is always the image's bytes, in every
    /// mode, after any fork, and a library is mapped in place at every exec (its data pages copied,
    /// as Linux copies them on write). When the zone was writable, a library's data written by one
    /// program kept it from ever being mapped in place again where nothing gives pages back
    /// (threaded and fork mode): fork mode copied nearly every exec's libraries, code and all
    /// (make -j4 copied 2.3 GB for 142 execs: native/PERF.md).
    fn map_in_zone(&mut self, file: &File, len: usize, layout: &[u8]) -> Result<Option<usize>, Error> {
        let (at, end) = self.zone;
        let size = len.next_multiple_of(4096);
        if end - at < size {
            return Ok(None);
        }
        // In the zone's unused part of the arena's reservation: nothing is there.
        if self.inv.map_image_at(at, file.as_raw_fd(), len).is_err() {
            return Ok(None);
        }
        self.zone.0 = at + size;
        for (lo, hi) in writable_pages(file, layout) {
            let (lo, hi) = (at + lo, (at + hi).min(at + size));
            if lo >= hi {
                continue;
            }
            // Executable too: a page shared by the end of the code and the start of the data.
            // SAFETY: pages of the mapping just made, which nothing uses yet.
            if unsafe { libc::mprotect(lo as *mut _, hi - lo, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) } != 0 {
                return Err(Error::io("the image zone's writable pages")(std::io::Error::last_os_error()));
            }
            guest::zone_writable(lo, hi)?;
        }
        Ok(Some(at))
    }

    /// `program`'s Nix closure (plus `allow_paths`, each a store path with its closure or a
    /// host directory, read-only) as images from the default cache ([`store::Cache::open_default`],
    /// built where missing), mapped, each with where [`setup::mount_closure`] mounts it.
    pub fn map_closure(&mut self, program: &Path, allow_paths: &[PathBuf]) -> Result<Vec<setup::Mount>, Error> {
        let store = store::Cache::open_default()?.store(program, allow_paths)?;
        self.map_store(&store)
    }

    /// Each of `store`'s images mapped, with where [`setup::mount_closure`] mounts it.
    pub fn map_store(&mut self, store: &store::Store) -> Result<Vec<setup::Mount>, Error> {
        store.mounts.iter().map(|m| Ok(setup::Mount { image: self.map_image(&m.image)?, at: m.guest.clone(), kind: m.kind })).collect()
    }

    /// Hold host fd `fd` for the hooks (a provider's connection, made before `run`): made
    /// nonblocking and kept open for the sandbox's life. Under a [`Sandbox`] the filter allows
    /// `read` and `write` on exactly it ([`Sandbox::hold_fd`]).
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        // SAFETY: fcntl on the caller's fd, owned.
        let fl = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above.
        if fl < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(Error::io("holding an fd")(std::io::Error::last_os_error()));
        }
        let fd = self.inv.keep(fd, Fd::Held).map_err(Error::io("holding an fd"))?;
        Ok(HeldFd { fd })
    }

    /// Route this thread's syscalls to the guest while the guard lives: from here on, until the
    /// guard drops, every syscall the calling thread makes is served by the guest kernel, as its
    /// init (PID 1, root). Anything the guest kernel can do, a guard can: mounts, files, ids
    /// (`setresuid`: the program is exec'd with init's credentials as they are then), the
    /// hostname, the clock (`clock_settime`; the program gets EPERM for both, as an unprivileged
    /// user would). The first guard installs the routing filter (permanent: seccomp filters can't
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
        let path = argv.first().ok_or(Error::NoProgram)?.clone();
        self.launch(net::Hooks::default(), Start::Exec(&path, argv, env), |_| {
            alloc::lockdown();
            Ok(())
        })
    }

    /// Install the network hooks, begin setup (the routing filter in, if it isn't), run
    /// `lockdown` (the security filter), start the hooks' `on_start` task, exec.
    ///
    /// Nothing here touches the guest's files: this runs after the caller's guards, as init with
    /// the credentials they left (a `setresuid` to a build user), which the exec is meant to have
    /// and exobox's own writes are not (the resolver's files are written at build).
    fn launch(
        mut self,
        hooks: net::Hooks,
        start: Start,
        lockdown: impl FnOnce(&Inventory) -> Result<(), Error>,
    ) -> Result<Infallible, Error> {
        self.own(None)?;
        let on_start = hooks.install();
        // Once the program runs, a panic is the runtime's: it ends the sandbox through the host
        // (`guest::runtime_panic`), not through the guest it was serving. Set now: setting a hook
        // allocates, which lockdown ends.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if guest::program_runs() {
                guest::runtime_panic(info);
            }
            prev(info)
        }));
        guest::route()?;
        guest::intercept_begin()?;
        lockdown(&self.inv)?;
        // Locked down: from here on, everything is the sandbox's.
        if let Some(f) = on_start {
            exobox_rt::executor::spawn(f(Cx));
        }
        match start {
            Start::Exec(path, argv, env) => {
                let args: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
                let envs: Vec<&[u8]> = env.iter().map(|a| a.as_bytes()).collect();
                let errno = guest::exec(path.as_bytes(), &args, &envs, self.aux);
                Err(Error::Exec { path: PathBuf::from(path), errno: std::io::Error::from_raw_os_error(errno.raw_os_error()) })
            }
            Start::Fn(f) => guest::run_fn(f),
        }
    }
}

/// What [`Guest::launch`] starts after lockdown.
enum Start<'a> {
    /// A program exec'd inside the guest: its path, argv and env.
    Exec(&'a OsString, &'a [OsString], &'a [OsString]),
    /// [`Sandbox::run_fn`]'s closure, run as the program.
    Fn(Box<dyn FnOnce() -> i32 + 'a>),
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
    max_procs: u32,
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

    /// Fork mode: at most `n` processes alive at once, the first one included; a fork past it
    /// fails with EAGAIN (default: no bound but the runtime's host-thread slots). Ignored in the
    /// other modes.
    pub fn max_procs(mut self, n: u32) -> Self {
        self.max_procs = n;
        self
    }

    /// Boot the guest for the mode. Fork mode's processes share the kernel's memory, mapped
    /// shared here. When the program's names resolve (an `on_resolve` or `on_connect` hook), the
    /// guest's `/etc/resolv.conf` and `/etc/hosts` are written now, root's ([`setup::resolver`]):
    /// a guard may change them.
    pub fn build(self) -> Result<Sandbox, Error> {
        let mut guest = Guest::boot_as(self.config, self.mode == Mode::Fork)?;
        if self.hooks.resolves() {
            setup::resolver().map_err(Error::io("the guest's resolver"))?;
        }
        if self.mode != Mode::Coroutine {
            // The CPU tokens' eventfds, where the runtime looks for them, then the runtime
            // switched to threaded (before lockdown), then the kernel idler host thread started
            // and waited for (it installs its signal stack).
            let base = exobox_rt::par::EFD_BASE as RawFd;
            guest.inv.token_eventfds(base, exobox_rt::par::N_SLOTS).map_err(Error::io("the CPU tokens' eventfds"))?;
            guest::enable_threaded()?;
            spawn_idler().map_err(Error::io("the kernel idler thread"))?;
            guest.inv.add_thread();
            guest::threaded_wait_ready();
            if self.mode == Mode::Fork {
                let pidfd = guest.inv.init_pidfd().map_err(Error::io("init's pidfd"))?;
                guest::enable_fork(self.max_procs, pidfd)?;
            }
        }
        Ok(Sandbox { guest, mode: self.mode, deny: self.deny, restrictions: self.restrictions, hooks: self.hooks })
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
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("mode", &self.mode)
            .field("fds", &self.guest.inv.fds())
            .field("maps", &self.guest.inv.maps())
            .finish_non_exhaustive()
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
        Builder { mode: Mode::default(), config: GuestConfig::default(), deny: Deny::Kill, restrictions: vec![], hooks: net::Hooks::default(), max_procs: 0 }
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
    pub fn map_closure(&mut self, program: &Path, allow_paths: &[PathBuf]) -> Result<Vec<setup::Mount>, Error> {
        self.guest.map_closure(program, allow_paths)
    }

    /// [`Guest::map_store`].
    pub fn map_store(&mut self, store: &store::Store) -> Result<Vec<setup::Mount>, Error> {
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
        let host = self.guest.inv.keep(fd, Fd::Passed).map_err(Error::io("passing an fd"))?;
        setup::host_fd(host, guest).map_err(Error::io(format!("the guest's fd {guest}")))
    }

    /// [`Guest::hold_fd`], and the filter widened to `read` and `write` on exactly that fd.
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        self.guest.hold_fd(fd)
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
        // The template isn't locked down: memory it shares with a child would be the child's to
        // write (fork mode's shared kernel memory, the only shared mapping exobox makes).
        if self.guest.inv.has_shared() {
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

    /// Lockdown and exec: the routing filter (if no guard installed it), the network hooks
    /// (whose resolver files, when names resolve, [`Builder::build`] wrote), then the security
    /// filter (the mode's, and the restrictions) and the exec of `argv[0]` inside the guest with
    /// `argv` and `env` (each `NAME=value`), as init with the credentials the guards left. Never returns on success: the process's status is the program's. On failure
    /// the error is the caller's to report and exit with (after lockdown its syscalls are the
    /// guest's, and printing and exiting work through it).
    ///
    /// The sandbox's process must have no host threads but the mode's own (the caller's would be
    /// left unfiltered, or routed into the guest): `Error::Threads`.
    pub fn run(self, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        let path = argv.first().ok_or(Error::NoProgram)?.clone();
        self.start(Start::Exec(&path, argv, env))
    }

    /// Lockdown, then `f` run as the program: on this thread, after both filters, its syscalls
    /// trapped and served by the guest kernel as an exec'd program's are (as init, with the
    /// credentials the guards left), and its return value the sandbox's exit status. Never
    /// returns on success; fails as [`Sandbox::run`] does, before `f` runs.
    ///
    /// `f` is ordinary Rust in this process, so it is the sandbox's program: what it can reach on
    /// the host is what the program's could (the security filter's list), and what it captures
    /// it may use (it's moved in). Its limits: no threads (`std::thread` makes a guest thread
    /// that knows nothing of Rust's TLS: don't); its allocations come from the region exobox
    /// reserved at build (the global allocator after lockdown); a panic in it is the runtime's
    /// (the sandbox dies of SIGABRT); its host fds are the inventory's (any other was closed
    /// at lockdown: a `File` captured from before is a closed or a guest fd now).
    pub fn run_fn(self, f: impl FnOnce() -> i32) -> Result<Infallible, Error> {
        self.start(Start::Fn(Box::new(f)))
    }

    fn start(mut self, start: Start) -> Result<Infallible, Error> {
        self.guest.own(None)?;
        let fds: Vec<RawFd> = self
            .guest
            .inv
            .fds()
            .iter()
            .filter(|(_, k)| matches!(k, Fd::Stdio | Fd::Passed | Fd::Held))
            .map(|&(fd, _)| fd)
            .collect();
        // How the runtime writes the guest's host fds (a pipe's in pieces that can't block, a
        // regular file's whole): looked at now, as they are for this run (after lockdown nothing
        // may fstat them).
        exobox_rt::host::note_host_fds(&fds);
        // Compiled now, on the host: lockdown allocates nothing.
        let mode = match self.mode {
            Mode::Coroutine => tcb::filter::Mode::Coroutine,
            Mode::Threaded => tcb::filter::Mode::Threaded,
            Mode::Fork => tcb::filter::Mode::Fork,
        };
        let deny = match self.deny {
            Deny::Kill => tcb::filter::Deny::Kill,
            Deny::Errno => tcb::filter::Deny::Errno,
        };
        let gate_ip = exobox_rt::trap::gate_ip();
        let security = tcb::filter::security(mode, deny, &self.guest.inv.pins(), gate_ip).map_err(|e| Error::Io {
            what: "the security filter".into(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
        })?;
        let restrictions: Vec<Vec<SockFilter>> =
            std::mem::take(&mut self.restrictions).iter().map(|r| tcb::filter::restriction(r, gate_ip)).collect();
        let hooks = std::mem::take(&mut self.hooks);
        self.guest.launch(hooks, start, move |inv| {
            // The security filter allows no host memory call: allocations are the region's.
            alloc::lockdown();
            // Setup code that still makes one gets ENOMEM (mmap) or nothing done, not the
            // filter's verdict.
            guest::host_memory(false);
            tcb::lockdown::lockdown(inv, &restrictions, &security).map_err(Error::io("lockdown"))
        })
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
    let mut sb = Sandbox::builder().mode(config.mode).deny(config.deny).max_procs(config.max_procs.unwrap_or(0)).build()?;
    let mut mounts = sb.map_store(&store)?;
    for i in &config.images {
        let img = sb.map_image_as(&i.path, &i.name)?;
        if let Some(at) = &i.mount {
            mounts.push(setup::Mount { image: img, at: at.clone(), kind: store::Kind::Dir });
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
}

/// The pages of an image (offsets in it) where its ELFs' writable segments land when mapped in
/// place: for each ELF of `layout` (exobox-erofs' `offset slot size elf|data path` lines), each
/// writable PT_LOAD's pages, placed as ld.so places them over the reservation of the file's span
/// (at the file's offset of its lowest segment, `exobox_erofs`'s `elf.rs`), within its slot. An
/// ELF whose headers can't be read has none (nothing of it can then be written in place: it is
/// copied).
///
/// The headers are read with `pread`, not from the image's mapping: touching the mapping made its
/// pages the sandbox's (1.5 MB more PSS per idle sandbox).
fn writable_pages(image: &File, layout: &[u8]) -> Vec<(usize, usize)> {
    use std::os::unix::fs::FileExt;
    const PAGE: u64 = 4096;
    let mut out = Vec::new();
    for line in layout.split(|&b| b == b'\n') {
        let mut f = line.splitn(5, |&b| b == b' ');
        let num = |x: Option<&[u8]>| x.and_then(|x| std::str::from_utf8(x).ok()?.parse::<u64>().ok());
        let (Some(offset), Some(slot), Some(size)) = (num(f.next()), num(f.next()), num(f.next())) else { continue };
        if f.next() != Some(b"elf".as_slice()) {
            continue;
        }
        // The ELF header, then as much as its program headers need (a page, nearly always).
        let mut head = vec![0u8; size.min(4096) as usize];
        if image.read_at(&mut head, offset).is_err() {
            continue;
        }
        let need = head.get(0x20..0x28).zip(head.get(0x36..0x3a)).map(|(o, n)| {
            let phoff = u64::from_le_bytes(o.try_into().unwrap());
            let (ent, num) = (u16::from_le_bytes([n[0], n[1]]) as u64, u16::from_le_bytes([n[2], n[3]]) as u64);
            phoff.saturating_add(ent * num)
        });
        if let Some(need) = need
            && need > head.len() as u64
            && need <= size.min(1 << 20)
        {
            head.resize(need as usize, 0);
            if image.read_at(&mut head, offset).is_err() {
                continue;
            }
        }
        let Some(loads) = elf_loads(&head) else { continue };
        let Some(&(vaddr0, off0, _, _, _)) = loads.iter().min_by_key(|l| l.0) else { continue };
        let lo = vaddr0 / PAGE * PAGE;
        let base = offset + off0 / PAGE * PAGE;
        for &(vaddr, _, memsz, writable, _) in &loads {
            if !writable {
                continue;
            }
            let Some(end) = vaddr.checked_add(memsz).and_then(|e| e.checked_next_multiple_of(PAGE)) else { continue };
            let (s, e) = (base + (vaddr / PAGE * PAGE - lo), (base + (end - lo)).min(offset + slot));
            if s < e {
                out.push((s as usize, e as usize));
            }
        }
    }
    out
}

/// An ELF64 little-endian file's PT_LOADs: (p_vaddr, p_offset, p_memsz, writable, p_filesz).
/// None if its headers aren't whole.
fn elf_loads(elf: &[u8]) -> Option<Vec<(u64, u64, u64, bool, u64)>> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(elf.get(o..o + 8)?.try_into().ok()?));
    if elf.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let (phoff, phentsize, phnum) = (u64_at(0x20)? as usize, u16_at(0x36)? as usize, u16_at(0x38)? as usize);
    let mut loads = Vec::new();
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        const PT_LOAD: u32 = 1;
        const PF_W: u32 = 2;
        if u32_at(ph)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(ph + 4)?;
        loads.push((u64_at(ph + 16)?, u64_at(ph + 8)?, u64_at(ph + 40)?, flags & PF_W != 0, u64_at(ph + 32)?));
    }
    Some(loads)
}
