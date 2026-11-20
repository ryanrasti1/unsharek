//! unsharek: run an unmodified Linux program on an in-process Linux kernel (LKL), behind a seccomp
//! filter that leaves the host a handful of syscalls.
//!
//! ```no_run
//! # fn main() -> Result<(), unsharek::Error> {
//! # let (program, argv, env): (std::path::PathBuf, Vec<std::ffi::OsString>, Vec<std::ffi::OsString>) = Default::default();
//! use unsharek::{Guest, GuestConfig, Mode};
//! let mut g = Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() })?; // the kernel
//! let mounts = g.map_closure(&program, &[])?;          // host work: images mapped
//! g.run(|| -> std::io::Result<()> {                    // this thread's syscalls are the guest's
//!     unsharek::setup::mount_closure(&mounts)?;          // ordinary Rust, in the guest, as init
//!     std::fs::write("/etc/motd", "hi\n")
//! })??;                                                // and the host's again
//! let g = g.lockdown(|s| {                             // the TCB's lockdown, the caller's grants
//!     s.grant(0).grant(1).grant(2);
//!     Ok(())
//! })?;
//! let Err(e) = g.exec(&argv, &env);                    // the program; never returns on success
//! # Err(e) }
//! ```
//!
//! **Where isolation is.** Not in this crate: in `unsharek-tcb` (`crates/unsharek-tcb/` at the repository's root,
//! re-exported as [`crates/unsharek-tcb`]), which [`Guest::lockdown`] calls. Its lockdown checks the process (one
//! thread; the guest's fds; every mapping), closes every fd not granted, drops what the process
//! may not keep (core dumps, capabilities, privileges) and installs one seccomp filter, before
//! anything untrusted runs. Everything here (this API, the runtime `unsharek-rt`, the guest kernel,
//! the batteries: [`setup`], [`store`](mod@store), [`net`], [`alloc`]) runs in the program's
//! address space after lockdown and protects nothing.
//!
//! **Two mechanisms, two jobs.** Before lockdown, [`Guest::run`]'s closure is routed to the guest
//! by syscall user dispatch, per thread and switched by a selector byte (free); between closures
//! the process is an ordinary one. From lockdown on, the filter traps every call not made from the
//! runtime's gate, in every thread and process made after it.
//!
//! The process becomes the sandbox: one guest per process, used from the thread that booted it
//! (a `Guest` is `!Send`). A template forks it before lockdown ([`Guest::fork`],
//! [`Guest::spawn`]): each child is a guest of its own, sharing the template's booted kernel
//! copy-on-write. [`run`] (the CLI's path) is the whole of it for a [`Config`].

pub mod alloc;
mod image;
mod memory;
pub mod hostfs;
pub mod net;
pub mod setup;
pub mod store;

pub use unsharek_tcb as tcb;
pub use image::Image;
pub use net::{Cx, GuestSocket, HeldFd, NetError, OnConnect, OnListen, OnResolve};
/// How the sandbox runs the program's threads and processes. Each mode's host allowlist is a
/// superset of the one before.
pub use tcb::Mode;
/// One classic-BPF instruction (`struct sock_filter`): [`tcb::filter`]'s output.
pub use tcb::sock_filter as SockFilter;
/// The auxiliary-vector tag under which a sandboxed program finds the gate's address (what the
/// escape tests call, as a compromised program that found the gate would).
pub use unsharek_rt::exec::AT_UNSHAREK_GATE;

use std::convert::Infallible;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use unsharek_rt::{guest, sched};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid image {0:?}: NAME=PATH[:MOUNTPOINT]")]
    ImageArg(String),
    #[error("no program to run (argv is empty)")]
    NoProgram,
    #[error(transparent)]
    Store(#[from] store::Error),
    #[error(transparent)]
    Erofs(#[from] unsharek_erofs::Error),
    #[error("{what}: {source}")]
    Io { what: String, source: std::io::Error },
    /// An I/O error of the caller's (inside a setup closure, say), as it came: `?` on `std::fs`
    /// and friends.
    #[error(transparent)]
    Os(#[from] std::io::Error),
    #[error("the guest: {0}")]
    Guest(guest::Error),
    #[error("{}: {errno}", .path.display())]
    Exec { path: PathBuf, errno: std::io::Error },
    #[error("lockdown: {0}")]
    Lockdown(#[from] tcb::Error),
    /// Other host threads at lockdown ([`Guest::lockdown`]'s check, before the TCB's own).
    #[error("{0}")]
    Threads(String),
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
// The guest.

/// What [`Guest::boot`] makes.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    /// The mode (default: coroutine).
    pub mode: Mode,
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
    /// Fork mode: at most this many processes alive at once, the first one included; a fork past
    /// it fails with EAGAIN (0: no bound but the runtime's host-thread slots). Ignored in the
    /// other modes. The runtime's bound, in the program's address space: a compromised program can
    /// bypass it. A bound the program can't is the caller's (`RLIMIT_NPROC`, a cgroup).
    pub max_procs: u32,
}

impl Default for GuestConfig {
    fn default() -> Self {
        // The kernel's memory holds its slab, the page cache of what the program reads from its
        // images (evictable) and its ramfs files (/tmp). 32 MiB: each MiB costs 16 KiB of struct
        // pages, all written at boot (64 MiB was 1 MiB of every sandbox).
        GuestConfig { mode: Mode::Coroutine, memory: 4 << 30, kernel_memory: 32 << 20, image_space: 64 << 30, max_procs: 0 }
    }
}

/// The guest kernel, booted in this process: [`Guest::boot`], then host work and setup in any
/// order ([`Guest::map_image`], [`Guest::pass_fd`], [`Guest::run`]), then [`Guest::lockdown`],
/// then the program ([`Locked::exec`], [`Locked::run`]). `!Send`: the thread that booted it is
/// the one that uses it.
pub struct Guest {
    mode: Mode,
    max_procs: u32,
    aux: guest::Aux,
    /// The image zone's unused part, `[next, end)`.
    zone: (usize, usize),
    /// Fork mode's kernel memory is mapped shared (no template may fork it).
    shared: bool,
    /// Passed and held host fds: the guest's plumbing, granted at lockdown.
    passed: Vec<RawFd>,
    held: Vec<RawFd>,
    /// The guest's own host fds, made at lockdown (the CPU tokens' eventfds, init's pidfd), for
    /// the TCB to check and keep ([`tcb::Confined::host_fds`]).
    host_fds: Vec<RawFd>,
    hooks: net::Hooks,
    _thread: PhantomData<*const ()>,
}

impl std::fmt::Debug for Guest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guest")
            .field("mode", &self.mode)
            .field("passed", &self.passed)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl tcb::Confined for Guest {
    fn host_fds(&self) -> &[RawFd] {
        &self.host_fds
    }
    fn gate_ip(&self) -> u64 {
        unsharek_rt::trap::gate_ip()
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

/// This process's other host threads (`/proc/self/task`, the caller's own excluded).
fn other_threads() -> Vec<i32> {
    // SAFETY: gettid.
    let me = unsafe { libc::gettid() };
    std::fs::read_dir("/proc/self/task")
        .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).filter(|&t| t != me).collect())
        .unwrap_or_default()
}

/// A setup's end, at the closure's return or a panic's unwinding.
struct SetupEnd;
impl Drop for SetupEnd {
    fn drop(&mut self) {
        guest::setup_end();
    }
}

impl Guest {
    /// Reserve the program's memory and the kernel's, boot the kernel on this thread, and set up
    /// the guest's basics ([`setup::defaults`]: `/proc`, `/dev`, `/tmp`, stdio, loopback,
    /// entropy). Fork mode's processes share the kernel's memory, mapped shared here. Host code.
    /// Once per process.
    pub fn boot(config: GuestConfig) -> Result<Guest, Error> {
        if BOOTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::NotImplemented("a second guest in one process"));
        }
        let shared = config.mode == Mode::Fork;
        const PAGE: usize = 4096;
        // The allocator's region for after lockdown (`alloc`): reserved now, while mmap is the host's.
        alloc::reserve().map_err(Error::io("the allocator's region"))?;
        // No core dumps from here on (lockdown makes it so for good, with the dump flag): the
        // sandbox killed by its filter (SIGSYS) would dump GiBs of reserved memory.
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: sets a limit of this process.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
        let memory = config.memory.next_multiple_of(PAGE);
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        let zone = config.image_space.next_multiple_of(PAGE);
        let reserving = |len| Error::io(format!("reserving {len} bytes"));
        let arena = memory::reserve(ARENA_AT, memory + zone, rwx, false).map_err(reserving(memory + zone))?;
        let mem_mb = config.kernel_memory.div_ceil(1 << 20).max(16);
        let heap_len = (mem_mb << 20) + PAGE;
        if shared {
            // The kernel's and the runtime's statics, before anything of them is used.
            // SAFETY: nothing else uses the runtime yet; this is the only thread.
            unsafe { memory::share_section() }.map_err(Error::io("sharing the kernel's data (fork mode)"))?;
        }
        let heap = memory::reserve(0, heap_len, rw, shared).map_err(reserving(heap_len))? as *mut u8;
        let stacks_len = COROUTINES * COROUTINE_STACK;
        let stacks = memory::reserve(0, stacks_len, rw, shared).map_err(reserving(stacks_len))? as *mut u8;
        let loglevel = std::env::var("UNSHAREK_KERNEL_LOGLEVEL").unwrap_or_else(|_| "1".into());
        // program_mem: what sysinfo and /proc/meminfo report (the kernel series' item 13): the
        // program's memory is the arena, not the kernel's pool (V8 sizes its heap from it).
        let cmdline = CString::new(format!("mem={mem_mb}M program_mem={memory} loglevel={loglevel}")).unwrap();
        // SAFETY: fresh reservations, the guest's from now on; this thread runs it.
        unsafe {
            guest::boot(guest::Boot {
                arena: (arena, memory + zone),
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
            mode: config.mode,
            max_procs: config.max_procs,
            aux: guest::Aux {
                hwcap: aux(libc::AT_HWCAP),
                hwcap2: aux(libc::AT_HWCAP2),
                sysinfo_ehdr: aux(libc::AT_SYSINFO_EHDR),
                minsigstksz: aux(libc::AT_MINSIGSTKSZ),
            },
            zone: (arena + memory, arena + memory + zone),
            shared,
            passed: vec![],
            held: vec![],
            host_fds: vec![],
            hooks: net::Hooks::default(),
            _thread: PhantomData,
        })
    }

    /// Its mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// A host fork's child (a template's instance: [`Guest::fork`], or a plain `fork()` of the
    /// process) takes the guest over before its first use: the guest's pid is its own, and the
    /// guest's RNG gets fresh host entropy and is reseeded (the fork copied its state: without it,
    /// every child of one template would draw the same random bytes). Nothing in the process that
    /// booted it.
    fn own(&mut self) -> Result<(), Error> {
        if !guest::forked() {
            return Ok(());
        }
        guest::fork_child();
        setup::reseed(&host_entropy()?).map_err(Error::io("reseeding the guest's RNG"))
    }

    /// Map an erofs image read-only (a host `mmap`, before lockdown): the guest's read-only block
    /// device `/dev/unsharek/<name>` (a memblk disk over the mapping), the name being the file's
    /// without `.erofs` (for an fd, `image<N>`). Mapped a second time, privately, in the arena's
    /// image zone ([`GuestConfig::image_space`]): the program's mappings of its files are made
    /// there in place. Host code (outside [`Guest::run`]).
    pub fn map_image<'a>(&mut self, source: impl Into<ImageSource<'a>>) -> Result<Image, Error> {
        self.map_image_named(source.into(), None)
    }

    /// [`Guest::map_image`] as `/dev/unsharek/<name>` (no `/`, not starting with `.`).
    pub fn map_image_as<'a>(&mut self, source: impl Into<ImageSource<'a>>, name: &str) -> Result<Image, Error> {
        self.map_image_named(source.into(), Some(name))
    }

    fn map_image_named(&mut self, source: ImageSource, name: Option<&str>) -> Result<Image, Error> {
        self.own()?;
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The layout unsharek-erofs wrote beside it (`X.layout` for `X.erofs`): where its ELFs are.
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
        let data = memory::map_image(file.as_raw_fd(), len).map_err(Error::io(format!("mapping {name}")))?;
        let in_zone = match layout.and_then(|l| std::fs::read(l).ok()) {
            Some(layout) => self.map_in_zone(&file, len, &layout)?,
            // No layout, no known slots: its files are copied when mapped.
            None => None,
        };
        let name: &'static str = Box::leak(name.into_boxed_str());
        image::register(name, data, in_zone).map_err(Error::io(format!("the guest's /dev/unsharek/{name}")))
    }

    /// The image mapped again, privately, in the arena's image zone (`unsharek_rt::memblk`): what
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
    /// (make -j4 copied 2.3 GB for 142 execs: bench/PERF.md).
    fn map_in_zone(&mut self, file: &File, len: usize, layout: &[u8]) -> Result<Option<usize>, Error> {
        let (at, end) = self.zone;
        let size = len.next_multiple_of(4096);
        if end - at < size {
            return Ok(None);
        }
        // In the zone's unused part of the arena's reservation: nothing is there.
        if memory::map_image_at(at, file.as_raw_fd(), len).is_err() {
            return Ok(None);
        }
        self.zone.0 = at + size;
        for (lo, hi) in image::writable_pages(file, layout) {
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

    /// `fd`, open, kept as one of the guest's plumbing fds.
    fn keep(fd: OwnedFd, what: &str) -> Result<RawFd, Error> {
        let fd = fd.into_raw_fd();
        // SAFETY: fcntl on the caller's fd, owned.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(Error::io(what)(std::io::Error::last_os_error()));
        }
        Ok(fd)
    }

    /// Give the guest host fd `fd` as its fd `guest` (e.g. a channel to the orchestrator at 1000),
    /// now: a guest file whose reads and writes the runtime does on `fd` (as fds 0-2 are). A guest
    /// read waits for the host fd without holding the guest's CPU, and the guest's `poll`/`epoll`
    /// on it see the host fd's readiness (the kernel asks the runtime, whose idle wait watches the
    /// fd). `fd` stays open for the sandbox's life; [`Guest::lockdown`] grants it read and write.
    /// Host code; fails if `fd` isn't open.
    pub fn pass_fd(&mut self, fd: OwnedFd, guest: i32) -> Result<(), Error> {
        self.own()?;
        let host = Guest::keep(fd, "passing an fd")?;
        self.passed.push(host);
        setup::host_fd(host, guest).map_err(Error::io(format!("the guest's fd {guest}")))
    }

    /// Hold host fd `fd` for the hooks (a provider's connection, made before lockdown): made
    /// nonblocking and kept open for the sandbox's life; [`Guest::lockdown`] grants it read and
    /// write.
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        // SAFETY: fcntl on the caller's fd, owned.
        let fl = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above.
        if fl < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(Error::io("holding an fd")(std::io::Error::last_os_error()));
        }
        let fd = Guest::keep(fd, "holding an fd")?;
        self.held.push(fd);
        Ok(HeldFd::from_raw(fd))
    }

    /// [`Guest::hold_fd`] under `name`, for the hooks to find with [`Cx::held`]: a template's
    /// hooks are given before it forks, each child holds its own provider's fd.
    pub fn hold_fd_as(&mut self, name: &str, fd: OwnedFd) -> Result<HeldFd, Error> {
        let held = self.hold_fd(fd)?;
        net::name_held(name, held);
        Ok(held)
    }

    /// The guest's `/etc/resolv.conf` and `/etc/hosts`, written (root's: [`setup::resolver`]) when
    /// the program's names first resolve (an `on_resolve` or `on_connect` hook). A setup may change
    /// them after.
    fn resolves(&mut self) -> Result<(), Error> {
        if !self.hooks.resolves() {
            return Ok(());
        }
        setup::resolver().map_err(Error::io("the guest's resolver"))
    }

    /// The program's connects beyond loopback ([`net`]).
    /// A hook is not a policy point: it runs in the program's address space after lockdown, and
    /// a compromised program can skip it. Policy belongs at the far end of the held fds.
    pub fn on_connect(&mut self, hook: OnConnect) -> Result<(), Error> {
        let first = !self.hooks.resolves();
        self.hooks.on_connect = hook;
        if first { self.resolves() } else { Ok(()) }
    }

    /// The program's listens beyond loopback ([`net`]).
    /// A hook is not a policy point: it runs in the program's address space after lockdown, and
    /// a compromised program can skip it. Policy belongs at the far end of the held fds.
    pub fn on_listen(&mut self, hook: OnListen) {
        self.hooks.on_listen = hook;
    }

    /// The program's name lookups ([`net`]); like every hook, not a policy point. Without one, but
    /// with an `on_connect`, every name resolves to an address of its own (see [`Cx::name_of`]).
    pub fn on_resolve(&mut self, hook: OnResolve) -> Result<(), Error> {
        let first = !self.hooks.resolves();
        self.hooks.on_resolve = hook;
        if first { self.resolves() } else { Ok(()) }
    }

    /// A task started on the hooks' executor at lockdown, before the program: a provider's
    /// session over a held fd ([`Cx::held`]), ready before the first connect.
    pub fn on_start<F, Fut>(&mut self, f: F)
    where
        F: FnOnce(Cx) -> Fut + 'static,
        Fut: std::future::Future<Output = ()> + 'static,
    {
        self.hooks.on_start = Some(Box::new(move |cx| Box::pin(f(cx))));
    }

    /// Run `f` on this thread with its syscalls routed to the guest: every syscall `f` makes is
    /// served by the guest kernel, as its init (PID 1, root), and once it returns the thread's
    /// syscalls are the host's again. Syscall user dispatch does the routing, for this thread
    /// only, switched by a selector byte (no syscall). Before lockdown: trusted setup, ordinary
    /// Rust. Anything the guest kernel can do, `f` can: mounts, files, ids (`setresuid`: the
    /// program runs with init's credentials as they are then), the hostname, the clock
    /// (`clock_settime`; the program gets EPERM for both, as an unprivileged user would). Any
    /// number of times, interleaved with host work.
    ///
    /// What runs where meanwhile:
    /// - **Only this thread.** Other host threads are the host's (and must be gone by lockdown).
    /// - **Memory stays the host's.** `mmap`, `munmap`, `mremap`, `mprotect`, `madvise`, `brk`
    ///   and friends go to the host, so the allocator works as ever: what is allocated inside is
    ///   ordinary host memory, valid after it.
    /// - **Everything else is the guest's**: files, fds, sockets, `getpid` (1), `getrandom` (the
    ///   guest's RNG). An fd opened inside is a guest fd: don't keep it for after (there it would
    ///   name some host fd), and don't use a host fd inside. The guest's fds 0-2 write and read the
    ///   host's 0-2, so printing works. Host data is read before and moved in (a `Vec`, a string):
    ///   a host path means nothing inside.
    /// - **std's lazy state** that makes no syscall (environment, thread-locals, the stdout
    ///   buffer) is unaffected. State that caches an fd or a syscall's answer on first use would
    ///   cache the guest's: first use it outside.
    /// - **No threads**: a `clone` inside fails with ENOSYS. No host signal handlers: a handler's
    ///   return (libc's restorer) would be the guest's `rt_sigreturn`.
    /// - **A panic** unwinds as usual, the routing ended on its way.
    ///
    /// Exec is not here: the loader runs after lockdown ([`Locked::exec`]), and refuses before.
    pub fn run<R>(&mut self, f: impl FnOnce() -> R) -> Result<R, Error> {
        self.own()?;
        guest::setup_begin()?;
        let _end = SetupEnd;
        Ok(f())
    }

    /// A host fork of the guest's process, before lockdown: a template's instance. The child is a
    /// guest of its own, a copy of this one as it is now (its kernel, its mounts and files, what
    /// it has mapped, passed and held), to set up further and lock down; the parent goes on, a
    /// template for more. The child's guest RNG is reseeded with fresh host entropy at its first
    /// use. Threaded mode's threads and CPU tokens are made at lockdown, so each child makes its
    /// own. The child's status, once it runs, is its program's. Usable in a loop (a long-lived
    /// template forking per request); outside [`Guest::run`]. The parent waits for its children
    /// itself ([`wait`], or `waitpid`).
    ///
    /// Fork mode: not yet (its processes share the guest kernel's memory, which each instance
    /// needs a copy of).
    pub fn fork(&mut self) -> Result<Fork, Error> {
        // The template isn't locked down: memory it shares with a child would be the child's to
        // write (fork mode's shared kernel memory).
        if self.shared {
            return Err(Error::NotImplemented("a fork-mode template: its kernel's shared memory needs a copy per child"));
        }
        self.own()?;
        // SAFETY: fork; the child is single-threaded and takes the guest over before using it.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(Error::io("fork")(std::io::Error::last_os_error()));
        }
        if pid == 0 {
            self.own()?;
            return Ok(Fork::Child);
        }
        Ok(Fork::Parent(pid as u32))
    }

    /// [`Guest::fork`], the child running `f` (its setup, lockdown, then the program) and ending
    /// with its program (or, if `f` fails or panics, reporting it and exiting 125 or 101).
    /// Returns the child to the parent.
    pub fn spawn(&mut self, f: impl FnOnce(Guest) -> Result<Infallible, Error>) -> Result<Child, Error> {
        match self.fork()? {
            Fork::Parent(pid) => Ok(Child { pid }),
            Fork::Child => {
                // SAFETY: this process's copy of the guest, moved into `f`; the original is
                // never used or dropped (the process ends here).
                let g = unsafe { std::ptr::read(self) };
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(g)));
                match r {
                    Ok(Err(e)) => {
                        eprintln!("unsharek: {e}");
                        std::process::exit(125)
                    }
                    _ => std::process::exit(101),
                }
            }
        }
    }

    /// Lock the process down: the guest's own host fds made (threaded and fork mode: the CPU
    /// tokens' eventfds; fork mode: init's pidfd), the network hooks installed, then unsharek-tcb's
    /// lockdown ([`tcb::Sandbox::configure_and_lockdown`]: one thread, the fds and mappings
    /// checked, every fd not granted closed, core dumps and capabilities gone, the filter in),
    /// then threaded mode's kernel thread started (under the filter), then the hooks' `on_start`.
    /// `grants` makes the caller's grants (fds 0-2 among them: none is kept unless granted, and
    /// the guest's stdio writes the host's 1 and 2); passed and held fds are granted read and
    /// write here. On failure nothing untrusted has run, and the error is the caller's to report.
    ///
    /// The process must have no host thread but this one.
    pub fn lockdown(mut self, grants: impl FnOnce(&mut tcb::Config) -> tcb::Result<()>) -> Result<Locked, Error> {
        self.own()?;
        let others = other_threads();
        if !others.is_empty() {
            // One more look a moment later: a thread just joined (the image cache's builders)
            // is still listed while it finishes exiting. The TCB checks again, for good.
            std::thread::sleep(std::time::Duration::from_millis(5));
            let others = other_threads();
            if !others.is_empty() {
                return Err(Error::Threads(format!(
                    "the sandbox's process has {} other host thread(s) (tids {others:?}): join them before lockdown, \
                     where only the thread that booted the guest may exist",
                    others.len()
                )));
            }
        }
        // How the runtime writes the guest's host fds (a pipe's in pieces that can't block, a
        // regular file's whole): looked at now, as they are for this run (after lockdown nothing
        // may fstat them).
        let mut plumbing: Vec<RawFd> = (0..3).collect();
        plumbing.extend(&self.passed);
        plumbing.extend(&self.held);
        unsharek_rt::host::note_host_fds(&plumbing);
        let on_start = std::mem::take(&mut self.hooks).install();
        // Once the program runs, a panic is the runtime's: it ends the sandbox through the host
        // (`guest::runtime_panic`), not through the guest it was serving. Set now: setting a hook
        // allocates.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if guest::program_runs() {
                guest::runtime_panic(info);
            }
            prev(info)
        }));
        if self.mode != Mode::Coroutine {
            // The CPU tokens' eventfds (fresh fds, the kernel's numbers), the runtime switched to
            // threaded; the kernel idler starts after the filter.
            guest::enable_threaded()?;
            self.host_fds.extend(guest::token_fds());
            if self.mode == Mode::Fork {
                // SAFETY: a pidfd of this process.
                let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
                if pidfd < 0 {
                    return Err(Error::io("init's pidfd")(std::io::Error::last_os_error()));
                }
                self.host_fds.push(pidfd as RawFd);
                guest::enable_fork(self.max_procs, pidfd as i32)?;
            }
        }
        // The filter allows no host memory call: allocations are the region's from here on (the
        // TCB's own among them), and setup code that still makes one gets ENOMEM (mmap) or
        // nothing done, not the filter's verdict.
        alloc::lockdown();
        guest::host_memory(false);
        // Seccomp's trap takes over from syscall user dispatch.
        guest::sud_off()?;
        let (passed, held) = (self.passed.clone(), self.held.clone());
        let mode = self.mode;
        tcb::Sandbox::configure_and_lockdown(
            |s| {
                s.mode = mode;
                for &fd in passed.iter().chain(&held) {
                    s.grant(fd);
                }
                grants(s)
            },
            &self,
        )?;
        // Locked down: from here on, everything is the sandbox's.
        guest::locked_down();
        if self.mode != Mode::Coroutine {
            guest::start_kernel_thread()?;
        }
        if let Some(f) = on_start {
            unsharek_rt::executor::spawn(f(Cx));
        }
        Ok(Locked { aux: self.aux, _thread: PhantomData })
    }
}

/// A guest after lockdown: the program is next, [`Locked::exec`] or [`Locked::run`]. Until then
/// this thread's syscalls are served by the guest, as init's (printing an error works).
pub struct Locked {
    aux: guest::Aux,
    _thread: PhantomData<*const ()>,
}

impl std::fmt::Debug for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Locked")
    }
}

/// The guest's `execve` of `argv[0]` with `argv` and `env` (each `NAME=value`), as init with the
/// credentials setup left. Never returns on success: the process's status is the program's. After
/// lockdown only (in a [`Locked::run`] closure, or by [`Locked::exec`]); before it, the runtime's
/// loader refuses (EPERM).
pub fn execve(argv: &[OsString], env: &[OsString]) -> Error {
    let Some(path) = argv.first() else { return Error::NoProgram };
    let aux = AUX.get().copied().unwrap_or_default();
    let args: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    let envs: Vec<&[u8]> = env.iter().map(|a| a.as_bytes()).collect();
    let errno = guest::exec(path.as_bytes(), &args, &envs, aux);
    Error::Exec { path: PathBuf::from(path), errno: std::io::Error::from_raw_os_error(errno.raw_os_error()) }
}

/// The host's auxiliary vector values, for [`execve`]: set at lockdown.
static AUX: std::sync::OnceLock<guest::Aux> = std::sync::OnceLock::new();

impl Locked {
    /// Exec `argv[0]` inside the guest ([`execve`]). Never returns on success; on failure the
    /// error is the caller's to report and exit with (its syscalls are the guest's, and printing
    /// and exiting work through it).
    pub fn exec(self, argv: &[OsString], env: &[OsString]) -> Result<Infallible, Error> {
        let _ = AUX.set(self.aux);
        Err(execve(argv, env))
    }

    /// `f` run as the program: on this thread, its syscalls trapped and served by the guest kernel
    /// as an exec'd program's are (as init, with the credentials setup left), and its return
    /// value the sandbox's exit status. Never returns. Exec is [`execve`] inside it.
    ///
    /// `f` is ordinary Rust in this process, so it is the sandbox's program: what it can reach on
    /// the host is what the program's could (the filter's list), and what it captures it may use
    /// (it's moved in). Its limits: no threads (`std::thread` makes a guest thread that knows
    /// nothing of Rust's TLS: don't); its allocations come from the region reserved at boot (the
    /// global allocator after lockdown); a panic in it is the runtime's (the sandbox dies of
    /// SIGABRT); its host fds are the granted ones (any other was closed at lockdown: a `File`
    /// captured from before is a closed or a guest fd now).
    pub fn run(self, f: impl FnOnce() -> i32) -> Result<Infallible, Error> {
        let _ = AUX.set(self.aux);
        guest::run_fn(f)
    }
}

/// Which side of [`Guest::fork`] this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fork {
    /// The new process: a guest of its own, to set up, lock down and run.
    Child,
    /// The template, with the child's host pid.
    Parent(u32),
}

/// A sandbox started by [`Guest::spawn`]: a child process of the caller's.
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

/// Wait for child process `pid` (a sandbox [`Guest::fork`] made): `waitpid`.
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

/// The program's stdio granted, as the CLI does ([`run`]): fds 0-2.
/// For [`Guest::lockdown`]'s grants (`g.lockdown(unsharek::stdio)`, or called inside one's own).
pub fn stdio(s: &mut tcb::Config) -> tcb::Result<()> {
    s.grant(0).grant(1).grant(2);
    Ok(())
}

/// Become the sandbox: [`Guest::boot`] for the mode, the closure's images (and `config.images`)
/// mapped and mounted in a [`Guest::run`] closure, [`Guest::lockdown`] with the program's stdio
/// granted (fds 0-2), [`Locked::exec`]. Returns only on failure before
/// the program starts; the process ends with the program's status.
pub fn run(config: Config) -> Result<Infallible, Error> {
    let store = store(&config)?;
    let mut g = Guest::boot(GuestConfig { mode: config.mode, max_procs: config.max_procs.unwrap_or(0), ..Default::default() })?;
    let mut mounts = g.map_store(&store)?;
    for i in &config.images {
        let img = g.map_image_as(&i.path, &i.name)?;
        if let Some(at) = &i.mount {
            mounts.push(setup::Mount { image: img, at: at.clone(), kind: store::Kind::Dir });
        }
    }
    // The program's path as the host resolves it: the guest's working directory is `/`.
    let mut argv = config.argv.clone();
    argv[0] = std::path::absolute(&argv[0]).map_err(Error::io("the program's path"))?.into_os_string();
    g.run(|| setup::mount_closure(&mounts))??;
    let locked = g.lockdown(stdio)?;
    locked.exec(&argv, &config.env)
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

    /// The runtime makes its threads and waits with the shapes the TCB's filter pins (a mismatch
    /// would be a sandbox killed at its first thread, never a wider filter: this says which to
    /// fix).
    #[test]
    fn the_runtimes_shapes() {
        assert_eq!(tcb::CLONE_THREAD_FLAGS, unsharek_rt::trap::CLONE_HOST_THREAD);
        assert_eq!(tcb::PPOLL_FDS, unsharek_rt::trap::PPOLL_FDS);
    }
}
