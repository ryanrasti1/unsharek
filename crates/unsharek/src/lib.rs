//! unsharek: run an unmodified Linux program on an in-process Linux kernel (LKL), behind a seccomp
//! filter that leaves the host a handful of syscalls.
//!
//! ```no_run
//! # fn main() -> Result<(), unsharek::Error> {
//! # let (closure, argv, env): (Vec<std::path::PathBuf>, Vec<std::ffi::OsString>, Vec<std::ffi::OsString>) = Default::default();
//! use unsharek::{Guest, GuestConfig, Mode};
//! let mut g = Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() })?; // the kernel
//! g.mount_closure(&closure)?;                          // store paths: mapped, and mounted in the guest
//! g.run(|| std::fs::write("/etc/motd", "hi\n"))??;    // this thread's syscalls are the guest's, as init
//! let c = unsharek::SandboxConfig::new()
//!     .grant([0, 1, 2])                                // kept: none but these, and the guest's
//!     .pipe(|c| g.configure_sandbox(c))?;              // the guest's part, setup's last step
//! unsharek::lockdown(c)?;                              // unsharek-tcb's lockdown, as it is
//! let e = g.run(|| unsharek::execve(&argv, &env))?; // the program; the process ends with it
//! # Err(e) }
//! ```
//!
//! **Where isolation is.** Not in this crate: in `unsharek-tcb` (`crates/unsharek-tcb/` at the repository's root,
//! re-exported as [`tcb`], its [`lockdown`] as this crate's). Its lockdown checks the process (one
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
pub mod provider;
pub mod pty;
pub mod setup;
pub mod store;

pub use unsharek_tcb as tcb;
/// Lockdown, unsharek-tcb's own: re-exported, not wrapped. It uses its config and nothing else; the
/// guest's part of it is [`Guest::configure_sandbox`]'s.
pub use unsharek_tcb::{Config as SandboxConfig, lockdown};
pub use image::Image;
pub use net::{Cx, GuestSocket, HeldFd, NetError, OnConnect, OnListen, Proto};
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

use unsharek_rt::{guest, sched};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid image name {0:?}")]
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
    /// The program's path is in nothing the guest is shown ([`run_with`]).
    #[error("{}: the program isn't in the sandbox: add --closure <its store path> or --system", .0.display())]
    ProgramNotInSandbox(PathBuf),
    /// Other host threads at lockdown (the guest's check, before the TCB's own).
    #[error("{0}")]
    Threads(String),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
    /// A [`Guest::run`] after [`Guest::configure_sandbox`] but without a lockdown (not yet made,
    /// or failed): setup is over (the routing is off), and the program runs only once locked down.
    #[error("setup is over (configure_sandbox ran) but the process isn't locked down: lock down, then run the program")]
    NotLockedDown,
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
/// order ([`Guest::mount_closure`], [`Guest::pass_fd`], [`Guest::run`]), then [`lockdown`], then
/// the program ([`Guest::run`] again). `!Send`: the thread that booted it is the one that uses it.
pub struct Guest {
    /// The image zone's unused part, `[next, end)`.
    zone: (usize, usize),
    /// Fork mode's kernel memory is mapped shared (no template may fork it).
    shared: bool,
    /// The guest's state for lockdown and after it.
    link: &'static Link,
    _thread: PhantomData<*const ()>,
}

impl std::fmt::Debug for Guest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.link.st.borrow();
        f.debug_struct("Guest").field("mode", &self.link.mode).field("passed", &st.passed).field("held", &st.held).finish_non_exhaustive()
    }
}

/// The guest's state around lockdown: one per process, made at boot, leaked (it lives as long as
/// the process: the program's run reads it after lockdown).
struct Link {
    mode: Mode,
    max_procs: u32,
    st: std::cell::RefCell<LinkState>,
}

#[derive(Default)]
struct LinkState {
    /// Passed and held host fds: the guest's plumbing, granted at lockdown.
    passed: Vec<RawFd>,
    held: Vec<RawFd>,
    /// The guest's own host fds, made at lockdown (the CPU tokens' eventfds, init's pidfd), for
    /// the TCB to check and keep ([`tcb::Config::guest_fds`]).
    host_fds: Vec<RawFd>,
    hooks: net::Hooks,
    /// The hooks' first task, spawned when the program starts.
    on_start: Option<net::StartFn>,
    /// [`Guest::configure_sandbox`] ran: setup is over, whether lockdown then succeeded or not.
    prepared: bool,
    /// The post-lockdown steps ran ([`Link::start`]).
    started: bool,
}

impl Link {
    /// Before lockdown's checks: the guest's own host fds made (threaded and fork mode: the CPU
    /// tokens' eventfds; fork mode: init's pidfd), the network hooks installed, the allocator and
    /// the runtime switched to the sandbox's (no host memory calls, the trap instead of syscall
    /// user dispatch). Setup is over from here, whatever lockdown says next.
    fn prepare(&self) -> Result<(), Error> {
        let mut st = self.st.borrow_mut();
        st.prepared = true;
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
        plumbing.extend(&st.passed);
        plumbing.extend(&st.held);
        unsharek_rt::host::note_host_fds(&plumbing);
        st.on_start = std::mem::take(&mut st.hooks).install();
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
            st.host_fds.extend(guest::token_fds());
            if self.mode == Mode::Fork {
                // SAFETY: a pidfd of this process.
                let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
                if pidfd < 0 {
                    return Err(Error::io("init's pidfd")(std::io::Error::last_os_error()));
                }
                st.host_fds.push(pidfd as RawFd);
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
        Ok(())
    }

    /// After lockdown, before the program: threaded mode's kernel thread started (under the
    /// filter), the hooks' first task spawned. Once.
    fn start(&self) -> Result<(), Error> {
        let mut st = self.st.borrow_mut();
        if st.started {
            return Ok(());
        }
        st.started = true;
        // Locked down: from here on, everything is the sandbox's.
        guest::locked_down();
        if self.mode != Mode::Coroutine {
            guest::start_kernel_thread()?;
        }
        if let Some(f) = st.on_start.take() {
            unsharek_rt::executor::spawn(f(Cx));
        }
        Ok(())
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
/// The guest's resolv.conf from the host's: its `nameserver`, `search`, `domain` and `options`
/// lines, the rest (comments) left out. Empty: no nameserver (glibc then asks 127.0.0.1, the
/// guest's own loopback, where nothing answers).
fn host_resolv(conf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in conf.split(|&b| b == b'\n') {
        let word = line.split(|b| b.is_ascii_whitespace()).next().unwrap_or_default();
        if [&b"nameserver"[..], b"search", b"domain", b"options"].contains(&word) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    out
}

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
        let _ = AUX.set(guest::Aux {
            hwcap: aux(libc::AT_HWCAP),
            hwcap2: aux(libc::AT_HWCAP2),
            sysinfo_ehdr: aux(libc::AT_SYSINFO_EHDR),
            minsigstksz: aux(libc::AT_MINSIGSTKSZ),
        });
        let link: &'static Link =
            Box::leak(Box::new(Link { mode: config.mode, max_procs: config.max_procs, st: Default::default() }));
        Ok(Guest { zone: (arena + memory, arena + memory + zone), shared, link, _thread: PhantomData })
    }

    /// Its mode.
    pub fn mode(&self) -> Mode {
        self.link.mode
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

    /// The closures of `paths` (each a store path, or a path inside one, with everything it
    /// references) shown to the guest, read-only, each at its own path: images from the default
    /// cache ([`store::Cache::open_default`], built where missing), mapped (host work) and mounted
    /// (the guest's, as [`Guest::run`] would). Before lockdown. The program's code maps in place
    /// from them.
    pub fn mount_closure(&mut self, paths: &[impl AsRef<Path>]) -> Result<(), Error> {
        let paths: Vec<PathBuf> = paths.iter().map(|p| p.as_ref().to_owned()).collect();
        let store = store::Cache::open_default()?.closures(&paths)?;
        let mounts = self.map_store(&store)?;
        self.run(|| setup::mount_closure(&mounts))??;
        Ok(())
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
    /// fd). `fd` stays open for the sandbox's life; [`lockdown`] grants it read and write.
    /// Host code; fails if `fd` isn't open.
    pub fn pass_fd(&mut self, fd: OwnedFd, guest: i32) -> Result<(), Error> {
        self.own()?;
        let host = Guest::keep(fd, "passing an fd")?;
        self.link.st.borrow_mut().passed.push(host);
        setup::host_fd(host, guest).map_err(Error::io(format!("the guest's fd {guest}")))
    }

    /// Hold host fd `fd` for the hooks (a provider's connection, made before lockdown): made
    /// nonblocking and kept open for the sandbox's life; [`lockdown`] grants it read and write.
    pub fn hold_fd(&mut self, fd: OwnedFd) -> Result<HeldFd, Error> {
        // SAFETY: fcntl on the caller's fd, owned.
        let fl = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above.
        if fl < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(Error::io("holding an fd")(std::io::Error::last_os_error()));
        }
        let fd = Guest::keep(fd, "holding an fd")?;
        self.link.st.borrow_mut().held.push(fd);
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
    /// the program first has a network (an `on_connect`): the host's resolv.conf (its
    /// nameservers, asked through the hook like any UDP peer), read here, on the host. A setup may
    /// change them after.
    fn resolves(&mut self) -> Result<(), Error> {
        let conf = std::fs::read("/etc/resolv.conf").unwrap_or_default();
        setup::resolver(&host_resolv(&conf)).map_err(Error::io("the guest's resolver"))
    }

    /// The program's connects beyond loopback ([`net`]).
    /// A hook is not a policy point: it runs in the program's address space after lockdown, and
    /// a compromised program can skip it. Policy belongs at the far end of the held fds.
    pub fn on_connect(&mut self, hook: OnConnect) -> Result<(), Error> {
        let first = !self.link.st.borrow().hooks.connects();
        self.link.st.borrow_mut().hooks.on_connect = hook;
        if first && self.link.st.borrow().hooks.connects() { self.resolves() } else { Ok(()) }
    }

    /// The program's listens beyond loopback ([`net`]).
    /// A hook is not a policy point: it runs in the program's address space after lockdown, and
    /// a compromised program can skip it. Policy belongs at the far end of the held fds.
    pub fn on_listen(&mut self, hook: OnListen) {
        self.link.st.borrow_mut().hooks.on_listen = hook;
    }

    /// A task started on the hooks' executor at lockdown, before the program: a provider's
    /// session over a held fd ([`Cx::held`]), ready before the first connect.
    pub fn on_start<F, Fut>(&mut self, f: F)
    where
        F: FnOnce(Cx) -> Fut + 'static,
        Fut: std::future::Future<Output = ()> + 'static,
    {
        self.link.st.borrow_mut().hooks.on_start = Some(Box::new(move |cx| Box::pin(f(cx))));
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
    /// Exec ([`execve`]) is refused here (the runtime's loader runs after lockdown only).
    ///
    /// **After [`lockdown`], `f` is the program** and the process ends with it: on this thread,
    /// its syscalls trapped and served by the guest kernel as an exec'd program's are (as init,
    /// with the credentials setup left), its status `f`'s return value if that is an `i32` (an
    /// [`Error`]: reported, and 127 for an exec's, 125 for others; anything else: 0). Exec is
    /// [`execve`] inside it. A runtime check (the TCB's [`tcb::locked_down`]), not a type: the
    /// lockdown is the TCB's, which knows no guest type. `f` is ordinary Rust in this process, so
    /// it is the sandbox's program: what it can reach on the host is what the program's could
    /// (the filter's list), and what it captures it may use (it's moved in). Its limits: no
    /// threads (`std::thread` makes a guest thread that knows nothing of Rust's TLS: don't); its
    /// allocations come from the region reserved at boot (the global allocator after lockdown); a
    /// panic in it is the runtime's (the sandbox dies of SIGABRT); its host fds are the granted
    /// ones (any other was closed at lockdown: a `File` captured from before is a closed or a
    /// guest fd now). After [`Guest::configure_sandbox`] without a lockdown: [`Error::NotLockedDown`].
    pub fn run<R: 'static>(&mut self, f: impl FnOnce() -> R) -> Result<R, Error> {
        // After `configure_sandbox` (setup's last step) a setup run would hang on the routing it
        // turned off: an error instead, below.
        if tcb::locked_down() {
            self.link.start()?;
            guest::run_fn(move || status(f()));
        }
        if self.link.st.borrow().prepared {
            return Err(Error::NotLockedDown);
        }
        self.own()?;
        guest::setup_begin()?;
        let _end = SetupEnd;
        Ok(f())
    }

    /// The guest's part of the sandbox's config, and setup's last step: the guest's own host fds
    /// made (threaded and fork mode: the CPU tokens' eventfds; fork mode: init's pidfd), the
    /// network hooks installed, the allocator and the runtime switched to the sandbox's (no host
    /// memory calls, the trap instead of syscall user dispatch); then `c` given the mode, those
    /// fds ([`tcb::Config::guest_fds`]), the gate ([`tcb::Config::gate`]) and the passed and held
    /// fds as grants. Untrusted code before lockdown, as all of this crate is: lockdown checks what
    /// it leaves behind. After it no setup [`Guest::run`] works ([`Error::NotLockedDown`]): call
    /// [`lockdown`] next.
    pub fn configure_sandbox(&mut self, c: SandboxConfig) -> Result<SandboxConfig, Error> {
        self.own()?;
        self.link.prepare()?;
        let st = self.link.st.borrow();
        Ok(c.mode(self.link.mode)
            .guest_fds(st.host_fds.iter().copied())
            .gate(unsharek_rt::trap::gate_ip())
            .grant(st.passed.iter().chain(&st.held).copied()))
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
}

/// The guest's `execve` of `argv[0]` with `argv` and `env` (each `NAME=value`), as init with the
/// credentials setup left. Never returns on success: the process's status is the program's. After
/// lockdown only (in a [`Guest::run`] closure); before it, the runtime's loader refuses (EPERM).
pub fn execve(argv: &[OsString], env: &[OsString]) -> Error {
    let Some(path) = argv.first() else { return Error::NoProgram };
    let aux = AUX.get().copied().unwrap_or_default();
    let args: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    let envs: Vec<&[u8]> = env.iter().map(|a| a.as_bytes()).collect();
    let errno = guest::exec(path.as_bytes(), &args, &envs, aux);
    Error::Exec { path: PathBuf::from(path), errno: std::io::Error::from_raw_os_error(errno.raw_os_error()) }
}

/// The host's auxiliary vector values, for [`execve`]: set at boot.
static AUX: std::sync::OnceLock<guest::Aux> = std::sync::OnceLock::new();

/// A program closure's return value as its exit status ([`Guest::run`] after lockdown).
fn status<R: 'static>(r: R) -> i32 {
    let r: Box<dyn std::any::Any> = Box::new(r);
    if let Some(code) = r.downcast_ref::<i32>() {
        return *code;
    }
    let Ok(e) = r.downcast::<Error>() else { return 0 };
    eprintln!("unsharek: {e}");
    if matches!(*e, Error::Exec { .. }) { 127 } else { 125 }
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

/// Everything a sandbox needs to start.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub mode: Mode,
    /// What the guest is shown of the store, read-only (the CLI's `--closure`): a store path (or a
    /// path in one) brings its closure; a host directory, the closures of the store paths its
    /// files reference (the directory itself is `host_dirs`' to show). Nothing implicit: not even
    /// the program's own.
    pub closures: Vec<PathBuf>,
    /// Fork mode: the most processes alive at once, the first one included.
    pub max_procs: Option<u32>,
    /// The program and its arguments; `argv[0]` is the program's path.
    pub argv: Vec<OsString>,
    /// The program's environment, `NAME=value` each.
    pub env: Vec<OsString>,
    /// Where store images are cached; None: [`store::Cache::default_dir`].
    pub image_cache: Option<PathBuf>,
    /// Host directories served live, through virtio-fs ([`hostfs`]): each a server's socket (the
    /// CLI's `--ro` and `--rw`, `unsharek-fs-server`), mounted at its guest path.
    pub host_dirs: Vec<HostDir>,
    /// Fork mode: the program on a terminal of the guest's own, of this size ([`pty`]), for a
    /// caller whose stdin is a terminal; `None`: the host's stdio as it is.
    pub tty: Option<pty::Size>,
}

/// A host directory served to the guest by a server on the other end of `fd` (a unix stream:
/// unsharek-fs's `wire`), mounted at `at`. The fd is the caller's, open until the program ends
/// (the caller grants it: [`run_with`]'s `grants`).
#[derive(Clone, Debug)]
pub struct HostDir {
    pub fd: RawFd,
    pub at: PathBuf,
}

/// The images the guest mounts for `config`'s closures, built where the cache lacks them (the
/// closure too is cached there: [`store::Cache::closure`]). Host-side, before lockdown; nothing
/// is opened or mapped yet.
pub fn store(config: &Config) -> Result<store::Store, Error> {
    let cache = match &config.image_cache {
        Some(dir) => store::Cache::new(dir),
        None => store::Cache::open_default()?,
    };
    Ok(cache.store_refs(&config.closures)?)
}

/// Become the sandbox: [`Guest::boot`] for the mode, the closures' images mapped and mounted in a
/// [`Guest::run`] closure, [`lockdown`] with the program's stdio granted
/// (fds 0-2), the program [`execve`]d in [`Guest::run`]. Returns only on failure before the
/// program starts; the process ends with the program's status.
pub fn run(config: Config) -> Result<Infallible, Error> {
    run_with(config, |_| Ok(()), |c| c)
}

/// [`run`], with the caller's two additions: `prepare`, on the booted guest before setup (hooks,
/// held fds: a plugin's), and `grants`, on the sandbox's config after stdio's (the fds `config`'s
/// host directories use, a plugin's control socket). Nothing here knows a plugin.
pub fn run_with(
    config: Config,
    prepare: impl FnOnce(&mut Guest) -> Result<(), Error>,
    grants: impl FnOnce(SandboxConfig) -> SandboxConfig,
) -> Result<Infallible, Error> {
    let store = store(&config)?;
    let mut g = Guest::boot(GuestConfig { mode: config.mode, max_procs: config.max_procs.unwrap_or(0), ..Default::default() })?;
    let mounts = g.map_store(&store)?;
    // The program's path as the host resolves it: the guest's working directory is `/`.
    let mut argv = config.argv.clone();
    let program = std::path::absolute(argv.first().ok_or(Error::NoProgram)?).map_err(Error::io("the program's path"))?;
    // Nothing is shown implicitly: the program must be in a closure or a host directory given.
    let shown = store.mounts.iter().map(|m| &m.guest).chain(config.host_dirs.iter().map(|d| &d.at));
    if !shown.into_iter().any(|at| program.starts_with(at)) {
        return Err(Error::ProgramNotInSandbox(program));
    }
    argv[0] = program.into_os_string();
    for (i, d) in config.host_dirs.iter().enumerate() {
        hostfs::add(&format!("host{i}"), d.fd).map_err(Error::io("a host directory's device"))?;
    }
    prepare(&mut g)?;
    let dirs: Vec<PathBuf> = config.host_dirs.iter().map(|d| d.at.clone()).collect();
    // Fork mode on a terminal: the program on a pty of the guest's, under its init (`pty`).
    let tty = config.tty.filter(|_| config.mode == Mode::Fork);
    if let Some(size) = tty {
        argv = pty::argv(&argv, size);
    }
    g.run(|| -> std::io::Result<()> {
        setup::mount_closure(&mounts)?;
        for (i, at) in dirs.iter().enumerate() {
            hostfs::mount(&format!("host{i}"), at)?;
        }
        if tty.is_some() {
            pty::install()?;
        }
        Ok(())
    })??;
    let c = grants(SandboxConfig::new().grant([0, 1, 2])).pipe(|c| g.configure_sandbox(c))?;
    lockdown(c)?;
    let env = config.env;
    // After lockdown the closure is the program: this returns only if the run itself failed.
    match g.run(move || execve(&argv, &env)) {
        Ok(e) | Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime makes its threads and waits with the shapes the TCB's filter pins (a mismatch
    /// would be a sandbox killed at its first thread, never a wider filter: this says which to
    /// fix).
    #[test]
    fn the_runtimes_shapes() {
        assert_eq!(tcb::CLONE_THREAD_FLAGS, unsharek_rt::trap::CLONE_HOST_THREAD);
        assert_eq!(tcb::PPOLL_FDS, unsharek_rt::trap::PPOLL_FDS);
    }
}
