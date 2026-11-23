//! A host directory served to the virtio-fs device in this process: each FUSE request answered
//! with the plain file calls unsharek-tcb's fs plugin allows (`openat`, `fstat`, `pread64`,
//! `getdents64`, `readlinkat`; read-write also `pwrite64`, `ftruncate`, `fsync`, `mkdirat`,
//! `unlinkat`, `renameat2`, `symlinkat`, `fchmodat`, `utimensat`; `close`), each through the
//! runtime's gate ([`Sys::call`]). Not trusted: Landlock confines the paths (unsharek-tcb's
//! `plugin::Files`), the filter the calls; a bug here can only make one of those refuse.
//!
//! **By path.** A node (the guest's inode) is a name under its parent, so its host file is a path
//! from the root: every call is on that absolute path (its directory fd is
//! [`ABS_DIRFD`], at or above the filter's floor and never open, which an absolute path ignores),
//! or on an fd opened from it. Nothing is held across requests that another process would need:
//! fork mode's processes share the kernel, and so its open files, but not the host's fd tables.
//! So the nodes are in memory the caller maps for the root ([`root`]: shared in fork mode, by
//! every process, touched with the CPU held), and the fds are only each process's cache of them
//! ([`Cache`]): a miss opens the path again. A file renamed on the host behind the guest's back is not found again by its old
//! name; one unlinked while the guest has it open is gone for it too (the price of keeping no fd
//! the other processes can't use).
//!
//! **What isn't served.** Devices and FIFOs are looked up but never opened for I/O (every open is
//! `O_NONBLOCK`, so a FIFO's or a device's open never waits; an `OPEN` of one is refused). No
//! hard links, no `mknod`, no owners changed, no xattrs, no locks (the guest's own),
//! no `fallocate`. A symlink's attributes are made up but for its size: `fstat` needs an open
//! file, and `O_PATH` (which opens a symlink itself) is no row of the filter's.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

/// What the passthrough needs of its host (the runtime), which this crate doesn't know.
pub struct Sys {
    /// A host call through the gate, raw: `-errno` on failure.
    pub call: fn(nr: u32, a: [usize; 6]) -> isize,
}

static SYS: AtomicPtr<Sys> = AtomicPtr::new(core::ptr::null_mut());

/// Use `sys` for the host calls. Before the first [`root`].
pub fn install(sys: &'static Sys) {
    SYS.store(sys as *const Sys as *mut Sys, Ordering::Release);
}

fn sys() -> &'static Sys {
    // SAFETY: a &'static Sys, set before any device exists.
    unsafe { SYS.load(Ordering::Acquire).as_ref().expect("passthrough::install first") }
}

// x86-64's numbers (arch/x86/entry/syscalls/syscall_64.tbl).
const NR_CLOSE: u32 = 3;
const NR_FSTAT: u32 = 5;
const NR_PREAD64: u32 = 17;
const NR_PWRITE64: u32 = 18;
const NR_FSYNC: u32 = 74;
const NR_FTRUNCATE: u32 = 77;
const NR_GETDENTS64: u32 = 217;
const NR_OPENAT: u32 = 257;
const NR_MKDIRAT: u32 = 258;
const NR_UNLINKAT: u32 = 263;
const NR_SYMLINKAT: u32 = 266;
const NR_READLINKAT: u32 = 267;
const NR_FCHMODAT: u32 = 268;
const NR_UTIMENSAT: u32 = 280;
const NR_RENAMEAT2: u32 = 316;

const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_ACCMODE: u32 = 3;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const O_TRUNC: usize = 0o1000;
const O_NONBLOCK: usize = 0o4000;
const O_DIRECTORY: usize = 0o200000;
const O_NOFOLLOW: usize = 0o400000;
const O_CLOEXEC: usize = 0o2000000;
/// Every open's: never waits (a FIFO's, a device's), never inherited.
const O_NB: usize = O_NONBLOCK | O_CLOEXEC;
const AT_REMOVEDIR: usize = 0x200;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
/// A mode the filter takes: no set-id bits.
const MODE_MAX: u32 = 0o1777;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;
const EROFS: i32 = 30;
const ENAMETOOLONG: i32 = 36;
const ENOSYS: i32 = 38;
const ELOOP: i32 = 40;
const EOPNOTSUPP: i32 = 95;

/// The directory fd of a path call (see the module's comment).
pub const ABS_DIRFD: usize = i32::MAX as usize;

fn call(nr: u32, a: [usize; 6]) -> Result<usize, i32> {
    let r = (sys().call)(nr, a);
    if r < 0 { Err(-r as i32) } else { Ok(r as usize) }
}

fn close(fd: i32) {
    let _ = call(NR_CLOSE, [fd as usize, 0, 0, 0, 0, 0]);
}

// ---- the nodes (shared) ----

/// The most nodes a root has at once (the guest's inodes of it; FORGET frees them).
const NODES: usize = 1 << 14;
const BUCKETS: usize = 1 << 12;
const PATH_MAX: usize = 4096;
const ROOT: u64 = 1;

/// A node: a name under its parent (the root has none).
#[derive(Clone, Copy)]
#[repr(C)]
struct Node {
    used: bool,
    /// Unlinked or renamed over: no longer found by name, alive until forgotten.
    detached: bool,
    name_len: u8,
    parent: u32,
    /// The hash chain of (parent, name): the next node's index, 0 for none.
    next: u32,
    /// Bumped each time the slot is reused: the fd caches' check.
    generation: u32,
    lookups: u64,
    name: [u8; 255],
}

/// A root's state, in its memory ([`root`]). All zeroes is empty.
#[repr(C)]
struct Root {
    writable: bool,
    path_len: usize,
    path: [u8; PATH_MAX],
    buckets: [u32; BUCKETS],
    /// Where the next free slot is looked for from.
    hint: usize,
    /// Node i, if used. 0 is unused, 1 the root.
    nodes: [Node; NODES],
}

/// The memory a root needs ([`root`]'s `mem`): zeroed, readable and writable, the same address
/// in every process that serves it (in fork mode, mapped shared before the first fork). Its
/// untouched pages cost nothing (it is mostly the node table).
pub const ROOT_SIZE: usize = core::mem::size_of::<Root>();

/// A host directory for the device, its state in `mem` ([`ROOT_SIZE`] bytes, as said there):
/// [`crate::add`]'s `state`. `path` absolute and canonical; `writable`: the read-write calls
/// (unsharek-tcb's fs-rw rows: without them a mutating request is EROFS here, never a call the
/// filter would kill). Host code, before the first fork, after [`install`].
///
/// # Safety
/// `mem` is as [`ROOT_SIZE`] says, and the root's alone for the process's life.
pub unsafe fn root(mem: *mut u8, path: &[u8], writable: bool) -> Option<usize> {
    if path.is_empty() || path.len() >= PATH_MAX || path[0] != b'/' {
        return None;
    }
    // SAFETY: the caller's: zeroed memory of Root's size (all zeroes is a valid Root).
    let r = unsafe { &mut *(mem as *mut Root) };
    r.writable = writable;
    r.path[..path.len()].copy_from_slice(path);
    // "/" itself: its children's paths shouldn't start "//".
    r.path_len = if path == b"/" { 0 } else { path.len() };
    r.hint = 2;
    r.nodes[ROOT as usize] = Node { used: true, lookups: 1, ..r.nodes[0] };
    Some(mem as usize)
}

fn name_of(n: &Node) -> &[u8] {
    &n.name[..n.name_len as usize]
}

fn hash(parent: u32, name: &[u8]) -> usize {
    let mut h: u32 = 2166136261 ^ parent;
    for &b in name {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    h as usize % BUCKETS
}

impl Root {
    fn node(&mut self, id: u64) -> Option<&mut Node> {
        self.nodes.get_mut(id as usize).filter(|n| n.used)
    }

    fn find(&mut self, parent: u32, name: &[u8]) -> Option<u32> {
        let mut i = self.buckets[hash(parent, name)];
        while i != 0 {
            let n = self.node(i as u64)?;
            if n.parent == parent && name_of(n) == name && !n.detached {
                return Some(i);
            }
            i = n.next;
        }
        None
    }

    /// The node for (parent, name), made if new, its lookup counted.
    fn lookup(&mut self, parent: u32, name: &[u8]) -> Result<u32, i32> {
        if let Some(i) = self.find(parent, name) {
            self.node(i as u64).ok_or(EIO)?.lookups += 1;
            return Ok(i);
        }
        if name.len() > 255 {
            return Err(ENAMETOOLONG);
        }
        let slot = (0..NODES - 2).map(|k| 2 + (self.hint - 2 + k) % (NODES - 2)).find(|&i| !self.nodes[i].used).ok_or(ENOMEM)?;
        let b = hash(parent, name);
        let n = &mut self.nodes[slot];
        let generation = n.generation.wrapping_add(1);
        *n = Node { used: true, detached: false, name_len: name.len() as u8, parent, next: self.buckets[b], generation, lookups: 1, name: [0; 255] };
        n.name[..name.len()].copy_from_slice(name);
        self.buckets[b] = slot as u32;
        self.hint = slot + 1;
        Ok(slot as u32)
    }

    fn unlink_chain(&mut self, id: u32) {
        let Some(n) = self.node(id as u64) else { return };
        let (b, next) = (hash(n.parent, name_of(n)), n.next);
        if self.buckets[b] == id {
            self.buckets[b] = next;
            return;
        }
        let mut i = self.buckets[b];
        while i != 0 {
            let Some(m) = self.node(i as u64) else { return };
            if m.next == id {
                m.next = next;
                return;
            }
            i = m.next;
        }
    }

    /// No longer found by its name (unlinked, or renamed over); freed once forgotten.
    fn detach(&mut self, id: u32) {
        if self.node(id as u64).is_some_and(|n| !n.detached) {
            self.unlink_chain(id);
            if let Some(n) = self.node(id as u64) {
                n.detached = true;
            }
        }
    }

    /// Node `id` renamed to (parent, name): the guest keeps its inode across a rename, so the node
    /// follows it (its fds stay valid: the file is the same).
    fn rename(&mut self, id: u32, parent: u32, name: &[u8]) {
        self.detach(id);
        let b = hash(parent, name);
        let head = self.buckets[b];
        let Some(n) = self.node(id as u64) else { return };
        n.detached = false;
        n.parent = parent;
        n.name_len = name.len() as u8;
        n.name[..name.len()].copy_from_slice(name);
        n.next = head;
        self.buckets[b] = id;
    }

    fn forget(&mut self, id: u64, k: u64) {
        if id == ROOT {
            return;
        }
        let Some(n) = self.node(id) else { return };
        n.lookups = n.lookups.saturating_sub(k);
        if n.lookups > 0 {
            return;
        }
        self.detach(id as u32);
        self.nodes[id as usize].used = false;
        Cache::get().drop_node(self as *const Root as usize, id as u32);
    }

    /// Node `id`'s path (and `child`'s under it), NUL-terminated, into `buf`: its length.
    fn path(&mut self, id: u64, child: Option<&[u8]>, buf: &mut [u8; PATH_MAX + 1]) -> Result<usize, i32> {
        // Components from the leaf up, written from the end of the buffer.
        let mut end = PATH_MAX;
        let mut push = |name: &[u8], end: &mut usize| -> Result<(), i32> {
            if name.len() + 1 > *end {
                return Err(ENAMETOOLONG);
            }
            *end -= name.len();
            buf[*end..*end + name.len()].copy_from_slice(name);
            *end -= 1;
            buf[*end] = b'/';
            Ok(())
        };
        if let Some(c) = child {
            push(c, &mut end)?;
        }
        let mut i = id;
        let mut depth = 0;
        while i != ROOT {
            let n = self.node(i).ok_or(ENOENT)?;
            let (parent, len) = (n.parent, n.name_len as usize);
            let name = n.name;
            push(&name[..len], &mut end)?;
            i = parent as u64;
            depth += 1;
            if depth > PATH_MAX {
                return Err(ELOOP);
            }
        }
        let tail = PATH_MAX - end;
        let len = self.path_len + tail;
        if len + 1 > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        buf.copy_within(end..PATH_MAX, self.path_len);
        buf[..self.path_len].copy_from_slice(&self.path[..self.path_len]);
        if len == 0 {
            buf[0] = b'/';
            buf[1] = 0;
            return Ok(1);
        }
        buf[len] = 0;
        Ok(len)
    }

    fn generation(&mut self, id: u64) -> u32 {
        self.node(id).map_or(0, |n| n.generation)
    }
}

// ---- each process's fds (private) ----

/// An open fd's kind, in the cache: reads (and `fstat`, `getdents64`), or writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy)]
struct Entry {
    root: usize,
    node: u32,
    generation: u32,
    access: Access,
    fd: i32,
    used: u64,
}

/// A directory read in progress: where the next `READDIR` offset would start, the entries the
/// last `getdents64` gave (in its slot's [`dir_buf`]) and how far into them it got.
struct Dir {
    root: usize,
    node: u32,
    generation: u32,
    fd: i32,
    /// The index of the entry at `pos`.
    index: u64,
    pos: usize,
    len: usize,
}

const CACHE: usize = 64;
const DIRS: usize = 4;
const DIR_BUF: usize = 16 << 10;

/// This process's open fds of the nodes: a cache of at most [`CACHE`] (the least recently used
/// closed for a new one), and the directories being read. A fork copies it, fds included: the
/// child's copy is as valid as the parent's.
struct Cache {
    entries: [Option<Entry>; CACHE],
    dirs: [Option<Dir>; DIRS],
    tick: u64,
}

struct CacheCell(UnsafeCell<Cache>);
// SAFETY: touched only within a request, which the guest's one CPU serializes (device.rs).
unsafe impl Sync for CacheCell {}
static CACHE_CELL: CacheCell = CacheCell(UnsafeCell::new(Cache { entries: [None; CACHE], dirs: [const { None }; DIRS], tick: 0 }));

impl Cache {
    fn get() -> &'static mut Cache {
        // SAFETY: as CacheCell's: one request at a time, and no two references live at once
        // (each use is within one call).
        unsafe { &mut *CACHE_CELL.0.get() }
    }

    fn find(&mut self, root: usize, node: u32, generation: u32, access: Access) -> Option<i32> {
        self.tick += 1;
        let t = self.tick;
        let e = self.entries.iter_mut().flatten().find(|e| e.root == root && e.node == node && e.generation == generation && e.access == access)?;
        e.used = t;
        Some(e.fd)
    }

    fn insert(&mut self, e: Entry) {
        self.tick += 1;
        let slot = match self.entries.iter().position(Option::is_none) {
            Some(i) => i,
            None => {
                let i = (0..CACHE).min_by_key(|&i| self.entries[i].map_or(0, |e| e.used)).unwrap_or(0);
                if let Some(old) = self.entries[i].take() {
                    close(old.fd);
                }
                i
            }
        };
        self.entries[slot] = Some(Entry { used: self.tick, ..e });
    }

    /// Node's read fd closed: a lookup checks the name again (its old fd would still `fstat` a
    /// file the host has since removed).
    fn drop_read(&mut self, root: usize, node: u32) {
        for e in self.entries.iter_mut() {
            if e.is_some_and(|x| x.root == root && x.node == node && x.access == Access::Read) {
                close(e.take().map_or(-1, |x| x.fd));
            }
        }
    }

    fn drop_node(&mut self, root: usize, node: u32) {
        for e in self.entries.iter_mut() {
            if e.is_some_and(|x| x.root == root && x.node == node) {
                close(e.take().map_or(-1, |x| x.fd));
            }
        }
        for d in self.dirs.iter_mut() {
            if d.as_ref().is_some_and(|x| x.root == root && x.node == node) {
                close(d.take().map_or(-1, |x| x.fd));
            }
        }
    }

    /// Every fd closed: before lockdown, so that none is left at a number lockdown's caller may
    /// move a kept fd to (the numbers below its floor).
    fn clear(&mut self) {
        for e in self.entries.iter_mut() {
            if let Some(x) = e.take() {
                close(x.fd);
            }
        }
        for d in self.dirs.iter_mut() {
            if let Some(x) = d.take() {
                close(x.fd);
            }
        }
    }
}

/// Close this process's cached fds (none is needed: the next request opens again). Lockdown's
/// caller calls it before it moves the kept fds to `0..n` (their numbers might be among them).
pub fn close_cached() {
    Cache::get().clear();
}

// ---- scratch (private) ----

/// Paths and link targets: statics, not the stack (a request is served on a kernel thread's
/// small stack). One request at a time (device.rs); each buffer has one user at a time:
/// [`P0`] and [`P1`] the request's own paths, [`PFD`] [`Root::fd`]'s, [`PT`] a link's target.
const P0: usize = 0;
const P1: usize = 1;
const PFD: usize = 2;
const PT: usize = 3;
struct Scratch(UnsafeCell<[[u8; PATH_MAX + 1]; 4]>);
// SAFETY: as CacheCell's.
unsafe impl Sync for Scratch {}
static SCRATCH: Scratch = Scratch(UnsafeCell::new([[0; PATH_MAX + 1]; 4]));

fn scratch(i: usize) -> &'static mut [u8; PATH_MAX + 1] {
    // SAFETY: one request at a time, and buffer i used by one caller at a time (see above).
    unsafe { &mut (*SCRATCH.0.get())[i] }
}

struct DirBufs(UnsafeCell<[[u8; DIR_BUF]; DIRS]>);
// SAFETY: as CacheCell's.
unsafe impl Sync for DirBufs {}
static DIR_BUFS: DirBufs = DirBufs(UnsafeCell::new([[0; DIR_BUF]; DIRS]));

fn dir_buf(i: usize) -> &'static mut [u8; DIR_BUF] {
    // SAFETY: as scratch's: slot i's, during one request.
    unsafe { &mut (*DIR_BUFS.0.get())[i] }
}

// ---- the host calls ----

struct Stat {
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    size: u64,
    blksize: u64,
    blocks: u64,
    times: [(u64, u32); 3],
}

fn fstat(fd: i32) -> Result<Stat, i32> {
    let mut b = [0u8; 144];
    call(NR_FSTAT, [fd as usize, b.as_mut_ptr() as usize, 0, 0, 0, 0])?;
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    // x86-64's struct stat.
    Ok(Stat {
        ino: u64_at(8),
        nlink: u64_at(16),
        mode: u32_at(24),
        uid: u32_at(28),
        gid: u32_at(32),
        rdev: u64_at(40),
        size: u64_at(48),
        blksize: u64_at(56),
        blocks: u64_at(64),
        times: [(u64_at(72), u64_at(80) as u32), (u64_at(88), u64_at(96) as u32), (u64_at(104), u64_at(112) as u32)],
    })
}

fn openat(path: &[u8; PATH_MAX + 1], flags: usize, mode: u32) -> Result<i32, i32> {
    call(NR_OPENAT, [ABS_DIRFD, path.as_ptr() as usize, flags | O_NB, mode as usize, 0, 0]).map(|fd| fd as i32)
}

/// What an `Access` opens with (flags the filter's rows take).
fn flags(a: Access) -> usize {
    match a {
        Access::Read => O_RDONLY | O_NOFOLLOW,
        Access::Write => O_WRONLY,
        Access::ReadWrite => O_RDWR,
    }
}

impl Root {
    /// An fd of node `id` for `access`: the cache's, or opened by its path.
    fn fd(&mut self, id: u64, access: Access) -> Result<i32, i32> {
        let me = self as *const Root as usize;
        let generation = self.generation(id);
        if self.node(id).is_none() {
            return Err(ENOENT);
        }
        let cache = Cache::get();
        if let Some(fd) = cache.find(me, id as u32, generation, access) {
            return Ok(fd);
        }
        let p = scratch(PFD);
        self.path(id, None, p)?;
        let fd = openat(p, flags(access), 0)?;
        cache.insert(Entry { root: me, node: id as u32, generation, access, fd, used: 0 });
        Ok(fd)
    }

    /// Node `id`'s attributes: `fstat` of an fd of it; a symlink's (which `O_NOFOLLOW` won't
    /// open) made up from `readlinkat`'s length.
    fn attr(&mut self, id: u64) -> Result<Attr, i32> {
        match self.fd(id, Access::Read) {
            Ok(fd) => fstat(fd).map(|s| Attr::of(&s)),
            Err(ELOOP) => {
                let p = scratch(PFD);
                self.path(id, None, p)?;
                let t = scratch(PT);
                let n = call(NR_READLINKAT, [ABS_DIRFD, p.as_ptr() as usize, t.as_mut_ptr() as usize, t.len(), 0, 0])?;
                Ok(Attr { ino: 0x8000_0000_0000_0000 | id, size: n as u64, mode: S_IFLNK | 0o777, nlink: 1, ..Attr::default() })
            }
            Err(e) => Err(e),
        }
    }
}

// ---- FUSE (include/uapi/linux/fuse.h) ----

const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_SYMLINK: u32 = 6;
const FUSE_MKNOD: u32 = 8;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_LINK: u32 = 13;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_CREATE: u32 = 35;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;
const FUSE_FALLOCATE: u32 = 43;
const FUSE_RENAME2: u32 = 45;
const FUSE_TMPFILE: u32 = 51;

const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;

const FUSE_BIG_WRITES: u32 = 1 << 5;
const FUSE_MAX_PAGES: u32 = 1 << 22;
const UTIME_NOW: u64 = (1 << 30) - 1;
const UTIME_OMIT: u64 = (1 << 30) - 2;

/// How long the guest may trust a lookup or attributes: the directory is live, so not long.
const VALID_S: u64 = 1;

#[derive(Default, Clone, Copy)]
struct Attr {
    ino: u64,
    size: u64,
    blocks: u64,
    times: [(u64, u32); 3],
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
}

impl Attr {
    fn of(s: &Stat) -> Attr {
        Attr {
            ino: s.ino,
            size: s.size,
            blocks: s.blocks,
            times: s.times,
            mode: s.mode,
            nlink: s.nlink as u32,
            uid: s.uid,
            gid: s.gid,
            rdev: s.rdev as u32,
            blksize: s.blksize as u32,
        }
    }

    /// `struct fuse_attr`: 88 bytes.
    fn put(&self, w: &mut Writer) {
        w.u64(self.ino);
        w.u64(self.size);
        w.u64(self.blocks);
        for t in self.times {
            w.u64(t.0);
        }
        for t in self.times {
            w.u32(t.1);
        }
        w.u32(self.mode);
        w.u32(self.nlink);
        w.u32(self.uid);
        w.u32(self.gid);
        w.u32(self.rdev);
        w.u32(self.blksize);
        w.u32(0);
    }
}

/// A reply, written into the device's buffer after its header (filled in by [`Writer::finish`]).
struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) {
        let k = b.len().min(self.buf.len().saturating_sub(self.len));
        self.buf[self.len..self.len + k].copy_from_slice(&b[..k]);
        self.len += k;
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    /// `struct fuse_entry_out`: 128 bytes.
    fn entry(&mut self, node: u64, a: &Attr) {
        self.u64(node);
        self.u64(0); // generation
        self.u64(VALID_S);
        self.u64(VALID_S);
        self.u32(0);
        self.u32(0);
        a.put(self);
    }
    /// `struct fuse_attr_out`: 104 bytes.
    fn attr(&mut self, a: &Attr) {
        self.u64(VALID_S);
        self.u32(0);
        self.u32(0);
        a.put(self);
    }
    /// `struct fuse_open_out`: 16 bytes, no handle (requests name the node).
    fn open(&mut self) {
        self.u64(0);
        self.u32(0);
        self.u32(0);
    }
}

/// A request's bytes after its header.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u64(&mut self) -> u64 {
        let v = self.0.get(..8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
        self.0 = self.0.get(8..).unwrap_or(&[]);
        v
    }
    fn u32(&mut self) -> u32 {
        let v = self.0.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
        self.0 = self.0.get(4..).unwrap_or(&[]);
        v
    }
    fn skip(&mut self, n: usize) {
        self.0 = self.0.get(n..).unwrap_or(&[]);
    }
    /// A NUL-terminated name, which must be one component.
    fn name(&mut self) -> Result<&'a [u8], i32> {
        let end = self.0.iter().position(|&b| b == 0).ok_or(EINVAL)?;
        let n = &self.0[..end];
        self.0 = &self.0[end + 1..];
        if n.is_empty() || n == b"." || n == b".." || n.contains(&b'/') || n.len() > 255 {
            return Err(EINVAL);
        }
        Ok(n)
    }
}

/// One request of the root at `state` ([`root`]'s): [`crate::Host::rpc`]. The reply's length (0:
/// a request that wants none), or an errno for the device to answer with.
pub fn serve(state: usize, request: &[u8], reply: &mut [u8]) -> Result<usize, i32> {
    if request.len() < 40 || reply.len() < 16 && !matches!(opcode(request), FUSE_FORGET | FUSE_BATCH_FORGET | FUSE_INTERRUPT) {
        return Err(EIO);
    }
    // SAFETY: a Root of root()'s, never freed; one request at a time (device.rs).
    let r = unsafe { &mut *(state as *mut Root) };
    let op = opcode(request);
    let unique = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let node = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let mut rd = Reader(&request[40..]);
    match op {
        FUSE_FORGET => {
            r.forget(node, rd.u64());
            return Ok(0);
        }
        FUSE_BATCH_FORGET => {
            let count = rd.u32();
            rd.u32();
            for _ in 0..count {
                let (id, k) = (rd.u64(), rd.u64());
                r.forget(id, k);
            }
            return Ok(0);
        }
        FUSE_INTERRUPT => return Ok(0),
        _ => {}
    }
    let mut w = Writer { buf: reply, len: 16 };
    let error = match handle(r, op, node, &mut rd, &mut w) {
        Ok(()) => 0,
        Err(e) => {
            w.len = 16;
            -e
        }
    };
    let len = w.len;
    reply[..4].copy_from_slice(&(len as u32).to_le_bytes());
    reply[4..8].copy_from_slice(&error.to_le_bytes());
    reply[8..16].copy_from_slice(&unique.to_le_bytes());
    Ok(len)
}

fn opcode(request: &[u8]) -> u32 {
    u32::from_le_bytes(request[4..8].try_into().unwrap())
}

fn handle(r: &mut Root, op: u32, node: u64, rd: &mut Reader, w: &mut Writer) -> Result<(), i32> {
    let rw = r.writable;
    let need_rw = || if rw { Ok(()) } else { Err(EROFS) };
    match op {
        FUSE_INIT => {
            let (major, minor) = (rd.u32(), rd.u32());
            if major < 7 {
                return Err(EINVAL);
            }
            w.u32(7);
            w.u32(minor.min(31));
            w.u32(128 << 10); // max_readahead
            w.u32(FUSE_BIG_WRITES | FUSE_MAX_PAGES);
            w.u16(16); // max_background
            w.u16(12); // congestion_threshold
            w.u32(crate::MAX_DATA as u32); // max_write
            w.u32(1); // time_gran
            w.u16((crate::MAX_DATA / 4096) as u16); // max_pages
            w.u16(0);
            w.u32(0);
            w.u32(0);
            w.bytes(&[0; 24]);
        }
        FUSE_DESTROY | FUSE_FLUSH | FUSE_RELEASE | FUSE_RELEASEDIR | FUSE_FSYNCDIR => {}
        FUSE_LOOKUP => {
            let name = rd.name()?;
            let id = r.lookup(node as u32, name)?;
            // By its path, now: the host may have removed or replaced it since.
            Cache::get().drop_read(r as *const Root as usize, id);
            match r.attr(id as u64) {
                Ok(a) => w.entry(id as u64, &a),
                Err(e) => {
                    r.forget(id as u64, 1);
                    return Err(e);
                }
            }
        }
        FUSE_GETATTR => {
            let a = r.attr(node)?;
            w.attr(&a);
        }
        FUSE_READLINK => {
            let p = scratch(P0);
            r.path(node, None, p)?;
            let t = scratch(PT);
            let n = call(NR_READLINKAT, [ABS_DIRFD, p.as_ptr() as usize, t.as_mut_ptr() as usize, t.len(), 0, 0])?;
            w.bytes(&t[..n]);
        }
        FUSE_OPEN => {
            let fl = rd.u32();
            let a = r.attr(node)?;
            // Only files are read and written (a FIFO's or a device's I/O is no call here).
            if a.mode & S_IFMT != S_IFREG {
                return Err(EACCES);
            }
            match fl & O_ACCMODE {
                0 => {}
                1 => {
                    need_rw()?;
                    r.fd(node, Access::Write)?;
                }
                _ => {
                    need_rw()?;
                    r.fd(node, Access::ReadWrite)?;
                }
            }
            w.open();
        }
        FUSE_OPENDIR => {
            if r.attr(node)?.mode & S_IFMT != S_IFDIR {
                return Err(libc_enotdir());
            }
            w.open();
        }
        FUSE_READ => {
            rd.u64(); // fh
            let off = rd.u64();
            let size = (rd.u32() as usize).min(crate::MAX_DATA);
            let fd = r.fd(node, Access::Read)?;
            let start = w.len;
            let room = (w.buf.len() - start).min(size);
            let mut got = 0;
            while got < room {
                let n = call(NR_PREAD64, [fd as usize, w.buf[start + got..].as_mut_ptr() as usize, room - got, off as usize + got, 0, 0])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            w.len = start + got;
        }
        FUSE_WRITE => {
            need_rw()?;
            rd.u64(); // fh
            let off = rd.u64();
            let size = rd.u32() as usize;
            rd.skip(4 + 8 + 4 + 4); // write_flags, lock_owner, flags, padding
            let data = &rd.0[..size.min(rd.0.len())];
            let fd = r.fd(node, Access::ReadWrite).or_else(|_| r.fd(node, Access::Write))?;
            let mut put = 0;
            while put < data.len() {
                let n = call(NR_PWRITE64, [fd as usize, data[put..].as_ptr() as usize, data.len() - put, off as usize + put, 0, 0])?;
                if n == 0 {
                    break;
                }
                put += n;
            }
            w.u32(put as u32);
            w.u32(0);
        }
        FUSE_FSYNC => {
            if rw {
                let fd = r.fd(node, Access::ReadWrite).or_else(|_| r.fd(node, Access::Write))?;
                call(NR_FSYNC, [fd as usize, 0, 0, 0, 0, 0])?;
            }
        }
        FUSE_STATFS => {
            // Made up (the filter has no statfs): plenty of room, 255-byte names.
            for v in [1u64 << 30, 1 << 29, 1 << 29, 1 << 20, 1 << 19] {
                w.u64(v);
            }
            w.u32(4096);
            w.u32(255);
            w.u32(4096);
            w.u32(0);
            w.bytes(&[0; 24]);
        }
        FUSE_READDIR => readdir(r, node, rd, w)?,
        FUSE_SETATTR => {
            need_rw()?;
            let valid = rd.u32();
            rd.u32();
            rd.u64(); // fh
            let size = rd.u64();
            rd.u64(); // lock_owner
            let (atime, mtime) = (rd.u64(), rd.u64());
            rd.u64(); // ctime
            let (atimensec, mtimensec) = (rd.u32(), rd.u32());
            rd.u32(); // ctimensec
            let mode = rd.u32();
            if valid & (FATTR_UID | FATTR_GID) != 0 {
                return Err(EPERM);
            }
            let p = scratch(P0);
            r.path(node, None, p)?;
            if valid & FATTR_MODE != 0 {
                call(NR_FCHMODAT, [ABS_DIRFD, p.as_ptr() as usize, (mode & MODE_MAX) as usize, 0, 0, 0])?;
            }
            if valid & FATTR_SIZE != 0 {
                let fd = r.fd(node, Access::Write).or_else(|_| r.fd(node, Access::ReadWrite))?;
                call(NR_FTRUNCATE, [fd as usize, size as usize, 0, 0, 0, 0])?;
            }
            if valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW) != 0 {
                let t = |set: u32, now: u32, s: u64, ns: u32| -> [u64; 2] {
                    if valid & now != 0 {
                        [0, UTIME_NOW]
                    } else if valid & set != 0 {
                        [s, ns as u64]
                    } else {
                        [0, UTIME_OMIT]
                    }
                };
                let times = [t(FATTR_ATIME, FATTR_ATIME_NOW, atime, atimensec), t(FATTR_MTIME, FATTR_MTIME_NOW, mtime, mtimensec)];
                call(NR_UTIMENSAT, [ABS_DIRFD, p.as_ptr() as usize, times.as_ptr() as usize, 0, 0, 0])?;
            }
            let a = r.attr(node)?;
            w.attr(&a);
        }
        FUSE_MKDIR => {
            need_rw()?;
            let (mode, umask) = (rd.u32(), rd.u32());
            let name = rd.name()?;
            let p = scratch(P0);
            r.path(node, Some(name), p)?;
            call(NR_MKDIRAT, [ABS_DIRFD, p.as_ptr() as usize, (mode & !umask & MODE_MAX) as usize, 0, 0, 0])?;
            entry(r, node, name, w)?;
        }
        FUSE_SYMLINK => {
            need_rw()?;
            let name = rd.name()?;
            let end = rd.0.iter().position(|&b| b == 0).ok_or(EINVAL)?;
            let target = &rd.0[..=end];
            let p = scratch(P0);
            r.path(node, Some(name), p)?;
            call(NR_SYMLINKAT, [target.as_ptr() as usize, ABS_DIRFD, p.as_ptr() as usize, 0, 0, 0])?;
            entry(r, node, name, w)?;
        }
        FUSE_CREATE => {
            need_rw()?;
            let (fl, mode, umask) = (rd.u32(), rd.u32(), rd.u32());
            rd.u32(); // open_flags
            let name = rd.name()?;
            let p = scratch(P0);
            r.path(node, Some(name), p)?;
            let excl = if fl as usize & O_EXCL != 0 { O_EXCL } else { 0 };
            let (access, base) = match fl & O_ACCMODE {
                0 => (Access::Read, O_RDONLY),
                1 => (Access::Write, O_WRONLY | if fl as usize & O_TRUNC != 0 && excl == 0 { O_TRUNC } else { 0 }),
                _ => (Access::ReadWrite, O_RDWR | if fl as usize & O_TRUNC != 0 && excl == 0 { O_TRUNC } else { 0 }),
            };
            let fd = openat(p, base | O_CREAT | excl, mode & !umask & MODE_MAX)?;
            let s = match fstat(fd) {
                Ok(s) => s,
                Err(e) => {
                    close(fd);
                    return Err(e);
                }
            };
            let id = r.lookup(node as u32, name)?;
            let me = r as *const Root as usize;
            let generation = r.generation(id as u64);
            // A read fd is O_NOFOLLOW's (the cache's Read kind): this one, opened without it, is
            // only kept for writes.
            if access == Access::Read {
                close(fd);
            } else {
                Cache::get().insert(Entry { root: me, node: id, generation, access, fd, used: 0 });
            }
            w.entry(id as u64, &Attr::of(&s));
            w.open();
        }
        FUSE_UNLINK | FUSE_RMDIR => {
            need_rw()?;
            let name = rd.name()?;
            let p = scratch(P0);
            r.path(node, Some(name), p)?;
            let flag = if op == FUSE_RMDIR { AT_REMOVEDIR } else { 0 };
            call(NR_UNLINKAT, [ABS_DIRFD, p.as_ptr() as usize, flag, 0, 0, 0])?;
            if let Some(id) = r.find(node as u32, name) {
                r.detach(id);
            }
        }
        FUSE_RENAME | FUSE_RENAME2 => {
            need_rw()?;
            let newdir = rd.u64();
            let flags = if op == FUSE_RENAME2 {
                let f = rd.u32();
                rd.u32();
                f
            } else {
                0
            };
            // RENAME_NOREPLACE (1) and RENAME_EXCHANGE (2) only: the filter's.
            if flags > 2 {
                return Err(EINVAL);
            }
            let (old, new) = (rd.name()?, rd.name()?);
            let (po, pn) = (scratch(P0), scratch(P1));
            r.path(node, Some(old), po)?;
            r.path(newdir, Some(new), pn)?;
            call(NR_RENAMEAT2, [ABS_DIRFD, po.as_ptr() as usize, ABS_DIRFD, pn.as_ptr() as usize, flags as usize, 0])?;
            // The names now: `old`'s node is at `new`; what was at `new` is gone, or, exchanged,
            // at `old`.
            let (from, to) = (r.find(node as u32, old), r.find(newdir as u32, new));
            if let Some(id) = to {
                r.detach(id);
            }
            if let Some(id) = from {
                r.rename(id, newdir as u32, new);
            }
            if let (Some(id), true) = (to, flags == 2) {
                r.rename(id, node as u32, old);
            }
        }
        FUSE_MKNOD | FUSE_LINK => {
            need_rw()?;
            return Err(EPERM);
        }
        FUSE_FALLOCATE | FUSE_TMPFILE => return Err(EOPNOTSUPP),
        _ => return Err(ENOSYS),
    }
    Ok(())
}

fn libc_enotdir() -> i32 {
    20
}

/// The entry of `name`, just made under `parent`.
fn entry(r: &mut Root, parent: u64, name: &[u8], w: &mut Writer) -> Result<(), i32> {
    let id = r.lookup(parent as u32, name)?;
    match r.attr(id as u64) {
        Ok(a) => {
            w.entry(id as u64, &a);
            Ok(())
        }
        Err(e) => {
            r.forget(id as u64, 1);
            Err(e)
        }
    }
}

/// `READDIR` from entry `offset` (each entry's `off` is the next one's index): from this
/// process's cursor if it is there, else a fresh `getdents64` from the start, skipping `offset`
/// entries (there is no `lseek`).
fn readdir(r: &mut Root, node: u64, rd: &mut Reader, w: &mut Writer) -> Result<(), i32> {
    rd.u64(); // fh
    let offset = rd.u64();
    let size = rd.u32() as usize;
    let me = r as *const Root as usize;
    let generation = r.generation(node);
    let cache = Cache::get();
    let at = cache.dirs.iter().position(|d| d.as_ref().is_some_and(|d| d.root == me && d.node == node as u32 && d.generation == generation && d.index == offset));
    let slot = match at {
        Some(i) => i,
        None => {
            let p = scratch(P0);
            r.path(node, None, p)?;
            let fd = openat(p, O_RDONLY | O_DIRECTORY, 0)?;
            // A free slot, or the first one's (closed).
            let i = cache.dirs.iter().position(Option::is_none).unwrap_or(0);
            if let Some(old) = cache.dirs[i].take() {
                close(old.fd);
            }
            cache.dirs[i] = Some(Dir { root: me, node: node as u32, generation, fd, index: 0, pos: 0, len: 0 });
            i
        }
    };
    let d = cache.dirs[slot].as_mut().ok_or(EIO)?;
    let buf = dir_buf(slot);
    let limit = w.len + size.min(w.buf.len() - w.len);
    loop {
        if d.pos >= d.len {
            let n = call(NR_GETDENTS64, [d.fd as usize, buf.as_mut_ptr() as usize, DIR_BUF, 0, 0, 0])?;
            if n == 0 {
                break;
            }
            d.pos = 0;
            d.len = n;
        }
        // struct linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
        let e = &buf[d.pos..d.len];
        let reclen = u16::from_le_bytes([e[16], e[17]]) as usize;
        let ino = u64::from_le_bytes(e[..8].try_into().unwrap());
        let ty = e[18];
        let name = &e[19..reclen];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
        if d.index >= offset {
            // struct fuse_dirent: ino, off, namelen, type, name padded to 8.
            let len = (24 + name.len() + 7) & !7;
            if w.len + len > limit {
                break;
            }
            w.u64(ino);
            w.u64(d.index + 1);
            w.u32(name.len() as u32);
            w.u32(ty as u32);
            w.bytes(name);
            w.bytes(&[0; 8][..len - 24 - name.len()]);
        }
        d.pos += reclen;
        d.index += 1;
    }
    Ok(())
}
