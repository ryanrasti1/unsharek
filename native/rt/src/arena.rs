//! The arena: the program's memory after lockdown.
//!
//! Before lockdown the runtime reserves one large `MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE`
//! mapping (read/write/execute: programs load their code into it, and JITs make theirs). After lockdown
//! the host allows no `mmap`, `mprotect`, `munmap` or `brk`, so the program's memory calls are
//! trapped and served here, inside `[base, base + len)`. This module never maps host memory; it
//! hands out addresses inside the reservation, copies file contents in (or hands out where an
//! image already holds them: the image zone, below), and gives pages back through the caller
//! ([`Backing`]).
//!
//! # State
//! One sorted table of extents covers the whole arena: each extent is free or mapped, and says
//! whether its pages are *clean* (known to be zero) or *dirty* (may hold data). The table is
//! caller-provided storage ([`Extent`] slice; [`CAPACITY`] entries in the runtime) because the
//! crate allocates nothing. Adjacent extents that agree are merged, so its length is about the
//! number of distinct mappings, as a VMA list's is.
//!
//! An operation that has to split extents checks first that the table has room for them, and
//! fails with `ENOMEM` *before changing anything* if it hasn't: memory, files and the table are
//! left as they were. That is Linux's own answer when a process exceeds `vm.max_map_count`
//! (65530 by default, which is why [`CAPACITY`] is 64Ki). Operations that only remove or merge
//! extents (unmapping a whole mapping) never need room, so a full table can always be drained.
//!
//! # Clean and dirty: why never-written pages are tracked
//! Free pages that were never handed out, and pages given back to the host, are zero. Reusing
//! them costs nothing. An anonymous mapping that was never writable (`PROT_NONE` or `PROT_READ`)
//! also still holds those zeros. glibc reserves 128 MiB `PROT_NONE` per malloc arena and trims it
//! with `munmap`; capnix cleared freed pages in place without knowing which had been written and
//! touched ~66 MB per sandbox doing it. Here a range stays clean until it is mapped or made
//! writable, and clean ranges are neither released nor zeroed. The cost: there is no host
//! `mprotect`, so a program that writes to a `PROT_NONE` page (it would have crashed natively)
//! succeeds, and its own later mapping of that page may not read zero.
//!
//! # Giving pages back: two modes
//! - [`Mode::Release`] (coroutine mode): freed dirty pages go back to the host at once
//!   through [`Backing::release`] (`madvise(MADV_DONTNEED)`), in calls of at most [`MADV_CHUNK`]
//!   bytes inside the arena: the filter allows only that. Free memory is then always clean.
//! - [`Mode::HighWater`] (threaded and fork mode): the filter allows no `madvise` at all (concurrent
//!   `madvise` and page faults is the Dirty-COW race class), so nothing is released and memory stays
//!   at its peak. Freed dirty pages stay dirty and are cleared in place when they are handed out
//!   again, only the pages that actually hold a nonzero byte: reading a page the program never
//!   touched maps the host's shared zero page (free), writing it would make it the sandbox's.
//!
//! # The image zone: files mapped in place
//! The arena's top part can be the image zone ([`Arena::set_image_zone`]): the runtime maps the
//! store's images there (privately, before lockdown), each file's bytes block-aligned and each
//! ELF's memory image left free after them (exobox-erofs' slots). The zone is read-only on the
//! host but for each ELF's writable segments in its slot ([`Arena::add_zone_writable`]), so its
//! other pages are always the image's bytes, in every mode and after every fork. A private
//! mapping of a file whose bytes are there ([`Backing::locate`]) is answered with their address
//! instead of a copy: ld.so's reservation of a library (unmapped in this process), then its
//! read-only segments `MAP_FIXED` where they already are; the writable pages a mapping covers get
//! the file's bytes copied in (what they held never matters), and read-only pages past the file's
//! end must read zero. The program's code is then the host's page cache, shared by every sandbox
//! and by the host's own processes, as a native libc is. Nothing is placed in the zone; memory of
//! the program's own goes there `MAP_FIXED` only onto writable pages (ENOMEM elsewhere), and the
//! read-only ones can't be made writable (`mprotect`: EACCES). (The zone was writable, and in
//! high-water mode, which gives nothing back, a library's written data kept it from being mapped
//! in place again: fork mode copied nearly every exec's libraries whole.) A non-PIE program
//! (gcc's cc1) is still copied: it must be at its own addresses.
//!
//! # What is not Linux
//! - **No protections after lockdown.** `mprotect` records the protection (for `/proc/self/maps`
//!   and for clean tracking) and has no host effect. Guard pages a program places after lockdown
//!   (glibc's thread-stack guards) are not enforced.
//! - **Executable memory is ordinary.** The reservation is read/write/execute, and `PROT_EXEC`
//!   is recorded like any protection: the sandbox's boundary is the host filter, and JITs work.
//! - **`brk` never grows.** It returns the current break whatever is asked, which glibc reads as
//!   failure and falls back to `mmap` for its main heap (capnix did the same).
//! - **File mappings are copies** made at `mmap` through [`Backing::read`] (private ones of an
//!   image's files, mapped in place, are the host's copy-on-write pages instead). A `MAP_SHARED`
//!   mapping that is writable at `mmap` is written back through [`Backing::write`] at `msync`,
//!   `munmap` (and anything that replaces it) and [`Arena::writeback_all`] (exit): the rule
//!   linux-workers' `NOMMU_LINUX_MAPPINGS` and capnix used. The whole range is written back, not
//!   only changed bytes. One process's sqlite `-shm` works this way; two processes sharing a file
//!   mapping don't see each other's writes until write-back.
//! - Not supported: `MAP_SHARED | MAP_ANONYMOUS` is private (a forked child doesn't share it);
//!   making a read-only `MAP_SHARED` file mapping writable with `mprotect` doesn't write it back;
//!   `mremap` growing a file mapping fills the new tail with zeros; `MREMAP_DONTUNMAP`, `mremap`
//!   with `old_len == 0`, `MADV_REMOVE` and `MADV_WIPEONFORK` return `EINVAL`, which callers
//!   already handle (OpenSSL falls back to checking its pid when `WIPEONFORK` fails).
//!
//! # Errors
//! Every call returns `Result<usize, Errno>`: the value on success (an address, or 0), and on
//! failure rustix's [`Errno`], whose `raw_os_error()` is the **positive** Linux errno value. The
//! raw syscall return value (`-errno` on failure) is [`ret`]. Addresses or ranges outside the
//! arena are errors here (`ENOMEM`, `EINVAL` for `munmap`); what to do with the program's
//! memory from before lockdown is the dispatcher's decision, made before it calls in.
//!
//! # Concurrency
//! Methods take `&mut self`: the caller serialises them (one lock around the arena). The program's
//! own threads may touch arena memory meanwhile, as they could natively.

use core::cmp::{max, min};
use core::ptr;

pub use rustix::io::Errno;

/// Every arena call's result: the value, or the Linux errno (positive, see the module docs).
pub type Result<T> = core::result::Result<T, Errno>;

/// The page size (x86-64, aarch64 with 4 KiB pages).
pub const PAGE: usize = 4096;
/// The most bytes one [`Backing::release`] call covers: the filter's bound on `madvise`'s length.
pub const MADV_CHUNK: usize = 1 << 20;
/// The runtime's table size: Linux's default `vm.max_map_count` (65530), rounded up. An entry is
/// [`core::mem::size_of::<Extent>()`] bytes (40 on 64-bit), 2.5 MiB in all, in the runtime's bss.
pub const CAPACITY: usize = 1 << 16;
/// Requests of at least this size are placed at this alignment, as Linux does for anonymous
/// mappings since 6.7, so the host can back them with transparent huge pages.
const HUGE: usize = 2 << 20;

// The syscalls' flag values (the generic ones, which x86-64 and aarch64 use).
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
pub const PROT_GROWSDOWN: u32 = 0x0100_0000;
pub const PROT_GROWSUP: u32 = 0x0200_0000;
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_SHARED_VALIDATE: u32 = 0x03;
pub const MAP_TYPE: u32 = 0x0f;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_NORESERVE: u32 = 0x4000;
pub const MAP_FIXED_NOREPLACE: u32 = 0x10_0000;
pub const MREMAP_MAYMOVE: u32 = 1;
pub const MREMAP_FIXED: u32 = 2;
pub const MREMAP_DONTUNMAP: u32 = 4;
pub const MS_ASYNC: u32 = 1;
pub const MS_INVALIDATE: u32 = 2;
pub const MS_SYNC: u32 = 4;
pub const MADV_NORMAL: u32 = 0;
pub const MADV_RANDOM: u32 = 1;
pub const MADV_SEQUENTIAL: u32 = 2;
pub const MADV_WILLNEED: u32 = 3;
pub const MADV_DONTNEED: u32 = 4;
pub const MADV_FREE: u32 = 8;
pub const MADV_REMOVE: u32 = 9;
pub const MADV_DONTFORK: u32 = 10;
pub const MADV_DOFORK: u32 = 11;
pub const MADV_MERGEABLE: u32 = 12;
pub const MADV_UNMERGEABLE: u32 = 13;
pub const MADV_HUGEPAGE: u32 = 14;
pub const MADV_NOHUGEPAGE: u32 = 15;
pub const MADV_DONTDUMP: u32 = 16;
pub const MADV_DODUMP: u32 = 17;
pub const MADV_WIPEONFORK: u32 = 18;
pub const MADV_KEEPONFORK: u32 = 19;
pub const MADV_COLD: u32 = 20;
pub const MADV_PAGEOUT: u32 = 21;
pub const MADV_POPULATE_READ: u32 = 22;
pub const MADV_POPULATE_WRITE: u32 = 23;
pub const MADV_DONTNEED_LOCKED: u32 = 24;
pub const MADV_COLLAPSE: u32 = 25;

/// The raw syscall return value of an arena call: the value, or `-errno`.
pub fn ret(r: Result<usize>) -> isize {
    match r {
        Ok(v) => v as isize,
        Err(e) => -(e.raw_os_error() as isize),
    }
}

/// How freed pages are given back (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Through [`Backing::release`], at once, in chunks of at most [`MADV_CHUNK`].
    Release,
    /// Never: pages are reused, and cleared in place first if they were written.
    HighWater,
}

/// What the arena needs from its caller: file contents, and the host's `madvise`. Addresses
/// passed are inside the arena; implementations read and write that memory directly (it is the
/// program's, e.g. through LKL's `pread64`/`pwrite64`).
pub trait Backing {
    /// Read up to `len` bytes of `file` at `offset` into `[addr, addr + len)`; `Ok(0)` at the end
    /// of the file (the rest of the mapping stays zero, as Linux zero-fills past EOF).
    fn read(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> Result<usize>;
    /// Write up to `len` bytes from `[addr, addr + len)` to `file` at `offset`.
    fn write(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> Result<usize>;
    /// A writable `MAP_SHARED` mapping outlives its fd: return a new handle to the same open file
    /// (a `dup`) that the arena keeps until [`Backing::close`]. It must differ from every handle
    /// the arena holds. Fail with `EACCES` if the file isn't open for writing, as Linux's mmap does.
    fn retain(&mut self, file: u64) -> Result<u64>;
    /// No mapping refers to a handle from [`Backing::retain`] any more.
    fn close(&mut self, file: u64);
    /// Give `[addr, addr + len)` back to the host (`madvise(MADV_DONTNEED)`): afterwards it reads
    /// zero (in the image zone, the image's bytes). `len <= MADV_CHUNK`; [`Mode::Release`] only.
    /// On error the arena clears the range in place instead.
    fn release(&mut self, addr: usize, len: usize) -> Result<()>;
    /// Where `file`'s bytes from `offset` to its end already are in the image zone
    /// ([`Arena::set_image_zone`]), and how many there are: `(address, bytes)`. None if they
    /// aren't (the default: no zone).
    fn locate(&mut self, file: u64, offset: u64) -> Option<(usize, u64)> {
        let _ = (file, offset);
        None
    }
}

/// A file to map: the handle the dispatcher resolved the program's fd to, and the offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMap {
    pub file: u64,
    pub offset: u64,
}

/// Counters for `/proc/meminfo` and `sysinfo` (MemTotal `size`, MemFree `size - mapped`) and for
/// tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// The arena's size in bytes.
    pub size: usize,
    /// Bytes mapped now.
    pub mapped: usize,
    /// The highest arena offset ever mapped: in [`Mode::HighWater`], about what the sandbox may
    /// hold.
    pub high_water: usize,
    /// Bytes given back through [`Backing::release`], in all.
    pub released: u64,
    /// Bytes cleared in place (only pages that held a nonzero byte), in all.
    pub zeroed: u64,
    /// Table entries in use.
    pub extents: usize,
}

/// A mapping, as `/proc/self/maps` would list it (adjacent extents are not merged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: usize,
    pub end: usize,
    pub prot: u32,
    /// The file a writable shared mapping is written back to, at the offset of `start`.
    pub shared: Option<FileMap>,
}

/// A writable shared file mapping: written back to `file` at `offset` (that of the extent's start).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shared {
    file: u64,
    offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Not mapped. `dirty`: may hold data (only in high-water mode; release mode frees clean).
    Free { dirty: bool },
    /// Mapped with `prot`. `dirty`: may hold data (it is or was writable since it was zero, or
    /// holds a file's bytes). `anon`: zeros, not a file's bytes (what `MADV_DONTNEED` restores).
    /// In the image zone a mapping is always dirty, except one mapped in place
    /// (`anon: false, dirty: false`): the image's own bytes, never writable.
    Mapped { prot: u8, dirty: bool, anon: bool, shared: Option<Shared> },
    /// Not mapped, in the image zone: holds the images' bytes (in release mode, as the host's
    /// file mapping has them, so it can be mapped in place); never placed.
    Image,
}

const FREE_CLEAN: Kind = Kind::Free { dirty: false };

impl Kind {
    /// This kind as seen `delta` bytes further on: a shared mapping's file offset moves with it.
    fn shifted(self, delta: usize) -> Kind {
        match self {
            Kind::Mapped { prot, dirty, anon, shared: Some(s) } => Kind::Mapped {
                prot,
                dirty,
                anon,
                shared: Some(Shared { file: s.file, offset: s.offset.wrapping_add(delta as u64) }),
            },
            k => k,
        }
    }
    /// Free to place a mapping in.
    fn is_free(self) -> bool {
        matches!(self, Kind::Free { .. })
    }
    fn is_mapped(self) -> bool {
        matches!(self, Kind::Mapped { .. })
    }
    /// Not mapped, as the program sees it (free or image).
    fn is_unmapped(self) -> bool {
        !self.is_mapped()
    }
    fn is_dirty(self) -> bool {
        match self {
            Kind::Free { dirty } | Kind::Mapped { dirty, .. } => dirty,
            Kind::Image => false,
        }
    }
}

/// `k` as it must be at `s` with the image zone from `zone`: there, unmapped and clean is
/// [`Kind::Image`] and a mapping is dirty unless mapped in place (a zero anonymous page there was
/// written zero, over the image's bytes, so it must be given back when freed). Unmapped and dirty
/// stays so: high-water mode gives nothing back, so a freed page that was written (a library's
/// data, relocated) no longer holds the image's bytes, and mapping it in place again handed the
/// next program a relocated copy (fork mode: ld.so's "Inconsistency detected ...
/// elf_machine_rela_relative", in a compiler run's linker; also a second exec in threaded mode).
fn in_zone(zone: usize, s: usize, k: Kind) -> Kind {
    if s < zone {
        return k;
    }
    match k {
        Kind::Free { dirty: false } => Kind::Image,
        Kind::Mapped { prot, anon: true, shared, .. } => Kind::Mapped { prot, dirty: true, anon: true, shared },
        k => k,
    }
}

/// One entry of the arena's table (storage the caller provides: `[Extent::EMPTY; CAPACITY]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    start: usize,
    kind: Kind,
}

impl Extent {
    pub const EMPTY: Extent = Extent { start: 0, kind: FREE_CLEAN };
}

/// The memory manager over one reservation. See the module docs.
pub struct Arena<'t> {
    base: usize,
    end: usize,
    mode: Mode,
    /// Sorted by start, covering `[base, end)`: entry i ends where i + 1 starts (the last at
    /// `end`). `table[..n]` is in use.
    table: &'t mut [Extent],
    n: usize,
    brk: usize,
    high: usize,
    released: u64,
    zeroed: u64,
    /// Where the image zone starts (`end` if there is none): see [`Arena::set_image_zone`].
    zone: usize,
    /// Files are mapped in place from the zone (it is set).
    in_place: bool,
    /// The zone's writable pages, sorted and disjoint `[lo, hi)` ranges (`rw[..n_rw]`): the pages
    /// of each ELF's writable segments in its slot ([`Arena::add_zone_writable`]). Every other
    /// zone page is read-only on the host: always the image's bytes.
    rw: &'t mut [(usize, usize)],
    n_rw: usize,
}

fn page_up(len: usize) -> Option<usize> {
    len.checked_add(PAGE - 1).map(|l| l & !(PAGE - 1))
}

impl<'t> Arena<'t> {
    /// An arena over `[base, base + len)`, all free, with `table` as its extent storage (its
    /// length is the capacity).
    ///
    /// # Safety
    /// `[base, base + len)` is a private anonymous read/write/execute mapping, all zero, that nothing else
    /// hands out and that stays mapped while the arena lives. The arena reads, writes, zeroes and
    /// copies it, and passes its addresses to `backing`.
    pub unsafe fn new(base: usize, len: usize, mode: Mode, table: &'t mut [Extent]) -> Result<Self> {
        if !base.is_multiple_of(PAGE) || len == 0 || !len.is_multiple_of(PAGE) || base.checked_add(len).is_none() || table.is_empty() {
            return Err(Errno::INVAL);
        }
        table[0] = Extent { start: base, kind: FREE_CLEAN };
        let end = base + len;
        Ok(Arena {
            base,
            end,
            mode,
            table,
            n: 1,
            brk: 0,
            high: base,
            released: 0,
            zeroed: 0,
            zone: end,
            in_place: false,
            rw: &mut [],
            n_rw: 0,
        })
    }

    /// Make `[zone, end)` the image zone, before anything is mapped there: where the host maps
    /// the images (privately, before lockdown), so that a file on one is mapped by handing out
    /// the address of its bytes ([`Backing::locate`]) instead of copying them. The program's code
    /// is then the host's page cache, shared by every sandbox, not a copy in each (libc alone is
    /// 2 MB). Nothing is placed in the zone; a mapping put there `MAP_FIXED` works, cleared
    /// first. A range is mapped in place only while it holds the image's bytes: never written,
    /// or given back since (release mode).
    ///
    /// Not counted in [`Stats::size`]: it is the images', not the program's memory.
    pub fn set_image_zone(&mut self, zone: usize) -> Result<()> {
        if !zone.is_multiple_of(PAGE) || zone <= self.base || zone >= self.end || !self.all(zone, self.end, |k| k == FREE_CLEAN) {
            return Err(Errno::INVAL);
        }
        self.room(1)?;
        self.zone = zone;
        self.apply(zone, self.end, &|_, _| Kind::Image);
        self.in_place = true;
        Ok(())
    }

    /// The storage for the zone's writable ranges ([`Arena::add_zone_writable`]): its length is
    /// how many there can be.
    pub fn set_zone_writable_table(&mut self, table: &'t mut [(usize, usize)]) {
        self.rw = table;
        self.n_rw = 0;
    }

    /// `[lo, hi)` (whole pages, in the zone) is writable on the host: an ELF's writable segments
    /// in its slot, made writable when its image was mapped (every other zone page is mapped
    /// read-only there). A mapping in place copies the file's bytes into these pages; nothing
    /// relies on what they held before. `ENOMEM` when the table is full.
    pub fn add_zone_writable(&mut self, lo: usize, hi: usize) -> Result<()> {
        if !lo.is_multiple_of(PAGE) || !hi.is_multiple_of(PAGE) || lo >= hi || lo < self.zone || hi > self.end {
            return Err(Errno::INVAL);
        }
        // Merged with what it overlaps or touches, kept sorted.
        let i = self.rw[..self.n_rw].partition_point(|r| r.1 < lo);
        let mut j = i;
        let (mut l, mut h) = (lo, hi);
        while j < self.n_rw && self.rw[j].0 <= hi {
            l = min(l, self.rw[j].0);
            h = max(h, self.rw[j].1);
            j += 1;
        }
        if j == i {
            if self.n_rw == self.rw.len() {
                return Err(Errno::NOMEM);
            }
            self.rw.copy_within(i..self.n_rw, i + 1);
            self.n_rw += 1;
        } else if j > i + 1 {
            self.rw.copy_within(j..self.n_rw, i + 1);
            self.n_rw -= j - i - 1;
        }
        self.rw[i] = (l, h);
        Ok(())
    }

    /// The zone's writable parts of `[lo, hi)`, in order.
    fn zone_rw(&self, lo: usize, hi: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        let i = self.rw[..self.n_rw].partition_point(|r| r.1 <= lo);
        self.rw[i..self.n_rw].iter().take_while(move |r| r.0 < hi).map(move |r| (max(r.0, lo), min(r.1, hi)))
    }

    /// At most 8 of [`Arena::zone_rw`]'s ranges, for a loop that changes the arena (a library's
    /// span holds one or two). None if there are more.
    fn zone_rw_list(&self, lo: usize, hi: usize) -> Option<([(usize, usize); 8], usize)> {
        let mut rw = [(0usize, 0usize); 8];
        let mut n = 0;
        for r in self.zone_rw(lo, hi) {
            *rw.get_mut(n)? = r;
            n += 1;
        }
        Some((rw, n))
    }

    /// Some page of `[lo, hi)` is a read-only page of the zone (the image's bytes: never written).
    fn zone_ro(&self, lo: usize, hi: usize) -> bool {
        let lo = max(lo, self.zone);
        if lo >= hi {
            return false;
        }
        let mut at = lo;
        for (s, e) in self.zone_rw(lo, hi) {
            if s > at {
                return true;
            }
            at = e;
        }
        at < hi
    }

    /// `[addr, addr + len)` lies inside the arena.
    pub fn contains(&self, addr: usize, len: usize) -> bool {
        self.range(addr, len).is_some()
    }

    /// The program's break, which `brk` returns (the loader sets it to the end of its data).
    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    /// Switch how freed pages are given back. Threaded mode sets [`Mode::HighWater`] before the
    /// program starts (its filter refuses `madvise`), while the arena still holds nothing.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// `brk(2)`: never grows, whatever is asked; the current break tells glibc it failed, and
    /// glibc's malloc falls back to `mmap`.
    pub fn brk(&self, _addr: usize) -> usize {
        self.brk
    }

    pub fn stats(&self) -> Stats {
        let mapped = (0..self.n).filter(|&i| self.table[i].kind.is_mapped()).map(|i| self.ext_end(i) - self.table[i].start).sum();
        Stats {
            size: self.zone - self.base,
            mapped,
            high_water: self.high - self.base,
            released: self.released,
            zeroed: self.zeroed,
            extents: self.n,
        }
    }

    /// The mapped extents, in address order.
    pub fn mappings(&self) -> impl Iterator<Item = Mapping> + '_ {
        (0..self.n).filter_map(move |i| match self.table[i].kind {
            Kind::Mapped { prot, shared, .. } => Some(Mapping {
                start: self.table[i].start,
                end: self.ext_end(i),
                prot: prot as u32,
                shared: shared.map(|s| FileMap { file: s.file, offset: s.offset }),
            }),
            Kind::Free { .. } | Kind::Image => None,
        })
    }

    /// `mmap(2)`. `file` is the mapped file when `flags` lacks `MAP_ANONYMOUS` (else ignored).
    /// Without `MAP_FIXED`, a free hint is used as is, else the lowest free range that fits.
    pub fn mmap<B: Backing>(&mut self, b: &mut B, addr: usize, len: usize, prot: u32, flags: u32, file: Option<FileMap>) -> Result<usize> {
        if len == 0 || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
            return Err(Errno::INVAL);
        }
        let len = page_up(len).ok_or(Errno::NOMEM)?;
        let shared = match flags & MAP_TYPE {
            MAP_SHARED | MAP_SHARED_VALIDATE => true,
            MAP_PRIVATE => false,
            _ => return Err(Errno::INVAL),
        };
        let file = if flags & MAP_ANONYMOUS != 0 { None } else { Some(file.ok_or(Errno::BADF)?) };
        if let Some(f) = file {
            if !f.offset.is_multiple_of(PAGE as u64) {
                return Err(Errno::INVAL);
            }
            f.offset.checked_add(len as u64).ok_or(Errno::OVERFLOW)?;
        }
        if let Some(f) = file
            && !shared
            && flags & MAP_FIXED_NOREPLACE == 0
            && let Some(at) = self.in_place(b, addr, len, prot, flags & MAP_FIXED != 0, f)
        {
            return Ok(at);
        }
        let lo = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
            if !addr.is_multiple_of(PAGE) {
                return Err(Errno::INVAL);
            }
            let hi = self.range(addr, len).ok_or(Errno::NOMEM)?;
            // The zone's read-only pages are the image's: only a mapping of its own bytes in place
            // goes there (above), never memory of the program's (ENOMEM, Linux's answer for a
            // mapping it can't make).
            if self.zone_ro(addr, hi) {
                return Err(Errno::NOMEM);
            }
            // NOREPLACE wins when both are set, as in Linux's do_mmap.
            if flags & MAP_FIXED_NOREPLACE != 0 && !self.all(addr, hi, Kind::is_unmapped) {
                return Err(Errno::EXIST);
            }
            addr
        } else {
            self.place(addr, len)?
        };
        let hi = lo + len;

        let retained = match file {
            Some(f) if shared && prot & PROT_WRITE != 0 => Some(b.retain(f.file)?),
            _ => None,
        };
        let offset = file.map_or(0, |f| f.offset);
        let new = move |s: usize, _: Kind| Kind::Mapped {
            prot: prot as u8,
            dirty: file.is_some() || prot & PROT_WRITE != 0,
            anon: file.is_none(),
            shared: retained.map(|h| Shared { file: h, offset: offset + (s - lo) as u64 }),
        };
        // If the file can't be read, the range ends up unmapped: room for either outcome.
        let hw = self.mode == Mode::HighWater;
        let failed = move |_: usize, _: Kind| Kind::Free { dirty: hw };
        let need = max(self.splits(lo, hi, &new), if file.is_some() { self.splits(lo, hi, &failed) } else { 0 });
        if let Err(e) = self.room(need) {
            if let Some(h) = retained {
                b.close(h);
            }
            return Err(e);
        }

        self.vacate(b, lo, hi, true, false);
        if let Some(f) = file
            && let Err(e) = Self::fill(b, f, lo, len)
        {
            if let Some(h) = retained {
                b.close(h);
            }
            if !hw {
                self.release(b, lo, hi);
            }
            self.apply(lo, hi, &failed);
            return Err(e);
        }
        self.apply(lo, hi, &new);
        self.high = max(self.high, hi);
        Ok(lo)
    }

    /// A private file mapping made by handing out where the file's bytes already are, in the
    /// image zone: `len` bytes from `f.offset` at the address [`Backing::locate`] gives. Without
    /// `fixed` (ld.so's reservation of a library's span, or any mapping of the file) the range must
    /// be unmapped in this process; with `fixed` (ld.so's segments over that reservation) only at
    /// `addr`, over whatever is there. The zone's read-only pages are the image's bytes as they
    /// are; its writable ones (an ELF's data and .bss pages in its slot) get the file's bytes
    /// copied in, zeros past its end; what the range covers past the file's end on read-only pages
    /// must read zero (its slot's, or its last block's padding). None: copy it.
    ///
    /// The read-only pages are why this holds in every mode and after every fork: nothing can
    /// write them. (They were writable, and a library's written data pages kept it from being
    /// mapped in place again in high-water mode: fork mode copied nearly every exec's libraries
    /// whole, code and all.)
    fn in_place<B: Backing>(&mut self, b: &mut B, addr: usize, len: usize, prot: u32, fixed: bool, f: FileMap) -> Option<usize> {
        if !self.in_place {
            return None;
        }
        let (at, avail) = b.locate(f.file, f.offset)?;
        let hi = self.range(at, len)?;
        if at < self.zone || !at.is_multiple_of(PAGE) || (fixed && addr != at) {
            return None;
        }
        if !fixed && !self.all(at, hi, Kind::is_unmapped) {
            return None;
        }
        // Past the file's end, read-only pages must read zero (Linux's last page of a mapping,
        // and the pages after it, which Linux would fault, read zero in a copy).
        let fend = at.checked_add(usize::try_from(avail).ok()?)?;
        if fend < hi {
            let page = page_up(fend)?;
            let ro_zero = |lo: usize, hi: usize| {
                // SAFETY: inside the zone, which is mapped (the images, and zeros between them).
                !self.zone_ro(lo, hi) || unsafe { core::slice::from_raw_parts(lo as *const u8, hi - lo) }.iter().all(|&x| x == 0)
            };
            if !ro_zero(fend, min(page, hi)) || !(page..hi).step_by(PAGE).all(|p| ro_zero(p, p + PAGE)) {
                return None;
            }
        }
        let (rw, n) = self.zone_rw_list(at, hi)?;
        let new = move |_: usize, _: Kind| Kind::Mapped { prot: prot as u8, dirty: prot & PROT_WRITE != 0, anon: false, shared: None };
        self.room(self.splits(at, hi, &new)).ok()?;
        self.vacate(b, at, hi, false, false);
        // The writable pages: the file's bytes, then zeros. (A failure leaves the range unmapped,
        // and the caller copies it, or fails.)
        for &(s, e) in &rw[..n] {
            let part = min(e, max(fend, s)) - s;
            if part > 0 && Self::fill(b, FileMap { file: f.file, offset: f.offset + (s - at) as u64 }, s, part).is_err() {
                let freed = self.freed();
                self.apply(at, hi, &freed);
                return None;
            }
            // SAFETY: writable zone pages, this mapping's.
            unsafe { ptr::write_bytes((s + part) as *mut u8, 0, e - s - part) };
        }
        self.apply(at, hi, &new);
        self.high = max(self.high, hi);
        Some(at)
    }

    /// A private mapping of `len` bytes of `f` in place ([`Arena::set_image_zone`]), or None
    /// (nothing done): for a loader that reserves a span the way ld.so does, from the file, only
    /// where that costs no copy.
    pub fn mmap_in_place<B: Backing>(&mut self, b: &mut B, len: usize, prot: u32, f: FileMap) -> Option<usize> {
        let len = page_up(len)?;
        if len == 0 || !f.offset.is_multiple_of(PAGE as u64) {
            return None;
        }
        self.in_place(b, 0, len, prot, false, f)
    }

    /// `munmap(2)`. Writable shared file mappings in the range are written back first.
    pub fn munmap<B: Backing>(&mut self, b: &mut B, addr: usize, len: usize) -> Result<usize> {
        if !addr.is_multiple_of(PAGE) || len == 0 {
            return Err(Errno::INVAL);
        }
        let len = page_up(len).ok_or(Errno::INVAL)?;
        let hi = self.range(addr, len).ok_or(Errno::INVAL)?;
        let freed = self.freed();
        self.room(self.splits(addr, hi, &freed))?;
        self.vacate(b, addr, hi, false, false);
        self.apply(addr, hi, &freed);
        Ok(0)
    }

    /// `mremap(2)`: shrink in place; grow in place when the pages after are free; else move
    /// (`MREMAP_MAYMOVE`), to `new_addr` with `MREMAP_FIXED`. A grown tail is zero, with the
    /// protection of the mapping's last page.
    pub fn mremap<B: Backing>(&mut self, b: &mut B, old: usize, old_len: usize, new_len: usize, flags: u32, new_addr: usize) -> Result<usize> {
        if !old.is_multiple_of(PAGE)
            || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
            || (flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0)
            || flags & MREMAP_DONTUNMAP != 0
            || old_len == 0
            || new_len == 0
        {
            return Err(Errno::INVAL);
        }
        let olen = page_up(old_len).ok_or(Errno::INVAL)?;
        let nlen = page_up(new_len).ok_or(Errno::NOMEM)?;
        let ohi = self.range(old, olen).ok_or(Errno::FAULT)?;
        if !self.all(old, ohi, Kind::is_mapped) {
            return Err(Errno::FAULT);
        }
        // A move rewrites one table entry per extent moved, each possibly splitting twice, plus
        // the tail, the shrink and the source: room for all of it before anything changes.
        let move_need = 2 * self.count(old, ohi) + 6;

        if flags & MREMAP_FIXED != 0 {
            if !new_addr.is_multiple_of(PAGE) {
                return Err(Errno::INVAL);
            }
            let nhi = self.range(new_addr, nlen).ok_or(Errno::NOMEM)?;
            if new_addr < ohi && old < nhi {
                return Err(Errno::INVAL);
            }
            if self.zone_ro(new_addr, nhi) {
                return Err(Errno::NOMEM);
            }
            self.room(move_need)?;
            let keep = min(olen, nlen);
            if keep < olen {
                self.munmap(b, old + keep, olen - keep)?;
            }
            self.move_to(b, old, keep, new_addr, nlen);
            return Ok(new_addr);
        }
        if nlen <= olen {
            if nlen < olen {
                self.munmap(b, old + nlen, olen - nlen)?;
            }
            return Ok(old);
        }
        if let Some(nhi) = self.range(old, nlen)
            && self.all(ohi, nhi, Kind::is_free)
            && !self.zone_ro(ohi, nhi)
        {
            let tail = self.tail_kind(ohi - PAGE);
            let f = move |_: usize, _: Kind| tail;
            self.room(self.splits(ohi, nhi, &f))?;
            self.vacate(b, ohi, nhi, true, false);
            self.apply(ohi, nhi, &f);
            self.high = max(self.high, nhi);
            return Ok(old);
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(Errno::NOMEM);
        }
        let dst = self.fit(nlen).ok_or(Errno::NOMEM)?;
        self.room(move_need)?;
        self.move_to(b, old, olen, dst, nlen);
        Ok(dst)
    }

    /// `mprotect(2)`: recorded, with no host effect (see the module docs). The whole range must be
    /// mapped (`ENOMEM`, as Linux), and nothing changes if it isn't.
    pub fn mprotect(&mut self, addr: usize, len: usize, prot: u32) -> Result<usize> {
        if !addr.is_multiple_of(PAGE) || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN | PROT_GROWSUP) != 0 {
            return Err(Errno::INVAL);
        }
        let prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
        if len == 0 {
            return Ok(0);
        }
        let len = page_up(len).ok_or(Errno::NOMEM)?;
        let hi = self.range(addr, len).ok_or(Errno::NOMEM)?;
        if !self.all(addr, hi, Kind::is_mapped) {
            return Err(Errno::NOMEM);
        }
        // An image's read-only pages can't be made writable (no host mprotect after lockdown):
        // EACCES, as Linux's for a file opened read-only mapped shared. (Text relocations, a
        // program patching a library's code.)
        if prot & PROT_WRITE != 0 && self.zone_ro(addr, hi) {
            return Err(Errno::ACCESS);
        }
        let f = move |_: usize, k: Kind| match k {
            // Writable: the program may write it from now on, so it is no longer known zero.
            Kind::Mapped { dirty, anon, shared, .. } => {
                Kind::Mapped { prot: prot as u8, dirty: dirty || prot & PROT_WRITE != 0, anon, shared }
            }
            k => k,
        };
        self.room(self.splits(addr, hi, &f))?;
        self.apply(addr, hi, &f);
        Ok(0)
    }

    /// `madvise(2)`. `MADV_DONTNEED` makes anonymous pages read zero (released, or cleared in
    /// place in high-water mode); file pages keep their bytes, the closest we can come to
    /// Linux re-reading the file. `MADV_FREE` releases in release mode and does nothing in
    /// high-water mode (keeping the old bytes is one of its allowed outcomes). Advice that only
    /// tunes performance is accepted and ignored.
    pub fn madvise<B: Backing>(&mut self, b: &mut B, addr: usize, len: usize, advice: u32) -> Result<usize> {
        if !addr.is_multiple_of(PAGE) {
            return Err(Errno::INVAL);
        }
        let zero = match advice {
            MADV_DONTNEED | MADV_DONTNEED_LOCKED => true,
            MADV_FREE => self.mode == Mode::Release,
            MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTFORK | MADV_DOFORK
            | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE | MADV_DONTDUMP
            | MADV_DODUMP | MADV_KEEPONFORK | MADV_COLD | MADV_PAGEOUT | MADV_POPULATE_READ
            | MADV_POPULATE_WRITE | MADV_COLLAPSE => false,
            // WIPEONFORK can't be honoured (a forked child would keep the bytes): refusing it is
            // safe, since a caller must handle kernels without it. REMOVE frees shared memory.
            _ => return Err(Errno::INVAL),
        };
        if len == 0 {
            return Ok(0);
        }
        let len = page_up(len).ok_or(Errno::NOMEM)?;
        let hi = self.range(addr, len).ok_or(Errno::NOMEM)?;
        if zero {
            let mut at = addr;
            while at < hi {
                let (e, k) = self.piece(at, hi);
                if let Kind::Mapped { dirty: true, anon: true, .. } = k {
                    self.clear(b, at, e);
                }
                at = e;
            }
            // Pages now zero that can't be written are clean again. Only a refinement, skipped
            // if the table has no room for it.
            let f = |_: usize, k: Kind| match k {
                Kind::Mapped { prot, dirty: true, anon: true, shared } if prot as u32 & PROT_WRITE == 0 => {
                    Kind::Mapped { prot, dirty: false, anon: true, shared }
                }
                k => k,
            };
            if self.room(self.splits(addr, hi, &f)).is_ok() {
                self.apply(addr, hi, &f);
            }
        }
        // Linux applies the advice to what is mapped and then reports the hole.
        if !self.all(addr, hi, Kind::is_mapped) {
            return Err(Errno::NOMEM);
        }
        Ok(0)
    }

    /// `mincore(2)`: every mapped arena page is resident (the host may not have it, but the program
    /// can't tell). `vec` is the program's buffer, already checked by the caller; `EFAULT` if it
    /// is shorter than the range's pages.
    pub fn mincore(&self, addr: usize, len: usize, vec: &mut [u8]) -> Result<usize> {
        if !addr.is_multiple_of(PAGE) {
            return Err(Errno::INVAL);
        }
        let len = page_up(len).ok_or(Errno::NOMEM)?;
        let hi = self.range(addr, len).ok_or(Errno::NOMEM)?;
        if !self.all(addr, hi, Kind::is_mapped) {
            return Err(Errno::NOMEM);
        }
        vec.get_mut(..len / PAGE).ok_or(Errno::FAULT)?.fill(1);
        Ok(0)
    }

    /// `msync(2)`: write back the writable shared file mappings in the range (synchronously,
    /// whatever the flags). The first write error is returned; `ENOMEM` if part of the range
    /// isn't mapped.
    pub fn msync<B: Backing>(&mut self, b: &mut B, addr: usize, len: usize, flags: u32) -> Result<usize> {
        if !addr.is_multiple_of(PAGE)
            || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
            || (flags & MS_ASYNC != 0 && flags & MS_SYNC != 0)
        {
            return Err(Errno::INVAL);
        }
        let len = page_up(len).ok_or(Errno::NOMEM)?;
        let hi = self.range(addr, len).ok_or(Errno::NOMEM)?;
        let mut r = Ok(0);
        let mut at = addr;
        while at < hi {
            let (e, k) = self.piece(at, hi);
            match k {
                Kind::Mapped { shared: Some(s), .. } => {
                    if let Err(err) = Self::write_back(b, s, at, e) {
                        r = r.and(Err(err));
                    }
                }
                Kind::Free { .. } | Kind::Image => r = r.and(Err(Errno::NOMEM)),
                _ => {}
            }
            at = e;
        }
        r
    }

    /// Write back every writable shared file mapping (at exit). Continues past errors and returns
    /// the first.
    pub fn writeback_all<B: Backing>(&mut self, b: &mut B) -> Result<usize> {
        let mut r = Ok(0);
        for i in 0..self.n {
            if let Kind::Mapped { shared: Some(s), .. } = self.table[i].kind
                && let Err(e) = Self::write_back(b, s, self.table[i].start, self.ext_end(i))
            {
                r = r.and(Err(e));
            }
        }
        r
    }

    // ----- The table -----

    /// The end of `[addr, addr + len)` if it lies inside the arena.
    fn range(&self, addr: usize, len: usize) -> Option<usize> {
        let hi = addr.checked_add(len)?;
        (addr >= self.base && hi <= self.end).then_some(hi)
    }

    fn ext_end(&self, i: usize) -> usize {
        if i + 1 < self.n { self.table[i + 1].start } else { self.end }
    }

    /// The extent holding `addr` (inside the arena).
    fn find(&self, addr: usize) -> usize {
        self.table[..self.n].partition_point(|e| e.start <= addr) - 1
    }

    /// The extent piece starting at `at`: where it ends (at most `hi`) and its kind there.
    fn piece(&self, at: usize, hi: usize) -> (usize, Kind) {
        let i = self.find(at);
        (min(self.ext_end(i), hi), self.table[i].kind.shifted(at - self.table[i].start))
    }

    fn all(&self, lo: usize, hi: usize, pred: fn(Kind) -> bool) -> bool {
        let mut at = lo;
        while at < hi {
            let (e, k) = self.piece(at, hi);
            if !pred(k) {
                return false;
            }
            at = e;
        }
        true
    }

    /// How many extents overlap `[lo, hi)`.
    fn count(&self, lo: usize, hi: usize) -> usize {
        if lo >= hi { 0 } else { self.find(hi - 1) - self.find(lo) + 1 }
    }

    fn room(&self, need: usize) -> Result<()> {
        if self.n + need <= self.table.len() { Ok(()) } else { Err(Errno::NOMEM) }
    }

    /// The new entries [`Arena::apply`] of `f` over `[lo, hi)` needs: one per range boundary that
    /// falls inside an extent whose kind `f` changes. (Merges afterwards only free entries.)
    fn splits(&self, lo: usize, hi: usize, f: &impl Fn(usize, Kind) -> Kind) -> usize {
        let changes_at = |at: usize| {
            let i = self.find(at);
            let s = self.table[i].start;
            if s == at {
                return false;
            }
            let ps = max(s, lo);
            let k = self.table[i].kind.shifted(ps - s);
            in_zone(self.zone, ps, f(ps, k)) != k
        };
        changes_at(lo) as usize + (hi < self.end && changes_at(hi)) as usize
    }

    /// Split the extent holding `at` there, if `f` changes the part of it inside `[lo, ..)`.
    fn split_at(&mut self, at: usize, lo: usize, f: &impl Fn(usize, Kind) -> Kind) {
        let i = self.find(at);
        let Extent { start: s, kind } = self.table[i];
        if s == at {
            return;
        }
        let ps = max(s, lo);
        let k = kind.shifted(ps - s);
        if in_zone(self.zone, ps, f(ps, k)) == k {
            return;
        }
        self.table.copy_within(i + 1..self.n, i + 2);
        self.table[i + 1] = Extent { start: at, kind: kind.shifted(at - s) };
        self.n += 1;
    }

    /// Map every extent of `[lo, hi)` through `f(piece start, kind)` (then [`in_zone`]), splitting
    /// at the ends and merging neighbours that end up alike. The caller has checked [`Arena::room`] for
    /// [`Arena::splits`].
    fn apply(&mut self, lo: usize, hi: usize, f: &impl Fn(usize, Kind) -> Kind) {
        debug_assert!(self.n + self.splits(lo, hi, f) <= self.table.len());
        self.split_at(lo, lo, f);
        if hi < self.end {
            self.split_at(hi, lo, f);
        }
        let (i, j) = (self.find(lo), self.find(hi - 1));
        for k in i..=j {
            let (s, e) = (self.table[k].start, self.ext_end(k));
            // An extent left whole across lo or hi is one f doesn't change.
            if s >= lo && e <= hi {
                self.table[k].kind = in_zone(self.zone, s, f(s, self.table[k].kind));
            }
        }
        self.coalesce(i.saturating_sub(1), min(j + 1, self.n - 1));
    }

    /// Merge alike neighbours among entries `a..=b`.
    fn coalesce(&mut self, a: usize, b: usize) {
        let mut w = a;
        for r in a + 1..=b {
            let (prev, cur) = (self.table[w], self.table[r]);
            // Never across the image zone's start, where the kinds mean different things.
            if prev.kind.shifted(cur.start - prev.start) != cur.kind || cur.start == self.zone {
                w += 1;
                self.table[w] = cur;
            }
        }
        if w < b {
            self.table.copy_within(b + 1..self.n, w + 1);
            self.n -= b - w;
        }
    }

    // ----- Placement -----

    /// Where a new mapping of `len` goes: the hint if it is free, else the first fit.
    fn place(&self, hint: usize, len: usize) -> Result<usize> {
        if hint != 0
            && hint.is_multiple_of(PAGE)
            && let Some(hi) = self.range(hint, len)
            && hi <= self.zone
            && self.all(hint, hi, Kind::is_free)
        {
            return Ok(hint);
        }
        self.fit(len).ok_or(Errno::NOMEM)
    }

    /// The lowest free range of `len`, 2 MiB-aligned when `len` is that big and such a range exists.
    fn fit(&self, len: usize) -> Option<usize> {
        if len >= HUGE
            && let Some(a) = self.first_fit(len, HUGE)
        {
            return Some(a);
        }
        self.first_fit(len, PAGE)
    }

    fn first_fit(&self, len: usize, align: usize) -> Option<usize> {
        let mut i = 0;
        // Nothing is placed in the image zone (where high-water mode leaves freed dirty pages).
        while i < self.n && self.table[i].start < self.zone {
            if !self.table[i].kind.is_free() {
                i += 1;
                continue;
            }
            // A free run can be several extents (clean and dirty ones).
            let mut j = i;
            while j + 1 < self.n && self.table[j + 1].kind.is_free() {
                j += 1;
            }
            let a = self.table[i].start.checked_add(align - 1)? & !(align - 1);
            if a.checked_add(len).is_some_and(|e| e <= self.ext_end(j).min(self.zone)) {
                return Some(a);
            }
            i = j + 1;
        }
        None
    }

    // ----- Memory -----

    /// What `munmap` turns a mapping into: free, still dirty in high-water mode if it was (release
    /// mode has given dirty pages back by then).
    fn freed(&self) -> impl Fn(usize, Kind) -> Kind + use<> {
        let hw = self.mode == Mode::HighWater;
        move |_, k| match k {
            Kind::Mapped { dirty, .. } => Kind::Free { dirty: hw && dirty },
            k => k,
        }
    }

    /// A grown tail's kind: zeros, with the protection of the mapping's page at `last`.
    fn tail_kind(&self, last: usize) -> Kind {
        match self.piece(last, last + PAGE).1 {
            Kind::Mapped { prot, .. } => Kind::Mapped { prot, dirty: prot as u32 & PROT_WRITE != 0, anon: true, shared: None },
            k => k,
        }
    }

    /// The side effects of removing whatever is in `[lo, hi)` (the table is the caller's to
    /// update): write back and let go of shared files (unless `moving`: they go with the
    /// mapping), give dirty pages back, and with `reuse`, leave every page zero.
    fn vacate<B: Backing>(&mut self, b: &mut B, lo: usize, hi: usize, reuse: bool, moving: bool) {
        let mut at = lo;
        while at < hi {
            let (e, k) = self.piece(at, hi);
            if !moving && let Kind::Mapped { shared: Some(s), .. } = k {
                // munmap reports no write-back errors (Linux's page cache would still hold them).
                let _ = Self::write_back(b, s, at, e);
                if !self.seen(s.file, lo, at) && !self.referenced_outside(s.file, lo, hi) {
                    b.close(s.file);
                }
            }
            if at >= self.zone {
                // Read-only pages are the image's, as ever: nothing to do. Writable ones are
                // overwritten by whatever maps them next (in place: the file's bytes; anything
                // else: cleared here for reuse), so what they held never matters.
                if reuse && let Some((rw, n)) = self.zone_rw_list(at, e) {
                    for &(s, t) in &rw[..n] {
                        // SAFETY: writable zone pages.
                        self.zeroed += unsafe { zero_nonzero(s, t - s) } as u64;
                    }
                }
            } else if k.is_dirty() && (reuse || self.mode == Mode::Release) {
                self.clear(b, at, e);
            }
            at = e;
        }
    }

    /// Make `[lo, hi)` read zero: given back in release mode, cleared in place in high-water mode.
    /// In the image zone (where `lo` is, `hi` too) given back is the image's bytes: cleared too.
    fn clear<B: Backing>(&mut self, b: &mut B, lo: usize, hi: usize) {
        if self.mode == Mode::Release {
            self.release(b, lo, hi);
            if lo < self.zone {
                return;
            }
        }
        // SAFETY: inside the arena (Arena::new's contract).
        self.zeroed += unsafe { zero_nonzero(lo, hi - lo) } as u64;
    }

    fn release<B: Backing>(&mut self, b: &mut B, lo: usize, hi: usize) {
        let mut a = lo;
        while a < hi {
            let n = min(hi - a, MADV_CHUNK);
            match b.release(a, n) {
                Ok(()) => self.released += n as u64,
                Err(_) => {
                    // SAFETY: inside the arena (Arena::new's contract).
                    self.zeroed += unsafe { zero_nonzero(a, n) } as u64;
                }
            }
            a += n;
        }
    }

    /// A shared file handle appears in `[lo, at)`.
    fn seen(&self, file: u64, lo: usize, at: usize) -> bool {
        let mut p = lo;
        while p < at {
            let (e, k) = self.piece(p, at);
            if matches!(k, Kind::Mapped { shared: Some(s), .. } if s.file == file) {
                return true;
            }
            p = e;
        }
        false
    }

    /// Some mapping outside `[lo, hi)` is written back to `file`.
    fn referenced_outside(&self, file: u64, lo: usize, hi: usize) -> bool {
        (0..self.n).any(|i| {
            matches!(self.table[i].kind, Kind::Mapped { shared: Some(s), .. } if s.file == file)
                && (self.table[i].start < lo || self.ext_end(i) > hi)
        })
    }

    fn write_back<B: Backing>(b: &mut B, s: Shared, lo: usize, hi: usize) -> Result<()> {
        let mut done = 0;
        while done < hi - lo {
            match b.write(s.file, s.offset + done as u64, lo + done, hi - lo - done)? {
                0 => return Err(Errno::IO),
                n => done += n,
            }
        }
        Ok(())
    }

    fn fill<B: Backing>(b: &mut B, f: FileMap, lo: usize, len: usize) -> Result<()> {
        let mut done = 0;
        while done < len {
            match b.read(f.file, f.offset + done as u64, lo + done, len - done)? {
                0 => break,
                n => done += min(n, len - done),
            }
        }
        Ok(())
    }

    /// Move the `olen` bytes at `src` to `dst` as a mapping of `nlen` (room checked by the caller):
    /// content, protections and shared files go with it; the source is freed.
    fn move_to<B: Backing>(&mut self, b: &mut B, src: usize, olen: usize, dst: usize, nlen: usize) {
        let (shi, dhi) = (src + olen, dst + nlen);
        let tail = self.tail_kind(shi - PAGE);
        self.vacate(b, dst, dhi, true, false);
        let mut at = src;
        while at < shi {
            let (e, k) = self.piece(at, shi);
            let d = dst + (at - src);
            // Moved, a page mapped in place is a copy of the image's bytes like any file's.
            let k = match k {
                Kind::Mapped { prot, anon: false, shared, .. } => Kind::Mapped { prot, dirty: true, anon: false, shared },
                k => k,
            };
            if k.is_dirty() {
                // SAFETY: both inside the arena and disjoint (dst was free or vacated, src mapped).
                unsafe { copy_nonzero(d, at, e - at) };
            }
            self.apply(d, d + (e - at), &move |s: usize, _: Kind| k.shifted(s - d));
            at = e;
        }
        if nlen > olen {
            self.apply(dst + olen, dhi, &move |_: usize, _: Kind| tail);
        }
        self.vacate(b, src, shi, false, true);
        let freed = self.freed();
        self.apply(src, shi, &freed);
        self.high = max(self.high, dhi);
    }

    #[cfg(test)]
    fn check(&self) {
        assert!(self.n >= 1 && self.n <= self.table.len());
        assert_eq!(self.table[0].start, self.base);
        for i in 0..self.n {
            let (s, e) = (self.table[i].start, self.ext_end(i));
            assert!(s < e && e <= self.end, "extent {i} [{s:#x}, {e:#x})");
            assert_eq!(s % PAGE, 0);
            if self.mode == Mode::Release {
                assert_ne!(self.table[i].kind, Kind::Free { dirty: true }, "release mode frees clean");
            }
            let k = self.table[i].kind;
            assert_eq!(in_zone(self.zone, s, k), k, "extent {i} [{s:#x}, {e:#x}) as the zone has it");
            assert!(s >= self.zone || k != Kind::Image, "an image extent outside the zone");
            assert!(s >= self.zone || e <= self.zone, "extent {i} across the zone's start");
            if i > 0 {
                let p = self.table[i - 1];
                assert_ne!(p.kind.shifted(s - p.start), self.table[i].kind, "extents {} and {i} unmerged", i - 1);
            }
        }
    }
}

/// Clear every page of `[addr, addr + len)` that holds a nonzero byte; the bytes written. Pages
/// that already read zero are left alone: a page the program never touched maps the host's zero
/// page when read, and would become the sandbox's memory if written.
///
/// # Safety
/// The range is mapped read/write, page-aligned.
unsafe fn zero_nonzero(addr: usize, len: usize) -> usize {
    let mut written = 0;
    for p in (addr..addr + len).step_by(PAGE) {
        // SAFETY: the caller's.
        if unsafe { !page_is_zero(p) } {
            unsafe { ptr::write_bytes(p as *mut u8, 0, PAGE) };
            written += PAGE;
        }
    }
    written
}

/// Copy `[src, src + len)` to `dst`, which is zero, skipping source pages that are zero (they
/// stay untouched at the destination too).
///
/// # Safety
/// Both ranges mapped read/write, page-aligned, disjoint.
unsafe fn copy_nonzero(dst: usize, src: usize, len: usize) {
    for off in (0..len).step_by(PAGE) {
        // SAFETY: the caller's.
        if unsafe { !page_is_zero(src + off) } {
            unsafe { ptr::copy_nonoverlapping((src + off) as *const u8, (dst + off) as *mut u8, PAGE) };
        }
    }
}

/// # Safety
/// `p` is a readable page.
unsafe fn page_is_zero(p: usize) -> bool {
    // Compared with a page of zeros: slice equality of bytes is one memcmp, fast in any build
    // (a loop over words is ~30x slower unoptimised, which the tests are).
    static ZERO: [u8; PAGE] = [0; PAGE];
    // SAFETY: the caller's. (The program's threads may write it meanwhile; then it was racing
    // its own munmap or madvise, natively too.)
    let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, PAGE) };
    bytes == ZERO
}

#[cfg(test)]
mod tests;
