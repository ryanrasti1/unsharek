//! The images' host mappings, by the guest's device number: a file the guest maps from an image
//! is mapped in place where the image is mapped in the arena's image zone, or else copied
//! straight from the host mapping, never through the guest's page cache.
//!
//! **Why.** A `pread` of an image file fills the kernel's page cache first (memblk copies the
//! blocks into it from the mapping), then copies to the arena: every library the program loads
//! was held twice, the second copy in the kernel's pool, which is never given back to the host
//! (an idle sandbox's pool was 5.3 MB, 2.4 of it libc and ld.so's page cache), and the first a
//! private copy too (another 2.4 MB). In place, the program's code is the host's page cache of
//! the image, shared by every sandbox, as a native process's libc is.
//!
//! **How.** Each image is mapped twice before lockdown (`exobox::Guest::map_image`): read-only,
//! for the guest's memblk disk, and privately into the arena's image zone, where the program
//! writes what it writes (its copy-on-write pages, never the disk's bytes). A file's place in
//! the image comes from the guest (`FS_IOC_FIEMAP`; erofs answers it for flat files, which is
//! every regular file exobox's images hold), its image from its `fstat`. Anything else (a file on
//! tmpfs, a compressed or inline extent of someone else's image) is read the usual way: this is
//! only a shortcut, never the only way.

use core::ffi::c_long;
use core::sync::atomic::{AtomicUsize, Ordering};

use lkl_sys as l;
use rustix::io::Errno;

use crate::xabi::LklStat;

/// How many images can be registered.
pub const MAX: usize = 256;

/// `(device, read-only mapping, length, mapping in the zone or 0)`, written once each before
/// `COUNT` covers them (before lockdown), then only read: atomics, so no lock and no unsafe,
/// whichever host thread reads.
static DEV: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];
static ADDR: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];
static LEN: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];
static IN_ZONE: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// A guest syscall (generic number), as the caller makes them.
pub type Syscall = fn(c_long, [usize; 6]) -> isize;

/// One extent of a memblk disk (the kernel's `struct lkl_memblk_extent`): `len` bytes, a whole
/// number of 512-byte sectors and not 0, of host memory at `addr`, or zeros when `addr` is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub addr: u64,
    pub len: u64,
}
const _: () = assert!(size_of::<Extent>() == 16);

/// At most this many extents make one disk (the kernel's `MEMBLK_MAX_EXTENTS`).
pub const MAX_EXTENTS: usize = 1 << 20;

/// A new memblk disk of `extents`, in order; returns its device number (`new_encode_dev`'s, as
/// `mknod` takes it). The kernel copies the table: where a block is in host memory is the
/// caller's to know from its own (the kernel has no call for it). Not registered for [`pread`]
/// and [`locate`]: [`add`] does that for a disk of one mapping.
///
/// # Safety
/// Each extent's memory stays mapped, readable and unchanged for as long as the process lives.
pub unsafe fn disk(sys: Syscall, extents: &[Extent]) -> Result<usize, Errno> {
    res(sys(l::__lkl__NR_memblk_add, [extents.as_ptr() as usize, extents.len(), 0, 0, 0, 0]))
}

/// Make `[addr, addr + len)` (host memory, read-only and unchanged for the process's life) the
/// guest's next memblk disk, of that one extent; returns its device number (`new_encode_dev`'s, as `mknod` takes it).
/// `in_zone`: where the same image is mapped privately in the arena's image zone, if it is.
///
/// # Safety
/// The memory stays mapped, readable and unchanged for as long as the process lives; so does
/// `in_zone`'s mapping, holding the same bytes until the program writes it. Not called from two
/// threads at once.
pub unsafe fn add(sys: Syscall, addr: *const u8, len: usize, in_zone: Option<usize>) -> Result<usize, Errno> {
    let n = COUNT.load(Ordering::Relaxed);
    if n == MAX {
        return Err(Errno::NOSPC);
    }
    // SAFETY: the caller's.
    let dev = unsafe { disk(sys, &[Extent { addr: addr as u64, len: len as u64 }]) }?;
    DEV[n].store(dev, Ordering::Relaxed);
    ADDR[n].store(addr as usize, Ordering::Relaxed);
    LEN[n].store(len, Ordering::Relaxed);
    IN_ZONE[n].store(in_zone.unwrap_or(0), Ordering::Relaxed);
    COUNT.store(n + 1, Ordering::Release);
    Ok(dev)
}

fn res(r: isize) -> Result<usize, Errno> {
    if r < 0 { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

/// `include/uapi/linux/fiemap.h`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FiemapExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}
const _: () = assert!(size_of::<FiemapExtent>() == 56);

/// How many extents one call asks for: a flat erofs file is one.
const EXTENTS: usize = 4;

#[repr(C)]
#[derive(Default)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped_extents: u32,
    extent_count: u32,
    reserved: u32,
    extents: [FiemapExtent; EXTENTS],
}

/// `_IOWR('f', 11, struct fiemap)`.
const FS_IOC_FIEMAP: usize = 0xc020_660b;
const FIEMAP_EXTENT_LAST: u32 = 0x1;
/// `FIEMAP_EXTENT_MERGED`: the only other flag a plain extent may carry.
const FIEMAP_EXTENT_MERGED: u32 = 0x1000;

/// Where `fd`'s bytes from `offset` on are, all of them in one run in an image: the image (its
/// index), their offset in it, and how many bytes there are (to the file's end, at least one).
fn find(sys: Syscall, fd: usize, offset: u64) -> Option<(usize, u64, u64)> {
    let n = COUNT.load(Ordering::Acquire);
    if n == 0 {
        return None;
    }
    let mut st = LklStat::default();
    res(sys(l::__lkl__NR_fstat, [fd, &mut st as *mut _ as usize, 0, 0, 0, 0])).ok()?;
    if st.st_mode & 0o170000 != 0o100000 {
        return None;
    }
    let i = (0..n).find(|&i| DEV[i].load(Ordering::Relaxed) as u64 == st.st_dev)?;
    let size = LEN[i].load(Ordering::Relaxed) as u64;
    let end = st.st_size as u64;
    if offset >= end {
        return None;
    }
    let mut map = Fiemap { start: offset, length: end - offset, extent_count: EXTENTS as u32, ..Default::default() };
    res(sys(l::__lkl__NR_ioctl, [fd, FS_IOC_FIEMAP, &mut map as *mut _ as usize, 0, 0, 0])).ok()?;
    // One run: extents that follow each other in the file and in the image, from before
    // `offset` to past `end`, plain (not inline, encoded or unwritten) and inside the image.
    let extents = &map.extents[..(map.mapped_extents as usize).min(EXTENTS)];
    let first = extents.first()?;
    let at = first.physical.checked_add(offset.checked_sub(first.logical)?)?;
    let mut next = first.logical;
    for e in extents {
        let plain = e.flags & !(FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_MERGED) == 0;
        let in_run = e.logical == next && e.physical.checked_sub(first.physical)? == e.logical - first.logical;
        let inside = e.physical.checked_add(e.length).is_some_and(|p| p <= size);
        if !plain || !in_run || !inside {
            return None;
        }
        next = e.logical + e.length;
    }
    (next >= end).then_some((i, at, end - offset))
}

/// Copy up to `len` bytes of `fd` (the guest's) at `offset` to `addr`, as `pread` would, from
/// the image's read-only host mapping. `None`: not a file this can serve (read it the usual
/// way); nothing was written to `addr` then.
///
/// # Safety
/// `[addr, addr + len)` is writable memory nothing else uses during the call.
pub unsafe fn pread(sys: Syscall, fd: usize, offset: u64, addr: usize, len: usize) -> Option<usize> {
    // (At the end of the file, None: pread's 0 reads nothing into the page cache either.)
    let (i, at, avail) = find(sys, fd, offset)?;
    let n = avail.min(len as u64) as usize;
    let src = ADDR[i].load(Ordering::Relaxed) + at as usize;
    // SAFETY: inside the image (`find` checked) and the caller's buffer.
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, addr as *mut u8, n) };
    Some(n)
}

/// Where `fd`'s bytes from `offset` on are in the arena's image zone, and how many there are
/// (to the file's end): `arena::Backing::locate`.
pub fn locate(sys: Syscall, fd: usize, offset: u64) -> Option<(usize, u64)> {
    let (i, at, avail) = find(sys, fd, offset)?;
    let zone = IN_ZONE[i].load(Ordering::Relaxed);
    (zone != 0).then(|| (zone + at as usize, avail))
}
