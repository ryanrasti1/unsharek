//! The process's global allocator: the system's (glibc's malloc) until lockdown, then talc over a
//! region reserved before it.
//!
//! Why a global allocator, not one for the runtime's tasks alone: what runs after lockdown, on
//! the sandbox's executor, is the hooks' ordinary Rust (a provider's session, its `Vec`s and
//! `Box`es, the futures unsharek boxes for it), and all of it allocates through the global
//! allocator. glibc's malloc can't serve it then: it grows with `mmap` (none after lockdown; in
//! the program's phase a trapped `mmap` would be served from the program's arena) and `brk`
//! (emulated in the arena), and its locks would need host futexes. So unsharek, a library that
//! takes its process over anyway (one sandbox per process), sets the global allocator: a binary
//! that links unsharek can't choose its own.
//!
//! - Before [`lockdown`]: everything is the system's.
//! - After: new blocks are talc's, from [`reserve`]'s region (reserved, not committed: it costs
//!   what is touched; never given back to the host, which allows no `madvise` outside the arena).
//!   A system block freed then is leaked (glibc's free could trim with `munmap` or `brk`); one
//!   grown is moved into talc's region. Running out is an allocation failure (the sandbox ends).
//! - talc's lock is a spin lock: no futex, and ready for threaded mode's host threads.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use talc::lock_api::{GuardSend, RawMutex};
use talc::source::Manual;
use talc::TalcLock;

/// The region's size: the hooks' heap after lockdown. Reserved with `MAP_NORESERVE`, so only what
/// is used is paid for.
pub const REGION: usize = 256 << 20;

/// A spin lock for talc: no host futex after lockdown.
pub struct Spin(AtomicBool);

// SAFETY: a mutex: lock and try_lock acquire, unlock releases, one holder at a time.
unsafe impl RawMutex for Spin {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: Spin = Spin(AtomicBool::new(false));
    type GuardMarker = GuardSend;

    fn lock(&self) {
        while !self.try_lock() {
            std::hint::spin_loop();
        }
    }

    fn try_lock(&self) -> bool {
        self.0.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    unsafe fn unlock(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// unsharek's global allocator (see the module comment).
pub struct Alloc {
    talc: TalcLock<Spin, Manual>,
    locked: AtomicBool,
    base: AtomicUsize,
    end: AtomicUsize,
}

#[global_allocator]
static ALLOC: Alloc = Alloc {
    talc: TalcLock::new(Manual),
    locked: AtomicBool::new(false),
    base: AtomicUsize::new(0),
    end: AtomicUsize::new(0),
};

impl Alloc {
    fn ours(&self, p: *mut u8) -> bool {
        let p = p as usize;
        p >= self.base.load(Ordering::Relaxed) && p < self.end.load(Ordering::Relaxed)
    }
}

/// Reserve the region and give it to talc. Host code, before lockdown (`Guest::boot`); once.
pub fn reserve() -> std::io::Result<()> {
    if ALLOC.base.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
    // SAFETY: a fresh anonymous mapping, the allocator's for the process's life.
    let p = unsafe { libc::mmap(std::ptr::null_mut(), REGION, libc::PROT_READ | libc::PROT_WRITE, flags, -1, 0) };
    if p == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the region is ours, readable and writable, overlapping nothing talc has.
    unsafe { ALLOC.talc.lock().claim(p as *mut u8, REGION) }
        .ok_or_else(|| std::io::Error::other("talc refused the region"))?;
    ALLOC.base.store(p as usize, Ordering::Release);
    ALLOC.end.store(p as usize + REGION, Ordering::Release);
    Ok(())
}

/// From now on, allocations are talc's (just before the filter, which allows no host
/// memory call). Idempotent; without [`reserve`], nothing changes.
pub fn lockdown() {
    if ALLOC.base.load(Ordering::Acquire) != 0 {
        ALLOC.locked.store(true, Ordering::Release);
    }
}

// SAFETY: each block is served and freed by one allocator: talc's region by talc, the rest by the
// system's (or leaked after lockdown); realloc moves a block between them by copying.
unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.locked.load(Ordering::Acquire) {
            // SAFETY: the caller's layout.
            unsafe { self.talc.alloc(layout) }
        } else {
            // SAFETY: as above.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if self.locked.load(Ordering::Acquire) {
            // SAFETY: the caller's layout.
            unsafe { self.talc.alloc_zeroed(layout) }
        } else {
            // SAFETY: as above.
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if self.ours(p) {
            // SAFETY: talc's block, with its layout.
            unsafe { self.talc.dealloc(p, layout) }
        } else if !self.locked.load(Ordering::Acquire) {
            // SAFETY: the system's block, with its layout.
            unsafe { System.dealloc(p, layout) }
        }
        // else: the system's block after lockdown, leaked (see the module comment).
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if self.ours(p) {
            // SAFETY: talc's block, with its layout.
            return unsafe { self.talc.realloc(p, layout, new_size) };
        }
        if !self.locked.load(Ordering::Acquire) {
            // SAFETY: the system's block, with its layout.
            return unsafe { System.realloc(p, layout, new_size) };
        }
        // The system's block after lockdown: moved into talc's region, the old one leaked.
        // SAFETY: new_size is the caller's valid size for this alignment.
        let new = unsafe { self.talc.alloc(Layout::from_size_align_unchecked(new_size, layout.align())) };
        if !new.is_null() {
            // SAFETY: both blocks are at least the smaller size, and distinct.
            unsafe { std::ptr::copy_nonoverlapping(p, new, layout.size().min(new_size)) };
        }
        new
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_then_talc() {
        let mut grown: Vec<u8> = vec![1; 100];
        let freed: Vec<u8> = vec![1; 100];
        super::reserve().unwrap();
        assert!(!super::ALLOC.ours(grown.as_mut_ptr()));
        super::lockdown();
        let mut after: Vec<u8> = vec![2; 100_000];
        assert!(super::ALLOC.ours(after.as_mut_ptr()));
        // A block from before, freed after: leaked, not given to talc.
        drop(freed);
        // A block from before, grown after: moved into the region.
        grown.extend_from_slice(&after);
        assert!(super::ALLOC.ours(grown.as_mut_ptr()));
        assert_eq!(grown.len(), 100_100);
    }
}
