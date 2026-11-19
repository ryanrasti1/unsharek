//! The memory fork mode's processes share: the kernel's (its data, its pool, every kernel stack)
//! and the runtime state that runs it (the scheduler, the CPU token, the host ops' pools, the
//! futex table, the process table).
//!
//! A guest fork is a host fork (`fork`), and the processes run one kernel. So everything the kernel
//! and the scheduler touch must be the same memory in every process, at the same address: mapped
//! shared before the first fork, which keeps it shared. Everything else stays private and is copied
//! by the fork: the program's memory (the arena), and the runtime's per-process state (the arena's
//! table, the signal restorers, the exec's scratch, `/proc/self/exe`).
//!
//! - **Statics: one section.** The kernel's writable data is one section of its object,
//!   `exobox_shared` (lkl/Makefile renames its `.data`, `.bss`, `.data.rel` and `.data.rel.local`
//!   to it and ends it with a page of padding, its alignment a page's). The runtime's shared
//!   statics join it with [`SHARED`]'s `#[link_section]` (they come first in the binary: the Rust
//!   objects precede the kernel's in the link). So the binary's `exobox_shared` starts and ends on
//!   a page and holds exactly the shared state; [`remap`] maps it shared, its contents kept.
//! - **The kernel's pool and the coroutine stacks** are reserved shared (anonymous `MAP_SHARED`)
//!   in fork mode, by exobox's `Guest::boot`.
//!
//! In coroutine and threaded mode nothing is remapped: the section is ordinary data.

use rustix::io::Errno;

/// The section the shared statics are in: `#[unsafe(link_section = "exobox_shared")]` (a literal:
/// the attribute takes no constant). Named as a C identifier, so the linker defines its bounds.
pub const SHARED: &str = "exobox_shared";

unsafe extern "C" {
    // The linker's bounds of the output section `exobox_shared` (defined for a section whose name
    // is a C identifier, when referenced).
    static __start_exobox_shared: u8;
    static __stop_exobox_shared: u8;
}

const PAGE: usize = 4096;
const NR_MMAP: usize = 9;
const NR_MREMAP: usize = 25;
const NR_MUNMAP: usize = 11;
const PROT_RW: usize = 1 | 2;
const MAP_SHARED: usize = 0x01;
const MAP_ANONYMOUS: usize = 0x20;
const MAP_NORESERVE: usize = 0x4000;
const MREMAP_MAYMOVE: usize = 1;
const MREMAP_FIXED: usize = 2;

/// The shared section, `[lo, hi)`: whole pages.
pub fn section() -> (usize, usize) {
    // Only the symbols' addresses are taken.
    (&raw const __start_exobox_shared as usize, &raw const __stop_exobox_shared as usize)
}

fn check(r: isize) -> Result<usize, Errno> {
    if (-4095..0).contains(&r) { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

/// Map the shared section shared (anonymous `MAP_SHARED`), its contents kept: a host fork from now
/// on shares it. Pages that are all zeros aren't copied (they cost nothing until written: the
/// kernel's bss, the scheduler's unused slots).
///
/// # Safety
/// Before lockdown, on the only thread that touches the section (nothing writes it meanwhile).
pub unsafe fn remap() -> Result<(), Errno> {
    let (lo, hi) = section();
    if !lo.is_multiple_of(PAGE) || !hi.is_multiple_of(PAGE) || hi <= lo {
        // The link didn't make it whole pages (the kernel object without lkl/Makefile's pad, or
        // the runtime's statics after it): sharing would take in its neighbours.
        return Err(Errno::NOEXEC);
    }
    let len = hi - lo;
    // SAFETY: a fresh mapping, ours.
    let tmp = check(unsafe {
        crate::trap::gate(NR_MMAP, 0, len, PROT_RW, MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, usize::MAX, 0)
    })?;
    let mut p = lo;
    while p < hi {
        // SAFETY: the section is mapped and readable; `tmp` is its size.
        unsafe {
            let page = core::slice::from_raw_parts(p as *const u64, PAGE / 8);
            if page.iter().any(|&w| w != 0) {
                core::ptr::copy_nonoverlapping(p as *const u8, (tmp + (p - lo)) as *mut u8, PAGE);
            }
        }
        p += PAGE;
    }
    // Over the section, atomically: nothing runs in between that could see it unmapped.
    // SAFETY: the caller's; the new mapping has the old one's contents.
    let r = unsafe { crate::trap::gate(NR_MREMAP, tmp, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, lo, 0) };
    if let Err(e) = check(r) {
        // SAFETY: ours, unused.
        unsafe { crate::trap::gate(NR_MUNMAP, tmp, len, 0, 0, 0, 0) };
        return Err(e);
    }
    Ok(())
}
