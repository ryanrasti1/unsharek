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
//!   in fork mode, by exobox's `Guest::boot` (its inventory).
//!
//! In coroutine and threaded mode nothing is remapped: the section is ordinary data.

/// The section the shared statics are in: `#[unsafe(link_section = "exobox_shared")]` (a literal:
/// the attribute takes no constant). Named as a C identifier, so the linker defines its bounds.
pub const SHARED: &str = "exobox_shared";

unsafe extern "C" {
    // The linker's bounds of the output section `exobox_shared` (defined for a section whose name
    // is a C identifier, when referenced).
    static __start_exobox_shared: u8;
    static __stop_exobox_shared: u8;
}


/// The shared section, `[lo, hi)`: whole pages.
pub fn section() -> (usize, usize) {
    // Only the symbols' addresses are taken.
    (&raw const __start_exobox_shared as usize, &raw const __stop_exobox_shared as usize)
}
