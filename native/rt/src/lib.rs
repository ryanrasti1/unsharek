//! exobox's in-sandbox runtime: the code that runs after lockdown, in the SIGSYS handler and as
//! the guest kernel's host operations.
//!
//! Rules for everything in this crate (they are why it is `no_std`):
//! - **No heap allocation**, but in the networking hooks' executor (`executor`, `tsi`, `dns`).
//!   After lockdown there is no host `mmap`, and the binary's malloc takes locks that would need
//!   host futexes. Storage is fixed-capacity (static) or handed in by the caller. The executor's
//!   tasks are the hooks' futures, boxed: they use `alloc`, served after lockdown by the
//!   binary's global allocator from a region reserved before it (exobox's `alloc`).
//! - **No thread-locals, no std.** The FS register belongs to the program while it runs; the
//!   runtime's state is reached through globals or explicit pointers.
//! - **No unwinding.** The crate is built `panic=abort` into the binary; a panic is a bug that
//!   ends the sandbox.
//! - **Host syscalls through the gate after lockdown** (`trap::gate` and its typed wrappers), and
//!   only those the filter (`filter`) allows from it. rustix's raw Linux backend (or the gate) is
//!   for setup before lockdown: rustix's own `syscall` instructions are not the gate, so after
//!   lockdown they trap.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arena;
pub mod context;
pub mod dns;
pub mod exec;
pub mod executor;
pub mod filter;
pub mod futex;
pub mod guest;
pub mod host;
pub mod memblk;
pub mod sched;
pub mod sync;
pub mod sysmap;
pub mod trap;
pub mod tsi;
pub mod xabi;
#[cfg(test)]
mod testutil;
