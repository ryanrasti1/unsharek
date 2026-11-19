//! exobox's batteries: what a sandbox is set up and served with, none of it trusted to protect
//! the host. exobox re-exports each module (`exobox::setup`, `exobox::store`, `exobox::net`,
//! `exobox::alloc`); the TCB is exobox's own `src/tcb`.
//!
//! - [`setup`]: the guest's basics and its mounts, as ordinary Rust inside a guard;
//! - [`store`]: Nix closures as erofs images, built and cached on the host;
//! - [`image`]: an image's block device in the guest, and its ELFs' layout;
//! - [`net`]: the network hooks' glue. They run after lockdown, in the program's address space:
//!   a check inside one is the program's to skip. Policy lives at the far end of the held fds;
//! - [`alloc`]: the global allocator after lockdown.

pub mod alloc;
pub mod image;
pub mod net;
pub mod setup;
pub mod store;
