//! **Plugin (experimental).** A host directory for a sandbox's virtio-fs device (unsharek-fs),
//! served from a process of its own: virtiofsd's passthrough file system (fuse-backend-rs) on the
//! other end of the device's socket. When enabled, this crate is part of the TCB (its process's
//! confinement), but not the core sandbox's: the sandbox's own filter gains nothing, and the
//! server is a granted socket to it.
//!
//! [`spawn`] makes the socket and the server, before the sandbox boots. The server confines
//! itself before it reads a request, in this order:
//! 1. Its fds: the socket, stderr, and what the file system opens (the directory, `/proc/self/fd`
//!    for reopening its inodes, a memfd for its replies); every other fd closed.
//! 2. Landlock: the directory, read-only (`--ro`) or read-write (`--rw`), and nothing else on the
//!    file system, so `..`, symlinks, renames and hard links can't reach outside it whatever the
//!    file system code does (the kernel resolves and checks each access).
//! 3. Core dumps off and not dumpable, every capability dropped, `no_new_privs`.
//! 4. Its seccomp filter ([`policy`]): the calls the file system makes, proven like the
//!    sandbox's.
//!
//! Its file system code isn't trusted: it runs under all four. The sandbox can send it anything
//! (a compromised program writes the guest kernel's memory, and so the device's requests); the
//! worst it can do is what the directory's Landlock rules allow.

pub mod policy;
#[cfg(feature = "serve")]
mod serve;

#[cfg(feature = "serve")]
pub use serve::{Dir, spawn};
