//! Host directories for the guest, through Linux's own virtio-fs driver.
//!
//! The guest kernel mounts `-t virtiofs <tag>`: its stock driver (`fs/fuse/virtio_fs.c`) puts
//! FUSE requests on a virtqueue of a virtio-mmio device. [`device`] is that device, the host's
//! side: it takes each request off the queue as bytes and serves it in this process
//! ([`passthrough`]: a host directory, by the plain file calls unsharek-tcb's fs plugin allows,
//! each through the runtime's gate), then puts the reply's bytes back.
//!
//! The device's MMIO registers are LKL's `iomem_access` host op ([`iomem_access`], [`ioremap`]);
//! its interrupt, its registration and its host calls are the caller's ([`Host`],
//! [`passthrough::Sys`]): this crate knows nothing of LKL.

pub mod device;
pub mod passthrough;

pub use device::{Devices, Host, add, install, iomem_access, ioremap};

/// The most data a FUSE read or write carries (the passthrough's `max_write`, and the guest's
/// reads, which `max_pages` bounds): 1 MiB.
pub const MAX_DATA: usize = 1 << 20;
