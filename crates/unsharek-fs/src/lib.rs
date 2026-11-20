//! Host directories for the guest, through Linux's own virtio-fs driver.
//!
//! The guest kernel mounts `-t virtiofs <tag>`: its stock driver (`fs/fuse/virtio_fs.c`) puts
//! FUSE requests on a virtqueue of a virtio-mmio device. [`device`] is that device, the host's
//! side: it takes each request off the queue as bytes, sends it to the device's server over a
//! socket ([`wire`]), and puts the reply's bytes back. The server is another process (the
//! `unsharek-fs-server` plugin serves a host directory), so the sandbox's part is `read` and
//! `write` on one granted fd: nothing its filter doesn't already allow.
//!
//! The device's MMIO registers are LKL's `iomem_access` host op ([`iomem_access`], [`ioremap`]);
//! its interrupt, its round trip and its registration are the caller's ([`Host`]): this crate
//! knows nothing of LKL.

pub mod device;
pub mod wire;

pub use device::{Devices, Host, add, install, iomem_access, ioremap};
