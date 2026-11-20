//! Host directories for the guest, through Linux's own virtio-fs driver.
//!
//! The guest kernel mounts `-t virtiofs <tag>`: its stock driver (`fs/fuse/virtio_fs.c`) puts
//! FUSE requests on a virtqueue of a virtio-mmio device. [`device`] is that device, the host's
//! side: it takes each request off the queue as bytes, hands it to a [`Backend`], and puts the
//! reply's bytes back. The backend is the file system: [`passthrough`] serves a host directory
//! with virtiofsd's passthrough file system (fuse-backend-rs). A backend sees FUSE messages only,
//! so it can live elsewhere (another process, across a socket) without the device changing.
//!
//! The device's MMIO registers are LKL's `iomem_access` host op ([`iomem_access`], [`ioremap`]);
//! its interrupt and registration are the caller's ([`Host`]): this crate knows nothing of LKL.

pub mod device;
#[cfg(feature = "passthrough")]
pub mod passthrough;

pub use device::{Host, VirtioFs, ioremap, iomem_access};

/// A FUSE file system, as virtio-fs carries it: one request in, its reply out.
pub trait Backend: Send {
    /// Answer `request` (a FUSE message: `fuse_in_header` and its arguments) into `reply`, and
    /// say how many bytes of it the reply is (`fuse_out_header` first); 0 for a request with no
    /// reply (`FORGET`, `BATCH_FORGET`).
    fn handle(&mut self, request: &[u8], reply: &mut [u8]) -> usize;
}
