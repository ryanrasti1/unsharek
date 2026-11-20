//! The device's socket to its server: a unix stream, one message each way per request, each a
//! little-endian `u32` length and that many bytes. The sandbox sends a FUSE request
//! (`fuse_in_header` and its arguments); the server answers with its reply (`fuse_out_header`
//! first), or with length 0 for a request that has none (`FORGET`, `BATCH_FORGET`). In lockstep:
//! one request, then its answer.
//!
//! A stream, not a seqpacket socket: a FUSE write's request is up to [`MAX_DATA`] and more, and a
//! seqpacket message can be no larger than the socket's send buffer, which an unprivileged
//! process can't raise past `net.core.wmem_max` (about 200 KiB by default). The sandbox's side is
//! `read` and `write` on one granted fd, which its filter already allows.

/// The most data a FUSE read or write carries (the server's `max_write`, and the guest's reads,
/// which the server's `max_pages` bounds): 1 MiB.
pub const MAX_DATA: usize = 1 << 20;

/// The header of a message: its length.
pub fn header(len: usize) -> [u8; 4] {
    (len as u32).to_le_bytes()
}

/// A message's length, from its header.
pub fn len(header: [u8; 4]) -> usize {
    u32::from_le_bytes(header) as usize
}
