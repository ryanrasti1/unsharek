//! A host directory as the guest's file system: virtiofsd's passthrough file system
//! (fuse-backend-rs's `PassthroughFs`, which virtiofsd itself grew from), answering each request.
//!
//! fuse-backend-rs writes a reply to a `/dev/fuse` fd (`FuseDevWriter`): here one end of a
//! `SOCK_SEQPACKET` pair, whose other end the reply is read back from whole. So the server sees
//! exactly the transport a separate server process would: a message out, a message back.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use fuse_backend_rs::transport::{FuseBuf, FuseDevWriter, Reader, Writer};

use crate::Backend;

/// `root`, served read-write (or read-only: `writable` false).
pub struct Passthrough {
    server: Server<PassthroughFs>,
    tx: OwnedFd,
    rx: OwnedFd,
    request: Vec<u8>,
    scratch: Vec<u8>,
    writable: bool,
}

impl Passthrough {
    /// Open `root` (host code: before lockdown).
    pub fn new(root: &str, writable: bool) -> io::Result<Passthrough> {
        let cfg = Config { root_dir: root.into(), do_import: true, xattr: false, ..Default::default() };
        let fs = PassthroughFs::new(cfg)?;
        fs.import()?;
        let mut sv = [0; 2];
        // SAFETY: socketpair into a local array.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the fresh pair's fds, owned from here.
        let (tx, rx) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
        Ok(Passthrough { server: Server::new(fs), tx, rx, request: Vec::new(), scratch: vec![0; (1 << 20) + 4096], writable })
    }
}

/// FUSE opcodes that change the file system: refused (EROFS) when read-only.
const WRITES: &[u32] = &[
    4,  // SETATTR
    6,  // SYMLINK
    8,  // MKNOD
    9,  // MKDIR
    10, // UNLINK
    11, // RMDIR
    12, // RENAME
    13, // LINK
    16, // WRITE
    21, // SETXATTR
    24, // REMOVEXATTR
    35, // CREATE
    43, // FALLOCATE
    45, // RENAME2
    47, // COPY_FILE_RANGE
];

impl Backend for Passthrough {
    fn handle(&mut self, request: &[u8], reply: &mut [u8]) -> usize {
        let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
        if !self.writable && WRITES.contains(&opcode) {
            // fuse_out_header: len, error (-EROFS), unique
            let unique = &request[8..16];
            reply[..4].copy_from_slice(&16u32.to_le_bytes());
            reply[4..8].copy_from_slice(&(-libc::EROFS).to_le_bytes());
            reply[8..16].copy_from_slice(unique);
            return 16;
        }
        self.request.clear();
        self.request.extend_from_slice(request);
        let Ok(r) = Reader::<()>::from_fuse_buffer(FuseBuf::new(&mut self.request)) else { return 0 };
        let Ok(w) = FuseDevWriter::<()>::new(self.tx.as_raw_fd(), &mut self.scratch) else { return 0 };
        if self.server.handle_message(r, Writer::FuseDev(w), None, None).is_err() {
            return 0;
        }
        // The reply, if the request has one (FORGET has none: nothing was sent).
        let mut n = 0;
        // SAFETY: a nonblocking read into `reply`.
        let got = unsafe { libc::recv(self.rx.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), libc::MSG_DONTWAIT) };
        if got > 0 {
            n = got as usize;
        }
        n
    }
}
