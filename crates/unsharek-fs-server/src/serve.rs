//! The server: its process, its confinement, and its loop.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use fuse_backend_rs::transport::{FuseBuf, FuseDevWriter, Reader, Writer};
use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
use unsharek_fs::wire;

/// A host directory to serve, and how.
#[derive(Clone, Debug, Default)]
pub struct Dir {
    pub host: PathBuf,
    pub writable: bool,
    /// Tests only: a read-only server without its early refusal of the write opcodes, so that
    /// Landlock's read-only rules alone are what refuses (tests/server.rs).
    #[doc(hidden)]
    pub landlock_only: bool,
}

/// The server for `dir`, as a process of its own: the sandbox's end of its socket (a unix
/// stream, unsharek-fs's `wire`), for the device (`unsharek::hostfs::add`) and the sandbox's
/// grants. The server is a grandchild (forked twice, its parent gone), so it is no child of the
/// sandbox's: fork mode's init waits for its children, and this one must not be one. It ends when
/// the sandbox's end closes (EOF). Before the sandbox boots, while this process has one thread
/// (`fork`).
pub fn spawn(dir: &Dir) -> io::Result<OwnedFd> {
    let root = CString::new(dir.host.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::other("a NUL in the path"))?;
    if !dir.host.is_dir() {
        return Err(io::Error::other(format!("{}: not a directory", dir.host.display())));
    }
    let mut sv = [0; 2];
    // SAFETY: socketpair into a local array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the fresh pair's fds, owned from here.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    // SAFETY: fork while single-threaded (this function's contract); the child forks again and
    // exits, the grandchild serves and never returns.
    match unsafe { libc::fork() } {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // SAFETY: as above.
            if unsafe { libc::fork() } == 0 {
                drop(ours);
                let code = match serve(theirs, &root, dir) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("unsharek fs server ({}): {e}", dir.host.display());
                        1
                    }
                };
                // SAFETY: ends the server.
                unsafe { libc::_exit(code) };
            }
            // SAFETY: ends the intermediate child.
            unsafe { libc::_exit(0) };
        }
        child => {
            let mut status = 0;
            // SAFETY: waits for the intermediate child, which exits at once.
            unsafe { libc::waitpid(child, &mut status, 0) };
        }
    }
    drop(theirs);
    Ok(ours)
}

/// Confine this process (the module's order: fds, the file system, Landlock, the rest, the
/// filter), then serve `sock` until EOF.
fn serve(sock: OwnedFd, root: &CString, dir: &Dir) -> io::Result<()> {
    // 1. fds: the socket at 3, stderr kept; the rest closed (then the file system's own).
    // SAFETY: dup2 onto 3, then the socket's old number closed with everything above 3.
    unsafe {
        if libc::dup2(sock.as_raw_fd(), 3) < 0 {
            return Err(io::Error::last_os_error());
        }
        libc::close(0);
        libc::close(1);
        if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::mem::forget(sock); // closed above, by number
    let sock: RawFd = 3;
    let root_s = root.to_str().map_err(|_| io::Error::other("not UTF-8"))?.to_owned();
    // Names and attributes cached by the guest for a second (virtiofsd's own default with its
    // "auto" cache), file data until the file is opened again: the host's changes are seen within
    // a second, a file's new contents at its next open.
    let second = std::time::Duration::from_secs(1);
    let cfg = Config { root_dir: root_s, do_import: true, xattr: false, entry_timeout: second, attr_timeout: second, ..Default::default() };
    let fs = PassthroughFs::<()>::new(cfg)?;
    fs.import()?;
    let server = Server::new(fs);
    // The replies are written here (fuse-backend-rs writes a reply to an fd, as to /dev/fuse),
    // then read back whole: a memfd, so a reply of any size fits.
    // SAFETY: a NUL-terminated name.
    let capture = unsafe { libc::memfd_create(c"reply".as_ptr(), libc::MFD_CLOEXEC) };
    if capture < 0 {
        return Err(io::Error::last_os_error());
    }
    // 2. Landlock: the directory, and nothing else.
    landlock_to(Path::new(&dir.host), dir.writable)?;
    // 3. No core dumps, not dumpable, no capabilities, no_new_privs (Landlock set it too).
    rustix::process::setrlimit(rustix::process::Resource::Core, rustix::process::Rlimit { current: Some(0), maximum: Some(0) })?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    let none = rustix::thread::CapabilitySet::empty();
    rustix::thread::set_capabilities(None, rustix::thread::CapabilitySets { effective: none, permitted: none, inheritable: none })?;
    rustix::thread::set_no_new_privs(true)?;
    // 4. The filter.
    install(&crate::policy::filter())?;
    run(&server, sock, capture, dir.writable || dir.landlock_only)
}

/// This process confined by Landlock to `dir`: read-only, or read-write. Every access right
/// Landlock knows (the newest ABI this kernel has) is handled, so anything not granted here is
/// denied; a kernel without Landlock is an error, not an unconfined server.
fn landlock_to(dir: &Path, writable: bool) -> io::Result<()> {
    let abi = ABI::V5;
    let access = if writable { AccessFs::from_all(abi) } else { AccessFs::from_read(abi) };
    let fd = PathFd::new(dir).map_err(|e| io::Error::other(format!("landlock: {e}")))?;
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rule(PathBeneath::new(fd, access)))
        .and_then(|r| r.restrict_self())
        .map_err(|e| io::Error::other(format!("landlock: {e}")))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(io::Error::other("landlock: not fully enforced"));
    }
    Ok(())
}

/// `prog` installed (`SECCOMP_SET_MODE_FILTER`; one thread, so no TSYNC).
fn install(prog: &[libc::sock_filter]) -> io::Result<()> {
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut libc::sock_filter };
    // SAFETY: seccomp reads `fprog` and the instructions, both live for the call.
    if unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog as *const libc::sock_fprog) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// FUSE opcodes that change the file system: refused (EROFS) by a read-only server before the
/// file system sees them. An early, friendlier error: Landlock's read-only rules are what enforce
/// it (an access they deny is EACCES).
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
const OPEN: u32 = 14;
const LOOKUP: u32 = 1;

/// Serve requests from `sock` until it closes.
fn run(server: &Server<PassthroughFs<()>>, sock: RawFd, capture: RawFd, no_refusal: bool) -> io::Result<()> {
    let mut request = vec![0u8; wire::MAX_DATA + 4096];
    let mut scratch = vec![0u8; wire::MAX_DATA + 4096];
    let mut reply = vec![0u8; wire::MAX_DATA + 4096];
    loop {
        let mut h = [0u8; 4];
        if !read_exact(sock, &mut h)? {
            return Ok(()); // the sandbox is gone
        }
        let n = wire::len(h);
        if n > request.len() || n < 40 {
            return Err(io::Error::other(format!("a request of {n} bytes")));
        }
        read_exact(sock, &mut request[..n])?;
        let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
        // The request's uid and gid (fuse_in_header's, at 24 and 28) are the guest's: the server
        // acts as itself (an unprivileged server can't switch to them; the host's permissions
        // are the server's user's), so they are zeroed, which fuse-backend-rs takes as "don't
        // switch".
        request[24..32].fill(0);
        // An OPEN's flags (fuse_open_in's, after the 40-byte header): a read-only server refuses
        // a write open or a truncation early, as the write opcodes.
        let write_open = opcode == OPEN && n >= 44 && {
            let flags = i32::from_le_bytes(request[40..44].try_into().unwrap());
            flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_TRUNC != 0
        };
        // A LOOKUP of `.` or `..`: refused. The guest's kernel resolves both itself and never asks,
        // but a compromised sandbox can: fuse-backend-rs answered `..` of the root with the
        // directory's parent, outside it, as an O_PATH fd Landlock doesn't check (opening it for
        // reading is checked, and refused; its metadata, and readlink, aren't)
        // (`dotdot_and_slashes_refused`). Names with a slash it refuses itself.
        let dots = opcode == LOOKUP && matches!(&request[40..n], b".\0" | b"..\0");
        let len = if dots {
            error(&request[..n], libc::ENOENT, &mut reply)
        } else if !no_refusal && (WRITES.contains(&opcode) || write_open) {
            error(&request[..n], libc::EROFS, &mut reply)
        } else {
            handle(server, &mut request[..n], capture, &mut scratch, &mut reply)?
        };
        write_all(sock, &wire::header(len))?;
        write_all(sock, &reply[..len])?;
    }
}

/// The reply to `request` from the file system, into `reply`: its length, 0 for none.
fn handle(server: &Server<PassthroughFs<()>>, request: &mut [u8], capture: RawFd, scratch: &mut [u8], reply: &mut [u8]) -> io::Result<usize> {
    // SAFETY: lseek on our memfd.
    unsafe { libc::lseek(capture, 0, libc::SEEK_SET) };
    let unique = request[8..16].to_vec();
    let r = Reader::<()>::from_fuse_buffer(FuseBuf::new(request)).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let w = FuseDevWriter::<()>::new(capture, scratch).map_err(|e| io::Error::other(format!("{e:?}")))?;
    if server.handle_message(r, Writer::FuseDev(w), None, None).is_err() {
        // A request it couldn't decode: EIO, so the guest's caller isn't left waiting.
        let mut req = [0u8; 16];
        req[8..16].copy_from_slice(&unique);
        return Ok(error(&req, libc::EIO, reply));
    }
    // SAFETY: lseek and pread on our memfd, into `reply`.
    let len = unsafe { libc::lseek(capture, 0, libc::SEEK_CUR) };
    if len <= 0 {
        return Ok(0); // no reply (FORGET)
    }
    let len = (len as usize).min(reply.len());
    // SAFETY: as above.
    let got = unsafe { libc::pread(capture, reply.as_mut_ptr().cast(), len, 0) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(got as usize)
}

/// A FUSE error reply (`fuse_out_header`: len, -errno, the request's unique).
fn error(request: &[u8], errno: i32, reply: &mut [u8]) -> usize {
    reply[..4].copy_from_slice(&16u32.to_le_bytes());
    reply[4..8].copy_from_slice(&(-errno).to_le_bytes());
    reply[8..16].copy_from_slice(&request[8..16]);
    16
}

/// `buf` filled from `fd`; false at EOF before the first byte.
fn read_exact(fd: RawFd, buf: &mut [u8]) -> io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: read into the rest of `buf`.
        let r = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        match r {
            0 if got == 0 => return Ok(false),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            r if r < 0 => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            r => got += r as usize,
        }
    }
    Ok(true)
}

fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: write from `buf`.
        let r = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        } else {
            buf = &buf[r as usize..];
        }
    }
    Ok(())
}
