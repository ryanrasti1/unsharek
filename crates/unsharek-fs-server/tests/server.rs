//! The server against a compromised sandbox: it writes the guest kernel's memory, so it can put
//! any FUSE request on the device's queue, not only what the guest's driver sends. These tests
//! talk to a spawned server over its socket directly, as such a sandbox would, and check that
//! nothing reaches outside the directory (`..`, names with a slash, links out, inodes it never
//! looked up), that a read-only server's Landlock rules alone refuse every change, and that its
//! filter kills a call it doesn't list.

use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use unsharek_fs_server::{Dir, spawn};

const LOOKUP: u32 = 1;
const GETATTR: u32 = 3;
const MKDIR: u32 = 9;
const UNLINK: u32 = 10;
const LINK: u32 = 13;
const OPEN: u32 = 14;
const READ: u32 = 15;
const INIT: u32 = 26;
const CREATE: u32 = 35;
const RENAME2: u32 = 45;
const ROOT: u64 = 1;

struct Conn {
    fd: OwnedFd,
    unique: u64,
}

impl Conn {
    fn new(dir: Dir) -> Conn {
        let mut c = Conn { fd: spawn(&dir).unwrap(), unique: 0 };
        // fuse_init_in: major 7, minor 31, max_readahead, flags
        let mut body = vec![];
        for v in [7u32, 31, 1 << 16, 0] {
            body.extend(v.to_le_bytes());
        }
        let (err, _) = c.call(INIT, 0, &body);
        assert_eq!(err, 0, "INIT");
        c
    }

    /// One request: (the reply's error, its payload after `fuse_out_header`).
    fn call(&mut self, opcode: u32, nodeid: u64, body: &[u8]) -> (i32, Vec<u8>) {
        self.unique += 2;
        let len = 40 + body.len();
        let mut req = vec![];
        req.extend((len as u32).to_le_bytes());
        req.extend(opcode.to_le_bytes());
        req.extend(self.unique.to_le_bytes());
        req.extend(nodeid.to_le_bytes());
        req.extend([0u8; 16]); // uid, gid, pid, padding (total_extlen)
        req.extend(body);
        let fd = self.fd.as_raw_fd();
        write_all(fd, &(req.len() as u32).to_le_bytes());
        write_all(fd, &req);
        let mut h = [0u8; 4];
        read_exact(fd, &mut h);
        let mut reply = vec![0u8; u32::from_le_bytes(h) as usize];
        read_exact(fd, &mut reply);
        assert!(reply.len() >= 16, "a reply of {} bytes", reply.len());
        let err = i32::from_le_bytes(reply[4..8].try_into().unwrap());
        (err, reply[16..].to_vec())
    }

    /// LOOKUP `name` in `parent`: its nodeid, or the error.
    fn lookup(&mut self, parent: u64, name: &str) -> Result<u64, i32> {
        let (err, out) = self.call(LOOKUP, parent, &cstr(name));
        if err != 0 { Err(err) } else { Ok(u64::from_le_bytes(out[..8].try_into().unwrap())) }
    }

    fn open(&mut self, node: u64, flags: i32) -> i32 {
        let mut body = (flags as u32).to_le_bytes().to_vec();
        body.extend(0u32.to_le_bytes());
        self.call(OPEN, node, &body).0
    }
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn write_all(fd: i32, mut b: &[u8]) {
    while !b.is_empty() {
        // SAFETY: write from `b`.
        let r = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
        assert!(r > 0, "write: {}", std::io::Error::last_os_error());
        b = &b[r as usize..];
    }
}

fn read_exact(fd: i32, b: &mut [u8]) {
    let mut got = 0;
    while got < b.len() {
        // SAFETY: read into the rest of `b`.
        let r = unsafe { libc::read(fd, b[got..].as_mut_ptr().cast(), b.len() - got) };
        assert!(r > 0, "read: {} (the server is gone)", std::io::Error::last_os_error());
        got += r as usize;
    }
}

/// `<tmp>/inside` (served) with a file `f`, and `<tmp>/outside.txt` next to it; symlinks in
/// `inside` to the outside file, absolute and relative.
fn tree() -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let inside = t.path().join("inside");
    fs::create_dir(&inside).unwrap();
    fs::write(inside.join("f"), "inside").unwrap();
    fs::write(t.path().join("outside.txt"), "outside").unwrap();
    std::os::unix::fs::symlink(t.path().join("outside.txt"), inside.join("abs")).unwrap();
    std::os::unix::fs::symlink("../outside.txt", inside.join("rel")).unwrap();
    std::os::unix::fs::symlink("..", inside.join("up")).unwrap();
    (t, inside)
}

fn untouched(t: &Path, inside: &Path) {
    assert_eq!(fs::read_to_string(t.join("outside.txt")).unwrap(), "outside");
    assert_eq!(fs::read_to_string(inside.join("f")).unwrap(), "inside");
}

#[test]
fn dotdot_and_slashes_refused() {
    let (t, inside) = tree();
    let mut c = Conn::new(Dir { host: inside.clone(), writable: true, ..Default::default() });
    for name in ["..", "../outside.txt", "f/..", "/etc/passwd", "a/b"] {
        assert!(c.lookup(ROOT, name).is_err(), "LOOKUP {name:?} succeeded");
    }
    untouched(t.path(), &inside);
}

#[test]
fn links_out_dont_reach_out() {
    let (t, inside) = tree();
    let mut c = Conn::new(Dir { host: inside.clone(), writable: true, ..Default::default() });
    for link in ["abs", "rel", "up"] {
        // The link itself is an inode of the tree; nothing through it is.
        let node = c.lookup(ROOT, link).expect(link);
        assert_ne!(c.open(node, libc::O_RDONLY), 0, "OPEN {link} reached its target");
        assert!(c.lookup(node, "outside.txt").is_err(), "LOOKUP through {link}");
        assert!(c.lookup(node, "inside").is_err(), "LOOKUP through {link}");
    }
    untouched(t.path(), &inside);
}

#[test]
fn unknown_inodes_refused() {
    let (t, inside) = tree();
    let mut c = Conn::new(Dir { host: inside.clone(), writable: true, ..Default::default() });
    for node in [0u64, 2, 12345, u64::MAX] {
        assert_ne!(c.call(GETATTR, node, &[0u8; 16]).0, 0, "GETATTR of nodeid {node}");
        // A hard link of an inode it never looked up, into the tree.
        let mut body = node.to_le_bytes().to_vec();
        body.extend(cstr("stolen"));
        assert_ne!(c.call(LINK, ROOT, &body).0, 0, "LINK of nodeid {node}");
        // A rename into a directory it never looked up.
        let mut body = node.to_le_bytes().to_vec();
        body.extend([0u8; 8]);
        body.extend(cstr("f"));
        body.extend(cstr("moved"));
        assert_ne!(c.call(RENAME2, ROOT, &body).0, 0, "RENAME2 into nodeid {node}");
    }
    assert!(!inside.join("stolen").exists());
    untouched(t.path(), &inside);
}

/// A read-only server without its early refusal: Landlock's read-only rules alone refuse every
/// change, and reads still work.
#[test]
fn read_only_is_landlocks() {
    let (t, inside) = tree();
    let mut c = Conn::new(Dir { host: inside.clone(), writable: false, landlock_only: true });
    let f = c.lookup(ROOT, "f").unwrap();
    assert_eq!(c.open(f, libc::O_RDONLY), 0, "a read open");
    for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_RDONLY | libc::O_TRUNC] {
        assert_ne!(c.open(f, flags), 0, "OPEN with {flags:#o}");
    }
    // fuse_create_in: flags, mode, umask, open_flags; the name
    let mut create = ((libc::O_WRONLY | libc::O_CREAT) as u32).to_le_bytes().to_vec();
    for v in [0o644u32, 0, 0] {
        create.extend(v.to_le_bytes());
    }
    create.extend(cstr("new"));
    assert_ne!(c.call(CREATE, ROOT, &create).0, 0, "CREATE");
    let mut mkdir = 0o755u32.to_le_bytes().to_vec();
    mkdir.extend(0u32.to_le_bytes());
    mkdir.extend(cstr("d"));
    assert_ne!(c.call(MKDIR, ROOT, &mkdir).0, 0, "MKDIR");
    assert_ne!(c.call(UNLINK, ROOT, &cstr("f")).0, 0, "UNLINK");
    let mut rename = ROOT.to_le_bytes().to_vec();
    rename.extend([0u8; 8]);
    rename.extend(cstr("f"));
    rename.extend(cstr("g"));
    assert_ne!(c.call(RENAME2, ROOT, &rename).0, 0, "RENAME2");
    assert!(!inside.join("new").exists() && !inside.join("d").exists() && !inside.join("g").exists());
    untouched(t.path(), &inside);
}

/// The same requests a read-write server serves (so the read-only test refuses for its rules,
/// not for malformed requests).
#[test]
fn read_write_serves() {
    let (t, inside) = tree();
    let mut c = Conn::new(Dir { host: inside.clone(), writable: true, ..Default::default() });
    let mut create = ((libc::O_WRONLY | libc::O_CREAT) as u32).to_le_bytes().to_vec();
    for v in [0o644u32, 0, 0] {
        create.extend(v.to_le_bytes());
    }
    create.extend(cstr("new"));
    assert_eq!(c.call(CREATE, ROOT, &create).0, 0, "CREATE");
    let mut mkdir = 0o755u32.to_le_bytes().to_vec();
    mkdir.extend(0u32.to_le_bytes());
    mkdir.extend(cstr("d"));
    assert_eq!(c.call(MKDIR, ROOT, &mkdir).0, 0, "MKDIR");
    assert!(inside.join("new").exists() && inside.join("d").is_dir());
    // and a read of f
    let f = c.lookup(ROOT, "f").unwrap();
    let mut open = (libc::O_RDONLY as u32).to_le_bytes().to_vec();
    open.extend(0u32.to_le_bytes());
    let (err, out) = c.call(OPEN, f, &open);
    assert_eq!(err, 0);
    let fh = u64::from_le_bytes(out[..8].try_into().unwrap());
    let mut read = fh.to_le_bytes().to_vec();
    read.extend(0u64.to_le_bytes());
    read.extend(64u32.to_le_bytes());
    read.extend([0u8; 4 + 8 + 4 + 4]);
    let (err, data) = c.call(READ, f, &read);
    assert_eq!((err, &data[..]), (0, &b"inside"[..]));
    untouched(t.path(), &inside);
}

/// The server's filter kills a call it doesn't list (here `socket`), and allows one it does.
#[test]
fn filter_kills_unlisted() {
    let prog = unsharek_fs_server::policy::filter();
    for (call, killed) in [("socket", true), ("getdents64", false)] {
        // SAFETY: the child only installs the filter and makes one call, then exits.
        match unsafe { libc::fork() } {
            0 => unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
                if libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0 {
                    libc::_exit(2);
                }
                if call == "socket" {
                    libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                } else {
                    libc::syscall(libc::SYS_getdents64, -1, 0, 0);
                }
                libc::syscall(libc::SYS_exit_group, 0);
                libc::_exit(0);
            },
            pid => {
                let mut st = 0;
                // SAFETY: waits for our child.
                unsafe { libc::waitpid(pid, &mut st, 0) };
                if killed {
                    assert!(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSYS, "{call}: status {st:#x}");
                } else {
                    assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{call}: status {st:#x}");
                }
            }
        }
    }
}
