//! Lockdown: the moment the process stops being the host's. One function, [`lockdown`], in this
//! order, before anything untrusted runs (the program's exec, `run_fn`'s closure, the network
//! hooks' first task):
//!
//! 0. the routing filter is in (the caller's `guest::route`, before; not TCB: it only routes);
//! 1. exactly the inventory's host threads exist;
//! 2. every fd not in the inventory is closed;
//! 3. the caller's restrictions, then the security filter, installed; the security filter with
//!    TSYNC, so it covers every thread of the process, and a failure to sync is lockdown's
//!    failure.
//!
//! The caller then hands over to the runtime. If lockdown fails, nothing untrusted has run, and
//! the caller reports the error.

use std::io;
use std::os::fd::RawFd;

use super::filter::SockFilter;
use super::inventory::{Inventory, sys};

const NR_CLOSE: usize = 3;
const NR_OPENAT: usize = 257;
const NR_READ: usize = 0;
const NR_PPOLL: usize = 271;
const NR_PRCTL: usize = 157;
const NR_SECCOMP: usize = 317;
const NR_CLOSE_RANGE: usize = 436;

/// Lock the process down (the module comment): `security` is the inventory's filter
/// ([`super::filter::security`]), `restrictions` the caller's, each already behind its prologue
/// ([`super::filter::restriction`]). Allocates nothing.
pub(crate) fn lockdown(inv: &Inventory, restrictions: &[Vec<SockFilter>], security: &[SockFilter]) -> io::Result<()> {
    // 1. A thread of the caller's would be left under the security filter (TSYNC) but serving
    // nothing, or run code we don't know. A thread just joined (the image cache's builders) is
    // still listed while it finishes exiting: a few milliseconds' grace.
    let mut threads = 0;
    for _ in 0..100 {
        threads = host_threads()?;
        if threads <= inv.threads() {
            break;
        }
        let ms = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let _ = sys(NR_PPOLL, [0, 0, &ms as *const _ as usize, 0, 8, 0]);
    }
    if threads != inv.threads() {
        return Err(io::Error::other(format!(
            "{threads} host threads at lockdown, {} expected: the others would run unknown code in the sandbox",
            inv.threads()
        )));
    }
    // 2. Every fd outside the inventory closed: between and above the kept ones.
    let mut keep: Vec<RawFd> = inv.fds().iter().map(|&(fd, _)| fd).collect();
    keep.sort_unstable();
    keep.dedup();
    let mut next: u32 = 0;
    for &fd in &keep {
        let fd = fd as u32;
        if fd > next {
            sys(NR_CLOSE_RANGE, [next as usize, (fd - 1) as usize, 0, 0, 0, 0])?;
        }
        next = fd + 1;
    }
    sys(NR_CLOSE_RANGE, [next as usize, u32::MAX as usize, 0, 0, 0, 0])?;
    // 3. The filters. Restrictions first (each lets the next install through); the security filter
    // last, which refuses `seccomp` and `prctl`: nothing can be stacked after it.
    for r in restrictions {
        install(r, false)?;
    }
    install(security, true)
}

/// The number of host threads in this process (`Threads:` of /proc/self/status, read through
/// the gate: lockdown runs while the routing filter traps every other call).
fn host_threads() -> io::Result<usize> {
    let fd = sys(NR_OPENAT, [libc::AT_FDCWD as usize, c"/proc/self/status".as_ptr() as usize, libc::O_RDONLY as usize, 0, 0, 0])?;
    let mut buf = [0u8; 4096];
    let r = sys(NR_READ, [fd, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0]);
    let _ = sys(NR_CLOSE, [fd, 0, 0, 0, 0, 0]);
    let text = &buf[..r?];
    text.split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"Threads:"))
        .and_then(|n| std::str::from_utf8(n).ok()?.trim().parse().ok())
        .ok_or_else(|| io::Error::other("no thread count in /proc/self/status"))
}

/// `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// no_new_privs, then `insns` installed (`SECCOMP_SET_MODE_FILTER`), with TSYNC on every thread
/// of the process when `all_threads`. Through the gate: the routing filter traps every other
/// call (seccompiler's own `apply_filter_all_threads` makes them with libc's `syscall`, which
/// would be served by the guest).
pub(crate) fn install(insns: &[SockFilter], all_threads: bool) -> io::Result<()> {
    let len = u16::try_from(insns.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // prctl(PR_SET_NO_NEW_PRIVS, 1): unprivileged seccomp needs it, and no setuid gains after.
    sys(NR_PRCTL, [libc::PR_SET_NO_NEW_PRIVS as usize, 1, 0, 0, 0, 0])?;
    let fprog = SockFprog { len, filter: insns.as_ptr() };
    let flags = if all_threads { libc::SECCOMP_FILTER_FLAG_TSYNC as usize } else { 0 };
    let r = sys(NR_SECCOMP, [libc::SECCOMP_SET_MODE_FILTER as usize, flags, &fprog as *const SockFprog as usize, 0, 0, 0])?;
    // With TSYNC, a positive result is the id of a thread that couldn't be synced.
    if r != 0 {
        return Err(io::Error::other(format!("host thread {r} couldn't take the security filter (TSYNC)")));
    }
    Ok(())
}
