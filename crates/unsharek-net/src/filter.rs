//! The provider's own filter (plugin: capnweb, experimental): what serving the sandbox takes, and
//! nothing that opens a file. One connect is `socket` (TCP, IPv4 or IPv6), a nonblocking
//! `connect`, `poll` and `getsockopt` for its end, `fcntl` for its flags; one lookup a UDP `socket`,
//! `bind`, `connect`, `setsockopt` (a timeout), `sendto` and `recvfrom`; one reply a `write` or, with
//! the socket in it, a `sendmsg` on the control socket only, then the socket's `close`. The rest is
//! a single-threaded Rust process's: memory, futexes, signal returns, the exit. Proven equal to
//! its program like the sandbox's (`policy!`).

use libc::{seccomp_data, sock_filter};
use libc::{
    SYS_bind, SYS_brk, SYS_close, SYS_connect, SYS_exit, SYS_exit_group, SYS_fcntl, SYS_futex, SYS_getrandom,
    SYS_getsockopt, SYS_ioctl, SYS_madvise, SYS_mmap, SYS_mprotect, SYS_mremap, SYS_munmap, SYS_poll, SYS_ppoll, SYS_read, SYS_recvfrom,
    SYS_rt_sigprocmask, SYS_rt_sigreturn, SYS_sendmsg, SYS_sendto, SYS_setsockopt, SYS_sigaltstack, SYS_socket,
    SYS_write,
};
pub use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS};

/// include/uapi/linux/audit.h's `AUDIT_ARCH_X86_64` (as unsharek-tcb's).
const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | 0x8000_0000 | 0x4000_0000;

/// The provider's verdict on a call `d`; `ctl` is its end of the control socket.
pub fn policy(ctl: u64) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        if d.arch != AUDIT_ARCH_X86_64 || d.nr as u32 >= 0x4000_0000 {
            return SECCOMP_RET_KILL_PROCESS;
        }
        match d.nr as i64 {
            // Its fds: the control socket, the sockets it dials, the lookup's.
            SYS_read | SYS_write | SYS_close | SYS_ppoll | SYS_poll | SYS_fcntl => SECCOMP_RET_ALLOW,
            // A TCP socket (close-on-exec), IPv4 or IPv6: a dial; a UDP one: a lookup.
            SYS_socket
                if (d.args[0] == libc::AF_INET as u64 || d.args[0] == libc::AF_INET6 as u64)
                    && (d.args[1] == (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64
                        || d.args[1] == (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as u64)
                    && d.args[2] == 0 =>
            {
                SECCOMP_RET_ALLOW
            }
            // A dialled socket made nonblocking (std's `FIONBIO`), nothing else of ioctl's.
            SYS_ioctl if d.args[1] == libc::FIONBIO => SECCOMP_RET_ALLOW,
            SYS_connect | SYS_bind | SYS_getsockopt | SYS_setsockopt | SYS_sendto | SYS_recvfrom => SECCOMP_RET_ALLOW,
            // A reply with a dialled socket in it: on the control socket only, no flags.
            SYS_sendmsg if d.args[0] == ctl && d.args[2] == 0 => SECCOMP_RET_ALLOW,
            // A Rust process's own: memory, locks, random seeds, signal returns, its end.
            SYS_mmap | SYS_mprotect | SYS_munmap | SYS_mremap | SYS_brk | SYS_madvise | SYS_futex | SYS_getrandom => SECCOMP_RET_ALLOW,
            SYS_rt_sigreturn | SYS_rt_sigprocmask | SYS_sigaltstack | SYS_exit | SYS_exit_group => SECCOMP_RET_ALLOW,
            // Nothing else: no file opened, no process made, no exec.
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

seccomp_fn_verify::policy!(policy, filter, unwind = 100, (_));

/// [`policy`]'s program, for the provider's control socket `ctl`.
pub fn filter(ctl: u64) -> Vec<sock_filter> {
    seccomp_fn::compile!(policy(ctl))
}
