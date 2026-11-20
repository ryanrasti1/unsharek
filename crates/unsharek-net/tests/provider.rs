//! The provider in a forked child, as the CLI runs it, against the client (crate's own, on the host:
//! a recvmsg socket and capnweb-rs's local runtime): a connect to a local server works under `all`
//! and is denied under `public`, as are private addresses; a lookup with no nameserver is NoName;
//! the provider's filter kills a call it doesn't list.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use capnweb::local::LocalRuntime;
use capnweb::packet::PacketSocket;
use unsharek_net::client::Client;
use unsharek_net::{Policy, protocol};

fn pair() -> [RawFd; 2] {
    let mut sv = [0; 2];
    // SAFETY: socketpair into a local.
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) };
    assert_eq!(r, 0);
    sv
}

/// The provider for `policy` on a fresh pair's one end, in a child; the other end.
fn provider(policy: Policy) -> (RawFd, libc::pid_t) {
    let [ours, theirs] = pair();
    // SAFETY: the child serves and exits; the parent goes on.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: the child's copy of our end, not its to keep.
        unsafe { libc::close(ours) };
        unsharek_net::serve(theirs, policy);
    }
    // SAFETY: the parent's copy of the provider's end.
    unsafe { libc::close(theirs) };
    (ours, pid)
}

/// The sandbox's side on the host: `recvmsg` for the fds, readiness by a blocking `ppoll` in the
/// runtime's idle.
struct Ctl {
    fd: RawFd,
    waiter: Arc<Mutex<Option<Waker>>>,
}

impl PacketSocket for Ctl {
    fn send(&self, bytes: &[u8]) -> std::io::Result<usize> {
        // SAFETY: the kernel reads `bytes`.
        let r = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(r as usize) }
    }
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Vec<RawFd>)> {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut control = [0u64; 4];
        // SAFETY: a msghdr over locals, filled by the kernel.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control);
            let r = libc::recvmsg(self.fd, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut fds = vec![];
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                fds.push(*(libc::CMSG_DATA(c) as *const i32));
            }
            Ok((r as usize, fds))
        }
    }
    fn poll_ready(&self, cx: &mut Context<'_>, write: bool) -> Poll<()> {
        // Ready now, or woken by the runtime's idle wait ([`with_client`]).
        let mut p = libc::pollfd { fd: self.fd, events: if write { libc::POLLOUT } else { libc::POLLIN }, revents: 0 };
        let now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: ppoll on one local pollfd, no wait.
        if unsafe { libc::ppoll(&mut p, 1, &now, std::ptr::null()) } > 0 {
            return Poll::Ready(());
        }
        *self.waiter.lock().unwrap() = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// `f`'s future run to its end on a local runtime, against the provider on `ctl`.
fn with_client<T>(ctl: RawFd, f: impl FnOnce(&Arc<Client<Ctl>>) -> std::pin::Pin<Box<dyn Future<Output = T> + Send>>) -> T {
    let runtime = LocalRuntime::new();
    let waiter = Arc::new(Mutex::new(None::<Waker>));
    let client = Client::new(runtime.handle(), Ctl { fd: ctl, waiter: Arc::clone(&waiter) });
    let fut = f(&client);
    runtime.block_on(fut, || {
        let mut p = libc::pollfd { fd: ctl, events: libc::POLLIN, revents: 0 };
        // SAFETY: ppoll on one local pollfd.
        unsafe { libc::ppoll(&mut p, 1, std::ptr::null(), std::ptr::null()) };
        if let Some(w) = waiter.lock().unwrap().take() {
            w.wake();
        }
    })
}

fn end(ctl: RawFd, pid: libc::pid_t) {
    // SAFETY: our end; the provider exits when it closes.
    unsafe { libc::close(ctl) };
    let mut status = 0;
    // SAFETY: waitpid into a local.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the provider ended with {status:#x}");
}

#[test]
fn connects_under_all() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let (ctl, pid) = provider(Policy::All);
    let fd = with_client(ctl, |c| Box::pin(c.connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port))).expect("connect");
    let (mut peer, _) = server.accept().unwrap();
    // SAFETY: the received socket, ours now.
    let mut s = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    s.set_nonblocking(false).unwrap();
    s.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    peer.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    end(ctl, pid);
}

#[test]
fn public_denies_local_and_private() {
    let (ctl, pid) = provider(Policy::Public);
    let ips = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(169, 254, 169, 254), Ipv4Addr::new(192, 168, 0, 1)];
    let got = with_client(ctl, move |c| {
        let c = Arc::clone(c);
        Box::pin(async move {
            let mut got = vec![];
            for ip in ips {
                got.push(c.connect(IpAddr::V4(ip), 80).await);
            }
            got
        })
    });
    for (ip, r) in ips.iter().zip(got) {
        assert_eq!(r, Err(Some(protocol::DENIED)), "{ip}");
    }
    end(ctl, pid);
}

#[test]
fn the_public_policy() {
    for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
        assert!(Policy::Public.allows(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
        "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00:ec2::254", "::ffff:10.0.0.1", "::",
    ] {
        assert!(!Policy::Public.allows(ip.parse().unwrap()), "{ip}");
        assert!(Policy::All.allows(ip.parse().unwrap()));
    }
}

/// Locked down, the provider can't open a file: its filter kills it.
#[test]
fn the_providers_filter_kills_an_unlisted_call() {
    let [a, _b] = pair();
    // SAFETY: the child locks down and tries an open; the parent waits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if unsharek_net::lockdown(a).is_err() {
            // SAFETY: exit.
            unsafe { libc::_exit(1) };
        }
        // SAFETY: an open the filter must kill.
        unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, c"/etc/passwd".as_ptr(), libc::O_RDONLY) };
        // SAFETY: exit.
        unsafe { libc::_exit(2) };
    }
    let mut status = 0;
    // SAFETY: waitpid into a local.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS, "status {status:#x}");
}
