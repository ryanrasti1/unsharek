//! Plugin (experimental): the host's network, by the host's own socket calls. The hooks
//! ([`install`]) make the program's non-loopback sockets host sockets: a connect is the host's
//! `socket` and `connect` (TCP, or UDP's connected socket: the resolver's queries among them), a
//! listen the host's `socket`, `bind` and `listen`, each accepted connection its `accept4`; the
//! guest's socket is then backed by the host fd (nothing copied). Any address and any port: what
//! the program can reach and listen on is the network namespace the process runs in (the
//! caller's), as with any process on the host.
//!
//! The calls are unsharek-tcb's net plugin's rows (`unsharek_tcb::plugin::Net`, which the caller
//! passes to lockdown: without it the first connect after lockdown is killed). These hooks are no
//! policy point either (net.rs): a compromised program can make the same calls itself, and gets
//! what the rows and the namespace allow.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustix::io::Errno;
use unsharek_rt::executor::{self, POLLIN, POLLOUT};
use unsharek_rt::trap;

use crate::net::{FdConn, NetError, OnConnect, OnListen, Proto};
use crate::{Error, Guest};

// x86-64's numbers (arch/x86/entry/syscalls/syscall_64.tbl), and the flags the rows take.
const NR_SOCKET: u32 = 41;
const NR_CONNECT: u32 = 42;
const NR_ACCEPT4: u32 = 288;
const NR_SHUTDOWN: u32 = 48;
const NR_BIND: u32 = 49;
const NR_LISTEN: u32 = 50;
const NR_SETSOCKOPT: u32 = 54;
const NR_GETSOCKOPT: u32 = 55;
const FLAGS: usize = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as usize;

/// The hooks: the program's connects and listens beyond loopback, on the host.
pub fn install(g: &mut Guest) -> Result<(), Error> {
    // The plugin's row lets one ppoll watch its bound of fds: the idle wait watches that many host
    // sockets at once (a server's), not the core's 8 (beyond which a watch was dropped, and a poll
    // of many idle connections slept until some other fd fired: `many_idle_connections_wake_promptly`).
    unsharek_rt::trap::set_ppoll_bound(unsharek_tcb::plugin::Net::PPOLL_FDS);
    g.on_connect(OnConnect::fd(|_cx, _pid, proto: Proto, addr: SocketAddr| async move {
        let SocketAddr::V4(addr) = addr else { return Err(NetError::Unsupported) };
        connect(proto, addr).await.map_err(net_error)
    }))?;
    g.on_listen(OnListen::fd(|_cx, _pid, addr: SocketAddr| async move {
        let SocketAddr::V4(addr) = addr else { return Err(NetError::Unsupported) };
        listen(addr).map_err(net_error)
    }));
    Ok(())
}

fn sys(nr: u32, a: [usize; 6]) -> Result<usize, Errno> {
    // SAFETY: the socket calls below, on their own buffers (each borrowed for the call).
    unsafe { trap::plugin_call(nr, a) }
}

fn net_error(e: Errno) -> NetError {
    match e {
        Errno::CONNREFUSED => NetError::Refused,
        Errno::TIMEDOUT => NetError::Timeout,
        Errno::NETUNREACH | Errno::HOSTUNREACH => NetError::Unreachable,
        Errno::ACCESS | Errno::PERM => NetError::Denied,
        Errno::AFNOSUPPORT => NetError::Unsupported,
        _ => NetError::Io,
    }
}

/// A `sockaddr_in`.
fn sockaddr(a: SocketAddrV4) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    s[2..4].copy_from_slice(&a.port().to_be_bytes());
    s[4..8].copy_from_slice(&a.ip().octets());
    s
}

fn socket(ty: i32) -> Result<Fd, Errno> {
    sys(NR_SOCKET, [libc::AF_INET as usize, ty as usize | FLAGS, 0, 0, 0, 0]).map(|fd| Fd(fd as RawFd))
}

/// A host socket of the plugin's, closed when dropped (unsharek-tcb's net `close` row: it is at
/// or above the floor).
struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            let _ = trap::close(self.0 as u32);
        }
    }
}

impl Fd {
    fn take(mut self) -> RawFd {
        std::mem::replace(&mut self.0, -1)
    }
}

/// Ready for `events`: a future on the executor (the hooks' readiness).
fn ready(fd: RawFd, events: i16) -> impl std::future::Future<Output = ()> {
    std::future::poll_fn(move |cx| executor::poll_fd(fd, events, cx))
}

async fn connect(proto: Proto, addr: SocketAddrV4) -> Result<(RawFd, Conn), Errno> {
    let fd = socket(if proto == Proto::Udp { libc::SOCK_DGRAM } else { libc::SOCK_STREAM })?;
    let sa = sockaddr(addr);
    match sys(NR_CONNECT, [fd.0 as usize, sa.as_ptr() as usize, sa.len(), 0, 0, 0]) {
        Ok(_) => {}
        Err(Errno::INPROGRESS) => {
            ready(fd.0, POLLOUT).await;
            let (mut err, mut len) = (0i32, 4u32);
            sys(
                NR_GETSOCKOPT,
                [fd.0 as usize, libc::SOL_SOCKET as usize, libc::SO_ERROR as usize, &mut err as *mut i32 as usize, &mut len as *mut u32 as usize, 0],
            )?;
            if err != 0 {
                return Err(Errno::from_raw_os_error(err));
            }
        }
        Err(e) => return Err(e),
    }
    let fd = fd.take();
    // Marked as the host's own number (made after lockdown: never a moved kept fd's).
    Ok((fd | unsharek_rt::host::FRESH, Conn(fd)))
}

fn listen(addr: SocketAddrV4) -> Result<Incoming, Errno> {
    let fd = socket(libc::SOCK_STREAM)?;
    let one = 1i32;
    sys(NR_SETSOCKOPT, [fd.0 as usize, libc::SOL_SOCKET as usize, libc::SO_REUSEADDR as usize, &one as *const i32 as usize, 4, 0])?;
    let sa = sockaddr(addr);
    sys(NR_BIND, [fd.0 as usize, sa.as_ptr() as usize, sa.len(), 0, 0, 0])?;
    sys(NR_LISTEN, [fd.0 as usize, 128, 0, 0, 0, 0])?;
    Ok(Incoming(fd))
}

/// A connection's host fd: the program's `shutdown` the host's, its close this object's drop.
pub struct Conn(RawFd);

impl FdConn for Conn {
    fn shutdown(&mut self, how: i32) {
        let _ = sys(NR_SHUTDOWN, [self.0 as usize, how as usize, 0, 0, 0, 0]);
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = trap::close(self.0 as u32);
    }
}

/// A listener's connections, one `accept4` each; the listener closed when the program closes its
/// own (this is dropped).
struct Incoming(Fd);

impl futures_core::Stream for Incoming {
    type Item = (SocketAddr, (RawFd, Conn));
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let lfd = self.0.0;
        loop {
            let mut sa = [0u8; 16];
            let mut len = 16u32;
            match sys(NR_ACCEPT4, [lfd as usize, sa.as_mut_ptr() as usize, &mut len as *mut u32 as usize, FLAGS, 0, 0]) {
                Ok(fd) => {
                    let ip = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
                    let peer = SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be_bytes([sa[2], sa[3]])));
                    return Poll::Ready(Some((peer, ((fd as RawFd) | unsharek_rt::host::FRESH, Conn(fd as RawFd)))));
                }
                Err(Errno::AGAIN) | Err(Errno::INTR) | Err(Errno::CONNABORTED) => match executor::poll_fd(lfd, POLLIN, cx) {
                    Poll::Ready(()) => continue,
                    Poll::Pending => return Poll::Pending,
                },
                // The listener failed: the listen's end.
                Err(_) => return Poll::Ready(None),
            }
        }
    }
}
