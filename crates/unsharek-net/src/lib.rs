//! Plugin (experimental): the network provider. Part of the TCB when the plugin is enabled, not
//! the core sandbox's: the sandbox gains only a control socket it may `recvmsg` on (unsharek-tcb's
//! `Config::recv_fds`); this process, outside it, makes the connections.
//!
//! **What it is.** A host process the CLI forks before the sandbox boots, with one end of a
//! `SOCK_SEQPACKET` pair (the sandbox holds the other). It serves one Cap'n Web object over it
//! ([`protocol`]): `connect(ip, port)` dials `ip:port` if [`Policy`] allows it and answers with the
//! connected socket, passed in (SCM_RIGHTS); `resolve(name)` asks the host's nameserver and answers
//! with the names' IPv4 addresses. The sandbox's side reads and writes the socket it is given; it
//! never makes a host connection itself, and nothing it sends can widen what this process allows.
//!
//! **The policy point.** [`Policy`] is checked here, on the address dialled, after resolution:
//! the sandbox can name any address, and only those the policy allows are dialled.
//!
//! **Its own confinement** ([`lockdown`]): every fd but the control socket and stderr closed,
//! `no_new_privs`, and its own seccomp filter ([`filter`]: what one connect, one lookup and one
//! reply take, each argument it can be pinned on), proven equal to its policy like the sandbox's.
//! A compromised provider has those calls and nothing else; it holds no file.

#![allow(non_upper_case_globals)]

pub mod client;
pub mod filter;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use capnweb::packet::{Fd, PacketSocket, PacketTransport};
use capnweb::{CapnwebError, CapnwebValue, Error, Result, RpcSession, RpcSessionOptions, rpc_target};

/// The wire: the object's methods and its rejections' names (the sandbox's side maps each to an
/// errno).
pub mod protocol {
    /// `connect(ip: string, port: number) -> [fd, Conn]`.
    pub const CONNECT: &str = "connect";
    /// `resolve(name: string) -> string[]` (IPv4 addresses).
    pub const RESOLVE: &str = "resolve";
    /// `listen(port: number) -> Listener`: the port published for the guest's `port`.
    pub const LISTEN: &str = "listen";
    /// `Listener.accept() -> [fd, peerIp: string, peerPort: number, Conn]`.
    pub const ACCEPT: &str = "accept";
    /// `Conn.shutdownWrite()`: the sandbox's half-close of the connection (it can't `shutdown` its
    /// own fd). Releasing the `Conn` closes the connection both ways.
    pub const SHUTDOWN_WRITE: &str = "shutdownWrite";
    /// The policy doesn't allow the address (EACCES).
    pub const DENIED: &str = "Denied";
    /// The destination refused (ECONNREFUSED).
    pub const REFUSED: &str = "Refused";
    /// No route, or the dial failed otherwise (ENETUNREACH).
    pub const UNREACHABLE: &str = "Unreachable";
    /// The dial timed out (ETIMEDOUT).
    pub const TIMEOUT: &str = "Timeout";
    /// The name has no IPv4 address (NXDOMAIN).
    pub const NO_NAME: &str = "NoName";
}

/// Which addresses the provider dials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Public addresses only: not loopback, private (RFC 1918, ULA), link-local (the cloud
    /// metadata address among them), CGNAT, multicast, broadcast, unspecified, documentation or
    /// reserved ranges, nor IPv4-mapped forms of them.
    Public,
    /// Any address the host can reach.
    All,
    /// None: the provider only serves published ports (no `--net`).
    Deny,
}

impl Policy {
    /// Whether this policy dials `ip`.
    pub fn allows(self, ip: IpAddr) -> bool {
        match self {
            Policy::All => true,
            Policy::Public => is_public(ip),
            Policy::Deny => false,
        }
    }
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || v6 == Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0))
        }
    }
}

/// How long a dial or a lookup waits.
pub const TIMEOUT: Duration = Duration::from_secs(10);

fn rejection(name: &str, message: impl Into<String>) -> Error {
    Error::Serialized(CapnwebError::new(name, message))
}

/// A published port: connections to `host` on the host are the guest's listener's on `guest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publish {
    pub host: SocketAddr,
    pub guest: u16,
}

impl std::str::FromStr for Publish {
    type Err = String;
    /// `HOST_PORT:GUEST_PORT` (on 127.0.0.1) or `IP:HOST_PORT:GUEST_PORT`, as docker's `-p`.
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let bad = || format!("{s:?}: expected [IP:]HOST_PORT:GUEST_PORT");
        let (rest, guest) = s.rsplit_once(':').ok_or_else(bad)?;
        let guest: u16 = guest.parse().map_err(|_| bad())?;
        let host = match rest.rsplit_once(':') {
            Some((ip, port)) => {
                let ip: IpAddr = ip.trim_matches(|c| c == '[' || c == ']').parse().map_err(|_| bad())?;
                SocketAddr::new(ip, port.parse().map_err(|_| bad())?)
            }
            None => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), rest.parse().map_err(|_| bad())?),
        };
        Ok(Publish { host, guest })
    }
}

/// The object the sandbox calls.
pub struct Provider {
    policy: Policy,
    nameserver: Option<SocketAddr>,
    /// The published ports' listeners, bound before lockdown: (guest port, listener).
    listeners: Vec<(u16, Arc<TcpListener>)>,
    reactor: Arc<Reactor>,
}

/// A published port's listener, for the guest's listen on its port: `accept()` waits for the
/// next connection and answers with it, passed in, and its peer.
pub struct Listener {
    tcp: Arc<TcpListener>,
    reactor: Arc<Reactor>,
}

/// The provider's copy of a connection it passed in: the sandbox can't `shutdown` or `close` its
/// own fd (no such row), so its half-close is [`Conn::shutdown_write`] and its close the release
/// of this object, which shuts the socket down both ways (the peer sees the end although the
/// sandbox's fd stays open).
pub struct Conn {
    fd: RawFd,
}

impl Conn {
    /// The provider's copy of `fd`, kept; `fd` is to be sent (and then closed: [`HostCtl::send_fds`]).
    fn of(fd: RawFd) -> Result<Conn> {
        // SAFETY: a dup of a socket this process owns.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if copy < 0 {
            return Err(rejection(protocol::UNREACHABLE, io::Error::last_os_error().to_string()));
        }
        Ok(Conn { fd: copy })
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // SAFETY: our copy; the shutdown is the socket's, the sandbox's fd included.
        unsafe {
            libc::shutdown(self.fd, libc::SHUT_RDWR);
            libc::close(self.fd);
        }
    }
}

#[rpc_target]
impl Conn {
    /// `shutdownWrite()`: the half-close.
    fn shutdown_write(&self) -> Result<()> {
        // SAFETY: our copy of the socket.
        unsafe { libc::shutdown(self.fd, libc::SHUT_WR) };
        Ok(())
    }
}

#[rpc_target]
impl Listener {
    /// `accept() -> [fd, peerIp, peerPort]`.
    async fn accept(&self) -> Result<Vec<CapnwebValue>> {
        loop {
            match self.tcp.accept() {
                Ok((tcp, peer)) => {
                    tcp.set_nonblocking(true).map_err(|e| rejection(protocol::UNREACHABLE, e.to_string()))?;
                    let fd = tcp.into_raw_fd();
                    let conn = Conn::of(fd)?;
                    return Ok(vec![
                        CapnwebValue::custom(Fd(fd)),
                        CapnwebValue::String(peer.ip().to_string()),
                        CapnwebValue::Number(f64::from(peer.port())),
                        CapnwebValue::Target(Arc::new(conn)),
                    ]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let fd = self.tcp.as_raw_fd();
                    std::future::poll_fn(|cx| self.reactor.poll(fd, libc::POLLIN, cx)).await;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(rejection(protocol::UNREACHABLE, e.to_string())),
            }
        }
    }
}

#[rpc_target]
impl Provider {
    /// `connect(ip, port)`: the connected socket, nonblocking, passed in, and its [`Conn`]; or a
    /// rejection.
    async fn connect(&self, ip: String, port: f64) -> Result<Vec<CapnwebValue>> {
        let ip: IpAddr = ip.parse().map_err(|_| Error::Type(format!("connect: {ip:?} is not an IP address")))?;
        if !(0.0..=65535.0).contains(&port) || port.fract() != 0.0 {
            return Err(Error::Type(format!("connect: port {port}")));
        }
        let addr = SocketAddr::new(ip, port as u16);
        if !self.policy.allows(ip) {
            return Err(rejection(protocol::DENIED, format!("{addr}: not allowed")));
        }
        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| {
            let name = match e.kind() {
                io::ErrorKind::ConnectionRefused => protocol::REFUSED,
                io::ErrorKind::TimedOut => protocol::TIMEOUT,
                _ => protocol::UNREACHABLE,
            };
            rejection(name, format!("{addr}: {e}"))
        })?;
        tcp.set_nonblocking(true).map_err(|e| rejection(protocol::UNREACHABLE, e.to_string()))?;
        // Ours until sent; the transport closes nothing, so [`HostCtl::send_fds`] closes it once
        // the sandbox has its copy. The [`Conn`] keeps one for the sandbox's half-close and close.
        let fd = tcp.into_raw_fd();
        let conn = Conn::of(fd)?;
        Ok(vec![CapnwebValue::custom(Fd(fd)), CapnwebValue::Target(Arc::new(conn))])
    }

    /// `listen(port)`: the listener of the port published for the guest's `port`; Denied if none
    /// is (a guest listen beyond loopback reaches the host only through `--publish`).
    async fn listen(&self, port: f64) -> Result<CapnwebValue> {
        let found = self.listeners.iter().find(|(g, _)| f64::from(*g) == port);
        let Some((_, tcp)) = found else {
            return Err(rejection(protocol::DENIED, format!("port {port}: not published")));
        };
        let l = Listener { tcp: Arc::clone(tcp), reactor: Arc::clone(&self.reactor) };
        Ok(CapnwebValue::Target(Arc::new(l)))
    }

    /// `resolve(name)`: the name's IPv4 addresses (A records) from the host's nameserver.
    async fn resolve(&self, name: String) -> Result<Vec<String>> {
        let ns = self.nameserver.ok_or_else(|| rejection(protocol::NO_NAME, "no nameserver"))?;
        let addrs = lookup(ns, &name).map_err(|e| rejection(protocol::NO_NAME, format!("{name}: {e}")))?;
        if addrs.is_empty() {
            return Err(rejection(protocol::NO_NAME, format!("{name}: no IPv4 address")));
        }
        Ok(addrs.iter().map(Ipv4Addr::to_string).collect())
    }
}

/// The first `nameserver` of `/etc/resolv.conf`, read before lockdown.
pub fn host_nameserver() -> Option<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|ip| ip.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
}

/// An `A` query for `name` to `ns` over UDP, its answers' addresses.
fn lookup(ns: SocketAddr, name: &str) -> io::Result<Vec<Ipv4Addr>> {
    let bad = || io::Error::from(io::ErrorKind::InvalidData);
    let mut q = vec![0x51, 0x7e, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    let bind: SocketAddr = if ns.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let udp = UdpSocket::bind(bind)?;
    udp.connect(ns)?;
    udp.set_read_timeout(Some(TIMEOUT))?;
    udp.send(&q)?;
    let mut r = [0u8; 1500];
    let n = udp.recv(&mut r)?;
    let r = &r[..n];
    if n < 12 || r[0..2] != q[0..2] || r[3] & 0x0f != 0 {
        return Err(bad());
    }
    let (qd, an) = (u16::from_be_bytes([r[4], r[5]]), u16::from_be_bytes([r[6], r[7]]));
    let mut i = 12;
    let skip_name = |mut i: usize| -> Option<usize> {
        loop {
            let len = *r.get(i)? as usize;
            if len & 0xc0 == 0xc0 {
                return Some(i + 2);
            }
            i += 1 + len;
            if len == 0 {
                return Some(i);
            }
        }
    };
    for _ in 0..qd {
        i = skip_name(i).ok_or_else(bad)? + 4;
    }
    let mut out = vec![];
    for _ in 0..an {
        i = skip_name(i).ok_or_else(bad)?;
        let h = r.get(i..i + 10).ok_or_else(bad)?;
        let (kind, len) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        let data = r.get(i + 10..i + 10 + len).ok_or_else(bad)?;
        if kind == 1 && len == 4 {
            out.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        i += 10 + len;
    }
    Ok(out)
}

/// The provider's waits: each a task's waker on an fd, woken by [`serve`]'s idle `ppoll` over
/// them all (the control socket's and the listeners').
#[derive(Default)]
pub struct Reactor {
    waits: Mutex<Vec<(RawFd, i16, Waker)>>,
}

impl Reactor {
    /// `fd` ready for `events` now, or the waker kept for the idle wait.
    fn poll(&self, fd: RawFd, events: i16, cx: &mut Context<'_>) -> Poll<()> {
        let mut p = libc::pollfd { fd, events, revents: 0 };
        let now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: ppoll on one local pollfd, no wait, no mask.
        if unsafe { libc::ppoll(&mut p, 1, &now, std::ptr::null()) } > 0 {
            return Poll::Ready(());
        }
        self.waits.lock().expect("waits poisoned").push((fd, events, cx.waker().clone()));
        Poll::Pending
    }

    /// Wait for any kept fd (and `ctl`, always, for its hangup) and wake the ready ones'
    /// tasks. The control socket's hangup ends the provider.
    fn wait(&self, ctl: RawFd) {
        let mut waits = std::mem::take(&mut *self.waits.lock().expect("waits poisoned"));
        let mut fds: Vec<libc::pollfd> = vec![libc::pollfd { fd: ctl, events: 0, revents: 0 }];
        fds.extend(waits.iter().map(|&(fd, events, _)| libc::pollfd { fd, events, revents: 0 }));
        // SAFETY: ppoll on a local array, no timeout, no mask.
        let r = unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as _, std::ptr::null(), std::ptr::null()) };
        if r > 0 && fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            std::process::exit(0);
        }
        let mut keep = vec![];
        for (w, p) in waits.drain(..).zip(&fds[1..]) {
            if p.revents != 0 { w.2.wake() } else { keep.push(w) }
        }
        self.waits.lock().expect("waits poisoned").extend(keep);
    }
}

/// The provider's end of the control socket, nonblocking.
struct HostCtl {
    fd: RawFd,
    reactor: Arc<Reactor>,
}

fn last<T>(r: isize, ok: T) -> io::Result<T> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(ok) }
}

impl PacketSocket for HostCtl {
    fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: the kernel reads `bytes`, borrowed for the call.
        let r = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        last(r, r as usize)
    }

    fn send_fds(&self, bytes: &[u8], fds: &[RawFd]) -> io::Result<usize> {
        let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut _, iov_len: bytes.len() };
        let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize;
        let mut control = vec![0u64; space.div_ceil(8)];
        // SAFETY: a msghdr over locals; CMSG_* lay out `fds` in `control`, sized for them.
        let r = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), fds.len());
            libc::sendmsg(self.fd, &msg, 0)
        };
        let sent = last(r, r as usize)?;
        // The sandbox has its copies: ours (the dialled sockets) are closed.
        for &fd in fds {
            // SAFETY: each fd is a socket this process dialled and owns.
            unsafe { libc::close(fd) };
        }
        Ok(sent)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Vec<RawFd>)> {
        // Nothing comes with the sandbox's messages but bytes: a plain read takes one packet.
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
        let r = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        last(r, (r as usize, vec![]))
    }

    fn poll_ready(&self, cx: &mut Context<'_>, write: bool) -> Poll<()> {
        self.reactor.poll(self.fd, if write { libc::POLLOUT } else { libc::POLLIN }, cx)
    }
}

/// Every fd but `ctl`, `keep` (the listeners) and stderr closed, no core dumps, `no_new_privs`,
/// the provider's filter installed: the provider's own lockdown, before it serves anything. An
/// error ends the provider.
pub fn lockdown(ctl: RawFd, keep: &[RawFd]) -> io::Result<()> {
    let close = |lo: u32, hi: u32| -> io::Result<()> {
        // SAFETY: closes fds of this process; `ctl` and stderr are outside every range.
        let r = unsafe { libc::syscall(libc::SYS_close_range, lo, hi, 0) };
        last(r as isize, ())
    };
    let mut keep: Vec<u32> = [2, ctl as u32].into_iter().chain(keep.iter().map(|&f| f as u32)).collect();
    keep.sort_unstable();
    keep.dedup();
    let mut next = 0u32;
    for fd in keep {
        if fd > next {
            close(next, fd - 1)?;
        }
        next = fd + 1;
    }
    close(next, u32::MAX)?;
    // No core dump (a crash must not write the provider's memory to the host's disk).
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: sets a limit and flags of this process.
    unsafe {
        last(libc::setrlimit(libc::RLIMIT_CORE, &none) as isize, ())?;
        last(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) as isize, ())?;
        last(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as isize, ())?;
    }
    let prog = filter::filter(ctl as u64);
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
    // SAFETY: seccomp reads `fprog` and the instructions, both live for the call.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog as *const _) };
    last(r as isize, ())
}

/// The published ports' listeners, bound and listening (nonblocking): before [`serve`]'s lockdown,
/// which allows no `bind` of a TCP socket's or `listen`.
pub fn bind_published(publish: &[Publish]) -> io::Result<Vec<(u16, TcpListener)>> {
    publish
        .iter()
        .map(|p| {
            let l = TcpListener::bind(p.host)?;
            l.set_nonblocking(true)?;
            Ok((p.guest, l))
        })
        .collect()
}

/// Serve the provider on `ctl` (the provider's end of the pair, nonblocking) with `policy` and the
/// published ports' `listeners` ([`bind_published`]), until the sandbox's end closes; then the
/// process exits 0. Locks down first ([`lockdown`]), keeping the listeners.
pub fn serve(ctl: RawFd, policy: Policy, listeners: Vec<(u16, TcpListener)>) -> ! {
    let nameserver = host_nameserver();
    let runtime = capnweb::local::LocalRuntime::new();
    let keep: Vec<RawFd> = listeners.iter().map(|(_, l)| l.as_raw_fd()).collect();
    if let Err(e) = lockdown(ctl, &keep) {
        eprintln!("unsharek: the network provider's lockdown failed: {e}");
        std::process::exit(125);
    }
    let reactor = Arc::new(Reactor::default());
    let transport = match PacketTransport::new(HostCtl { fd: ctl, reactor: Arc::clone(&reactor) }) {
        Ok(t) => t,
        Err(_) => std::process::exit(125),
    };
    let listeners = listeners.into_iter().map(|(g, l)| (g, Arc::new(l))).collect();
    let main = CapnwebValue::Target(Arc::new(Provider { policy, nameserver, listeners, reactor: Arc::clone(&reactor) }));
    let session = runtime.block_on(async { RpcSession::new(Arc::new(transport), Some(main), RpcSessionOptions::default()) }, || {});
    if session.is_err() {
        std::process::exit(125);
    }
    runtime.block_on(std::future::pending::<()>(), || reactor.wait(ctl));
    unreachable!("the provider serves until the sandbox's end closes")
}

impl AsRawFd for HostCtl {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
