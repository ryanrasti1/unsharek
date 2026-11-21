//! The program's network through a sandbox's hooks (`unsharek::net`), each case a sandbox in a
//! child process of its own (this binary re-run), named `<case>::coroutine` as the suite's are.
//!
//! The provider plays capnix's part: it holds ONE fd (a socketpair end, the child's fd 3, held as
//! "net" and found by its hooks with `cx.held`), starts its session at lockdown (`on_start`: a
//! reader and a writer task) and multiplexes every
//! connect over it with a trivial framing (stream id, op, length, bytes), one stream per connect.
//! This process holds the other end: a proxy that makes real loopback TCP connections to the echo
//! and HTTP servers it started (any 10.0.0.0/8 address, port P, is 127.0.0.1:P; 10.0.0.66 is
//! refused, 10.0.0.67 denied, 10.0.0.68 reset once connected).
//!
//! Names are no special case: the `dns` kinds' guest resolv.conf names 10.0.0.53, and their
//! `OnConnect::fd` hook answers each UDP connect to its port 53 with a UDP socket made before
//! lockdown, connected to a stub nameserver here ([`dns_server`]: `echo.test` 10.0.0.1,
//! `denied.test` NOTAUTH, others NXDOMAIN, AAAA queries no data).

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

use unsharek::net::FdConn;
use unsharek::{Cx, HeldFd, NetError, OnConnect, OnListen, Proto};
use unsharek_fixtures as fx;
use futures_io::{AsyncRead, AsyncWrite};
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

const CHILD: &str = "UNSHAREK_NET_TEST_CHILD";
const ARGV: &str = "UNSHAREK_NET_TEST_ARGV";
const DNS: &str = "UNSHAREK_NET_TEST_DNS";

// ---- the framing ----

const CONNECT: u8 = 1;
const DATA: u8 = 2;
const CLOSE: u8 = 3;
const RESET: u8 = 4;
const CONNECTED: u8 = 10;
const ERROR: u8 = 11;

fn frame(id: u32, op: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&id.to_le_bytes());
    f.push(op);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// A whole frame at the front of `buf`, taken out.
fn take_frame(buf: &mut Vec<u8>) -> Option<(u32, u8, Vec<u8>)> {
    if buf.len() < 9 {
        return None;
    }
    let len = u32::from_le_bytes(buf[5..9].try_into().unwrap()) as usize;
    if buf.len() < 9 + len {
        return None;
    }
    let id = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let op = buf[4];
    let payload = buf[9..9 + len].to_vec();
    buf.drain(..9 + len);
    Some((id, op, payload))
}

const ERRORS: [NetError; 5] = [NetError::Denied, NetError::Refused, NetError::Unreachable, NetError::Timeout, NetError::NoName];

// ---- the provider, in the sandbox ----

#[derive(Default)]
struct Stream {
    inbuf: VecDeque<u8>,
    eof: bool,
    reset: bool,
    reader: Option<Waker>,
}

/// A request's reply (its op and payload), once there, and who waits for it.
type Reply = (Option<(u8, Vec<u8>)>, Option<Waker>);

#[derive(Default)]
struct Session {
    out: Vec<u8>,
    writer: Option<Waker>,
    streams: HashMap<u32, Stream>,
    replies: HashMap<u32, Reply>,
    next: u32,
}

type Shared = Rc<RefCell<Session>>;

thread_local! {
    static SESSION: RefCell<Option<Shared>> = const { RefCell::new(None) };
}

/// The session over the held fd, started on first use: its reader and writer tasks.
fn session(cx: Cx, fd: HeldFd) -> Shared {
    SESSION.with(|s| {
        s.borrow_mut()
            .get_or_insert_with(|| {
                let sess: Shared = Rc::default();
                cx.spawn(reader(fd, sess.clone()));
                cx.spawn(writer(fd, sess.clone()));
                sess
            })
            .clone()
    })
}

fn send(s: &Shared, id: u32, op: u8, payload: &[u8]) {
    let mut s = s.borrow_mut();
    s.out.extend_from_slice(&frame(id, op, payload));
    if let Some(w) = s.writer.take() {
        w.wake();
    }
}

async fn reader(mut fd: HeldFd, s: Shared) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let n = poll_fn(|cx| Pin::new(&mut fd).poll_read(cx, &mut chunk)).await.unwrap_or(0);
        if n == 0 {
            // The proxy is gone: every stream is reset.
            for st in s.borrow_mut().streams.values_mut() {
                st.reset = true;
                if let Some(w) = st.reader.take() {
                    w.wake();
                }
            }
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some((id, op, payload)) = take_frame(&mut buf) {
            let mut ss = s.borrow_mut();
            match op {
                CONNECTED | ERROR => {
                    if let Some(r) = ss.replies.get_mut(&id) {
                        r.0 = Some((op, payload));
                        if let Some(w) = r.1.take() {
                            w.wake();
                        }
                    }
                }
                DATA | CLOSE | RESET => {
                    if let Some(st) = ss.streams.get_mut(&id) {
                        match op {
                            DATA => st.inbuf.extend(payload),
                            CLOSE => st.eof = true,
                            _ => st.reset = true,
                        }
                        if let Some(w) = st.reader.take() {
                            w.wake();
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

async fn writer(mut fd: HeldFd, s: Shared) {
    loop {
        let r = poll_fn(|cx| {
            let mut ss = s.borrow_mut();
            if ss.out.is_empty() {
                ss.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            match Pin::new(&mut fd).poll_write(cx, &ss.out) {
                Poll::Ready(Ok(n)) => {
                    ss.out.drain(..n);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        if r.is_err() {
            return;
        }
    }
}

/// One request: its reply's op and payload.
async fn request(s: &Shared, op: u8, payload: &[u8], stream: bool) -> (u32, u8, Vec<u8>) {
    let id = {
        let mut ss = s.borrow_mut();
        ss.next += 1;
        let id = ss.next;
        ss.replies.insert(id, (None, None));
        if stream {
            ss.streams.insert(id, Stream::default());
        }
        id
    };
    send(s, id, op, payload);
    let (op, data) = poll_fn(|cx| {
        let mut ss = s.borrow_mut();
        let r = ss.replies.get_mut(&id).unwrap();
        match r.0.take() {
            Some(v) => Poll::Ready(v),
            None => {
                r.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
    .await;
    s.borrow_mut().replies.remove(&id);
    (id, op, data)
}

/// One connection's stream over the session.
struct Proxied {
    id: u32,
    s: Shared,
    closed: bool,
}

impl AsyncRead for Proxied {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut ss = self.s.borrow_mut();
        let st = ss.streams.get_mut(&self.id).unwrap();
        if !st.inbuf.is_empty() {
            let n = buf.len().min(st.inbuf.len());
            for (d, b) in buf.iter_mut().zip(st.inbuf.drain(..n)) {
                *d = b;
            }
            return Poll::Ready(Ok(n));
        }
        if st.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if st.eof {
            return Poll::Ready(Ok(0));
        }
        st.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Proxied {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let n = buf.len().min(32 << 10);
        send(&self.s, self.id, DATA, &buf[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            send(&self.s, self.id, CLOSE, &[]);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Proxied {
    fn drop(&mut self) {
        // Dropped without a close: an abort.
        if !self.closed {
            send(&self.s, self.id, RESET, &[]);
        }
        self.s.borrow_mut().streams.remove(&self.id);
    }
}

fn error_of(payload: &[u8]) -> NetError {
    ERRORS.get(payload.first().copied().unwrap_or(4) as usize).copied().unwrap_or(NetError::Io)
}

/// A host connection for the `listen` case: says hello, then EOF.
struct Hello(&'static [u8]);

impl AsyncRead for Hello {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for Hello {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// One inbound connection, then none (the listen stays offered).
struct OneConn(Option<(SocketAddr, Hello)>);

impl futures_core::Stream for OneConn {
    type Item = (SocketAddr, Hello);
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.take() {
            Some(c) => Poll::Ready(Some(c)),
            None => Poll::Pending,
        }
    }
}

/// The `provider_syscall` child's: the connect hook makes a syscall of its own first, as
/// capnweb-rs's stacker does (it reads /proc/self/maps for the stack's bounds).
static STRAY_SYSCALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The held fd the hooks talk over (the child's own, under a name: the hooks are given at build).
fn net_fd(cx: &Cx) -> HeldFd {
    cx.held("net").expect("no fd held as \"net\"")
}

/// The connect hook: through the proxy.
fn connect_hook() -> OnConnect {
    OnConnect::new(move |cx: Cx, _pid, addr: SocketAddr| async move {
        if STRAY_SYSCALL.load(std::sync::atomic::Ordering::Relaxed) {
            // SAFETY: getpid has no arguments.
            unsafe { libc::getpid() };
        }
        let s = session(cx, net_fd(&cx));
        let SocketAddr::V4(a) = addr else { return Err(NetError::Unsupported) };
        let mut p = a.ip().octets().to_vec();
        p.extend_from_slice(&a.port().to_be_bytes());
        let (id, op, data) = request(&s, CONNECT, &p, true).await;
        match op {
            CONNECTED => Ok(Proxied { id, s, closed: false }),
            _ => {
                s.borrow_mut().streams.remove(&id);
                Err(error_of(&data))
            }
        }
    })
}

fn provider() -> (OnConnect, OnListen) {
    let connect = connect_hook();
    let listen = OnListen::new(move |_cx: Cx, _pid, _addr| async move {
        let peer = SocketAddr::from(([10, 9, 9, 9], 4242));
        Ok(OneConn(Some((peer, Hello(b"hello from the host")))))
    });
    (connect, listen)
}

/// The nameserver the `dns` kinds' guests ask: an address of no one's, its port 53 served by
/// the stub ([`dns_server`]) through the UDP sockets [`dns_hook`] hands in.
const DNS_NAMESERVER: [u8; 4] = [10, 0, 0, 53];

/// A UDP socket the guest's socket is backed by: closed with its last reference.
struct Udp(RawFd);

impl FdConn for Udp {
    fn shutdown(&mut self, _how: i32) {}
}

impl Drop for Udp {
    fn drop(&mut self) {
        // SAFETY: ours, handed in once.
        unsafe { libc::close(self.0) };
    }
}

/// `n` UDP sockets connected to the stub at `stub`, made before lockdown (after it, no host
/// socket can be made), then an `OnConnect::fd` hook that answers each UDP connect to the
/// nameserver's port 53 with the next: a connected UDP socket of the host's, as a provider's
/// would be. Anything else is unreachable: this guest's network is its lookups. The sockets are
/// returned too: lockdown keeps only what is granted.
fn dns_hook(stub: SocketAddr, n: usize) -> (OnConnect, Vec<RawFd>) {
    let pool: Vec<RawFd> = (0..n)
        .map(|_| {
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            u.connect(stub).unwrap();
            u.set_nonblocking(true).unwrap();
            u.into_raw_fd()
        })
        .collect();
    let fds = pool.clone();
    let pool = std::sync::Mutex::new(pool);
    let hook = OnConnect::fd(move |_cx: Cx, _pid, proto: Proto, addr: SocketAddr| {
        let fd = if proto == Proto::Udp && addr == SocketAddr::from((DNS_NAMESERVER, 53)) { pool.lock().unwrap().pop() } else { None };
        async move { fd.map(|fd| (fd, Udp(fd))).ok_or(NetError::Unreachable) }
    });
    (hook, fds)
}

/// The child: a sandbox for argv (`ARGV`), with the provider (`provider`; `provider_user`: and
/// the setup drops init to uid/gid 1000), the stub nameserver's UDP sockets (`dns`, `dns_user`,
/// `dns_fork`: `UNSHAREK_NET_TEST_DNS` its address), or fd 3 passed as fd 1000 (`passfd`). (A sandbox with no hooks is the CLI's: its unreachable network and loopback are
/// guest-tests' net::unreachable and net::tcp_loopback.)
fn child(kind: &str) -> ! {
    let argv: Vec<OsString> = std::env::var(ARGV).unwrap().split('\x1f').map(OsString::from).collect();
    let fork = kind == "provider_fork" || kind == "dns_fork";
    let mode = if fork { unsharek::Mode::Fork } else { unsharek::Mode::Coroutine };
    let mut g = unsharek::Guest::boot(unsharek::GuestConfig { mode, ..Default::default() }).unwrap();
    let mut udp: Vec<RawFd> = vec![];
    match kind {
        "provider" | "provider_syscall" | "provider_user" | "provider_fork" => {
            STRAY_SYSCALL.store(kind == "provider_syscall", std::sync::atomic::Ordering::Relaxed);
            let (connect, listen) = provider();
            // The session up before the program: no first hook has to start it.
            g.on_connect(connect).unwrap();
            g.on_listen(listen);
            g.on_start(|cx| async move {
                let _ = session(cx, net_fd(&cx));
            });
        }
        "dns" | "dns_user" | "dns_fork" => {
            let stub: SocketAddr = std::env::var(DNS).unwrap().parse().unwrap();
            let (hook, fds) = dns_hook(stub, 32);
            g.on_connect(hook).unwrap();
            udp = fds;
        }
        _ => {}
    }
    // SAFETY: fd 3 is this process's, from the parent, and nothing else owns it.
    let fd3 = unsafe { OwnedFd::from_raw_fd(3) };
    match kind {
        "provider" | "provider_syscall" | "provider_user" | "provider_fork" => drop(g.hold_fd_as("net", fd3).unwrap()),
        "passfd" => g.pass_fd(fd3, 1000).unwrap(),
        _ => drop(fd3),
    }
    // The fixtures' directory, and the program's store path if it is one (python).
    let mut roots = vec![fx::bin_dir()];
    roots.extend(Path::new(&argv[0]).starts_with("/nix/store").then(|| PathBuf::from(&argv[0])));
    g.mount_closure(&roots).unwrap();
    g.run(|| {
        if kind.starts_with("dns") {
            // The guest's resolver asks the stub's address (the host's resolv.conf was copied when
            // the hook was set: a setup may change it, as here).
            let ns = Ipv4Addr::from(DNS_NAMESERVER);
            std::fs::write("/etc/resolv.conf", format!("nameserver {ns}\noptions timeout:2 attempts:2\n")).unwrap();
        }
        if kind == "provider_user" || kind == "dns_user" {
            // SAFETY: the guest's init dropping to uid/gid 1000 (a build user, as capnix's).
            unsafe { assert!(libc::setresgid(1000, 1000, 1000) == 0 && libc::setresuid(1000, 1000, 1000) == 0) };
        }
    })
    .unwrap();
    let env: Vec<OsString> = vec![if fork { "UNSHAREK_TEST_MODE=fork" } else { "UNSHAREK_TEST_MODE=coroutine" }.into()];
    g.configure_sandbox(unsharek::SandboxConfig::new().grant([0, 1, 2]).grant(udp.iter().copied()))
        .and_then(|c| unsharek::lockdown(c).map_err(Into::into))
        .unwrap();
    let e = match g.run(move || unsharek::execve(&argv, &env)) {
        Ok(e) | Err(e) => e,
    };
    eprintln!("unsharek: {e}");
    std::process::exit(125)
}

// ---- this process: the servers and the proxy ----

/// An echo server: each connection's bytes back, and its EOF (after them) back too.
/// The stub nameserver on loopback (one for this process), its address. A query (DNS's, one
/// question) gets an answer from its table: `echo.test` A 10.0.0.1, `denied.test` NOTAUTH, other
/// names NXDOMAIN, any other type no data. A datagram that isn't a query (`ping…`) comes back as
/// `pong…`: the `udp` case's echo.
fn dns_server() -> SocketAddr {
    static ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
    *ADDR.get_or_init(|| {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = u.local_addr().unwrap();
        thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = u.recv_from(&mut b) {
                let q = &b[..n];
                if let Some(rest) = q.strip_prefix(b"ping") {
                    let _ = u.send_to(&[b"pong", rest].concat(), from);
                } else if let Some(r) = dns_answer(q) {
                    let _ = u.send_to(&r, from);
                }
            }
        });
        addr
    })
}

/// [`dns_server`]'s answer to query `q`, if it is one.
fn dns_answer(q: &[u8]) -> Option<Vec<u8>> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    // The question: labels, then type and class.
    let (mut i, mut name) = (12, vec![]);
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        name.push(String::from_utf8_lossy(q.get(i..i + len)?).to_lowercase());
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let question = &q[12..i + 4];
    let (rcode, answer): (u8, Option<[u8; 4]>) = match (name.join(".").as_str(), qtype) {
        ("echo.test", 1) => (0, Some([10, 0, 0, 1])),
        ("echo.test", _) => (0, None),
        ("denied.test", _) => (9, None), // NOTAUTH
        _ => (3, None),                  // NXDOMAIN
    };
    // The header: the query's id, a response (recursion available), one question, the answers.
    let mut r = vec![q[0], q[1], 0x81, 0x80 | rcode, 0, 1, 0, answer.is_some() as u8, 0, 0, 0, 0];
    r.extend_from_slice(question);
    if let Some(a) = answer {
        // A pointer to the question's name, type A, class IN, a TTL of 60, 4 bytes.
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&a);
    }
    Some(r)
}

fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 16 << 10];
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if c.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = c.shutdown(Shutdown::Write);
            });
        }
    });
    port
}

/// An HTTP server answering every request with NET_HTTP_OK.
fn http_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let body = "NET_HTTP_OK\n";
                let _ = write!(c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            });
        }
    });
    port
}

/// The provider's other end: connects and lookups served, streams relayed.
fn proxy(sock: UnixStream) {
    let w = Arc::new(Mutex::new(sock.try_clone().unwrap()));
    let send = |w: &Arc<Mutex<UnixStream>>, id, op, p: &[u8]| {
        let _ = w.lock().unwrap().write_all(&frame(id, op, p));
    };
    let mut conns: HashMap<u32, TcpStream> = HashMap::new();
    let mut sock = sock;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let n = match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some((id, op, p)) = take_frame(&mut buf) {
            match op {
                CONNECT => {
                    let ip = Ipv4Addr::new(p[0], p[1], p[2], p[3]);
                    let port = u16::from_be_bytes([p[4], p[5]]);
                    let refuse = |code: u8| send(&w, id, ERROR, &[code]);
                    if ip == Ipv4Addr::new(10, 0, 0, 66) {
                        refuse(1);
                        continue;
                    }
                    if ip == Ipv4Addr::new(10, 0, 0, 67) || ip.octets()[0] != 10 {
                        refuse(0);
                        continue;
                    }
                    if ip == Ipv4Addr::new(10, 0, 0, 68) {
                        send(&w, id, CONNECTED, &[]);
                        send(&w, id, RESET, &[]);
                        continue;
                    }
                    match TcpStream::connect(("127.0.0.1", port)) {
                        Ok(t) => {
                            let mut r = t.try_clone().unwrap();
                            conns.insert(id, t);
                            send(&w, id, CONNECTED, &[]);
                            let w = w.clone();
                            thread::spawn(move || {
                                let mut b = vec![0u8; 32 << 10];
                                loop {
                                    match r.read(&mut b) {
                                        Ok(0) => {
                                            send(&w, id, CLOSE, &[]);
                                            return;
                                        }
                                        Ok(n) => send(&w, id, DATA, &b[..n]),
                                        Err(_) => {
                                            send(&w, id, RESET, &[]);
                                            return;
                                        }
                                    }
                                }
                            });
                        }
                        Err(_) => refuse(1),
                    }
                }
                DATA => {
                    if let Some(t) = conns.get_mut(&id) {
                        let _ = t.write_all(&p);
                    }
                }
                CLOSE => {
                    if let Some(t) = conns.get(&id) {
                        let _ = t.shutdown(Shutdown::Write);
                    }
                }
                RESET => {
                    if let Some(t) = conns.remove(&id) {
                        let _ = t.shutdown(Shutdown::Both);
                    }
                }
                _ => {}
            }
        }
    }
}

struct Servers {
    echo: u16,
    http: u16,
}

/// Runs `argv` in a child sandbox of `kind`, this process at the other end of its fd 3 (`peer`).
fn run(kind: &str, argv: &[String], peer: impl FnOnce(UnixStream) + Send + 'static) -> Result<(i32, String, String), Failed> {
    let (ours, theirs) = UnixStream::pair()?;
    let theirs_fd = theirs.as_raw_fd();
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.env(CHILD, kind)
        .env(ARGV, argv.join("\x1f"))
        .env(DNS, dns_server().to_string())
        .env("UNSHAREK_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: dup2 between fork and exec, async-signal-safe.
    unsafe {
        cmd.pre_exec(move || if libc::dup2(theirs_fd, 3) < 0 { Err(io::Error::last_os_error()) } else { Ok(()) });
    }
    let t = thread::spawn(move || peer(ours));
    let r = common::spawn_bounded(cmd, None, Duration::from_secs(10));
    drop(theirs);
    let (status, _, out, err) = r?;
    let _ = t.join();
    Ok((status.code().unwrap_or(-1), out, err))
}

fn check(kind: &'static str, argv: Vec<String>, marker: &'static str) -> Result<(), Failed> {
    let (code, out, err) = run(kind, &argv, proxy)?;
    if code != 0 || !out.contains(marker) {
        return Err(format!("exit {code}, wanted {marker}\n--- stdout:\n{out}\n--- stderr:\n{err}").into());
    }
    Ok(())
}

fn main() {
    if let Ok(kind) = std::env::var(CHILD) {
        child(&kind);
    }
    let args = Arguments::from_args();
    let s = Arc::new(Servers { echo: echo_server(), http: http_server() });
    let net = |c: &str, a: &[&str]| -> Vec<String> {
        let mut v = vec![fx::bin("net").display().to_string(), c.to_string()];
        v.extend(a.iter().map(|s| s.to_string()));
        v
    };
    let echo = s.echo.to_string();
    let mut trials = vec![];
    let mut case = |name: &'static str, kind: &'static str, argv: Vec<String>, marker: &'static str| {
        trials.push(Trial::test(format!("{name}::coroutine"), move || check(kind, argv, marker)));
    };
    case("net_echo", "provider", net("echo", &["10.0.0.1", &echo]), "NET_ECHO_OK");
    case("net_many", "provider", net("many", &["10.0.0.1", &echo]), "NET_MANY_OK");
    case("net_nonblock", "provider", net("nonblock", &["10.0.0.1", &echo]), "NET_NONBLOCK_OK");
    case("net_names", "provider", net("names", &["10.0.0.1", &echo]), "NET_NAMES_OK");
    case("net_refused", "provider", net("refused", &["10.0.0.66", &echo]), "NET_REFUSED_OK");
    case("net_denied", "provider", net("denied", &["10.0.0.67", &echo]), "NET_DENIED_OK");
    case("net_reset", "provider", net("reset", &["10.0.0.68", &echo]), "NET_RESET_OK");
    case("net_loopback", "provider", net("loopback", &[]), "NET_LOOPBACK_OK");
    // Names: the guest's libc asks its nameserver over UDP, a connected UDP socket the fd hook
    // hands in, to the stub here (no resolver of unsharek's).
    case("net_resolve", "dns", net("resolve", &["echo.test", "10.0.0.1", "nx.test", "denied.test"]), "NET_RESOLVE_OK");
    // The resolver's files are unsharek's, written when the hook is set, before the setup closures:
    // a setup's setresuid doesn't keep them from being written (they were once written after
    // setup, as uid 1000: EACCES).
    case("net_resolve_user", "dns_user", net("resolve", &["echo.test", "10.0.0.1", "nx.test", "denied.test"]), "NET_RESOLVE_OK");
    // A connected UDP socket's datagrams both ways; an unconnected sendto beyond loopback refused.
    case("net_udp", "dns", net("udp", &["10.0.0.53", "53"]), "NET_UDP_OK");
    case("net_listen", "provider", net("listen", &["7000", "10.9.9.9:4242"]), "NET_LISTEN_OK");
    if let Some(py) = std::env::var_os("UNSHAREK_TEST_PYTHON") {
        let url = format!("http://10.0.0.2:{}/", s.http);
        case(
            "net_python_http",
            "provider",
            vec![
                py.to_string_lossy().into_owned(),
                "-c".into(),
                format!("import urllib.request, sys; sys.stdout.write(urllib.request.urlopen({url:?}, timeout=5).read().decode())"),
            ],
            "NET_HTTP_OK",
        );
    }
    // Fork mode, from forked processes: the hooks are init's process's, and a forked process's
    // host ops were refused (ENETUNREACH, no answers, its listen the guest's own: bash running
    // curl, every interactive shell). They are forwarded to init's executor now; a child and a
    // grandchild connect, resolve, and take a host connection. And init itself still does.
    let forked = |depth: &str, c: &str, a: &[&str]| -> Vec<String> {
        let mut v = vec![fx::bin("net").display().to_string(), "fork".into(), depth.into(), c.to_string()];
        v.extend(a.iter().map(|s| s.to_string()));
        v
    };
    let mut fork_case = |name: &'static str, kind: &'static str, argv: Vec<String>, marker: &'static str| {
        trials.push(Trial::test(format!("{name}::fork"), move || check(kind, argv, marker)));
    };
    fork_case("net_echo", "provider_fork", net("echo", &["10.0.0.1", &echo]), "NET_ECHO_OK");
    fork_case("net_echo_child", "provider_fork", forked("1", "echo", &["10.0.0.1", &echo]), "NET_ECHO_OK");
    fork_case("net_echo_grandchild", "provider_fork", forked("2", "echo", &["10.0.0.1", &echo]), "NET_ECHO_OK");
    fork_case("net_many_child", "provider_fork", forked("1", "many", &["10.0.0.1", &echo]), "NET_MANY_OK");
    fork_case("net_nonblock_child", "provider_fork", forked("1", "nonblock", &["10.0.0.1", &echo]), "NET_NONBLOCK_OK");
    fork_case("net_refused_child", "provider_fork", forked("1", "refused", &["10.0.0.66", &echo]), "NET_REFUSED_OK");
    fork_case("net_listen_child", "provider_fork", forked("1", "listen", &["7000", "10.9.9.9:4242"]), "NET_LISTEN_OK");
    // A forked process's lookups and UDP: its connected UDP sockets' datagrams served by init's
    // process (the fd is init's), whole, through a seqpacket end. Known bug, so ignored: in fork
    // mode a UDP fd this harness's `OnConnect::fd` hook hands in (granted at lockdown, not
    // received) has the kernel hit lkl_bug ("thread_sched_jb() can be used only for host task")
    // at the program's first send. The CLI's provider (fds received on its control socket) does
    // the same in fork mode and works (`unsharek --mode fork --net all -- net udp IP PORT`, and
    // real lookups).
    for (name, argv, marker) in [
        ("net_resolve_child", forked("1", "resolve", &["echo.test", "10.0.0.1", "nx.test", "denied.test"]), "NET_RESOLVE_OK"),
        ("net_udp", net("udp", &["10.0.0.53", "53"]), "NET_UDP_OK"),
        ("net_udp_child", forked("1", "udp", &["10.0.0.53", "53"]), "NET_UDP_OK"),
    ] {
        trials.push(Trial::test(format!("{name}::fork"), move || check("dns_fork", argv, marker)).with_ignored_flag(true));
    }
    trials.push(Trial::test("passfd_epoll::coroutine", || {
        let argv = vec![fx::bin("fd_epoll").display().to_string()];
        let (code, out, err) = run("passfd", &argv, |mut sock| {
            // "ready" from the program once it waits in epoll; then the host writes.
            let mut b = [0u8; 5];
            if sock.read_exact(&mut b).is_ok() {
                thread::sleep(Duration::from_millis(50));
                let _ = sock.write_all(b"ping");
            }
        })?;
        if code != 0 || !out.contains("FD_EPOLL_OK") {
            return Err(format!("exit {code}\n--- stdout:\n{out}\n--- stderr:\n{err}").into());
        }
        Ok(())
    }));
    // capnix's repro: edge-triggered epoll on a passed fd, three rounds (tokio's use).
    trials.push(Trial::test("passfd_epoll_et::coroutine", || {
        let argv = vec![fx::bin("fd_epoll_et").display().to_string()];
        let (code, out, err) = run("passfd", &argv, |mut sock| {
            for _ in 0..3 {
                let mut b = [0u8; 5];
                if sock.read_exact(&mut b).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
                let _ = sock.write_all(b"ping");
            }
        })?;
        if code != 0 || !out.contains("FD_EPOLL_ET_OK") {
            return Err(format!("exit {code}\n--- stdout:\n{out}\n--- stderr:\n{err}").into());
        }
        Ok(())
    }));
    // The sandbox's end with a hook's session still waiting on its held fd: the program connects
    // once (the connect hook making a syscall of its own, as capnweb-rs's stacker does) and exits
    // 3 at once, its socket open. It must end with 3, promptly. It hung when the hook's syscall
    // made the executor a thread of init's process (capnix's `the_default_net_refuses_without_caps`).
    let echo = s.echo.to_string();
    for kind in ["provider", "provider_syscall"] {
        let argv = vec![fx::bin("net_exit").display().to_string(), "connect".into(), "10.0.0.1".into(), echo.clone(), "3".into()];
        trials.push(Trial::test(format!("net_exit_code_{kind}::coroutine"), move || {
            let t0 = std::time::Instant::now();
            let (code, out, err) = run(kind, &argv, proxy)?;
            let took = t0.elapsed();
            if code != 3 || !out.contains("NET_EXIT_CONNECTED") || took > Duration::from_secs(3) {
                return Err(format!("exit {code} after {took:?}, wanted 3\n--- stdout:\n{out}\n--- stderr:\n{err}").into());
            }
            Ok(())
        }));
    }
    // Bytes the program writes and shuts down just before it exits reach the hook's stream, all of
    // them and then the EOF, as a closed socket's data is still sent on Linux (capnix's
    // `bytes_written_just_before_exit_arrive`). They were lost: the sandbox ended at init's exit,
    // before the copy ran. 1 MiB: more than the kernel's socket buffers hold at the exit.
    for n in [5usize, 1 << 20] {
        let argv = vec![fx::bin("net_exit").display().to_string(), "write".into(), "10.0.0.1".into(), "9".into(), n.to_string()];
        trials.push(Trial::test(format!("net_exit_flush_{n}::coroutine"), move || {
            let got = Arc::new(Mutex::new(Sunk::default()));
            let g = got.clone();
            let (code, out, err) = run("provider", &argv, move |sock| sink(sock, &g))?;
            let got = got.lock().unwrap();
            let want: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            if code != 0 || !out.contains("NET_EXIT_WRITTEN") || got.data != want || !got.eof || got.reset {
                return Err(format!(
                    "exit {code}; the stream got {} of {n} bytes (matching: {}), eof {}, reset {}\n--- stdout:\n{out}\n--- stderr:\n{err}",
                    got.data.len(),
                    got.data == want[..got.data.len().min(n)],
                    got.eof,
                    got.reset
                )
                .into());
            }
            Ok(())
        }));
    }
    libtest_mimic::run(&args, trials).exit();
}

/// What a [`sink`] got on its one connection.
#[derive(Default)]
struct Sunk {
    data: Vec<u8>,
    eof: bool,
    reset: bool,
}

/// The provider's other end as a sink: every connect accepted, its bytes and its end noted.
fn sink(sock: UnixStream, got: &Mutex<Sunk>) {
    let mut w = sock.try_clone().unwrap();
    let mut sock = sock;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let n = match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some((id, op, p)) = take_frame(&mut buf) {
            let mut g = got.lock().unwrap();
            match op {
                CONNECT => {
                    let _ = w.write_all(&frame(id, CONNECTED, &[]));
                }
                DATA => g.data.extend_from_slice(&p),
                CLOSE => g.eof = true,
                RESET => g.reset = true,
                _ => {}
            }
        }
    }
}
