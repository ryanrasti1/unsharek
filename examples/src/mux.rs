//! A tiny multiplexing protocol for `net-policy`: every connect and lookup of a sandbox over ONE
//! host fd (a socketpair end the sandbox holds as "net", `Sandbox::hold_fd_as`, which the hooks
//! find with `cx.held`), to a proxy process at its other end. After
//! `native/exobox/tests/net.rs`'s test provider.
//!
//! A frame is `id: u32 LE, op: u8, len: u32 LE, payload`. A connect or lookup is a request with a
//! fresh id, answered by one reply; a connected stream's bytes and closes then go both ways under
//! the request's id.
//!
//! Two halves: [`hooks`] runs inside the sandbox (exobox's async hooks, on its executor), and
//! [`serve`] in the proxy (ordinary blocking Rust, a thread per connection), which asks a
//! [`Policy`] about each request. The policy lives in the proxy, not in the hooks: see the
//! authority rule in `net-policy.rs`.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use exobox::{Cx, HeldFd, NetError, OnConnect, OnResolve};
use futures_io::{AsyncRead, AsyncWrite};

const CONNECT: u8 = 1; // pid: i32 LE, ip: 4 bytes, port: u16 BE, the name it was resolved from
const RESOLVE: u8 = 2; // pid: i32 LE, name
const DATA: u8 = 3;
const CLOSE: u8 = 4; // a half-close
const RESET: u8 = 5; // an abort
const CONNECTED: u8 = 10;
const ERROR: u8 = 11; // the index of a NetError in ERRORS
const ADDRS: u8 = 12; // IPv4 addresses, 4 bytes each

const ERRORS: [NetError; 4] = [NetError::Denied, NetError::Refused, NetError::NoName, NetError::Io];

fn frame(id: u32, op: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = id.to_le_bytes().to_vec();
    f.push(op);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// A whole frame at the front of `buf`, taken out.
fn take_frame(buf: &mut Vec<u8>) -> Option<(u32, u8, Vec<u8>)> {
    let len = u32::from_le_bytes(buf.get(5..9)?.try_into().unwrap()) as usize;
    if buf.len() < 9 + len {
        return None;
    }
    let f = (u32::from_le_bytes(buf[..4].try_into().unwrap()), buf[4], buf[9..9 + len].to_vec());
    buf.drain(..9 + len);
    Some(f)
}

// ---- in the sandbox --------------------------------------------------------------------------

#[derive(Default)]
struct Stream {
    inbuf: VecDeque<u8>,
    eof: bool,
    reset: bool,
    reader: Option<Waker>,
}

/// The session over the held fd: one per sandbox, shared by its hooks. `Rc<RefCell>` is fine:
/// every hook and task runs on the sandbox's one executor, and no borrow is held across an await.
#[derive(Default)]
struct Session {
    out: Vec<u8>,
    writer: Option<Waker>,
    streams: HashMap<u32, Stream>,
    replies: HashMap<u32, Reply>,
    next: u32,
}

type Shared = Rc<RefCell<Session>>;
/// A request's reply (op, payload) once it's there, and who waits for it.
type Reply = (Option<(u8, Vec<u8>)>, Option<Waker>);

fn wake(w: &mut Option<Waker>) {
    if let Some(w) = w.take() {
        w.wake();
    }
}

fn send(s: &Shared, id: u32, op: u8, payload: &[u8]) {
    let mut s = s.borrow_mut();
    s.out.extend_from_slice(&frame(id, op, payload));
    wake(&mut s.writer);
}

/// Reads frames off the fd: replies to their requests, stream data to its stream.
async fn reader(mut fd: HeldFd, s: Shared) {
    let (mut buf, mut chunk) = (Vec::new(), vec![0u8; 64 << 10]);
    loop {
        let n = poll_fn(|cx| Pin::new(&mut fd).poll_read(cx, &mut chunk)).await.unwrap_or(0);
        let mut ss = s.borrow_mut();
        if n == 0 {
            // The proxy is gone: every stream is reset.
            for st in ss.streams.values_mut() {
                st.reset = true;
                wake(&mut st.reader);
            }
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some((id, op, payload)) = take_frame(&mut buf) {
            if let (CONNECTED | ERROR | ADDRS, Some(r)) = (op, ss.replies.get_mut(&id)) {
                r.0 = Some((op, payload));
                wake(&mut r.1);
            } else if let Some(st) = ss.streams.get_mut(&id) {
                match op {
                    DATA => st.inbuf.extend(payload),
                    CLOSE => st.eof = true,
                    _ => st.reset = true,
                }
                wake(&mut st.reader);
            }
        }
    }
}

/// Writes what `send` queued.
async fn writer(mut fd: HeldFd, s: Shared) {
    let _ = poll_fn(|cx| loop {
        let mut ss = s.borrow_mut();
        if ss.out.is_empty() {
            ss.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match Pin::new(&mut fd).poll_write(cx, &ss.out) {
            Poll::Ready(Ok(n)) => drop(ss.out.drain(..n)),
            Poll::Ready(Err(e)) => return Poll::Ready(e),
            Poll::Pending => return Poll::Pending,
        }
    })
    .await;
}

/// One request and its reply.
async fn request(s: &Shared, op: u8, payload: &[u8]) -> (u32, u8, Vec<u8>) {
    let id = {
        let mut ss = s.borrow_mut();
        ss.next += 1;
        let id = ss.next;
        ss.replies.insert(id, (None, None));
        if op == CONNECT {
            ss.streams.insert(id, Stream::default());
        }
        id
    };
    send(s, id, op, payload);
    let (op, data) = poll_fn(|cx| {
        let mut ss = s.borrow_mut();
        let r = ss.replies.get_mut(&id).unwrap();
        match r.0.take() {
            Some(reply) => Poll::Ready(reply),
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

/// A connection's stream over the session: what exobox copies the program's socket to and from.
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
            buf.iter_mut().zip(st.inbuf.drain(..n)).for_each(|(d, b)| *d = b);
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
        if !std::mem::replace(&mut self.closed, true) {
            send(&self.s, self.id, CLOSE, &[]);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Proxied {
    fn drop(&mut self) {
        if !self.closed {
            send(&self.s, self.id, RESET, &[]); // dropped without a close: an abort
        }
        self.s.borrow_mut().streams.remove(&self.id);
    }
}

fn error_of(payload: &[u8]) -> NetError {
    payload.first().and_then(|&i| ERRORS.get(i as usize)).copied().unwrap_or(NetError::Io)
}

thread_local! {
    /// The sandbox's one session (every hook and task runs on its one executor).
    static SESSION: RefCell<Option<Shared>> = const { RefCell::new(None) };
}

/// The session over the fd held as "net": its reader and writer tasks, started by [`start`] (at
/// lockdown) or else by the first hook.
fn session(cx: Cx) -> Shared {
    SESSION.with(|s| {
        s.borrow_mut()
            .get_or_insert_with(|| {
                let fd = cx.held("net").expect("no fd held as \"net\"");
                let s = Shared::default();
                cx.spawn(reader(fd, s.clone()));
                cx.spawn(writer(fd, s.clone()));
                s
            })
            .clone()
    })
}

/// For `Builder::on_start`: the session up at lockdown, before the program's first connect.
pub async fn start(cx: Cx) {
    session(cx);
}

/// The sandbox's network hooks, over the fd held as "net". A connect carries the name its address
/// was resolved from (`cx.name_of`), so the proxy decides by name.
pub fn hooks() -> (OnConnect, OnResolve) {
    let connect = OnConnect::new(move |cx: Cx, pid, addr| {
        let s = session(cx);
        let name = cx.name_of(addr.ip()).unwrap_or_default();
        async move {
            let SocketAddr::V4(a) = addr else { return Err(NetError::Unsupported) };
            let mut p = pid.to_le_bytes().to_vec();
            p.extend_from_slice(&a.ip().octets());
            p.extend_from_slice(&a.port().to_be_bytes());
            p.extend_from_slice(name.as_bytes());
            match request(&s, CONNECT, &p).await {
                (id, CONNECTED, _) => Ok(Proxied { id, s, closed: false }),
                (id, _, e) => {
                    s.borrow_mut().streams.remove(&id);
                    Err(error_of(&e))
                }
            }
        }
    });
    let resolve = OnResolve::new(move |cx, pid, name: String| {
        let s = session(cx);
        async move {
            let mut p = pid.to_le_bytes().to_vec();
            p.extend_from_slice(name.as_bytes());
            match request(&s, RESOLVE, &p).await {
                (_, ADDRS, a) => Ok(a.chunks(4).map(|c| IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3]))).collect()),
                (_, _, e) => Err(error_of(&e)),
            }
        }
    });
    (connect, resolve)
}

// ---- in the proxy ----------------------------------------------------------------------------

/// What the proxy allows. `pid` is the guest's, and a connect's `name` the one its address was
/// resolved from, as the sandbox reports them: the program could lie about both, so they are for
/// logs and for picking a target, never for trust. What the proxy grants is the policy.
pub trait Policy {
    fn resolve(&mut self, pid: i32, name: &str) -> Result<Vec<Ipv4Addr>, NetError>;
    fn connect(&mut self, pid: i32, addr: SocketAddrV4, name: &str) -> Result<TcpStream, NetError>;
}

/// Serves one sandbox's session on `sock` until it closes.
pub fn serve(mut sock: UnixStream, mut policy: impl Policy) {
    let w = Arc::new(Mutex::new(sock.try_clone().unwrap()));
    let send = |w: &Mutex<UnixStream>, id, op, p: &[u8]| drop(w.lock().unwrap().write_all(&frame(id, op, p)));
    let code = |e: NetError| [ERRORS.iter().position(|&x| x == e).unwrap_or(ERRORS.len() - 1) as u8];
    let mut conns: HashMap<u32, TcpStream> = HashMap::new();
    let (mut buf, mut chunk) = (Vec::new(), vec![0u8; 64 << 10]);
    while let Ok(n @ 1..) = sock.read(&mut chunk) {
        buf.extend_from_slice(&chunk[..n]);
        while let Some((id, op, p)) = take_frame(&mut buf) {
            let pid = || i32::from_le_bytes(p[..4].try_into().unwrap());
            match op {
                RESOLVE => match policy.resolve(pid(), &String::from_utf8_lossy(&p[4..])) {
                    Ok(ips) => send(&w, id, ADDRS, &ips.iter().flat_map(|ip| ip.octets()).collect::<Vec<_>>()),
                    Err(e) => send(&w, id, ERROR, &code(e)),
                },
                CONNECT => {
                    let addr = SocketAddrV4::new(Ipv4Addr::new(p[4], p[5], p[6], p[7]), u16::from_be_bytes([p[8], p[9]]));
                    match policy.connect(pid(), addr, &String::from_utf8_lossy(&p[10..])) {
                        Ok(t) => {
                            let (mut r, w) = (t.try_clone().unwrap(), w.clone());
                            conns.insert(id, t);
                            send(&w, id, CONNECTED, &[]);
                            // The connection's bytes back to the sandbox, then its EOF (or reset).
                            std::thread::spawn(move || {
                                let mut b = vec![0u8; 32 << 10];
                                loop {
                                    match r.read(&mut b) {
                                        Ok(0) => return send(&w, id, CLOSE, &[]),
                                        Ok(n) => send(&w, id, DATA, &b[..n]),
                                        Err(_) => return send(&w, id, RESET, &[]),
                                    }
                                }
                            });
                        }
                        Err(e) => send(&w, id, ERROR, &code(e)),
                    }
                }
                DATA => drop(conns.get_mut(&id).map(|t| t.write_all(&p))),
                CLOSE => drop(conns.get(&id).map(|t| t.shutdown(Shutdown::Write))),
                RESET => drop(conns.remove(&id).map(|t| t.shutdown(Shutdown::Both))),
                _ => {}
            }
        }
    }
}
