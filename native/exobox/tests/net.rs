//! The program's network through a sandbox's hooks (`exobox::net`), each case a sandbox in a
//! child process of its own (this binary re-run), named `<case>::coroutine` as the suite's are.
//!
//! The provider plays capnix's part: it holds ONE fd (a socketpair end, the child's fd 3), starts
//! its session on first use (`cx.spawn`: a reader and a writer task) and multiplexes every
//! connect and lookup over it with a trivial framing (stream id, op, length, bytes), one stream
//! per connect. This process holds the other end: a proxy that makes real loopback TCP
//! connections to the echo and HTTP servers it started (any 10.0.0.0/8 address, port P, is
//! 127.0.0.1:P; 10.0.0.66 is refused, 10.0.0.67 denied, 10.0.0.68 reset once connected) and answers lookups from a table
//! (`echo.test` 10.0.0.1, `web.test` 10.0.0.2, `denied.test` denied, others no such name).

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

use exobox::{Cx, HeldFd, Hooks, NetError, OnConnect, OnListen, OnResolve, PreExec};
use exobox_fixtures as fx;
use futures_io::{AsyncRead, AsyncWrite};
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

const CHILD: &str = "EXOBOX_NET_TEST_CHILD";
const ARGV: &str = "EXOBOX_NET_TEST_ARGV";

// ---- the framing ----

const CONNECT: u8 = 1;
const DATA: u8 = 2;
const CLOSE: u8 = 3;
const RESET: u8 = 4;
const RESOLVE: u8 = 5;
const CONNECTED: u8 = 10;
const ERROR: u8 = 11;
const ADDRS: u8 = 12;

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
                CONNECTED | ERROR | ADDRS => {
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

fn provider(fd: HeldFd) -> (OnConnect, OnResolve, OnListen) {
    let connect = OnConnect::new(move |cx: Cx, _pid, addr: SocketAddr| async move {
        let s = session(cx, fd);
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
    });
    let resolve = OnResolve::new(move |cx: Cx, _pid, name: String| async move {
        let s = session(cx, fd);
        let (_, op, data) = request(&s, RESOLVE, name.as_bytes(), false).await;
        match op {
            ADDRS => Ok(data.chunks(4).map(|c| IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3]))).collect()),
            _ => Err(error_of(&data)),
        }
    });
    let listen = OnListen::new(move |_cx: Cx, _pid, _addr| async move {
        let peer = SocketAddr::from(([10, 9, 9, 9], 4242));
        Ok(OneConn(Some((peer, Hello(b"hello from the host")))))
    });
    (connect, resolve, listen)
}

/// The child: a sandbox for argv (`ARGV`), with the provider (`provider`), none (`nohooks`), or
/// fd 3 passed as fd 1000 (`passfd`).
fn child(kind: &str) -> ! {
    let argv: Vec<OsString> = std::env::var(ARGV).unwrap().split('\x1f').map(OsString::from).collect();
    let config = exobox::Config {
        argv: vec![argv[0].clone()],
        allow_paths: vec![fx::bin_dir()],
        image_cache: std::env::var_os("EXOBOX_NET_TEST_CACHE").map(PathBuf::from),
        ..Default::default()
    };
    let store = exobox::store(&config).unwrap();
    let mut sb = exobox::Sandbox::boot(exobox::Mode::Coroutine, exobox::GuestConfig::default()).unwrap();
    // SAFETY: fd 3 is this process's, from the parent, and nothing else owns it.
    let fd3 = unsafe { OwnedFd::from_raw_fd(3) };
    let mut hooks = Hooks::default();
    match kind {
        "provider" => {
            let held = sb.hold_fd(fd3).unwrap();
            (hooks.on_connect, hooks.on_resolve, hooks.on_listen) = provider(held);
        }
        "passfd" => {
            sb.pass_fd(fd3, 1000);
        }
        _ => drop(fd3),
    }
    let mounts: Vec<_> = store.mounts.iter().map(|m| (sb.map_image(&m.image).unwrap(), m.guest.clone())).collect();
    hooks.pre_exec = PreExec::new(move || exobox::setup::mount_closure(&mounts));
    let env: Vec<OsString> = vec!["EXOBOX_TEST_MODE=coroutine".into()];
    let e = sb.run(hooks, &argv, &env).unwrap_err();
    eprintln!("exobox: {e}");
    std::process::exit(125)
}

// ---- this process: the servers and the proxy ----

/// An echo server: each connection's bytes back, and its EOF (after them) back too.
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
                RESOLVE => match std::str::from_utf8(&p).unwrap_or("") {
                    "echo.test" => send(&w, id, ADDRS, &[10, 0, 0, 1]),
                    "web.test" => send(&w, id, ADDRS, &[10, 0, 0, 2]),
                    "denied.test" => send(&w, id, ERROR, &[0]),
                    _ => send(&w, id, ERROR, &[4]),
                },
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
        .env("EXOBOX_NET_TEST_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
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
    case("net_unreachable", "nohooks", net("unreachable", &["10.0.0.1", &echo]), "NET_UNREACHABLE_OK");
    case("net_loopback", "provider", net("loopback", &[]), "NET_LOOPBACK_OK");
    case("net_loopback_nohooks", "nohooks", net("loopback", &[]), "NET_LOOPBACK_OK");
    case(
        "net_resolve",
        "provider",
        net("resolve", &["echo.test", "10.0.0.1", "nx.test", "denied.test"]),
        "NET_RESOLVE_OK",
    );
    case("net_listen", "provider", net("listen", &["7000", "10.9.9.9:4242"]), "NET_LISTEN_OK");
    if let Some(py) = std::env::var_os("EXOBOX_TEST_PYTHON") {
        let url = format!("http://web.test:{}/", s.http);
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
    // A socket used after fork is fork mode's (the hooks run in init's process, the child's host
    // ops would forward to it): not yet.
    trials.push(Trial::test("net_fork::fork", || Ok(())).with_ignored_flag(true));
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
    libtest_mimic::run(&args, trials).exit();
}
