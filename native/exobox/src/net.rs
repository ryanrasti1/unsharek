//! Pluggable networking: the hooks a sandbox runs for the program's network (README plan item 9).
//!
//! The program's AF_INET sockets are its own for loopback (127.0.0.0/8, 0.0.0.0): connects, binds
//! and listens there are the guest kernel's, as always. Everything else goes to the [`Hooks`]
//! given to [`Sandbox::run`](crate::Sandbox::run):
//!
//! - **`on_connect(cx, pid, addr)`**: a program's `connect` to `addr`. `Ok(stream)`: the program's
//!   connect succeeds, and exobox copies both ways between its socket and `stream` (who closes
//!   what: below). `Err(e)`: the connect fails with `e`'s errno. A blocking connect waits for the
//!   hook; a nonblocking one is `EINPROGRESS`, then poll/epoll and `SO_ERROR` say how it went. If
//!   the program closes the socket first, the hook's future is dropped.
//! - **`on_listen(cx, pid, addr)`**: a program's `listen` on `addr` (not bound to loopback: the
//!   guest's own clients connect first, locally, whatever the hook says). `Ok(incoming)`: each
//!   `(peer, stream)` it yields is a connection the program accepts, `peer` its getpeername;
//!   until the stream ends or the program closes the listener (the stream is dropped then). An
//!   error leaves the listen the guest's alone (the program's `listen` succeeded already).
//! - **`on_resolve(cx, pid, name)`**: a name lookup. The guest's `/etc/resolv.conf` names
//!   10.0.2.3, the guest's libc asks it over UDP, and exobox answers from this hook: A records
//!   for its IPv4 addresses (IPv6 ones are left out), AAAA with no data.
//! - **`pre_exec()`**: host code run as the guest's init before the program (what `run`'s setup
//!   closure was): mounts, files.
//!
//! With no hook, everything but loopback is unreachable (`ENETUNREACH`, and lookups fail).
//!
//! **Errors** ([`NetError`]), as the program sees them: for a connect, `Denied` EACCES,
//! `Refused` ECONNREFUSED, `Unreachable` ENETUNREACH, `Timeout` ETIMEDOUT, `NoName` ENETUNREACH,
//! `Unsupported` EAFNOSUPPORT, `Io` EIO. For a lookup (getaddrinfo's codes, through glibc's
//! resolver): `NoName` NXDOMAIN (EAI_NONAME); `Denied` and `Unsupported` NOTAUTH, a failure
//! not to retry (musl's EAI_FAIL; glibc folds it into EAI_NONAME: it would have retried REFUSED
//! and NOTIMP, as a server's trouble, into EAI_AGAIN); the rest SERVFAIL (EAI_AGAIN).
//!
//! **Who closes what**, between the program's socket and a hook's stream (each direction a byte
//! stream of its own):
//! - The program's `shutdown(SHUT_WR)`: the stream is closed for writing (`poll_close`, a
//!   half-close, after everything the program wrote); the program may go on reading.
//! - The program's `close()`: the same close, then the stream is dropped: nothing more is read.
//! - The program's close with data it hadn't read (TCP's RST): the stream is dropped without a
//!   close (an abort).
//! - The stream's EOF (a read of 0): the program reads EOF; it may go on writing.
//! - An error from the stream (a read, write or close): the program's socket is reset (its next
//!   call fails with ECONNRESET) and the stream is dropped.
//! - Both directions done: the stream is dropped, the program's socket closed.
//!
//! **Where the hooks run, and the authority rule.** The hooks run inside the sandbox, after
//! lockdown, on its executor ([`Cx`]): in the program's address space, on one of its coroutines.
//! A compromised program can read and write their memory, and so drive whatever connection a
//! provider holds (a [`HeldFd`]) as it likes. That connection must therefore carry no more
//! authority than the program's own channel would: policy (which addresses, which names) lives
//! behind it, in the process at its other end, never in the hook. The hook is plumbing, not a
//! guard.
//!
//! What the hooks may do: compute, allocate (exobox's allocator serves the sandbox after
//! lockdown), spawn tasks ([`Cx::spawn`]), wait on time and on the host fds held for them
//! ([`Sandbox::hold_fd`](crate::Sandbox::hold_fd), [`Cx::readable`]), and use streams opened
//! before lockdown (a `TcpStream` connected before `run`, held). Not: make syscalls (they would
//! be the guest's, as init's: a thread of the program's process, which an exec waits for), open
//! host sockets or files (no host syscall is left for that), or block (the executor is one of
//! the sandbox's coroutines: a blocking call stops the program too).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use exobox_rt::dns::Rcode;
use exobox_rt::executor::{self, POLLIN, POLLOUT};
use exobox_rt::tsi::{self, ByteStream, Conn};
use futures_io::{AsyncRead, AsyncWrite};
use rustix::io::Errno;

pub use exobox_rt::executor::{FdReady, Sleep};

use crate::Error;

/// Why a hook refused (see the module comment for each one's errno).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("denied")]
    Denied,
    #[error("refused")]
    Refused,
    #[error("unreachable")]
    Unreachable,
    #[error("timed out")]
    Timeout,
    #[error("no such name")]
    NoName,
    #[error("not supported")]
    Unsupported,
    #[error("I/O error")]
    Io,
}

impl NetError {
    /// What a program's `connect` fails with.
    pub fn connect_errno(self) -> i32 {
        match self {
            NetError::Denied => libc::EACCES,
            NetError::Refused => libc::ECONNREFUSED,
            NetError::Unreachable | NetError::NoName => libc::ENETUNREACH,
            NetError::Timeout => libc::ETIMEDOUT,
            NetError::Unsupported => libc::EAFNOSUPPORT,
            NetError::Io => libc::EIO,
        }
    }

    /// The resolver's answer for a lookup that failed so.
    fn rcode(self) -> Rcode {
        match self {
            NetError::NoName => Rcode::NxDomain,
            NetError::Denied | NetError::Unsupported => Rcode::NotAuth,
            _ => Rcode::ServFail,
        }
    }
}

/// An I/O error by its kind: refused, denied, timed out, unreachable; anything else `Io`.
impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => NetError::Refused,
            io::ErrorKind::PermissionDenied => NetError::Denied,
            io::ErrorKind::TimedOut => NetError::Timeout,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => NetError::Unreachable,
            io::ErrorKind::Unsupported => NetError::Unsupported,
            _ => NetError::Io,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The hooks.

/// What a sandbox runs for its program: before it starts, and for its network (module comment).
/// Each field defaults to none: `Hooks { on_connect: OnConnect::new(..), ..Default::default() }`.
#[derive(Default)]
pub struct Hooks {
    pub pre_exec: PreExec,
    pub on_connect: OnConnect,
    pub on_listen: OnListen,
    pub on_resolve: OnResolve,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field("pre_exec", &self.pre_exec.0.is_some())
            .field("on_connect", &self.on_connect.0.is_some())
            .field("on_listen", &self.on_listen.0.is_some())
            .field("on_resolve", &self.on_resolve.0.is_some())
            .finish()
    }
}

type PreExecFn = Box<dyn FnOnce() -> Result<(), Error>>;

/// Host code run as the guest's init before the program's exec: every syscall it makes is the
/// guest's (host data must be read before `run` and moved in). Files and fds it leaves open are
/// the program's.
#[derive(Default)]
pub struct PreExec(pub(crate) Option<PreExecFn>);

impl PreExec {
    pub fn new<F, E>(f: F) -> PreExec
    where
        F: FnOnce() -> Result<(), E> + 'static,
        E: Into<Error>,
    {
        PreExec(Some(Box::new(move || f().map_err(Into::into))))
    }
}

use tsi::{ConnectFn, ListenFn, ResolveFn};

/// The program's connects to anything but loopback: `async |cx, pid, addr| -> Result<stream,
/// NetError>`, the stream any `AsyncRead + AsyncWrite` (futures-io's; tokio's with
/// [`OnConnect::tokio`]).
#[derive(Default)]
pub struct OnConnect(pub(crate) Option<ConnectFn>);

fn errno(e: NetError) -> Errno {
    Errno::from_raw_os_error(e.connect_errno())
}

impl OnConnect {
    pub fn new<F, Fut, S>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<S, NetError>> + 'static,
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move { fut.await.map(|s| Conn::Stream(Box::pin(Io(s)))).map_err(errno) })
        })))
    }

    /// For a provider that drives the program's socket itself: `Ok(drive)` connects it, and
    /// `drive` is called with the program's end ([`GuestSocket`]) once connected.
    pub fn drive<F, Fut, D>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<D, NetError>> + 'static,
        D: FnOnce(GuestSocket) + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|d| Conn::Drive(Box::new(move |g: tsi::GuestSocket| d(GuestSocket(Some(g))))))
                    .map_err(errno)
            })
        })))
    }

    /// As [`OnConnect::new`], for streams with tokio's `AsyncRead + AsyncWrite`.
    #[cfg(feature = "tokio")]
    pub fn tokio<F, Fut, S>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<S, NetError>> + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move { fut.await.map(|s| Conn::Stream(Box::pin(TokioIo(s)))).map_err(errno) })
        })))
    }
}

/// The program's listens on anything but loopback: `async |cx, pid, addr| -> Result<incoming,
/// NetError>`, `incoming` a `Stream` of `(peer, stream)`.
#[derive(Default)]
pub struct OnListen(pub(crate) Option<ListenFn>);

impl OnListen {
    pub fn new<F, Fut, St, S>(mut f: F) -> OnListen
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<St, NetError>> + 'static,
        St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        OnListen(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|st| {
                        let b: tsi::BoxIncoming =
                            Box::pin(IncomingOf(st, |s| -> tsi::BoxStream { Box::pin(Io(s)) }));
                        b
                    })
                    .map_err(errno)
            })
        })))
    }

    /// As [`OnListen::new`], for streams with tokio's `AsyncRead + AsyncWrite`.
    #[cfg(feature = "tokio")]
    pub fn tokio<F, Fut, St, S>(mut f: F) -> OnListen
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<St, NetError>> + 'static,
        St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    {
        OnListen(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|st| {
                        let b: tsi::BoxIncoming =
                            Box::pin(IncomingOf(st, |s| -> tsi::BoxStream { Box::pin(TokioIo(s)) }));
                        b
                    })
                    .map_err(errno)
            })
        })))
    }
}

/// The program's name lookups: `async |cx, pid, name| -> Result<Vec<IpAddr>, NetError>`. `name`
/// is lowercased, without a trailing dot.
#[derive(Default)]
pub struct OnResolve(pub(crate) Option<ResolveFn>);

impl OnResolve {
    pub fn new<F, Fut>(mut f: F) -> OnResolve
    where
        F: FnMut(Cx, i32, String) -> Fut + 'static,
        Fut: Future<Output = Result<Vec<IpAddr>, NetError>> + 'static,
    {
        OnResolve(Some(Box::new(move |_, pid, name| {
            let fut = f(Cx, pid, name);
            Box::pin(async move {
                match fut.await {
                    Ok(ips) => Ok(ips
                        .into_iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(v4) => Some(v4),
                            IpAddr::V6(_) => None,
                        })
                        .collect()),
                    Err(e) => Err(e.rcode()),
                }
            })
        })))
    }
}

impl Hooks {
    /// The network hooks, given to the runtime (the rest is `pre_exec`).
    pub(crate) fn install(self) -> (PreExec, bool) {
        let resolves = self.on_resolve.0.is_some();
        tsi::set_hooks(tsi::Hooks { connect: self.on_connect.0, listen: self.on_listen.0, resolve: self.on_resolve.0 });
        (self.pre_exec, resolves)
    }
}

// ------------------------------------------------------------------------------------------------
// The adapters: a hook's streams as the runtime's.

fn to_errno(e: io::Error) -> Errno {
    Errno::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO))
}

/// A futures-io stream as the runtime's `ByteStream`.
struct Io<S>(S);

impl<S: AsyncRead + AsyncWrite + Unpin> ByteStream for Io<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_read(cx, buf).map_err(to_errno)
    }
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(to_errno)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(to_errno)
    }
}

/// A tokio stream as the runtime's `ByteStream`.
#[cfg(feature = "tokio")]
struct TokioIo<S>(S);

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> ByteStream for TokioIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(to_errno(e))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(to_errno)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>> {
        Pin::new(&mut self.0).poll_shutdown(cx).map_err(to_errno)
    }
}

/// A `Stream` of `(peer, stream)` as the runtime's `Incoming` (IPv6 peers are left out: the
/// program's socket is AF_INET).
struct IncomingOf<St, F>(St, F);

impl<St, S, F> tsi::Incoming for IncomingOf<St, F>
where
    St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin,
    F: Fn(S) -> tsi::BoxStream + Unpin,
{
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<(SocketAddrV4, tsi::BoxStream)>> {
        loop {
            match Pin::new(&mut self.0).poll_next(cx) {
                Poll::Ready(Some((SocketAddr::V4(peer), s))) => return Poll::Ready(Some((peer, (self.1)(s)))),
                Poll::Ready(Some((SocketAddr::V6(_), _))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The executor's handle, held fds, the guest's socket.

/// The hooks' handle on the sandbox's executor: spawn a task, the clock, timers, held fds. A
/// token (`Copy`, `Send`, `Sync`: one executor per sandbox), so a no_std protocol core's runtime
/// is a newtype over it (capnweb's `Runtime { spawn, now, sleep_until }`: `spawn(task)` is
/// `cx.spawn(task)`, `now()` is `cx.now()`, `sleep_until(d)` is `Box::pin(cx.sleep_until(d))`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Cx;

impl Cx {
    /// Run `f` in the background on the executor, to completion (a provider's session, say).
    pub fn spawn(&self, f: impl Future<Output = ()> + 'static) {
        executor::spawn(f)
    }

    /// Monotonic time since an arbitrary origin (CLOCK_MONOTONIC).
    pub fn now(&self) -> Duration {
        executor::Cx.now()
    }

    /// Ready once [`Cx::now`] reaches `deadline`.
    pub fn sleep_until(&self, deadline: Duration) -> Sleep {
        executor::Cx.sleep_until(deadline)
    }

    /// Ready once `fd` is readable (or has an error or hangup).
    pub fn readable(&self, fd: &HeldFd) -> FdReady {
        executor::Cx.readable(fd.fd)
    }

    /// Ready once `fd` is writable (or has an error or hangup).
    pub fn writable(&self, fd: &HeldFd) -> FdReady {
        executor::Cx.writable(fd.fd)
    }
}

/// A host fd held for the hooks ([`Sandbox::hold_fd`](crate::Sandbox::hold_fd)): a provider's
/// connection, made before lockdown. Nonblocking; read and written through the runtime's gate,
/// the filter allowing `read` and `write` on exactly this fd; waited on by the executor
/// ([`Cx::readable`]). As `AsyncRead + AsyncWrite` it is a provider's stream. Open for the
/// sandbox's life (`Copy`: a handle).
#[derive(Clone, Copy, Debug)]
pub struct HeldFd {
    pub(crate) fd: RawFd,
}

impl AsRawFd for HeldFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

fn io_err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

impl HeldFd {
    /// One `read`; `WouldBlock` if nothing is there.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        exobox_rt::trap::read(self.fd as u32, buf).map_err(io_err)
    }

    /// One `write`; `WouldBlock` if there's no room.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        exobox_rt::trap::write(self.fd as u32, buf).map_err(io_err)
    }

    fn poll_io(&self, cx: &mut Context<'_>, events: i16, mut f: impl FnMut() -> io::Result<usize>) -> Poll<io::Result<usize>> {
        loop {
            match f() {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if executor::poll_fd(self.fd, events, cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => return Poll::Ready(r),
            }
        }
    }
}

impl AsyncRead for HeldFd {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLIN, || fd.read(buf))
    }
}

impl AsyncWrite for HeldFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLOUT, || fd.write(buf))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    /// A held fd stays open for the sandbox's life (no host `shutdown` is allowed): nothing.
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for HeldFd {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let fd = *self;
        let dst = buf.initialize_unfilled();
        match fd.poll_io(cx, POLLIN, || fd.read(dst)) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for HeldFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLOUT, || fd.write(buf))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The host's end of one of the program's connections, for a provider that drives it itself
/// ([`OnConnect::drive`]): what the program writes is read here, what is written here it reads.
/// `poll_close` is a half-close (the program reads EOF, and may still write); dropped, the
/// program's socket is closed (EOF); [`GuestSocket::reset`] resets it (ECONNRESET). A read of 0
/// is the program's shutdown of its writing or its close; an error `ConnectionReset` its close
/// with data unread.
#[derive(Debug)]
pub struct GuestSocket(Option<tsi::GuestSocket>);

impl GuestSocket {
    fn inner(&mut self) -> &mut tsi::GuestSocket {
        self.0.as_mut().expect("GuestSocket used after reset")
    }

    /// Close with a reset: the program's next call on its socket fails with ECONNRESET.
    pub fn reset(mut self) {
        if let Some(g) = self.0.take() {
            g.reset();
        }
    }
}

impl AsyncRead for GuestSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.inner().poll_read(cx, buf) {
            // The program's close: an EOF, as its shutdown is.
            Poll::Ready(Err(Errno::PIPE)) => Poll::Ready(Ok(0)),
            p => p.map_err(io_err),
        }
    }
}

impl AsyncWrite for GuestSocket {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.inner().poll_write(cx, buf).map_err(io_err)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner().shutdown().map_err(io_err))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for GuestSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match AsyncRead::poll_read(self.as_mut(), cx, dst) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for GuestSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}
