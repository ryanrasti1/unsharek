//! The sandbox's side of the protocol: one session on the control socket, and the provider's
//! two calls. Generic over the socket (the sandbox's reads and receives go through its gate) and
//! the runtime (its executor), so the same code is tested on the host. Not trusted: it decides
//! nothing; a compromised program can make these calls itself, and the provider's policy is what
//! holds.

use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use capnweb::packet::{Fd, PacketSocket, PacketTransport};
use capnweb::runtime::Runtime;
use capnweb::{CapnwebValue, Error, RpcPayload, RpcSession, RpcSessionOptions, RpcStub};

use crate::protocol;

/// Why a call failed: a rejection's name ([`protocol`]), or `None` for anything else (the session
/// gone, a malformed answer).
pub type Rejection = Option<&'static str>;

fn rejection(e: &Error) -> Rejection {
    let Error::Serialized(e) = e else { return None };
    [protocol::DENIED, protocol::REFUSED, protocol::UNREACHABLE, protocol::TIMEOUT]
        .into_iter()
        .find(|n| *n == e.received_name())
}

enum State<S> {
    Idle(Option<S>),
    Started { _session: RpcSession, main: RpcStub },
    Failed,
}

/// The session, started at the first call (made with `runtime` entered: its read loop is
/// spawned on it).
pub struct Client<S: PacketSocket> {
    runtime: Arc<dyn Runtime>,
    state: Mutex<State<S>>,
}

impl<S: PacketSocket> Client<S> {
    pub fn new(runtime: Arc<dyn Runtime>, socket: S) -> Arc<Self> {
        Arc::new(Client { runtime, state: Mutex::new(State::Idle(Some(socket))) })
    }

    /// The provider's object; the lock is held for this synchronous function only.
    fn main(&self) -> Result<RpcStub, Rejection> {
        let mut state = self.state.lock().expect("client state poisoned");
        if let State::Idle(socket) = &mut *state {
            let socket = socket.take().expect("an idle client has its socket");
            *state = match PacketTransport::new(socket)
                .and_then(|t| RpcSession::new(Arc::new(t), None, RpcSessionOptions::default()))
            {
                Ok(session) => State::Started { main: session.get_remote_main(), _session: session },
                Err(_) => State::Failed,
            };
        }
        match &*state {
            State::Started { main, .. } => Ok(main.clone()),
            _ => Err(None),
        }
    }

    /// `connect(ip, port, udp)`: the connected socket's fd (TCP, or with `udp` a connected UDP
    /// socket), received, and its `Conn` (the half-close; released, the close).
    pub fn connect(
        self: &Arc<Self>,
        ip: IpAddr,
        port: u16,
        udp: bool,
    ) -> impl Future<Output = Result<(RawFd, RpcStub), Rejection>> + Send + use<S> {
        let this = Arc::clone(self);
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let main = this.main()?;
            let args = vec![CapnwebValue::String(ip.to_string()), CapnwebValue::Number(f64::from(port)), CapnwebValue::Bool(udp)];
            let call = main.call(vec![protocol::CONNECT.to_owned()], RpcPayload::from_app_params(CapnwebValue::Array(args)));
            let CapnwebValue::Array(v) = call.pull().await.map_err(|e| rejection(&e))? else { return Err(None) };
            let [fd, CapnwebValue::Stub(conn)] = &v[..] else { return Err(None) };
            Ok((fd.downcast_custom::<Fd>().map_err(|_| None)?.0, conn.clone()))
        })
    }

    /// `listen(port)`: the published port's listener for the guest's `port`, then its connections,
    /// one [`Client::accept`] each.
    pub fn listen(self: &Arc<Self>, port: u16) -> impl Future<Output = Result<RpcStub, Rejection>> + Send + use<S> {
        let this = Arc::clone(self);
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let main = this.main()?;
            let call = main.call(
                vec![protocol::LISTEN.to_owned()],
                RpcPayload::from_app_params(CapnwebValue::Array(vec![CapnwebValue::Number(f64::from(port))])),
            );
            match call.pull().await.map_err(|e| rejection(&e))? {
                CapnwebValue::Stub(stub) => Ok(stub),
                _ => Err(None),
            }
        })
    }

    /// The listener's next connection: its fd, received, and its peer.
    pub fn accept(&self, listener: &RpcStub) -> impl Future<Output = Result<(RawFd, std::net::SocketAddr, RpcStub), Rejection>> + Send + use<S> {
        // The call made inside the scope: made outside, its session work would go to capnweb-rs's
        // default runtime (a thread), not the caller's.
        let listener = listener.clone();
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let call = listener.call(vec![protocol::ACCEPT.to_owned()], RpcPayload::from_app_params(CapnwebValue::Array(vec![])));
            let CapnwebValue::Array(v) = call.pull().await.map_err(|e| rejection(&e))? else { return Err(None) };
            let [fd, ip, port, CapnwebValue::Stub(conn)] = &v[..] else { return Err(None) };
            let fd = fd.downcast_custom::<Fd>().map_err(|_| None)?.0;
            let (CapnwebValue::String(ip), CapnwebValue::Number(port)) = (ip, port) else { return Err(None) };
            let ip: IpAddr = ip.parse().map_err(|_| None)?;
            Ok((fd, std::net::SocketAddr::new(ip, *port as u16), conn.clone()))
        })
    }

    /// `conn.shutdownWrite()`: the half-close of a connection the provider passed in.
    pub fn shutdown_write(&self, conn: &RpcStub) -> impl Future<Output = ()> + Send + use<S> {
        let conn = conn.clone();
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let call = conn.call(vec![protocol::SHUTDOWN_WRITE.to_owned()], RpcPayload::from_app_params(CapnwebValue::Array(vec![])));
            let _ = call.pull().await;
        })
    }
}
