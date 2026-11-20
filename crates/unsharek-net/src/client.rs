//! The sandbox's side of the protocol: one session on the control socket, and the provider's
//! two calls. Generic over the socket (the sandbox's reads and receives go through its gate) and
//! the runtime (its executor), so the same code is tested on the host. Not trusted: it decides
//! nothing; a compromised program can make these calls itself, and the provider's policy is what
//! holds.

use std::net::{IpAddr, Ipv4Addr};
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
    [protocol::DENIED, protocol::REFUSED, protocol::UNREACHABLE, protocol::TIMEOUT, protocol::NO_NAME]
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

    /// `connect(ip, port)`: the connected socket's fd, received.
    pub fn connect(self: &Arc<Self>, ip: IpAddr, port: u16) -> impl Future<Output = Result<RawFd, Rejection>> + Send + use<S> {
        let this = Arc::clone(self);
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let main = this.main()?;
            let args = vec![CapnwebValue::String(ip.to_string()), CapnwebValue::Number(f64::from(port))];
            let call = main.call(vec![protocol::CONNECT.to_owned()], RpcPayload::from_app_params(CapnwebValue::Array(args)));
            let value = call.pull().await.map_err(|e| rejection(&e))?;
            value.downcast_custom::<Fd>().map(|fd| fd.0).map_err(|_| None)
        })
    }

    /// `resolve(name)`: its IPv4 addresses.
    pub fn resolve(self: &Arc<Self>, name: String) -> impl Future<Output = Result<Vec<Ipv4Addr>, Rejection>> + Send + use<S> {
        let this = Arc::clone(self);
        capnweb::runtime::scope(Arc::clone(&self.runtime), async move {
            let main = this.main()?;
            let call = main.call(
                vec![protocol::RESOLVE.to_owned()],
                RpcPayload::from_app_params(CapnwebValue::Array(vec![CapnwebValue::String(name)])),
            );
            match call.pull().await.map_err(|e| rejection(&e))? {
                CapnwebValue::Array(ips) => ips
                    .into_iter()
                    .map(|ip| match ip {
                        CapnwebValue::String(ip) => ip.parse().map_err(|_| None),
                        _ => Err(None),
                    })
                    .collect(),
                _ => Err(None),
            }
        })
    }
}
