//! Pluggable networking with a policy. Three processes:
//!
//! - this one: starts a local HTTP server and the proxy, builds the sandbox and forks it off
//!   (`Guest::spawn`), the proxy and the sandbox joined by a socketpair;
//! - the proxy (this example re-run, started before the sandbox's first guard: after it, the
//!   process can't exec): holds the real network and the policy, an allowlist of addresses and
//!   ports, and logs every attempt with the guest pid that made it;
//! - the sandbox: Python's `urllib` fetching an allowed URL and some refused ones. Its network
//!   hook (`OnConnect`) sends every TCP connect over its one held fd (`Guest::hold_fd_as`,
//!   found by the hook with `cx.held`) to the proxy (`unsharek_examples::mux`: a tiny framing),
//!   a session started at lockdown (`on_start`). (Names: the guest's resolver speaks UDP to its
//!   nameservers, which a stream hook doesn't carry; an `OnConnect::fd` provider would.)
//!
//! Run it:
//!
//!     cargo run -p unsharek-examples --bin net-policy                 # fully local
//!     cargo run -p unsharek-examples --bin net-policy -- --internet   # example.com:80 allowed too
//!
//! **The authority rule.** The hooks run inside the sandbox, in the program's address space: a
//! compromised program can rewrite them, and drive the held fd itself. So the policy can't live
//! in the hooks; it lives in the proxy, a separate process, and the fd's authority is exactly what
//! the proxy grants. The hooks are plumbing. (After lockdown the sandbox can't open host sockets
//! anyway: the proxy is the only way out, and it had to be connected before the boot.)

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use unsharek::{Guest, GuestConfig, NetError};
use unsharek_examples::{self as ex, mux};

const CLIENT: &str = r#"
import sys, urllib.request
for url in sys.argv[1:]:
    try:
        body = urllib.request.urlopen(url, timeout=5).read().decode().strip()
        print(f"[python] GET {url} -> {body[:40]!r}")
    except Exception as e:
        print(f"[python] GET {url} -> failed: {getattr(e, 'reason', e)}")
"#;

/// The allowlist: an address of no one's (10.0.0.N: a loopback one would be the guest's own
/// loopback, which never reaches the hooks), the one port allowed on it, and where the proxy
/// really connects.
struct Allow {
    addr: Ipv4Addr,
    port: u16,
    target: String,
}

struct Proxy(Vec<Allow>);

impl mux::Policy for Proxy {
    fn connect(&mut self, pid: i32, addr: SocketAddrV4) -> Result<TcpStream, NetError> {
        // The target is the allowlist's, whatever the sandbox would rather reach.
        let Some(a) = self.0.iter().find(|a| a.addr == *addr.ip()) else { return refuse(pid, addr, "not on the list") };
        if a.port != addr.port() {
            return refuse(pid, addr, &format!("{} allows port {} only", a.addr, a.port));
        }
        eprintln!("[proxy] guest pid {pid}: connect {addr} -> allowed, to {}", a.target);
        let target = a.target.to_socket_addrs().map_err(NetError::from)?.next().ok_or(NetError::NoName)?;
        Ok(TcpStream::connect(target)?)
    }
}

fn refuse(pid: i32, addr: SocketAddrV4, why: &str) -> Result<TcpStream, NetError> {
    eprintln!("[proxy] guest pid {pid}: connect {addr} -> refused ({why})");
    Err(NetError::Refused)
}

/// The sandbox, built here and forked off: `sock` is its end of the socketpair, held for the hooks.
fn sandbox(sock: UnixStream, urls: Vec<String>) -> Result<unsharek::Child, unsharek::Error> {
    let python = ex::nix_program("UNSHAREK_TEST_PYTHON");
    let mut g = Guest::boot(GuestConfig::default())?;
    g.on_connect(mux::hooks())?;
    g.on_start(mux::start);
    g.hold_fd_as("net", sock.into())?;
    g.mount_closure(&[&python])?;
    let mut argv = vec![python.display().to_string(), "-c".into(), CLIENT.into()];
    argv.extend(urls);
    let argv: Vec<_> = argv.into_iter().map(Into::into).collect();
    let env = ex::os(&["PYTHONUNBUFFERED=1"]); // its lines in order with the proxy's
    g.spawn(move |mut g| {
        unsharek::lockdown(unsharek::stdio())?;
        Err(g.run(move || unsharek::execve(&argv, &env))?)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if ex::role().as_deref() == Some("proxy") {
        let port: u16 = args[0].parse().unwrap();
        let mut allow = vec![Allow { addr: Ipv4Addr::new(10, 0, 0, 1), port, target: format!("127.0.0.1:{port}") }];
        if args.iter().any(|a| a == "--internet") {
            allow.push(Allow { addr: Ipv4Addr::new(10, 0, 0, 2), port: 80, target: "example.com:80".into() });
        }
        // SAFETY: fd 3 is the proxy's end, from the parent (`give_fd`), and nothing else owns it.
        mux::serve(UnixStream::from(unsafe { OwnedFd::from_raw_fd(3) }), Proxy(allow));
        return;
    }
    let _ = ex::nix_program("UNSHAREK_TEST_PYTHON"); // skip before starting anything
    let port = http_server();
    let mut urls = vec![
        format!("http://10.0.0.1:{port}/"),     // allowed
        format!("http://10.0.0.1:{}/", port + 1), // the address, but not the port
        "http://10.0.0.9/".to_string(),           // an address not on the list
    ];
    let internet = args.iter().any(|a| a == "--internet");
    if internet {
        urls.push("http://10.0.0.2/".into()); // example.com:80, as the proxy maps it
    }

    let (a, b) = UnixStream::pair().expect("socketpair");
    let mut proxy = ex::self_command("proxy");
    proxy.arg(port.to_string()).args(internet.then_some("--internet"));
    ex::give_fd(&mut proxy, &a, 3);
    let mut proxy = proxy.spawn().expect("spawn the proxy");
    drop(a); // the proxy's now
    let sandbox = sandbox(b, urls).unwrap_or_else(|e| ex::fail(e));
    println!("sandbox: {}", ex::describe(sandbox.wait().unwrap()));
    // This process (the template) still holds its copy of the sandbox's end, so the proxy would
    // never see EOF: it is stopped instead.
    let _ = proxy.kill();
    let _ = proxy.wait();
}

/// A one-line HTTP server on loopback, in this process: what the allowlist lets the sandbox reach.
fn http_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut req = [0u8; 4096];
            let _ = c.read(&mut req);
            let _ = c.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 21\r\n\r\nhello from the host!\n");
        }
    });
    port
}
