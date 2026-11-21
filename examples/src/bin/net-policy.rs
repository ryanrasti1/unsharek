//! Pluggable networking with a policy. Three processes:
//!
//! - this one: starts a local HTTP server and the proxy, builds the sandbox and forks it off
//!   (`Guest::spawn`), the proxy and the sandbox joined by a socketpair;
//! - the proxy (this example re-run, started before the sandbox's first guard: after it, the
//!   process can't exec): holds the real network and the policy, an allowlist of names and
//!   ports, and logs every attempt with the guest pid that made it;
//! - the sandbox: Python's `urllib` fetching an allowed URL and some refused ones. Its network
//!   hooks (`OnConnect`, `OnResolve`) send every connect and lookup over its one held fd
//!   (`Guest::hold_fd_as`, found by the hooks with `cx.held`) to the proxy
//!   (`unsharek_examples::mux`: a tiny framing), a session started at lockdown (`on_start`). A
//!   connect carries the name its address was resolved from (`cx.name_of`).
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

/// The allowlist: a name, the one port allowed on it, and where the proxy really connects. Each
/// name resolves to an address of no one (10.0.0.N): a loopback answer would be the guest's own
/// loopback, which never reaches the hooks. (Without an `on_resolve` at all, unsharek would give
/// each name an address of its own, and the connect would still carry the name.)
struct Allow {
    name: String,
    port: u16,
    target: String,
}

struct Proxy(Vec<Allow>);

impl mux::Policy for Proxy {
    fn resolve(&mut self, pid: i32, name: &str) -> Result<Vec<Ipv4Addr>, NetError> {
        let r = match self.0.iter().position(|a| a.name == name) {
            Some(i) => Ok(vec![Ipv4Addr::new(10, 0, 0, i as u8 + 1)]),
            None => Err(NetError::NoName),
        };
        match &r {
            Ok(ips) => eprintln!("[proxy] guest pid {pid}: resolve {name} -> {}", ips[0]),
            Err(e) => eprintln!("[proxy] guest pid {pid}: resolve {name} -> refused ({e})"),
        }
        r
    }

    fn connect(&mut self, pid: i32, addr: SocketAddrV4, name: &str) -> Result<TcpStream, NetError> {
        // By name: the target is the allowlist's, whatever address the sandbox says.
        let Some(a) = self.0.iter().find(|a| a.name == name) else { return refuse(pid, addr, "not a name we gave out") };
        if a.port != addr.port() {
            return refuse(pid, addr, &format!("{} allows port {} only", a.name, a.port));
        }
        eprintln!("[proxy] guest pid {pid}: connect {addr} ({}:{}) -> allowed, to {}", a.name, a.port, a.target);
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
    let (on_connect, on_resolve) = mux::hooks();
    let mut g = Guest::boot(GuestConfig::default())?;
    g.on_connect(on_connect)?;
    g.on_resolve(on_resolve)?;
    g.on_start(mux::start);
    g.hold_fd_as("net", sock.into())?;
    g.mount_closure(&[&python])?;
    let mut argv = vec![python.display().to_string(), "-c".into(), CLIENT.into()];
    argv.extend(urls);
    let argv: Vec<_> = argv.into_iter().map(Into::into).collect();
    let env = ex::os(&["PYTHONUNBUFFERED=1"]); // its lines in order with the proxy's
    g.spawn(move |mut g| {
        unsharek::lockdown(unsharek::SandboxConfig::new().grant([0, 1, 2]).pipe(|c| g.configure_sandbox(c))?)?;
        Err(g.run(move || unsharek::execve(&argv, &env))?)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if ex::role().as_deref() == Some("proxy") {
        let port: u16 = args[0].parse().unwrap();
        let mut allow = vec![Allow { name: "web.local".into(), port, target: format!("127.0.0.1:{port}") }];
        if args.iter().any(|a| a == "--internet") {
            allow.push(Allow { name: "example.com".into(), port: 80, target: "example.com:80".into() });
        }
        // SAFETY: fd 3 is the proxy's end, from the parent (`give_fd`), and nothing else owns it.
        mux::serve(UnixStream::from(unsafe { OwnedFd::from_raw_fd(3) }), Proxy(allow));
        return;
    }
    let _ = ex::nix_program("UNSHAREK_TEST_PYTHON"); // skip before starting anything
    let port = http_server();
    let mut urls = vec![
        format!("http://web.local:{port}/"),     // allowed
        format!("http://web.local:{}/", port + 1), // the name, but not the port
        "http://elsewhere.test/".to_string(),      // a name not on the list
    ];
    let internet = args.iter().any(|a| a == "--internet");
    if internet {
        urls.push("http://example.com/".into());
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
