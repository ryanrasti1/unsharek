//! The network plugin from the CLI (`--net`, `--publish`; src/provider.rs, crates/unsharek-net):
//! the `net` fixture in the sandbox, its peers on the host. Each scenario in each mode it works in
//! (`MODES`); every run bounded.
//!
//! - `--net all`: a connect to a host echo server works, bytes both ways and the half-close. It
//!   listens on the host's own non-loopback address: the guest's 127.0.0.1 is its own loopback.
//! - `--net public`: the host's address (private), 10.x and the metadata address are refused
//!   (EACCES), by the provider's policy.
//! - no `--net`: the same connect is unreachable (no provider dials).
//! - `--publish 127.0.0.1:P:80`: a host client's connection to P reaches the guest's listener on
//!   80, "ping" and "pong" exchanged; without `--publish` the guest's listen is its own only.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use unsharek_fixtures as fx;

/// The modes the plugin works in.
const MODES: [&str; 3] = ["coroutine", "threaded", "fork"];

/// The host's address on its default route (a UDP socket's local address, no packet sent).
fn host_ip() -> String {
    let u = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    u.connect("192.0.2.1:9").unwrap();
    u.local_addr().unwrap().ip().to_string()
}

fn echo_server() -> u16 {
    let l = TcpListener::bind((host_ip().as_str(), 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 16 << 10];
                while let Ok(n @ 1..) = c.read(&mut buf) {
                    if c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = c.shutdown(Shutdown::Write);
            });
        }
    });
    port
}

fn unsharek(mode: &str, flags: &[String], args: &[String]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_unsharek"))
        .args(["--mode", mode, "--ro"])
        .arg(fx::bin_dir())
        .args(flags)
        .arg("--")
        .arg(fx::bin("net"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The run's exit code and output, killed past 10 s.
fn finish(mut child: Child) -> (Option<i32>, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    child.stderr.take().unwrap().read_to_string(&mut out).unwrap();
    (status.code(), out)
}

fn run(mode: &str, flags: &[&str], args: &[String]) -> (Option<i32>, String) {
    finish(unsharek(mode, &flags.iter().map(|s| s.to_string()).collect::<Vec<_>>(), args))
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn net_all_connects() {
    let port = echo_server().to_string();
    for mode in MODES {
        let (code, out) = run(mode, &["--net", "all"], &s(&["echo", &host_ip(), &port]));
        assert!(code == Some(0) && out.contains("NET_ECHO_OK"), "{mode}: {code:?}\n{out}");
    }
}

#[test]
fn net_public_refuses_local_and_private() {
    let port = echo_server().to_string();
    for mode in MODES {
        for ip in [host_ip().as_str(), "10.1.2.3", "169.254.169.254"] {
            let (code, out) = run(mode, &["--net", "public"], &s(&["denied", ip, &port]));
            assert!(code == Some(0) && out.contains("NET_DENIED_OK"), "{mode} {ip}: {code:?}\n{out}");
        }
    }
}

#[test]
fn no_net_is_unreachable() {
    let port = echo_server().to_string();
    for mode in MODES {
        let (code, out) = run(mode, &[], &s(&["echo", &host_ip(), &port]));
        assert!(code != Some(0) && !out.contains("NET_ECHO_OK"), "{mode}: {code:?}\n{out}");
    }
}

#[test]
fn publish_reaches_the_guests_listener() {
    for mode in MODES {
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let child = unsharek(mode, &s(&["--publish", &format!("127.0.0.1:{free}:80")]), &s(&["serve", "80"]));
        // The provider listens before the guest boots; the guest's listener is up a moment later.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut c = loop {
            match TcpStream::connect(("127.0.0.1", free)) {
                Ok(c) => break c,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{mode}: connect to the published port: {e}"),
            }
        };
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        let read = c.read_exact(&mut got);
        let (code, out) = finish(child);
        assert!(read.is_ok() && &got == b"pong", "{mode}: read {read:?} {got:?}\n{out}");
        assert!(code == Some(0) && out.contains("NET_SERVE_OK"), "{mode}: {code:?}\n{out}");
    }
}
