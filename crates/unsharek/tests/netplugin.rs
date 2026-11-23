//! The network plugin from the CLI (`--net host`; src/hostnet.rs, unsharek-tcb's `plugin::Net`):
//! the `net` fixture in the sandbox, its peers on the host. Each scenario in each mode it works in
//! (`MODES`); every run bounded.
//!
//! - `--net host`: a connect to a host echo server works, bytes both ways and the half-close. It
//!   listens on the host's own non-loopback address: the guest's 127.0.0.1 is its own loopback.
//! - no `--net`: the same connect is unreachable (nothing dials).
//! - a guest listener on a port is the host's listener on it: a host client's connection reaches
//!   it, "ping" and "pong" exchanged.

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
    unsharek_stdin(mode, flags, args, Stdio::null())
}

fn unsharek_stdin(mode: &str, flags: &[String], args: &[String], stdin: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_unsharek"))
        .args(["--mode", mode, "--mount"])
        .arg(format!("{}:ro", fx::bin_dir().display()))
        .arg("--mount")
        .arg(format!("{}:closure", fx::bin_dir().display()))
        .args(flags)
        .arg("--")
        .arg(fx::bin("net"))
        .args(args)
        .stdin(stdin)
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
fn net_host_connects() {
    let port = echo_server().to_string();
    for mode in MODES {
        let (code, out) = run(mode, &["--net", "host"], &s(&["echo", &host_ip(), &port]));
        assert!(code == Some(0) && out.contains("NET_ECHO_OK"), "{mode}: {code:?}\n{out}");
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

/// A free port of the host's (bound, then let go).
fn free_port() -> u16 {
    TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn host_listener_reaches_the_guest() {
    for mode in MODES {
        let free = free_port();
        let child = unsharek(mode, &s(&["--net", "host"]), &s(&["serve", &free.to_string()]));
        // The guest's listener is the host's, up a moment after the sandbox starts.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut c = loop {
            match TcpStream::connect(("127.0.0.1", free)) {
                Ok(c) => break c,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{mode}: connect to the guest's port: {e}"),
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

/// Fork mode, from forked processes (a child, a grandchild): connects, and a listener's
/// connection taken by a server that isn't init. A host socket is init's process's: a forked
/// process's host ops were refused (ENETUNREACH: `bash -c 'curl …; echo'`, every interactive
/// shell); they are forwarded to init's executor, which serves the connection's bytes.
#[test]
fn forked_processes_have_the_network() {
    let port = echo_server().to_string();
    for depth in ["1", "2"] {
        let (code, out) = run("fork", &["--net", "host"], &s(&["fork", depth, "echo", &host_ip(), &port]));
        assert!(code == Some(0) && out.contains("NET_ECHO_OK"), "depth {depth}: {code:?}\n{out}");
    }
    let free = free_port();
    let child = unsharek("fork", &s(&["--net", "host"]), &s(&["fork", "1", "serve", &free.to_string()]));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut c = loop {
        match TcpStream::connect(("127.0.0.1", free)) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect to the guest's port: {e}"),
        }
    };
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    let read = c.read_exact(&mut got);
    let (code, out) = finish(child);
    assert!(read.is_ok() && &got == b"pong", "serve: read {read:?} {got:?}\n{out}");
    assert!(code == Some(0) && out.contains("NET_SERVE_OK"), "serve: {code:?}\n{out}");
}

/// Many idle connections polled at once (a server's wait): a write on the last wakes the program
/// promptly. The runtime watched 16 host fds and polled 8 at a time whatever the plugin's row
/// allowed (4096): past them a watch was dropped, and the poll slept until some other fd fired,
/// here never.
#[test]
fn many_idle_connections_wake_promptly() {
    const N: usize = 64;
    for mode in MODES {
        let l = TcpListener::bind((host_ip().as_str(), 0)).unwrap();
        let port = l.local_addr().unwrap().port().to_string();
        let child = unsharek(mode, &s(&["--net", "host"]), &s(&["idle", &N.to_string(), &host_ip(), &port]));
        let conns: Vec<TcpStream> = (0..N).map(|_| l.accept().unwrap().0).collect();
        // The program's poll is up once it has them all; a moment more for it to be asleep in it.
        thread::sleep(Duration::from_millis(200));
        let mut last = &conns[N - 1];
        last.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let t = Instant::now();
        last.write_all(b"go").unwrap();
        let mut got = [0u8; 3];
        let read = last.read_exact(&mut got);
        let took = t.elapsed();
        let (code, out) = finish(child);
        assert!(read.is_ok() && &got == b"ack", "{mode}: read {read:?} after {took:?}\n{out}");
        assert!(took < Duration::from_millis(200), "{mode}: woken after {took:?}");
        assert!(code == Some(0) && out.contains("NET_IDLE_OK"), "{mode}: {code:?}\n{out}");
    }
}

/// 1000 connections, each closed: the sandbox's host fds don't grow with them (each host socket
/// is closed when the guest closes its own).
#[test]
fn no_fd_leak_over_1000_connections() {
    let port = echo_server().to_string();
    for mode in MODES {
        let mut child = unsharek_stdin(mode, &s(&["--net", "host"]), &s(&["churn", &host_ip(), &port, "1000"]), Stdio::piped());
        let pid = child.id();
        // The fd table's size (/proc/PID/fd is closed to us: the sandbox isn't dumpable), which
        // grows past 1000 if the connections' fds leak.
        let count = || -> usize {
            let st = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("the sandbox's status");
            st.lines().find_map(|l| l.strip_prefix("FDSize:")).expect("FDSize").trim().parse().unwrap()
        };
        // Wait for the churn's end (its line), then count.
        let mut out = child.stdout.take().unwrap();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        let deadline = Instant::now() + Duration::from_secs(30);
        while !line.ends_with(b"connections\n") && Instant::now() < deadline {
            if out.read(&mut b).unwrap_or(0) == 0 {
                break;
            }
            line.push(b[0]);
        }
        let n = count();
        drop(child.stdin.take());
        let _ = child.wait();
        assert!(line.ends_with(b"connections\n"), "{mode}: {}", String::from_utf8_lossy(&line));
        assert!(n < 1000, "{mode}: an fd table of {n} after 1000 connections");
    }
}
