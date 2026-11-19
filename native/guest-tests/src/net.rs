//! Sockets on the guest's own loopback (hello.c's TCP part, net.c's `loopback`), and the network
//! beyond it as a sandbox without network hooks has it (the CLI's: none). What a sandbox's hooks
//! do with the program's connects is native/exobox/tests/net.rs's (the library's API).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::thread;

use crate::tmp;

/// A server on 127.0.0.1, a client: bytes both ways (more than a socket buffer's worth), then a
/// half-close: the server's EOF after everything.
pub fn tcp_loopback() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    assert_ne!(at.port(), 0);
    let server = thread::spawn(move || {
        let (mut s, peer) = l.accept().unwrap();
        let mut all = vec![];
        s.read_to_end(&mut all).unwrap();
        s.write_all(&(all.len() as u64).to_le_bytes()).unwrap();
        (all, peer)
    });
    let mut c = TcpStream::connect(at).unwrap();
    c.set_nodelay(true).unwrap();
    let (mine, theirs) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
    let big: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7) as u8).collect();
    c.write_all(&big).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut n = [0u8; 8];
    c.read_exact(&mut n).unwrap();
    assert_eq!(u64::from_le_bytes(n), big.len() as u64);
    let mut rest = vec![];
    assert_eq!(c.read_to_end(&mut rest).unwrap(), 0, "no EOF after the server's reply");
    let (all, peer) = server.join().unwrap();
    assert!(all == big, "the server got {} bytes, not what was sent", all.len());
    assert_eq!(peer, mine);
    assert_eq!(theirs, at);
}

pub fn udp_loopback() {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..10u8 {
        a.send_to(&[i; 100], b.local_addr().unwrap()).unwrap();
    }
    for i in 0..10u8 {
        let mut buf = [0u8; 200];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!((n, from, buf[0]), (100, a.local_addr().unwrap(), i));
    }
}

/// AF_UNIX: a socketpair, a datagram pair, a listener on a path in /tmp.
pub fn unix_sockets() {
    let (mut x, mut y) = UnixStream::pair().unwrap();
    x.write_all(b"pair").unwrap();
    let mut b = [0u8; 4];
    y.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"pair");

    let (d1, d2) = UnixDatagram::pair().unwrap();
    d1.send(b"dgram").unwrap();
    let mut b = [0u8; 16];
    assert_eq!(d2.recv(&mut b).unwrap(), 5);

    let p = tmp("unix.sock");
    let l = UnixListener::bind(&p).unwrap();
    let t = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.write_all(b"from the listener").unwrap();
    });
    let mut c = UnixStream::connect(&p).unwrap();
    let mut got = String::new();
    c.read_to_string(&mut got).unwrap();
    t.join().unwrap();
    assert_eq!(got, "from the listener");
    std::fs::remove_file(&p).unwrap();
}

/// With no hooks, everything but loopback is unreachable: a connect is ENETUNREACH (net.c's
/// `unreachable`). Natively the host's network is whatever it is: not checked.
pub fn unreachable() {
    if crate::mode() == "native" {
        println!("natively: the host's network, not checked");
        return;
    }
    let e = TcpStream::connect("10.0.0.1:9").expect_err("a connect beyond loopback without hooks");
    assert_eq!(e.raw_os_error(), Some(libc::ENETUNREACH), "{e}");
}
