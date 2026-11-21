//! The CLI on a terminal (cli/tty.rs, src/pty.rs), driven through a host pty as a person at a
//! terminal would: in fork mode the program gets a pty of the guest's, so an interactive bash
//! sees a terminal, prompts, runs what is typed, takes ^C for its foreground job and keeps going,
//! and ends with its status; the host terminal is put back as it was. Before this, the guest saw
//! its stdio as plain host fds: no terminal, so bash printed no prompt and `stty` failed.

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// A host pty, its size set; the CLI started on its slave (stdin, stdout and stderr, its
/// controlling terminal). The master and the child's pid.
fn spawn(args: &[&str]) -> (OwnedFd, libc::pid_t) {
    let bin = CString::new(env!("CARGO_BIN_EXE_unsharek")).unwrap();
    let argv: Vec<CString> = std::iter::once(bin.clone()).chain(args.iter().map(|a| CString::new(*a).unwrap())).collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let (mut m, mut s): (RawFd, RawFd) = (-1, -1);
    let ws = libc::winsize { ws_row: 33, ws_col: 101, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: openpty into locals; the child only sets up its terminal and execs.
    unsafe {
        assert_eq!(libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::setsid();
            libc::ioctl(s, libc::TIOCSCTTY, 0);
            for fd in 0..3 {
                libc::dup2(s, fd);
            }
            libc::close(m);
            libc::execv(bin.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
        libc::close(s);
        (OwnedFd::from_raw_fd(m), pid)
    }
}

/// What the master gives within `t`, appended to `out`.
fn read_for(m: &OwnedFd, out: &mut Vec<u8>, t: Duration) {
    use std::os::fd::AsRawFd;
    let end = Instant::now() + t;
    let mut buf = [0u8; 4096];
    while Instant::now() < end {
        let mut p = libc::pollfd { fd: m.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: poll and read on our fd, into locals.
        unsafe {
            if libc::poll(&mut p, 1, 50) > 0 {
                let n = libc::read(m.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len());
                if n <= 0 {
                    return;
                }
                out.extend_from_slice(&buf[..n as usize]);
            }
        }
    }
}

/// Until `want` is in `out`, or `t` is over.
fn wait_for(m: &OwnedFd, out: &mut Vec<u8>, want: &str, t: Duration) -> bool {
    let end = Instant::now() + t;
    while Instant::now() < end {
        if String::from_utf8_lossy(out).contains(want) {
            return true;
        }
        read_for(m, out, Duration::from_millis(100));
    }
    String::from_utf8_lossy(out).contains(want)
}

fn send(m: &OwnedFd, b: &[u8]) {
    use std::os::fd::AsRawFd;
    // SAFETY: a write from a borrowed buffer.
    assert_eq!(unsafe { libc::write(m.as_raw_fd(), b.as_ptr().cast(), b.len()) }, b.len() as isize);
}

/// The child's end, within `t`: its exit status, or None.
fn status(pid: libc::pid_t, t: Duration) -> Option<i32> {
    let end = Instant::now() + t;
    let mut st = 0;
    while Instant::now() < end {
        // SAFETY: waitpid into a local.
        if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
            return Some(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -libc::WTERMSIG(st) });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: the child we made.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    None
}

fn bash() -> String {
    std::env::var("UNSHAREK_TEST_BASH").expect("UNSHAREK_TEST_BASH (the devshell's bash)")
}

#[test]
fn interactive_bash_on_a_guest_pty() {
    let (m, pid) = spawn(&["--mode", "fork", "--closure", &bash(), "--", &bash(), "--norc", "-i"]);
    let mut out = vec![];
    let t = Duration::from_secs(5);
    assert!(wait_for(&m, &mut out, "# ", t), "no prompt: {}", String::from_utf8_lossy(&out));
    send(&m, b"[ -t 0 ] && echo IS-A-TTY\r");
    assert!(wait_for(&m, &mut out, "IS-A-TTY\r\n", t), "{}", String::from_utf8_lossy(&out));
    // The guest pty's size is the host terminal's.
    send(&m, b"shopt -s checkwinsize; echo COLS-$COLUMNS-ROWS-$LINES\r");
    assert!(wait_for(&m, &mut out, "COLS-101-ROWS-33", t), "{}", String::from_utf8_lossy(&out));
    // ^C is the guest's: it interrupts the foreground job, and the shell goes on.
    // (A builtin that waits: bash's closure has no `sleep`.)
    send(&m, b"read -t 100 x\r");
    read_for(&m, &mut out, Duration::from_millis(500));
    send(&m, b"\x03");
    read_for(&m, &mut out, Duration::from_millis(300));
    send(&m, b"echo AFTER-INT-$?\r");
    assert!(wait_for(&m, &mut out, "AFTER-INT-130", t), "{}", String::from_utf8_lossy(&out));
    send(&m, b"exit 7\r");
    read_for(&m, &mut out, Duration::from_millis(300));
    assert_eq!(status(pid, t), Some(7), "{}", String::from_utf8_lossy(&out));
}

/// The network from the interactive shell: on a terminal the program is a child of the pty's init
/// (src/pty_init.c), and a forked process had no network (the provider's fds are init's process's):
/// a typed command's connect was ENETUNREACH. Forwarded to init's executor now, it echoes through
/// the provider (`--net all`) to a host server.
#[test]
fn interactive_shell_has_the_network() {
    use std::io::{Read, Write};
    // The host's address on its default route: the guest's 127.0.0.1 is its own loopback.
    let u = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    u.connect("192.0.2.1:9").unwrap();
    let ip = u.local_addr().unwrap().ip().to_string();
    let l = std::net::TcpListener::bind((ip.as_str(), 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = c.read(&mut buf) {
                    if c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = c.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    let bin_dir = unsharek_fixtures::bin_dir().display().to_string();
    let (m, pid) = spawn(&[
        "--mode", "fork", "--net", "all", "--ro", &bin_dir, "--closure", &bin_dir, "--closure", &bash(), "--", &bash(), "--norc", "-i",
    ]);
    let mut out = vec![];
    let t = Duration::from_secs(5);
    assert!(wait_for(&m, &mut out, "# ", t), "no prompt: {}", String::from_utf8_lossy(&out));
    let net = unsharek_fixtures::bin("net").display().to_string();
    send(&m, format!("{net} echo {ip} {port}\r").as_bytes());
    assert!(wait_for(&m, &mut out, "NET_ECHO_OK", t), "{}", String::from_utf8_lossy(&out));
    send(&m, b"exit 0\r");
    read_for(&m, &mut out, Duration::from_millis(300));
    assert_eq!(status(pid, t), Some(0), "{}", String::from_utf8_lossy(&out));
}

/// The terminal's settings after the CLI are those before it (raw mode undone), and a run that
/// isn't on a terminal is as ever: no pty (the suite's cases, whose stdin is a pipe or /dev/null).
#[test]
fn terminal_settings_restored() {
    let script = "stty -g > /dev/null; before=$(stty -g); X --mode fork --closure B -- B -c 'exit 3'; s=$?; after=$(stty -g); \
                  [ \"$before\" = \"$after\" ] && echo SAME-$s || echo DIFFERENT-$s";
    let script = script.replace('X', env!("CARGO_BIN_EXE_unsharek")).replace('B', &bash());
    let (m, pid) = spawn_host_shell(&script);
    let mut out = vec![];
    assert!(wait_for(&m, &mut out, "SAME-3", Duration::from_secs(5)), "{}", String::from_utf8_lossy(&out));
    assert_eq!(status(pid, Duration::from_secs(5)), Some(0));
}

/// A host bash running `script` on a fresh host pty.
fn spawn_host_shell(script: &str) -> (OwnedFd, libc::pid_t) {
    let bash = CString::new(bash()).unwrap();
    let args = [bash.clone(), CString::new("-c").unwrap(), CString::new(script).unwrap()];
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let (mut m, mut s): (RawFd, RawFd) = (-1, -1);
    // SAFETY: as spawn's.
    unsafe {
        assert_eq!(libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::setsid();
            libc::ioctl(s, libc::TIOCSCTTY, 0);
            for fd in 0..3 {
                libc::dup2(s, fd);
            }
            libc::close(m);
            libc::execv(bash.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
        libc::close(s);
        (OwnedFd::from_raw_fd(m), pid)
    }
}
