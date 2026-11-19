//! Stdio as nextest gives it: stdin /dev/null, stdout and stderr pipes it reads (or the
//! terminal with --no-capture).

use std::io::{Read, Write};

/// Each of fds 0-2 has a file type (fork mode's were anon inodes with none: Node's
/// process.stdout threw).
pub fn stdio_types() {
    for fd in 0..=2 {
        // SAFETY: a zeroed out-struct.
        let st = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            assert_eq!(libc::fstat(fd, &mut st), 0, "fstat({fd})");
            st
        };
        assert_ne!(st.st_mode & libc::S_IFMT, 0, "fd {fd} has no file type (mode {:o})", st.st_mode);
    }
}

/// Nextest's stdin is /dev/null: a read is EOF at once.
pub fn stdin_eof() {
    let mut b = vec![];
    assert_eq!(std::io::stdin().read_to_end(&mut b).unwrap(), 0);
}

/// A megabyte to stdout and to stderr, which nextest's reader drains as it comes.
pub fn stdout_large() {
    let line = [b'x'; 1023];
    let mut out = std::io::stdout().lock();
    for _ in 0..1024 {
        out.write_all(&line).unwrap();
        out.write_all(b"\n").unwrap();
    }
    out.flush().unwrap();
    let mut err = std::io::stderr().lock();
    for _ in 0..1024 {
        err.write_all(&line).unwrap();
        err.write_all(b"\n").unwrap();
    }
}
