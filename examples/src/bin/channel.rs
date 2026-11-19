//! A channel between the host and a sandboxed program: `Guest::pass_fd` gives the guest one end
//! of a socketpair as its fd 1000 (capnix's pattern: its Cap'n Web session runs over that fd).
//! The parent sends numbers; Python in the sandbox answers each with its square.
//!
//!     cargo run -p exobox-examples --bin channel
//!
//! Lockdown grants `read` and `write` on exactly that host fd: the channel is the
//! program's one way out, and whatever authority it carries is decided at the parent's end.
//!
//! This process builds the sandbox, and `Guest::spawn` forks it off to lock down and run (a
//! template's child: lockdown takes its process over, so it runs in a process of its own). The parent keeps its
//! end of the socketpair and talks; its own syscalls stay the host's.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use exobox::{Guest, GuestConfig, setup};
use exobox_examples as ex;

/// The program: a line-oriented server on fd 1000, until EOF.
const SQUARES: &str = r#"
import os
rx, tx = os.fdopen(1000, "r"), os.fdopen(os.dup(1000), "w", buffering=1)
for line in rx:
    n = int(line)
    tx.write(f"{n * n}\n")
"#;

fn main() -> Result<(), exobox::Error> {
    let python = ex::nix_program("EXOBOX_TEST_PYTHON");
    let (ours, theirs) = UnixStream::pair()?;

    let mut g = Guest::boot(GuestConfig::default())?;
    g.pass_fd(theirs.into(), 1000)?;
    let store = g.map_closure(&python, &[])?;
    g.run(|| setup::mount_closure(&store))??;
    let argv = ex::os(&[python.to_str().unwrap(), "-c", SQUARES]);
    let child = g.spawn(move |g| g.lockdown(exobox::stdio)?.exec(&argv, &[]))?;

    let mut answers = BufReader::new(ours.try_clone()?);
    let mut tx = ours;
    for n in [3, 7, 12, 99] {
        writeln!(tx, "{n}")?;
        let mut line = String::new();
        answers.read_line(&mut line)?;
        println!("host sent {n:>3}, sandbox answered {}", line.trim());
    }
    // A half-close: the program's `for line in rx` ends, and so does the program.
    tx.shutdown(std::net::Shutdown::Write)?;
    println!("sandbox: {}", ex::describe(child.wait()?));
    Ok(())
}
