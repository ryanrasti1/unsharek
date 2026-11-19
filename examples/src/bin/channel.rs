//! A channel between the host and a sandboxed program: `Sandbox::pass_fd` gives the guest one end
//! of a socketpair as its fd 1000 (capnix's pattern: its Cap'n Web session runs over that fd).
//! The parent sends numbers; Python in the sandbox answers each with its square.
//!
//!     cargo run -p exobox-examples --bin channel
//!
//! The filter is widened to `read` and `write` on exactly that host fd: the channel is the
//! program's one way out, and whatever authority it carries is decided at the parent's end.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use exobox::{GuestConfig, Hooks, Mode, PreExec, Sandbox, setup};
use exobox_examples as ex;

/// The program: a line-oriented server on fd 1000, until EOF.
const SQUARES: &str = r#"
import os
rx, tx = os.fdopen(1000, "r"), os.fdopen(os.dup(1000), "w", buffering=1)
for line in rx:
    n = int(line)
    tx.write(f"{n * n}\n")
"#;

/// The sandbox, in a child: its fd 3 (the parent's socketpair end) becomes the guest's fd 1000.
fn sandbox(python: &Path) -> ! {
    let run = || -> Result<std::convert::Infallible, exobox::Error> {
        let mut sb = Sandbox::boot(Mode::Coroutine, GuestConfig::default())?;
        // SAFETY: fd 3 is ours, put there by the parent (`give_fd`), and nothing else owns it.
        sb.pass_fd(unsafe { OwnedFd::from_raw_fd(3) }, 1000);
        let store = ex::mount_closure(&mut sb, python, &[])?;
        let hooks = Hooks { pre_exec: PreExec::new(move || setup::mount_closure(&store)), ..Default::default() };
        sb.run(hooks, &ex::os(&[python.to_str().unwrap(), "-c", SQUARES]), &[])
    };
    let Err(e) = run();
    ex::fail(e)
}

fn main() {
    let python = ex::nix_program("EXOBOX_TEST_PYTHON");
    if ex::role().as_deref() == Some("sandbox") {
        sandbox(&python);
    }
    let (ours, theirs) = UnixStream::pair().expect("socketpair");
    let mut cmd = ex::self_command("sandbox");
    ex::give_fd(&mut cmd, &theirs, 3);
    let mut child = cmd.spawn().expect("spawn");
    drop(theirs); // the child's now: our copy would keep its reads from ever seeing EOF

    let mut answers = BufReader::new(ours.try_clone().unwrap());
    let mut tx = ours;
    for n in [3, 7, 12, 99] {
        writeln!(tx, "{n}").unwrap();
        let mut line = String::new();
        answers.read_line(&mut line).unwrap();
        println!("host sent {n:>3}, sandbox answered {}", line.trim());
    }
    // A half-close: the program's `for line in rx` ends, and so does the program.
    tx.shutdown(std::net::Shutdown::Write).unwrap();
    let status = child.wait().unwrap();
    println!("sandbox: {}", ex::describe(status));
}
