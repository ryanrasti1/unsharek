//! The host filter at work: a hostile program (c/gate_probe.c) calls host syscalls through the
//! runtime's own syscall instruction, the "gate", as a compromised program that found it would.
//! Run three ways:
//!
//! 1. the default deny, `Deny::Kill`: its first forbidden call kills the sandbox (SIGSYS);
//! 2. `.deny(Deny::Errno)`: each forbidden call fails with EPERM, and it lives to say so;
//! 3. `.allow("getppid")` on top: that one host syscall goes through (the answer is the real host
//!    parent: this process), the rest stay refused.
//!
//!     cargo run -p exobox-examples --bin escape
//!
//! Why the gate matters: the routing filter tells exobox's own syscalls (made from the gate) from
//! the program's (trapped, served by the guest kernel) by the instruction's address. That is
//! routing, not security, since the program shares the address space and can jump there. What
//! the gate may do is the mode's short allowlist, each argument pinned, plus rules like `allow`.

use exobox::{Deny, GuestConfig, Hooks, Mode, PreExec, Rule, Sandbox, setup};
use exobox_examples as ex;

fn sandbox(how: &str) -> ! {
    let run = || -> Result<std::convert::Infallible, exobox::Error> {
        let prog = ex::c_program("gate_probe");
        let mut sb = Sandbox::boot(Mode::Coroutine, GuestConfig::default())?;
        match how {
            "errno" => {
                sb.deny(Deny::Errno);
            }
            "allow" => {
                // A rule is a syscall plus conditions on its arguments: "write:arg0=3" is
                // `write` on fd 3 only. getppid has no arguments to pin.
                sb.deny(Deny::Errno).allow("getppid".parse::<Rule>()?);
            }
            _ => {} // Deny::Kill, the default
        }
        let store = ex::mount_closure(&mut sb, &prog, &[prog.parent().unwrap().to_owned()])?;
        let hooks = Hooks { pre_exec: PreExec::new(move || setup::mount_closure(&store)), ..Default::default() };
        sb.run(hooks, &ex::os(&[prog.to_str().unwrap()]), &[])
    };
    let Err(e) = run();
    ex::fail(e)
}

fn main() {
    if let Some(how) = ex::role() {
        sandbox(&how);
    }
    println!("this process (the sandbox's host parent) is pid {}", std::process::id());
    for (how, what) in [
        ("kill", "default: Deny::Kill"),
        ("errno", ".deny(Deny::Errno)"),
        ("allow", ".deny(Deny::Errno).allow(\"getppid\")"),
    ] {
        println!("\n{what}");
        let out = ex::self_command(how).output().expect("spawn");
        print!("{}", String::from_utf8_lossy(&out.stdout));
        print!("{}", String::from_utf8_lossy(&out.stderr));
        println!("  => {}", ex::describe(out.status));
    }
}
