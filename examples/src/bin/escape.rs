//! The host filter at work: a hostile program (c/gate_probe.c) calls host syscalls through the
//! runtime's own syscall instruction, the "gate", as a compromised program that found it would.
//! Run three ways:
//!
//! 1. as a sandbox is: its first forbidden call kills the sandbox (SIGSYS);
//! 2. with `.deny(Deny::Errno)`, a debugging knob the escape tests use: each forbidden call fails
//!    with EPERM, and it lives to say so;
//! 3. with a restriction on top (`Builder::restrict`, a seccomp program of the caller's, stacked
//!    with the mode's filter) that kills `getppid` from anywhere: the program's own `getppid`,
//!    the guest's until now, kills it. A restriction sees the program's syscalls as well as the
//!    gate's (a kill outranks the routing filter's trap; an errno doesn't, and is felt by the
//!    gate's calls only), and only ever takes away: the filter can't be widened (a sandbox's host
//!    fds are its typed calls, `pass_fd` and `hold_fd`).
//!
//!     cargo run -p exobox-examples --bin escape
//!
//! Why the gate matters: the routing filter tells exobox's own syscalls (made from the gate) from
//! the program's (trapped, served by the guest kernel) by the instruction's address. That is
//! routing, not security, since the program shares the address space and can jump there. What
//! the gate may do is the mode's short allowlist, each argument pinned, and less with restrictions.

use exobox::{Deny, Mode, Sandbox, SockFilter, setup};
use exobox_examples as ex;

fn sandbox(how: &str) -> ! {
    let run = || -> Result<std::convert::Infallible, exobox::Error> {
        let prog = ex::c_program("gate_probe");
        let b = Sandbox::builder().mode(Mode::Coroutine);
        let b = match how {
            "errno" => b.deny(Deny::Errno),
            // Classic BPF over `struct seccomp_data`: the number, and getppid's is a kill
            // (seccompiler or libseccomp would write the same program).
            "restrict" => b.deny(Deny::Errno).restrict([
                SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 }, // load the syscall number
                SockFilter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_getppid as u32 },
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x8000_0000 }, // KILL_PROCESS
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x7fff_0000 }, // ALLOW
            ]),
            _ => b, // a sandbox as it is: the filter kills
        };
        let mut sb = b.build()?;
        let store = sb.map_closure(&prog, &[prog.parent().unwrap().to_owned()])?;
        {
            let _g = sb.intercept()?;
            setup::mount_closure(&store)?;
        }
        sb.run(&ex::os(&[prog.to_str().unwrap()]), &[])
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
        ("kill", "a sandbox as it is"),
        ("errno", ".deny(Deny::Errno)"),
        ("restrict", ".deny(Deny::Errno).restrict(getppid: kill)"),
    ] {
        println!("\n{what}");
        let out = ex::self_command(how).output().expect("spawn");
        print!("{}", String::from_utf8_lossy(&out.stdout));
        print!("{}", String::from_utf8_lossy(&out.stderr));
        println!("  => {}", ex::describe(out.status));
    }
}
