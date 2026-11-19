//! The host filter at work: a closure run as the sandbox's program (`Locked::run`) tries to
//! reach the host, as a compromised program would. Run three ways:
//!
//! 1. as a sandbox is: its first forbidden host call kills the sandbox (SIGSYS);
//! 2. with `.deny(Deny::Errno)`, a debugging knob the escape tests use: each forbidden call fails
//!    with EPERM, and it lives to say so;
//! 3. with a restriction on top (`tcb::Config::restrict`, a seccomp program of the caller's,
//!    stacked with the filter) that kills `getppid` from anywhere: the program's own `getppid`,
//!    the guest's until now, kills it. A restriction sees the program's syscalls as well as the
//!    gate's (a kill outranks the filter's trap; an errno doesn't, and is felt by the gate's calls
//!    only), and only ever takes away.
//!
//!     cargo run -p exobox-examples --bin escape
//!
//! What the closure tries: an ordinary syscall (trapped: the guest kernel's answer); the same call
//! made from exobox's own syscall instruction, the "gate", which it finds by scanning the
//! binary's code for it (it shares the address space: nothing in it is hidden from the program);
//! a host file through the gate; and a host fd the process had open before lockdown (closed at
//! lockdown: it wasn't granted). The gate's address check only routes; what the gate may do is the
//! filter's short list, each argument pinned.

use std::os::fd::AsRawFd;

use exobox::{Deny, Guest, GuestConfig, SockFilter};
use exobox_examples as ex;

/// The gate's last instructions: `mov r9, [rsp + 8]; syscall; ret` (exobox-rt's `trap::gate`).
const GATE_TAIL: [u8; 8] = [0x4c, 0x8b, 0x4c, 0x24, 0x08, 0x0f, 0x05, 0xc3];

unsafe extern "C" {
    // The linker's bounds of the binary's code.
    static __executable_start: u8;
    static etext: u8;
}

/// The gate's `syscall` instruction, found the way a compromised program would: in the code.
fn find_gate() -> Option<usize> {
    let (lo, hi) = (&raw const __executable_start as usize, &raw const etext as usize);
    // SAFETY: the binary's own code, mapped readable for the process's life.
    let text = unsafe { std::slice::from_raw_parts(lo as *const u8, hi - lo) };
    text.windows(GATE_TAIL.len()).position(|w| w == GATE_TAIL).map(|i| lo + i + 5)
}

/// A raw syscall made from the gate's `syscall` instruction: what the host's filter judges as
/// one of exobox's own.
fn via_gate(gate: usize, nr: i64, a0: usize, a1: usize, a2: usize) -> isize {
    let r: isize;
    // SAFETY: the gate's `syscall; ret`, called: the call's result comes back in rax. Whatever it
    // does is the host filter's to allow.
    unsafe {
        std::arch::asm!(
            "call {gate}",
            gate = in(reg) gate,
            inlateout("rax") nr as isize => r,
            in("rdi") a0, in("rsi") a1, in("rdx") a2, in("r10") 0, in("r8") 0, in("r9") 0,
            lateout("rcx") _, lateout("r11") _,
        );
    }
    r
}

fn show(what: &str, r: isize) {
    if r < 0 {
        println!("  {what:<38} -> {}", std::io::Error::from_raw_os_error(-r as i32));
    } else {
        println!("  {what:<38} -> {r}");
    }
}

/// The hostile program, after lockdown.
fn hostile(secret_fd: i32) -> i32 {
    // An ordinary call traps and is the guest kernel's: init's parent, 0.
    // SAFETY: getppid.
    show("getppid(), trapped: the guest's", unsafe { libc::getppid() } as isize);
    let Some(gate) = find_gate() else {
        println!("  no gate found");
        return 2;
    };
    // The same number from the gate is a host syscall: the filter decides.
    show("getppid() via the gate: the host's", via_gate(gate, libc::SYS_getppid, 0, 0, 0));
    let path = c"/etc/passwd";
    show("openat(\"/etc/passwd\") via the gate", via_gate(gate, libc::SYS_openat, libc::AT_FDCWD as usize, path.as_ptr() as usize, 0));
    // An fd the process had before lockdown: closed then, and not one the filter allows.
    let mut b = [0u8; 16];
    show("read(an fd from before) via the gate", via_gate(gate, libc::SYS_read, secret_fd as usize, b.as_mut_ptr() as usize, b.len()));
    println!("  survived");
    0
}

fn sandbox(how: &str) -> ! {
    let run = || -> Result<std::convert::Infallible, exobox::Error> {
        let g = Guest::boot(GuestConfig::default())?;
        // A host file opened before lockdown (here, this program's own binary), its fd number
        // kept for the closure: what a program might have inherited.
        let secret = std::fs::File::open(std::env::current_exe()?)?;
        let fd = secret.as_raw_fd();
        std::mem::forget(secret);
        let locked = g.lockdown(|s| {
            match how {
                "errno" => drop(s.deny(Deny::Errno)),
                // Classic BPF over `struct seccomp_data`: the number, and getppid's is a kill
                // (seccompiler or libseccomp would write the same program).
                "restrict" => drop(s.deny(Deny::Errno).restrict([
                    SockFilter { code: 0x20, jt: 0, jf: 0, k: 0 }, // load the syscall number
                    SockFilter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_getppid as u32 },
                    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x8000_0000 }, // KILL_PROCESS
                    SockFilter { code: 0x06, jt: 0, jf: 0, k: 0x7fff_0000 }, // ALLOW
                ])),
                _ => {} // a sandbox as it is: the filter kills
            }
            exobox::stdio(s)
        })?;
        locked.run(move || hostile(fd))
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
        ("errno", "s.deny(Deny::Errno)"),
        ("restrict", "s.deny(Deny::Errno).restrict(getppid: kill)"),
    ] {
        println!("\n{what}");
        let out = ex::self_command(how).output().expect("spawn");
        print!("{}", String::from_utf8_lossy(&out.stdout));
        print!("{}", String::from_utf8_lossy(&out.stderr));
        println!("  => {}", ex::describe(out.status));
    }
}
