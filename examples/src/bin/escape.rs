//! The host filter at work: a closure run as the sandbox's program (`Locked::run`) tries to
//! reach the host, as a compromised program would, one attempt per sandbox. Each starts with an
//! ordinary syscall (trapped: the guest kernel's answer), then makes one forbidden host call,
//! which kills the sandbox (SIGSYS):
//!
//!     cargo run -p unsharek-examples --bin escape
//!
//! The attempts: `getppid` made from unsharek's own syscall instruction, the "gate", which the
//! closure finds by scanning the binary's code for it (it shares the address space: nothing in it
//! is hidden from the program); a host file opened through the gate; and a host socket made
//! through it. The gate's address check only routes; what the gate may do is the filter's short
//! list, each argument pinned. (A host fd the process had open before lockdown is closed then:
//! `read` on it from the gate is EBADF, not a kill.)

use std::os::fd::AsRawFd;

use unsharek::{Guest, GuestConfig};
use unsharek_examples as ex;

/// The gate's last instructions: `mov r9, [rsp + 8]; syscall; ret` (unsharek-rt's `trap::gate`).
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
/// one of unsharek's own.
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

/// The hostile program, after lockdown: `attempt` is one of [`ATTEMPTS`].
fn hostile(attempt: &str, secret_fd: i32) -> i32 {
    // An ordinary call traps and is the guest kernel's: init's parent, 0.
    // SAFETY: getppid.
    show("getppid(), trapped: the guest's", unsafe { libc::getppid() } as isize);
    let Some(gate) = find_gate() else {
        println!("  no gate found");
        return 2;
    };
    let mut b = [0u8; 16];
    match attempt {
        // The same number from the gate is a host syscall: the filter decides.
        "getppid" => show("getppid() via the gate: the host's", via_gate(gate, libc::SYS_getppid, 0, 0, 0)),
        "openat" => {
            let path = c"/etc/passwd";
            show("openat(\"/etc/passwd\") via the gate", via_gate(gate, libc::SYS_openat, libc::AT_FDCWD as usize, path.as_ptr() as usize, 0))
        }
        _ => {
            // An fd the process had before lockdown: closed then (EBADF, the process lives on).
            show("read(an fd from before) via the gate", via_gate(gate, libc::SYS_read, secret_fd as usize, b.as_mut_ptr() as usize, b.len()));
            show("socket() via the gate", via_gate(gate, libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0))
        }
    }
    println!("  survived");
    0
}

const ATTEMPTS: [&str; 3] = ["getppid", "openat", "socket"];

fn sandbox(attempt: &str) -> ! {
    let run = || -> Result<std::convert::Infallible, unsharek::Error> {
        let g = Guest::boot(GuestConfig::default())?;
        // A host file opened before lockdown (here, this program's own binary), its fd number
        // kept for the closure: what a program might have inherited.
        let secret = std::fs::File::open(std::env::current_exe()?)?;
        let fd = secret.as_raw_fd();
        std::mem::forget(secret);
        let locked = g.lockdown(unsharek::stdio)?;
        let attempt = attempt.to_owned();
        locked.run(move || hostile(&attempt, fd))
    };
    let Err(e) = run();
    ex::fail(e)
}

fn main() {
    if let Some(attempt) = ex::role() {
        sandbox(&attempt);
    }
    println!("this process (the sandbox's host parent) is pid {}", std::process::id());
    for attempt in ATTEMPTS {
        println!("\n{attempt}");
        let out = ex::self_command(attempt).output().expect("spawn");
        print!("{}", String::from_utf8_lossy(&out.stdout));
        print!("{}", String::from_utf8_lossy(&out.stderr));
        println!("  => {}", ex::describe(out.status));
    }
}
