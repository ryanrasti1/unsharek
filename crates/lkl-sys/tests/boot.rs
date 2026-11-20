//! The plumbing, proven on stock parts: the kernel boots with tools/lkl's posix host, answers
//! syscalls, and halts. This is the only place the posix host is linked; exobox provides its own
//! host operations.

use core::ffi::{CStr, c_long};
use std::process::Command;

use lkl_sys::*;

// tools/lkl/lib (crates/lkl-sys/Makefile's liblkl-posix.a): the posix host's table, and its lkl_printf and
// lkl_bug, which win over shim.c's weak ones.
#[link(name = "lkl-posix", kind = "static")]
unsafe extern "C" {
    static mut lkl_host_ops: lkl_host_operations;
}

// shim.c's callbacks: the linker may still pull shim.c's object in (when it meets lkl-shim before
// the posix host's definitions), and then they must exist. Unused here.
#[unsafe(no_mangle)]
extern "C" fn exobox_lkl_print(_: *const core::ffi::c_char, _: core::ffi::c_ulong) {}
#[unsafe(no_mangle)]
extern "C" fn exobox_lkl_panic() -> ! {
    std::process::abort()
}

fn syscall(nr: c_long, args: &[c_long]) -> c_long {
    let mut params = [0; 6];
    params[..args.len()].copy_from_slice(args);
    // SAFETY: the kernel is running, and each caller's arguments are valid for its syscall.
    unsafe { lkl_syscall(nr, params.as_mut_ptr()) }
}

#[test]
fn boot_syscall_halt() {
    // SAFETY: one kernel per process (nextest runs each test in its own); the posix host's table
    // is static.
    unsafe {
        assert_eq!(lkl_init(&raw mut lkl_host_ops), 0);
        // A small pool: the test is about the plumbing, not memory.
        assert_eq!(lkl_start_kernel(c"mem=16M loglevel=4".as_ptr()), 0);
    }

    // struct new_utsname: six fields of 65 bytes, sysname first.
    let mut uts = [0u8; 6 * 65];
    assert_eq!(syscall(__lkl__NR_uname, &[uts.as_mut_ptr() as c_long]), 0);
    let sysname = CStr::from_bytes_until_nul(&uts[..65]).unwrap();
    assert_eq!(sysname, c"Linux");
    let release = CStr::from_bytes_until_nul(&uts[2 * 65..3 * 65]).unwrap();
    assert!(release.to_bytes().starts_with(b"6.12"), "{release:?}");
    assert!(syscall(__lkl__NR_getpid, &[]) > 0);

    // SAFETY: the kernel is running; nothing uses it after.
    unsafe {
        assert_eq!(lkl_sys_halt(), 0);
        lkl_cleanup();
    }
}

/// The kernel object can't be mis-relaxed (crates/lkl-sys/Makefile's -mrelax-relocations=no): it has no
/// R_X86_64_GOTPCRELX or REX_GOTPCRELX relocation, the kinds ld may rewrite. ld 2.46 rewrote a
/// GOTPCRELX `push` of a function pointer into `addr32 call` (capnix tier A).
#[test]
fn kernel_has_no_relaxable_got_relocations() {
    let obj = env!("LKL_KERNEL_OBJ");
    let out = Command::new("readelf")
        .args(["-rW", obj])
        .output()
        .expect("readelf (binutils, in the devshell)");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("R_X86_64_GOTPCREL "),
        "{obj}: no GOT relocations at all?"
    );
    let relaxable: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("GOTPCRELX"))
        .take(5)
        .collect();
    assert!(
        relaxable.is_empty(),
        "{obj}: relaxable GOT relocations:\n{}",
        relaxable.join("\n")
    );
}

/// The safety net: no `addr32 call` in this binary, which holds the kernel linked as any binary
/// linking lkl-sys does. That instruction is what a mis-relaxed GOT push turns into.
#[test]
fn no_mis_relaxed_got_push() {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("objdump")
        .arg("-d")
        .arg("--no-show-raw-insn")
        .arg(&exe)
        .output()
        .expect("objdump (binutils, in the devshell)");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let sites: Vec<&str> = text.lines().filter(|l| l.contains("addr32 call")).collect();
    assert!(
        sites.is_empty(),
        "{}: addr32 calls (a mis-relaxed GOT push?):\n{}",
        exe.display(),
        sites.join("\n")
    );
}
