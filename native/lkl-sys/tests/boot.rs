//! The plumbing, proven on stock parts: the kernel boots with tools/lkl's posix host, answers
//! syscalls, and halts. This is the only place the posix host is linked; exobox provides its own
//! host operations.

use core::ffi::{CStr, c_long};
use std::process::Command;

use lkl_sys::*;

// tools/lkl/lib (lkl/Makefile's liblkl-posix.a): the posix host's table, and lkl_printf and lkl_bug,
// which the kernel object needs from its host.
#[link(name = "lkl-posix", kind = "static")]
unsafe extern "C" {
    static mut lkl_host_ops: lkl_host_operations;
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

/// The link went as build.rs meant (`--no-relax`): no `addr32 call` anywhere in this binary, the
/// sign of ld relaxing a GOT push into a call (build.rs). The binary holds the kernel, linked as
/// any binary linking lkl-sys does.
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
