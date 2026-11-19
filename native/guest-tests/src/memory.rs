//! Memory: big allocations, generated code, the stack below a syscall, the GS base.

use std::arch::asm;
use std::thread;

/// hello.c's big allocation: 64 MB, touched, freed (the arena serves it after lockdown).
pub fn big_alloc() {
    let mut v = vec![0u8; 64 << 20];
    for i in (0..v.len()).step_by(4096) {
        v[i] = 1;
    }
    assert_eq!(v.iter().step_by(4096).map(|&b| b as usize).sum::<usize>(), 64 << 8);
}

fn emit_and_run(p: *mut u8, want: u8) {
    // mov $want, %eax; ret
    let code = [0xb8, want, 0, 0, 0, 0xc3];
    // SAFETY: p is a writable and executable page of ours; the code is a complete function.
    let r = unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), p, code.len());
        std::mem::transmute::<*mut u8, extern "C" fn() -> i32>(p)()
    };
    assert_eq!(r, want as i32, "generated code's return");
}

/// Generated code runs: writable and executable memory, by mmap and by mprotect (JITs: V8, the
/// JVM, LuaJIT). The sandbox's boundary is the host filter, not W^X, which would be hardening of
/// the program itself; so every mode allows it, with no flag.
pub fn rwx() {
    // SAFETY: fresh anonymous pages of our own.
    unsafe {
        let anon = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let p = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, anon, -1, 0);
        assert_ne!(p, libc::MAP_FAILED, "RWX mmap: {}", crate::errno());
        emit_and_run(p.cast(), 42);
        let q = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, anon, -1, 0);
        assert_ne!(q, libc::MAP_FAILED);
        *(q as *mut u8) = 0;
        assert_eq!(libc::mprotect(q, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC), 0, "mprotect(+X): {}", crate::errno());
        emit_and_run(q.cast(), 7);
    }
}

/// A raw syscall with the stack pointer at `sp`.
unsafe fn syscall_on(sp: *mut u8, nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
    let r;
    // SAFETY: the caller's: sp is in writable memory with room above for nothing (the syscall
    // pushes nothing), and rsp is restored before anything else runs here.
    unsafe {
        asm!(
            "mov r12, rsp",
            "mov rsp, {sp}",
            "syscall",
            "mov rsp, r12",
            sp = in(reg) sp,
            inlateout("rax") nr => r,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") 0i64,
            out("rcx") _,
            out("r11") _,
            out("r12") _,
        );
    }
    r
}

/// A syscall writes nothing below the caller's stack pointer. Go makes raw syscalls on goroutine
/// stacks with as little as ~128 bytes to spare; a sandbox that leaves its trap's signal frame
/// (siginfo, ucontext, xsave: ~2 KB) on the app's stack overwrites the next goroutine's (capnix
/// tier A: "unexpected return pc" in parallel mode). Each syscall here runs with the stack pointer
/// in the middle of a poisoned buffer, and the whole buffer below it must be intact afterwards.
pub fn small_stack() {
    const POISON: u8 = 0xab;
    let mut stack = vec![0u8; 64 << 10];
    let base = stack.as_mut_ptr();
    let half = (stack.len() / 2) & !63;
    // SAFETY: inside `stack`.
    let sp = unsafe { base.add(half) };
    let ts = unsafe { base.add(stack.len() - 64) };
    let calls: [(&str, i64, i64, i64, i64); 4] = [
        ("getppid (the guest's)", libc::SYS_getppid, 0, 0, 0),
        ("write(1, \"\", 0) (stdio)", libc::SYS_write, 1, c"".as_ptr() as i64, 0),
        ("clock_gettime", libc::SYS_clock_gettime, 1, ts as i64, 0),
        ("sched_yield", libc::SYS_sched_yield, 0, 0, 0),
    ];
    for (what, nr, a0, a1, a2) in calls {
        // SAFETY: the buffer's lower half, then the syscall on its middle.
        let r = unsafe {
            std::ptr::write_bytes(base, POISON, half);
            syscall_on(sp, nr, a0, a1, a2)
        };
        assert!(r >= 0, "{what} -> {r}");
        let dirty = stack[..half].iter().filter(|&&b| b != POISON).count();
        assert_eq!(dirty, 0, "{what} wrote {dirty} bytes below the stack pointer");
    }
}

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_GET_GS: i32 = 0x1004;
const HWCAP2_FSGSBASE: u64 = 1 << 1;

fn get_gs() -> u64 {
    let mut v = 0u64;
    // SAFETY: an out-word.
    assert_eq!(unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_GS, &mut v) }, 0, "arch_prctl(ARCH_GET_GS)");
    v
}

fn rdgs() -> u64 {
    let v;
    // SAFETY: FSGSBASE is enabled (the caller checked HWCAP2).
    unsafe { asm!("rdgsbase {}", out(reg) v) };
    v
}

fn syscalls_and_threads(want: u64, fsgsbase: bool, how: &str) {
    for _ in 0..1000 {
        // SAFETY: no arguments.
        assert!(unsafe { libc::getppid() } >= 0);
    }
    assert_eq!(get_gs(), want, "{how}: ARCH_GET_GS");
    if fsgsbase {
        assert_eq!(rdgs(), want, "{how}: rdgsbase");
    }
    // Syscalls of each thread's own, then its GS base: its creator's, as Linux's clone copies it.
    let ts: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..100 {
                    // SAFETY: no arguments; a zero-length write.
                    unsafe { assert!(libc::getppid() >= 0 && libc::write(1, c"".as_ptr().cast(), 0) == 0) };
                }
                get_gs()
            })
        })
        .collect();
    for (i, t) in ts.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), want, "{how}: thread {i}'s GS base");
    }
    assert_eq!(get_gs(), want, "{how}: after the threads");
}

/// The GS base is the program's: set by arch_prctl(ARCH_SET_GS) and, with FSGSBASE, by wrgsbase
/// (no syscall: no filter sees it), it survives syscalls, a thread's creation and join, and the
/// sandbox keeps working. Threaded mode kept each host thread's runtime record at the GS base, so
/// a program that set GS clobbered it (the next trap read the program's value as the record).
/// A new thread starts with its creator's GS base, as Linux's clone copies it.
pub fn gsbase() {
    static AREA: [[u8; 64]; 2] = [[0; 64]; 2];
    // SAFETY: getauxval.
    let fsgsbase = unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_FSGSBASE != 0;
    let a = AREA[0].as_ptr() as u64;
    // SAFETY: GS is the program's own (nothing here uses it).
    assert_eq!(unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, a) }, 0, "arch_prctl(ARCH_SET_GS)");
    syscalls_and_threads(a, fsgsbase, "arch_prctl");
    if fsgsbase {
        let b = AREA[1].as_ptr() as u64;
        // SAFETY: as above; FSGSBASE is enabled.
        unsafe { asm!("wrgsbase {}", in(reg) b) };
        syscalls_and_threads(b, true, "wrgsbase");
    } else {
        println!("no FSGSBASE: wrgsbase skipped");
    }
}
