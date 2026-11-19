//! The gate and the trap path against the real kernel. Each test runs in a forked child that
//! installs the handler and a filter and then traps for real; the child reports through its exit
//! status and a shared page, so a crash (or a filter kill) can't take the harness down. After
//! lockdown a child makes no allocation and no std call that could make a syscall: those would
//! trap into the test's fake dispatcher.

use super::*;
use crate::context::{self, Context};
use crate::filter::{self, Deny, Mode, Params, Policy, Program};
use core::arch::asm;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------------------------------
// Layouts.

#[test]
fn layouts_match_glibc() {
    use libc::{mcontext_t, siginfo_t, stack_t, ucontext_t};
    assert_eq!(size_of::<StackT>(), size_of::<stack_t>());
    assert_eq!(offset_of!(StackT, flags), offset_of!(stack_t, ss_flags));
    assert_eq!(offset_of!(StackT, size), offset_of!(stack_t, ss_size));
    assert_eq!(size_of::<Mcontext>(), size_of::<mcontext_t>());
    assert_eq!(size_of::<Siginfo>(), size_of::<siginfo_t>());
    assert_eq!(offset_of!(Ucontext, stack), offset_of!(ucontext_t, uc_stack));
    assert_eq!(offset_of!(Ucontext, mcontext), offset_of!(ucontext_t, uc_mcontext));
    assert_eq!(offset_of!(Ucontext, sigmask), offset_of!(ucontext_t, uc_sigmask));
    assert_eq!(offset_of!(Mcontext, fpregs), offset_of!(mcontext_t, fpregs));
    let gregs = offset_of!(mcontext_t, gregs);
    let reg = |r: i32| gregs + 8 * r as usize;
    for (ours, theirs) in [
        (offset_of!(Mcontext, r8), libc::REG_R8),
        (offset_of!(Mcontext, r9), libc::REG_R9),
        (offset_of!(Mcontext, r10), libc::REG_R10),
        (offset_of!(Mcontext, r11), libc::REG_R11),
        (offset_of!(Mcontext, r12), libc::REG_R12),
        (offset_of!(Mcontext, r13), libc::REG_R13),
        (offset_of!(Mcontext, r14), libc::REG_R14),
        (offset_of!(Mcontext, r15), libc::REG_R15),
        (offset_of!(Mcontext, rdi), libc::REG_RDI),
        (offset_of!(Mcontext, rsi), libc::REG_RSI),
        (offset_of!(Mcontext, rbp), libc::REG_RBP),
        (offset_of!(Mcontext, rbx), libc::REG_RBX),
        (offset_of!(Mcontext, rdx), libc::REG_RDX),
        (offset_of!(Mcontext, rax), libc::REG_RAX),
        (offset_of!(Mcontext, rcx), libc::REG_RCX),
        (offset_of!(Mcontext, rsp), libc::REG_RSP),
        (offset_of!(Mcontext, rip), libc::REG_RIP),
        (offset_of!(Mcontext, eflags), libc::REG_EFL),
        (offset_of!(Mcontext, csgsfs), libc::REG_CSGSFS),
        (offset_of!(Mcontext, cr2), libc::REG_CR2),
    ] {
        assert_eq!(ours, reg(theirs));
    }
    // fs_base is glibc's __reserved1[0], right after fpregs.
    assert_eq!(offset_of!(Mcontext, fs_base), offset_of!(mcontext_t, fpregs) + 8);
}

// ------------------------------------------------------------------------------------------------
// The child harness.

/// Values a child reports (and the parent prints on failure), in a page shared across the fork.
const NVALS: usize = 32;
static SHARED: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());

fn put(i: usize, v: u64) {
    // SAFETY: run_child mapped NVALS of them before forking.
    unsafe { (*SHARED.load(Ordering::Relaxed).add(i)).store(v, Ordering::Relaxed) }
}

/// Run `body` in a forked child (bounded: 5 s) and return what it `put`. The child's status is
/// `body`'s; a panic is 99. Fails the test unless it exits 0.
fn run_child(body: fn() -> u8) -> [u64; NVALS] {
    // SAFETY: a fresh shared anonymous page.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    SHARED.store(page.cast(), Ordering::Relaxed);
    // SAFETY: the child only runs `body` and exits through the gate (no return into the harness).
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = std::panic::catch_unwind(body).unwrap_or(99);
        exit_group(code as i32);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = 0;
    loop {
        // SAFETY: our child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        assert_eq!(r, 0);
        if Instant::now() > deadline {
            // SAFETY: our child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            unsafe { libc::waitpid(pid, &mut status, 0) };
            panic!("child timed out");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut vals = [0u64; NVALS];
    for (i, v) in vals.iter_mut().enumerate() {
        // SAFETY: the shared page.
        *v = unsafe { (*page.cast::<AtomicU64>().add(i)).load(Ordering::Relaxed) };
    }
    // SAFETY: mapped above.
    unsafe { libc::munmap(page, 4096) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child status {status:#x} (exit {}), vals {vals:x?}",
        libc::WEXITSTATUS(status)
    );
    vals
}

/// `if !cond { return code }`: a child's check.
macro_rules! check {
    ($cond:expr, $code:expr) => {
        if !$cond {
            return $code;
        }
    };
}

#[repr(C, align(64))]
struct Mem<const N: usize>([u8; N]);

const CONTROL_SIZE: usize = 256 * 1024;
static mut ALT: Mem<ALTSTACK_SIZE> = Mem([0; ALTSTACK_SIZE]);
/// The control stack the target hook puts frames on (production: the trapping coroutine's).
static mut CONTROL: Mem<CONTROL_SIZE> = Mem([0; CONTROL_SIZE]);

fn control() -> (usize, usize) {
    let lo = &raw mut CONTROL as usize;
    (lo, lo + CONTROL_SIZE)
}

/// The production hook's shape: program code (any stack but ours) → the control stack's top;
/// runtime code already on it (a nested trap) → below its sp.
fn to_control(uc: &Ucontext) -> usize {
    let (lo, hi) = control();
    if (lo..hi).contains(&(uc.mcontext.rsp as usize)) { below_red_zone(uc) } else { hi }
}

/// The runtime's FS as `install` captured it (the child's, before lockdown).
static RUNTIME: AtomicUsize = AtomicUsize::new(0);

/// Install the handler on this (child) thread and lock down: `mode`'s filter with deny=errno.
fn lockdown(dispatch: Dispatch, target: Target, mode: Mode, arena: &[(u64, u64)], tokens: (u32, u32)) {
    let mut prog = Box::new(Program::new());
    let params = Params { policy: Policy::Mode(mode), deny: Deny::Errno, gate_ip: gate_ip(), arena, token_fds: tokens, pid: std::process::id(), extra: &[] };
    filter::compile(&params, &mut prog).unwrap();
    RUNTIME.store(context::read_fs(), Ordering::Relaxed);
    // SAFETY: the child's own alternate stack; the dispatchers keep to the contract.
    unsafe {
        set_altstack(&raw mut ALT as *mut u8, ALTSTACK_SIZE).unwrap();
        install(dispatch, target).unwrap();
    }
    filter::install(&prog, 0).unwrap();
    // The kernel has its own copy; ours is leaked, as freeing it now could make a host call.
    Box::leak(prog);
}

/// A syscall *not* from the gate: after lockdown it traps.
#[inline(always)]
fn raw(nr: usize, a: [usize; 6]) -> isize {
    let r: isize;
    // SAFETY: after lockdown the dispatcher serves it; nothing below sp is written either way.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as isize => r,
            in("rdi") a[0], in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        )
    };
    r
}

// What the fake dispatcher saw last (each child has its own copy).
static SEEN_FS: AtomicUsize = AtomicUsize::new(0);
static SEEN_FS_BASE: AtomicUsize = AtomicUsize::new(0);
static SEEN_SP: AtomicUsize = AtomicUsize::new(0);
static SEEN_UC: AtomicUsize = AtomicUsize::new(0);
static SEEN_ARGS: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];
static BAD_FRAME: AtomicUsize = AtomicUsize::new(0);

const NR_NESTED: usize = 999;
const NR_ARCH_PRCTL: usize = 158;
const ARCH_SET_FS: usize = 0x1002;

/// The fake: `nr * 1000 + a0` for anything but stdio writes and exit_group (forwarded through the
/// gate, so a panic's message gets out), `arch_prctl(ARCH_SET_FS)` (sets the FS the program
/// resumes with), and NR_NESTED (traps itself, from inside the dispatcher). Clobbers every vector
/// register, so the register test proves the xsave area round-trips.
fn fake(uc: &mut Ucontext) {
    let sp: usize;
    // SAFETY: reads rsp.
    unsafe { asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack)) };
    SEEN_SP.store(sp, Ordering::Relaxed);
    SEEN_UC.store(uc as *mut Ucontext as usize, Ordering::Relaxed);
    SEEN_FS.store(context::read_fs(), Ordering::Relaxed);
    SEEN_FS_BASE.store(uc.mcontext.fs_base as usize, Ordering::Relaxed);
    let (nr, a) = uc.syscall();
    for (s, v) in SEEN_ARGS.iter().zip(a) {
        s.store(v, Ordering::Relaxed);
    }
    // SAFETY: a frame from the entry.
    let si = unsafe { uc.siginfo() };
    if si.signo != 31 || si.syscall as usize != nr || si.call_addr != uc.mcontext.rip {
        BAD_FRAME.fetch_add(1, Ordering::Relaxed);
    }
    // The xsave area: in the moved frame (above the ucontext, within an alternate stack's
    // length), 64-aligned.
    let at = uc as *const Ucontext as usize;
    let fp = uc.mcontext.fpregs;
    if fp < at || fp - at > ALTSTACK_SIZE || !fp.is_multiple_of(64) {
        BAD_FRAME.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: only clobbers vector registers, all caller-saved.
    unsafe {
        asm!(
            "pcmpeqd xmm0, xmm0", "pcmpeqd xmm1, xmm1", "pcmpeqd xmm2, xmm2", "pcmpeqd xmm3, xmm3",
            "pcmpeqd xmm4, xmm4", "pcmpeqd xmm5, xmm5", "pcmpeqd xmm6, xmm6", "pcmpeqd xmm7, xmm7",
            "pcmpeqd xmm8, xmm8", "pcmpeqd xmm9, xmm9", "pcmpeqd xmm10, xmm10", "pcmpeqd xmm11, xmm11",
            "pcmpeqd xmm12, xmm12", "pcmpeqd xmm13, xmm13", "pcmpeqd xmm14, xmm14", "pcmpeqd xmm15, xmm15",
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _, out("xmm4") _, out("xmm5") _,
            out("xmm6") _, out("xmm7") _, out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nomem, nostack),
        )
    };
    let r = match nr {
        // SAFETY: forwarded as the program asked; the filter judges.
        1 | 231 => unsafe { gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) },
        NR_ARCH_PRCTL if a[0] == ARCH_SET_FS => {
            uc.mcontext.fs_base = a[1] as u64;
            0
        }
        NR_NESTED => raw(NR_NESTED - 1, a) + 1,
        _ => nr.wrapping_mul(1000).wrapping_add(a[0]) as isize,
    };
    uc.set_return(r);
}

fn coroutine_lockdown(dispatch: Dispatch, arena: &[(u64, u64)]) {
    lockdown(dispatch, to_control, Mode::Coroutine, arena, (0, 0));
}

// ------------------------------------------------------------------------------------------------
// The tests.

/// Trapped syscalls get the fake's values, with every argument and the siginfo right; the
/// dispatcher runs on the control stack with the runtime's FS; a trap inside the dispatcher is
/// served too (SA_NODEFER); the gate's allowed calls work and denied ones are EPERM; SIGPIPE is
/// ignored.
#[test]
fn traps_and_the_gate() {
    run_child(|| {
        // An arena for madvise: two chunks, as the filter's arena ranges are (inclusive).
        // SAFETY: a fresh mapping, the child's.
        let arena = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * filter::MADV_CHUNK as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } as usize;
        let ranges = [(arena as u64, arena as u64 + filter::MADV_CHUNK)];
        coroutine_lockdown(fake, &ranges);

        let args = [7, 0x11, 0x22, 0x33, 0x44, 0x55];
        for nr in [39usize, 110, 102, 500] {
            check!(raw(nr, args) == (nr * 1000 + 7) as isize, 1);
            for (s, v) in SEEN_ARGS.iter().zip(args) {
                check!(s.load(Ordering::Relaxed) == v, 2);
            }
        }
        check!(BAD_FRAME.load(Ordering::Relaxed) == 0, 3);
        let (lo, hi) = control();
        put(0, SEEN_SP.load(Ordering::Relaxed) as u64);
        put(1, SEEN_UC.load(Ordering::Relaxed) as u64);
        check!((lo..hi).contains(&SEEN_SP.load(Ordering::Relaxed)), 4);
        check!((lo..hi).contains(&SEEN_UC.load(Ordering::Relaxed)), 5);
        check!(SEEN_FS.load(Ordering::Relaxed) == RUNTIME.load(Ordering::Relaxed), 6);
        // A trap from inside the dispatcher: its frame lands below the outer one.
        check!(raw(NR_NESTED, args) == ((NR_NESTED - 1) * 1000 + 7 + 1) as isize, 7);

        // Through the gate: allowed, denied (deny=errno).
        // SAFETY: write of nothing; getppid.
        check!(unsafe { gate(1, 1, b"".as_ptr() as usize, 0, 0, 0, 0) } == 0, 10);
        check!(unsafe { gate(110, 0, 0, 0, 0, 0, 0) } == -1, 11);
        check!(write(1, b"") == Ok(0), 12);
        check!(write(3, b"") == Err(Errno::PERM), 13);
        check!(read(0, &mut []) == Ok(0), 14);
        check!(ppoll(None, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })) == Ok(0), 15);
        // SAFETY: the arena is ours and unused.
        unsafe {
            (arena as *mut u8).write(1);
            check!(madvise_dontneed(arena, 4096) == Ok(()), 16);
            check!((arena as *const u8).read() == 0, 17);
            check!(madvise_dontneed(arena + 2 * filter::MADV_CHUNK as usize, 4096) == Err(Errno::PERM), 18);
        }
        0
    });
}

/// The handler's other half of install: SIGPIPE ignored (checked before lockdown).
#[test]
fn sigpipe_ignored() {
    run_child(|| {
        // SAFETY: the child's own handlers.
        unsafe { install(fake, to_control).unwrap() };
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a query.
        check!(unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut old) } == 0, 1);
        check!(old.sa_sigaction == libc::SIG_IGN, 2);
        check!(unsafe { libc::sigaction(libc::SIGSYS, std::ptr::null(), &mut old) } == 0, 3);
        let want = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
        check!(old.sa_flags & want == want, 4);
        0
    });
}

/// Mirrors guest-tests' `memory::small_stack`: a syscall writes nothing below the caller's sp, and
/// a trapped one must not either. Here the trap comes with 256 bytes of headroom, everything below
/// poisoned; the frame goes to the alternate stack and then the control stack.
#[test]
fn small_stack() {
    run_child(|| {
        const POISON: u8 = 0xab;
        #[repr(C, align(64))]
        struct Stack([u8; 4096]);
        static mut STACK: Stack = Stack([0; 4096]);
        coroutine_lockdown(fake, &[]);
        let base = &raw mut STACK as *mut u8;
        let sp = base as usize + 256;
        for (i, nr) in [110usize, 39, 24].into_iter().enumerate() {
            // SAFETY: the whole static.
            unsafe { base.write_bytes(POISON, 4096) };
            let r: isize;
            // SAFETY: switches to the poisoned stack only around the syscall.
            unsafe {
                asm!(
                    "mov r12, rsp",
                    "mov rsp, {sp}",
                    "syscall",
                    "mov rsp, r12",
                    sp = in(reg) sp,
                    inlateout("rax") nr as isize => r,
                    in("rdi") 5usize,
                    out("r12") _, lateout("rcx") _, lateout("r11") _,
                )
            };
            check!(r == (nr * 1000 + 5) as isize, 1 + i as u8 * 10);
            // SAFETY: the static, below sp.
            let below = unsafe { std::slice::from_raw_parts(base, 256) };
            let dirty = below.iter().filter(|&&b| b != POISON).count();
            put(i, dirty as u64);
            check!(dirty == 0, 2 + i as u8 * 10);
            let (lo, hi) = control();
            check!((lo..hi).contains(&SEEN_UC.load(Ordering::Relaxed)), 3 + i as u8 * 10);
        }
        0
    });
}

/// The program's FS base (a fake TLS block) is put aside for the dispatcher, which runs with the
/// runtime's, and is the program's again after the return; the dispatcher can change it.
#[test]
fn fs_switch() {
    run_child(|| {
        static TLS_A: [u64; 8] = [0; 8];
        static TLS_B: [u64; 8] = [0; 8];
        coroutine_lockdown(fake, &[]);
        let (a, b) = (&raw const TLS_A as usize, &raw const TLS_B as usize);
        // The trap with FS = `fs`; returns (result, FS just after the trap). FS is the test's own
        // again before any Rust code can use TLS.
        let trap_with_fs = |fs: usize, nr: usize, a0: usize, a1: usize| -> (isize, usize) {
            let (r, after): (isize, usize);
            // SAFETY: FS is swapped only for the syscall.
            unsafe {
                asm!(
                    "rdfsbase {saved}",
                    "wrfsbase {fs}",
                    "syscall",
                    "rdfsbase {after}",
                    "wrfsbase {saved}",
                    saved = out(reg) _,
                    fs = in(reg) fs,
                    after = lateout(reg) after,
                    inlateout("rax") nr as isize => r,
                    in("rdi") a0, in("rsi") a1,
                    lateout("rcx") _, lateout("r11") _,
                    options(nostack),
                )
            };
            (r, after)
        };
        let runtime = RUNTIME.load(Ordering::Relaxed);
        check!(runtime != 0 && runtime != a, 1);
        let (r, after) = trap_with_fs(a, 39, 3, 0);
        put(0, SEEN_FS.load(Ordering::Relaxed) as u64);
        put(1, SEEN_FS_BASE.load(Ordering::Relaxed) as u64);
        put(2, after as u64);
        check!(r == 39003, 2);
        check!(SEEN_FS.load(Ordering::Relaxed) == runtime, 3);
        check!(SEEN_FS_BASE.load(Ordering::Relaxed) == a, 4);
        check!(after == a, 5);
        // arch_prctl(ARCH_SET_FS, b), emulated: the program resumes with b.
        let (r, after) = trap_with_fs(a, NR_ARCH_PRCTL, ARCH_SET_FS, b);
        check!(r == 0 && after == b, 6);
        check!(context::read_fs() == runtime, 7);
        0
    });
}

/// All 16 GPRs and xmm registers, loaded from `[rdi]`, through one `syscall`, stored to `[rsi]`:
/// rax rbx rcx rdx rsi rdi rbp rsp(unused) r8–r15 (as `context::Registers`), then xmm0–15.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Regs {
    gpr: [u64; 16],
    xmm: [[u64; 2]; 16],
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_with_regs(regs_in: *const Regs, regs_out: *mut Regs) {
    core::arch::naked_asm!(
        "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
        "push rsi",
        "movdqu xmm0, [rdi + 128]", "movdqu xmm1, [rdi + 144]", "movdqu xmm2, [rdi + 160]",
        "movdqu xmm3, [rdi + 176]", "movdqu xmm4, [rdi + 192]", "movdqu xmm5, [rdi + 208]",
        "movdqu xmm6, [rdi + 224]", "movdqu xmm7, [rdi + 240]", "movdqu xmm8, [rdi + 256]",
        "movdqu xmm9, [rdi + 272]", "movdqu xmm10, [rdi + 288]", "movdqu xmm11, [rdi + 304]",
        "movdqu xmm12, [rdi + 320]", "movdqu xmm13, [rdi + 336]", "movdqu xmm14, [rdi + 352]",
        "movdqu xmm15, [rdi + 368]",
        "mov rax, [rdi]", "mov rbx, [rdi + 8]", "mov rcx, [rdi + 16]", "mov rdx, [rdi + 24]",
        "mov rsi, [rdi + 32]", "mov rbp, [rdi + 48]",
        "mov r8, [rdi + 64]", "mov r9, [rdi + 72]", "mov r10, [rdi + 80]", "mov r11, [rdi + 88]",
        "mov r12, [rdi + 96]", "mov r13, [rdi + 104]", "mov r14, [rdi + 112]", "mov r15, [rdi + 120]",
        "mov rdi, [rdi + 40]",
        "syscall",
        "push r15",
        "mov r15, [rsp + 8]",
        "mov [r15], rax", "mov [r15 + 8], rbx", "mov [r15 + 16], rcx", "mov [r15 + 24], rdx",
        "mov [r15 + 32], rsi", "mov [r15 + 40], rdi", "mov [r15 + 48], rbp",
        "mov [r15 + 64], r8", "mov [r15 + 72], r9", "mov [r15 + 80], r10", "mov [r15 + 88], r11",
        "mov [r15 + 96], r12", "mov [r15 + 104], r13", "mov [r15 + 112], r14",
        "pop qword ptr [r15 + 120]",
        "movdqu [r15 + 128], xmm0", "movdqu [r15 + 144], xmm1", "movdqu [r15 + 160], xmm2",
        "movdqu [r15 + 176], xmm3", "movdqu [r15 + 192], xmm4", "movdqu [r15 + 208], xmm5",
        "movdqu [r15 + 224], xmm6", "movdqu [r15 + 240], xmm7", "movdqu [r15 + 256], xmm8",
        "movdqu [r15 + 272], xmm9", "movdqu [r15 + 288], xmm10", "movdqu [r15 + 304], xmm11",
        "movdqu [r15 + 320], xmm12", "movdqu [r15 + 336], xmm13", "movdqu [r15 + 352], xmm14",
        "movdqu [r15 + 368], xmm15",
        "add rsp, 8",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
        "ret",
    )
}

/// Every GPR but rax (the result) and rcx/r11 (which `syscall` clobbers natively), and every xmm
/// register, survives a trap whose dispatcher clobbers all the vector registers.
#[test]
fn registers_preserved() {
    run_child(|| {
        coroutine_lockdown(fake, &[]);
        let mut input = Regs { gpr: [0; 16], xmm: [[0; 2]; 16] };
        for (i, g) in input.gpr.iter_mut().enumerate() {
            *g = (0x0101_0101_0101_0101 * (i as u64 + 1)) ^ 0x8000_0000_0000_0000;
        }
        input.gpr[5] = 7; // rdi: a0
        for (i, x) in input.xmm.iter_mut().enumerate() {
            *x = [0x1234_5678_0000_0000 + i as u64, 0x0fed_cba9_0000_0000 + i as u64];
        }
        // getpid; then NR_NESTED, whose dispatcher traps again: the nested frame overwrites the
        // alternate stack, so the outer one's xmm state must come from the moved copy (a stale
        // `fpregs` would still find the right bytes on the alternate stack otherwise).
        for (round, (nr, want_rax)) in [(39u64, 39_007u64), (NR_NESTED as u64, 998_007 + 1)].into_iter().enumerate() {
            let code = round as u8 * 100;
            input.gpr[0] = nr;
            let mut out = Regs { gpr: [0; 16], xmm: [[0; 2]; 16] };
            // SAFETY: both buffers live; the function restores the callee-saved registers.
            unsafe { syscall_with_regs(&input, &mut out) };
            for (i, v) in out.gpr.iter().enumerate() {
                put(i, *v);
            }
            check!(out.gpr[0] == want_rax, code + 1);
            for i in [1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15] {
                check!(out.gpr[i] == input.gpr[i], code + 10 + i as u8);
            }
            // What the dispatcher saw: the arguments as loaded.
            let want = [input.gpr[5], input.gpr[4], input.gpr[3], input.gpr[10], input.gpr[8], input.gpr[9]];
            for (s, v) in SEEN_ARGS.iter().zip(want) {
                check!(s.load(Ordering::Relaxed) as u64 == v, code + 2);
            }
            for i in 0..16 {
                check!(out.xmm[i] == input.xmm[i], code + 30 + i as u8);
            }
        }
        check!(BAD_FRAME.load(Ordering::Relaxed) == 0, 3);
        0
    });
}

// Two "program threads" as coroutines on one host thread, each with its own program and control
// stack. The first traps and its dispatcher switches to the second, which starts fresh (program
// code, inside the first's handler) and traps too; its dispatcher switches back. If the frames
// stayed on the shared alternate stack the second would overwrite the first's; if SIGSYS were
// blocked in the handler (no SA_NODEFER) the second's trap would kill the process.
const PROG_STACK: usize = 64 * 1024;
static mut PROG: [Mem<PROG_STACK>; 2] = [const { Mem([0; PROG_STACK]) }; 2];
static mut CTRL: [Mem<PROG_STACK>; 2] = [const { Mem([0; PROG_STACK]) }; 2];
static mut CTX: [Context; 3] = [Context::empty(); 3]; // root, A, B
static CURRENT: AtomicUsize = AtomicUsize::new(0); // 1 = A, 2 = B
static DONE: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
static RESULT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
const NR_DONE: usize = 502;

fn ctx(i: usize) -> *mut Context {
    // SAFETY: an element of the static; only this host thread uses them.
    unsafe { (&raw mut CTX as *mut Context).add(i) }
}

fn coroutine_target(uc: &Ucontext) -> usize {
    match CURRENT.load(Ordering::Relaxed) {
        0 => to_control(uc), // the root (it doesn't trap after lockdown)
        c => &raw mut CTRL as usize + c * PROG_STACK, // the top of CTRL[c - 1]
    }
}

fn switch_to(from: usize, to: usize) {
    CURRENT.store(to, Ordering::Relaxed);
    // SAFETY: distinct contexts, `to` suspended or fresh, their stacks static.
    unsafe { context::switch(ctx(from), ctx(to)) }
}

fn coroutine_dispatch(uc: &mut Ucontext) {
    let (nr, a) = uc.syscall();
    let me = CURRENT.load(Ordering::Relaxed);
    match nr {
        // A's trap: run B (fresh) before answering.
        500 => switch_to(1, 2),
        // B's trap: back to A's dispatch, which answers A first.
        501 => switch_to(2, 1),
        NR_DONE => {
            DONE[me - 1].store(1, Ordering::Relaxed);
            let other = 3 - me;
            if DONE[other - 1].load(Ordering::Relaxed) == 0 { switch_to(me, other) } else { switch_to(me, 0) }
            unreachable!();
        }
        _ => {}
    }
    uc.set_return((nr * 1000 + a[0]) as isize);
}

extern "C" fn program(i: usize) -> ! {
    let r = raw(500 + i, [i, 0, 0, 0, 0, 0]);
    RESULT[i].store(r as u64, Ordering::Relaxed);
    raw(NR_DONE, [0; 6]);
    unreachable!()
}

#[test]
fn coroutines_switch_inside_the_dispatcher() {
    run_child(|| {
        lockdown(coroutine_dispatch, coroutine_target, Mode::Coroutine, &[], (0, 0));
        for i in 0..2 {
            let top = &raw mut PROG as usize + (i + 1) * PROG_STACK;
            // SAFETY: a fresh coroutine on its own static stack.
            unsafe { ctx(i + 1).write(Context::new(top, program, i, 0)) };
        }
        switch_to(0, 1);
        put(0, RESULT[0].load(Ordering::Relaxed));
        put(1, RESULT[1].load(Ordering::Relaxed));
        check!(RESULT[0].load(Ordering::Relaxed) == 500_000, 1);
        check!(RESULT[1].load(Ordering::Relaxed) == 501_001, 2);
        0
    });
}

/// The wrappers threaded mode uses, under its filter: the token eventfd both ways, a host thread
/// by `clone_thread` that hands a token back and exits, its tid word cleared.
#[test]
fn threaded_wrappers() {
    run_child(|| {
        static mut STACK: Mem<{ 64 * 1024 }> = Mem([0; 64 * 1024]);
        static mut ALT: Mem<{ 64 * 1024 }> = Mem([0; 64 * 1024]);
        static CTID: AtomicU32 = AtomicU32::new(1);
        // SAFETY: a plain eventfd.
        let fd = unsafe { libc::eventfd(0, 0) };
        check!(fd >= 0, 1);
        let fd = fd as u32;
        lockdown(fake, to_control, Mode::Threaded, &[], (fd, fd));
        check!(eventfd_write(fd, 1) == Ok(()), 2);
        check!(eventfd_read(fd) == Ok(1), 3);
        extern "C" fn thread(fd: usize) -> ! {
            let _ = eventfd_write(fd as u32, 5);
            // SAFETY: nothing needs this stack after.
            unsafe { exit_thread() }
        }
        let top = &raw mut STACK as usize + 64 * 1024;
        // A minimal template ucontext: user segment selectors and flags, so rt_sigreturn can
        // resume in user mode (production copies the trapped clone's). cs=0x33, ss=0x2b.
        let mut tmpl = Ucontext::default();
        tmpl.mcontext.csgsfs = 0x33 | (0x2b << 48);
        tmpl.mcontext.eflags = 0x202;
        let alt = &raw mut ALT as usize;
        // SAFETY: the static stacks are the thread's alone; CTID is static.
        let tid = unsafe { clone_thread(top, alt, 64 * 1024, CTID.as_ptr(), &tmpl, thread, fd as usize) };
        put(0, tid.map_or_else(|e| e.raw_os_error() as u64, |t| t as u64));
        check!(tid.is_ok_and(|t| t > 0), 4);
        check!(eventfd_read(fd) == Ok(5), 5);
        let nap = Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        for _ in 0..2000 {
            if CTID.load(Ordering::Acquire) == 0 {
                break;
            }
            let _ = ppoll(None, Some(&nap));
        }
        check!(CTID.load(Ordering::Acquire) == 0, 6);
        // clone with other flags, and exit with a status: refused.
        // SAFETY: refused by the filter (deny=errno), so nothing happens.
        check!(unsafe { gate(56, 0x11, 0, 0, 0, 0, 0) } == -1, 7);
        0
    });
}

/// The cost of a trap's round trip (capnix: ~1.5 µs), next to a gate call and a native syscall.
#[test]
fn throughput() {
    const N: u64 = 100_000;
    let v = run_child(|| {
        let t = Instant::now();
        for _ in 0..N {
            raw(110, [0; 6]);
        }
        put(0, t.elapsed().as_nanos() as u64);
        coroutine_lockdown(fake, &[]);
        // Instant::now is the vDSO: no syscall.
        let t = Instant::now();
        for _ in 0..N {
            raw(110, [0; 6]);
        }
        put(1, t.elapsed().as_nanos() as u64);
        let t = Instant::now();
        for _ in 0..N {
            let _ = write(1, b"");
        }
        put(2, t.elapsed().as_nanos() as u64);
        0
    });
    let per = |ns: u64| ns as f64 / N as f64;
    eprintln!(
        "native getppid {:.0} ns; gate write(1, \"\", 0) {:.0} ns; trapped syscall {:.0} ns \
         ({:.0}/s)",
        per(v[0]),
        per(v[2]),
        per(v[1]),
        1e9 / per(v[1])
    );
}
