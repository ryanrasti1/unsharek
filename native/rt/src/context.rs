//! The context switch: one host thread's CPU state handed between coroutines (x86-64, SysV).
//!
//! A switch is an ordinary function call from both sides' point of view, so it saves only what
//! the ABI says a callee must preserve: rbx, rbp, r12–r15, rsp, and the control bits of MXCSR and
//! the x87 control word (a coroutine that changes the rounding mode must not change it for the
//! others). Everything else is dead across a call. The saved state lives on the suspended
//! coroutine's own stack; the [`Context`] holds only its stack pointer, plus its FS base.
//!
//! The FS base (the program's TLS pointer) is switched only by [`switch_fs`], with
//! `rdfsbase`/`wrfsbase` (FSGSBASE, Linux ≥ 5.9 on a CPU that has it): the scheduler chooses per
//! instance. Production switches it, because the program's threads each have their own TLS; the
//! tests run in std's harness, whose TLS (stdout capture, panics) must stay put, so they don't.
//!
//! Frame of a suspended coroutine, from its saved rsp upward:
//!
//! ```text
//!   +0   MXCSR (4 bytes) | x87 control word (2) | pad (2)
//!   +8   r15
//!   +16  r14
//!   +24  r13
//!   +32  r12
//!   +40  rbx
//!   +48  rbp
//!   +56  return address (where `switch` returns to)
//! ```

/// A suspended coroutine: its saved stack pointer (the frame above holds the rest) and FS base.
/// `#[repr(C)]` because the assembly reads `sp` at +0 and `fs` at +8.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Context {
    sp: usize,
    fs: usize,
}

/// MXCSR's power-on value (all exceptions masked, round to nearest) and the x87 control word's
/// (`fninit`): what a fresh coroutine starts with, as a fresh thread would.
const MXCSR_DEFAULT: u64 = 0x1f80;
const FCW_DEFAULT: u64 = 0x037f;

impl Context {
    /// A context that has never run. Only valid as the `from` of a switch (it is filled in then):
    /// how the host thread's own first stack becomes a coroutine.
    pub const fn empty() -> Self {
        Context { sp: 0, fs: 0 }
    }

    /// A fresh coroutine that starts at `entry(arg)` on the stack whose (exclusive) top is
    /// `stack_top`, with FS base `fs` (loaded only by [`switch_fs`]).
    ///
    /// `entry` sees the SysV entry alignment: `rsp % 16 == 8`, as if `call`ed. (capnix got this
    /// wrong once: a misaligned entry works until the first `movaps` to a stack slot.) It must
    /// not return; if it does, it hits `ud2`.
    ///
    /// # Safety
    /// `stack_top` is the top of writable memory with room for at least the 64-byte frame plus
    /// whatever `entry` uses; nothing else uses that stack until this coroutine is done.
    pub unsafe fn new(stack_top: usize, entry: extern "C" fn(usize) -> !, arg: usize, fs: usize) -> Self {
        // After `switch`'s `ret` pops the frame, rsp is `top`, 16-aligned; `start` then `call`s
        // entry, which pushes 8 bytes: entry sees rsp % 16 == 8.
        let top = stack_top & !15;
        let sp = top - 64;
        let frame = sp as *mut u64;
        let words: [u64; 8] = [
            MXCSR_DEFAULT | (FCW_DEFAULT << 32),
            0,                   // r15
            0,                   // r14
            entry as usize as u64, // r13: what `start` calls
            arg as u64,          // r12: its argument
            0,                   // rbx
            0,                   // rbp: 0 ends frame-pointer walks here
            start as *const () as u64, // return address
        ];
        for (i, w) in words.iter().enumerate() {
            // SAFETY: the caller gave us this stack; `frame..top` is inside it.
            unsafe { frame.add(i).write(*w) };
        }
        Context { sp, fs }
    }

    /// A fresh coroutine that resumes a program thread at the register state `regs` (e.g. right
    /// after its `clone`: rax = 0, rsp = the child's stack, rip after the `syscall`), with FS base
    /// `fs`. `regs` is copied to the top of `stack_top`'s stack (the coroutine's control stack, not
    /// the program's), so the caller's copy needn't outlive this call.
    ///
    /// # Safety
    /// As [`Context::new`]; and `regs` must be a state the program can run from.
    pub unsafe fn with_registers(stack_top: usize, regs: &Registers, fs: usize) -> Self {
        // SAFETY: the caller's contract.
        let at = unsafe { place_registers(stack_top, regs) };
        // SAFETY: below the copy is the rest of the caller's stack.
        unsafe { Context::new(at as usize, restore_entry, at as usize, fs) }
    }

    pub fn fs(&self) -> usize {
        self.fs
    }

    pub fn set_fs(&mut self, fs: usize) {
        self.fs = fs;
    }
}

/// Copy `regs` just below `stack_top` (16-aligned), returning where. The space below it is the
/// rest of the stack. Shared by [`Context::with_registers`] and the scheduler, which starts such a
/// coroutine through its own entry first.
///
/// # Safety
/// As [`Context::new`].
pub unsafe fn place_registers(stack_top: usize, regs: &Registers) -> *const Registers {
    let at = ((stack_top & !15) - core::mem::size_of::<Registers>()) & !15;
    // SAFETY: inside the caller's stack.
    unsafe { (at as *mut Registers).write(*regs) };
    at as *const Registers
}

extern "C" fn restore_entry(regs: usize) -> ! {
    // SAFETY: `with_registers` put a valid Registers there.
    unsafe { restore(regs as *const Registers) }
}

/// A program thread's general registers and instruction pointer. `#[repr(C)]` with fixed offsets:
/// [`restore`] reads them.
///
/// Not included, on purpose: rflags (after a `syscall` only DF matters, and the ABI keeps it
/// clear), the vector and x87 registers (a `syscall` preserves them, but the code after a
/// `clone`'s child return doesn't depend on them: it is libc's thread start), and FS (the
/// coroutine's [`Context`] carries it). r11 is left pointing at the copy of this struct: after a
/// `syscall`, r11 holds rflags, garbage to the program, so nothing reads it.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

// The asm below depends on these offsets.
const _: () = {
    assert!(core::mem::offset_of!(Registers, rsp) == 56);
    assert!(core::mem::offset_of!(Registers, r12) == 96);
    assert!(core::mem::offset_of!(Registers, rip) == 128);
    assert!(core::mem::offset_of!(Context, fs) == 8);
};

/// Push the callee-saved state (the frame in the module comment, below the return address).
macro_rules! save_frame {
    () => {
        "push rbp
         push rbx
         push r12
         push r13
         push r14
         push r15
         sub rsp, 8
         stmxcsr dword ptr [rsp]
         fnstcw word ptr [rsp + 4]"
    };
}

/// Pop a frame `save_frame` pushed (or `Context::new` built) and return through it.
macro_rules! restore_frame_and_return {
    () => {
        "ldmxcsr dword ptr [rsp]
         fldcw word ptr [rsp + 4]
         add rsp, 8
         pop r15
         pop r14
         pop r13
         pop r12
         pop rbx
         pop rbp
         ret"
    };
}

/// Suspend the running coroutine into `*from` and resume `*to`. Returns when something switches
/// back to `*from`. The FS base is left alone (see [`switch_fs`]).
///
/// # Safety
/// `to` is a context made by [`Context::new`]/[`Context::with_registers`] or saved by a switch,
/// not running, and whose stack is still there. `from` may be the same object only if it is not
/// also `to`.
#[unsafe(naked)]
pub unsafe extern "C" fn switch(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        save_frame!(),
        "mov [rdi], rsp",
        "mov rsp, [rsi]",
        restore_frame_and_return!(),
    )
}

/// [`switch`], also saving the FS base into `from.fs` and loading `to.fs`.
///
/// # Safety
/// As [`switch`]; and the CPU and kernel support FSGSBASE (else `rdfsbase` is #UD: SIGILL).
#[unsafe(naked)]
pub unsafe extern "C" fn switch_fs(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        save_frame!(),
        "mov [rdi], rsp",
        "rdfsbase rax",
        "mov [rdi + 8], rax",
        "mov rax, [rsi + 8]",
        "wrfsbase rax",
        "mov rsp, [rsi]",
        restore_frame_and_return!(),
    )
}

/// A fresh coroutine's first instructions: `switch`'s `ret` lands here with the entry in r13 and
/// its argument in r12 (from [`Context::new`]'s frame), rsp 16-aligned.
#[unsafe(naked)]
unsafe extern "C" fn start() {
    core::arch::naked_asm!("mov rdi, r12", "call r13", "ud2")
}

/// Load every register in `*regs` and jump to `regs.rip`. Never returns.
///
/// # Safety
/// `regs` is a state that can run: rsp a valid stack for the code at rip, and so on.
#[unsafe(naked)]
pub unsafe extern "C" fn restore(regs: *const Registers) -> ! {
    core::arch::naked_asm!(
        "mov r11, rdi",
        "mov rax, [r11]",
        "mov rbx, [r11 + 8]",
        "mov rcx, [r11 + 16]",
        "mov rdx, [r11 + 24]",
        "mov rsi, [r11 + 32]",
        "mov rdi, [r11 + 40]",
        "mov rbp, [r11 + 48]",
        "mov rsp, [r11 + 56]",
        "mov r8, [r11 + 64]",
        "mov r9, [r11 + 72]",
        "mov r10, [r11 + 80]",
        "mov r12, [r11 + 96]",
        "mov r13, [r11 + 104]",
        "mov r14, [r11 + 112]",
        "mov r15, [r11 + 120]",
        "jmp qword ptr [r11 + 128]",
    )
}

/// A jump-back point on the *current* stack, for LKL's `jmp_buf_set`/`jmp_buf_longjmp` (see
/// `sync::jmp_buf_set`). One word: the stack pointer of a frame like a suspended context's.
#[repr(C)]
#[derive(Debug, Default)]
pub struct JmpBuf {
    sp: usize,
}

impl JmpBuf {
    pub const fn new() -> Self {
        JmpBuf { sp: 0 }
    }
}

/// Save a jump-back point in `*buf`, then call `f(arg)` on this stack. Returns 0 when `f`
/// returns, or `val` when `f` (or anything it calls, on this stack) calls [`jump`]`(buf, val)`.
///
/// Unlike C's `setjmp` this returns exactly once, either way, so Rust's "returns twice" problem
/// doesn't arise: from the caller's side it is an ordinary call that preserves the callee-saved
/// registers (the jump restores the ones saved here).
///
/// # Safety
/// `f` is a function that can be called so. A [`jump`] skips the frames between it and here
/// without running their destructors: they must have none to run (C frames, or Rust frames that
/// own nothing).
#[unsafe(naked)]
pub unsafe extern "C" fn call_with_jump_back(
    buf: *mut JmpBuf,
    f: unsafe extern "C" fn(usize),
    arg: usize,
) -> usize {
    core::arch::naked_asm!(
        // Entry rsp % 16 == 8; the frame is 56 bytes, so rsp is 16-aligned for the call.
        save_frame!(),
        "mov [rdi], rsp",
        "mov rdi, rdx",
        "call rsi",
        "xor eax, eax",
        restore_frame_and_return!(),
    )
}

/// Return from the [`call_with_jump_back`] that filled `*buf`, with `val`. Never returns.
///
/// # Safety
/// That call is still active, on the current stack (the same coroutine), below this frame.
#[unsafe(naked)]
pub unsafe extern "C" fn jump(buf: *const JmpBuf, val: usize) -> ! {
    core::arch::naked_asm!(
        "mov rsp, [rdi]",
        "mov rax, rsi",
        restore_frame_and_return!(),
    )
}

/// The running thread's FS base.
#[inline]
pub fn read_fs() -> usize {
    let fs: usize;
    // SAFETY: reads a register; FSGSBASE is required, as for `switch_fs`.
    unsafe { core::arch::asm!("rdfsbase {}", out(reg) fs, options(nomem, nostack, preserves_flags)) };
    fs
}

/// The running thread's GS base. Threaded mode keeps each host thread's own record there (the
/// program doesn't use the GS base; `arch_prctl(ARCH_SET_GS)` would clobber it and is rare).
#[inline]
pub fn read_gs() -> usize {
    let gs: usize;
    // SAFETY: reads a register; FSGSBASE as above.
    unsafe { core::arch::asm!("rdgsbase {}", out(reg) gs, options(nomem, nostack, preserves_flags)) };
    gs
}

/// Set the running thread's GS base (threaded mode: its host-thread record).
///
/// # Safety
/// FSGSBASE is required; the value stays valid while this thread reads it.
#[inline]
pub unsafe fn write_gs(gs: usize) {
    // SAFETY: the caller's.
    unsafe { core::arch::asm!("wrgsbase {}", in(reg) gs, options(nomem, nostack, preserves_flags)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Stack;
    use std::time::Instant;

    // Contexts the coroutines below switch between: a test's root and its one coroutine. Each
    // test reaches its own through the argument, so tests don't share state.
    struct Pair {
        root: Context,
        co: Context,
        count: usize,
        seen: [usize; 8],
    }

    impl Pair {
        fn new() -> Box<Pair> {
            Box::new(Pair { root: Context::empty(), co: Context::empty(), count: 0, seen: [0; 8] })
        }
    }

    extern "C" fn ping(p: usize) -> ! {
        let p = p as *mut Pair;
        loop {
            // SAFETY: the test's Pair outlives this coroutine's every run.
            unsafe {
                (*p).count += 1;
                switch(&raw mut (*p).co, &raw const (*p).root);
            }
        }
    }

    #[test]
    fn ping_pong_a_million() {
        let stack = Stack::new(64 * 1024);
        let mut p = Pair::new();
        let pp: *mut Pair = &mut *p;
        // SAFETY: a fresh stack; `p` outlives the coroutine (never resumed after the test).
        unsafe { p.co = Context::new(stack.top(), ping, pp as usize, 0) };
        const N: usize = 1_000_000;
        let t = Instant::now();
        for _ in 0..N {
            // SAFETY: co is suspended (or fresh); root is ours.
            unsafe { switch(&raw mut (*pp).root, &raw const (*pp).co) };
        }
        let el = t.elapsed();
        assert_eq!(p.count, N);
        // Two switches per round trip.
        println!("context switch: {:.1} ns", el.as_nanos() as f64 / (2 * N) as f64);
        assert!(el.as_secs() < 2, "a million round trips took {el:?}");
    }

    extern "C" fn record_alignment(p: usize) -> ! {
        let p = p as *mut Pair;
        unsafe { switch(&raw mut (*p).co, &raw const (*p).root) };
        unreachable!()
    }

    // Records rsp exactly at entry (a Rust function's prologue would move it first), then
    // continues in record_alignment.
    #[unsafe(naked)]
    extern "C" fn entry_rsp(p: usize) -> ! {
        core::arch::naked_asm!(
            "mov [rdi + {seen}], rsp",
            "jmp {next}",
            seen = const core::mem::offset_of!(Pair, seen),
            next = sym record_alignment,
        )
    }

    #[test]
    fn entry_is_sysv_aligned() {
        // Every top alignment mod 16: Context::new must align down itself.
        for skew in [0usize, 8, 3, 15] {
            let stack = Stack::new(16 * 1024);
            let mut p = Pair::new();
            let pp: *mut Pair = &mut *p;
            unsafe {
                p.co = Context::new(stack.top() - skew, entry_rsp, pp as usize, 0);
                switch(&raw mut (*pp).root, &raw const (*pp).co);
            }
            assert_eq!(p.seen[0] % 16, 8, "rsp at entry {:#x} (skew {skew})", p.seen[0]);
        }
    }

    // Fill the callee-saved registers with sentinels, switch to `to`, and record what they hold
    // when the switch returns. Also records MXCSR.
    #[unsafe(naked)]
    unsafe extern "C" fn switch_with_sentinels(from: *mut Context, to: *const Context, out: *mut [u64; 7]) {
        core::arch::naked_asm!(
            "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
            "push rdx", // out; rsp is now 16-aligned (8 + 7 * 8)
            "mov rbx, 0x1111111111111111",
            "mov rbp, 0x2222222222222222",
            "mov r12, 0x3333333333333333",
            "mov r13, 0x4444444444444444",
            "mov r14, 0x5555555555555555",
            "mov r15, 0x6666666666666666",
            "call {switch}",
            "pop rdx",
            "mov [rdx], rbx",
            "mov [rdx + 8], rbp",
            "mov [rdx + 16], r12",
            "mov [rdx + 24], r13",
            "mov [rdx + 32], r14",
            "mov [rdx + 40], r15",
            "stmxcsr dword ptr [rdx + 48]",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
            "ret",
            switch = sym switch,
        )
    }

    // The other side: trash every callee-saved register and MXCSR's rounding mode, then switch
    // back. If `switch` didn't restore, the root would see this coroutine's values.
    #[unsafe(naked)]
    unsafe extern "C" fn clobber_and_switch(from: *mut Context, to: *const Context) {
        core::arch::naked_asm!(
            "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
            "sub rsp, 8",
            "stmxcsr dword ptr [rsp]",
            "or dword ptr [rsp], 0x6000", // round toward zero
            "ldmxcsr dword ptr [rsp]",
            "mov rbx, -1", "mov rbp, -1", "mov r12, -1", "mov r13, -1", "mov r14, -1", "mov r15, -1",
            "call {switch}",
            "add rsp, 8",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
            "ret",
            switch = sym switch,
        )
    }

    extern "C" fn clobberer(p: usize) -> ! {
        let p = p as *mut Pair;
        loop {
            unsafe { clobber_and_switch(&raw mut (*p).co, &raw const (*p).root) };
        }
    }

    #[test]
    fn callee_saved_registers_preserved() {
        let stack = Stack::new(16 * 1024);
        let mut p = Pair::new();
        let pp: *mut Pair = &mut *p;
        let mut out = [0u64; 7];
        let mxcsr_before: u32;
        unsafe {
            let mut m = 0u32;
            core::arch::asm!("stmxcsr [{}]", in(reg) &mut m);
            mxcsr_before = m;
            p.co = Context::new(stack.top(), clobberer, pp as usize, 0);
            // Twice: the first enters fresh, the second resumes a coroutine suspended mid-call.
            for _ in 0..2 {
                switch_with_sentinels(&raw mut (*pp).root, &raw const (*pp).co, &mut out);
                assert_eq!(
                    out[..6],
                    [
                        0x1111111111111111,
                        0x2222222222222222,
                        0x3333333333333333,
                        0x4444444444444444,
                        0x5555555555555555,
                        0x6666666666666666
                    ]
                );
                assert_eq!(out[6] as u32, mxcsr_before, "MXCSR not restored");
            }
        }
    }

    extern "C" fn read_fs_and_return(p: usize) -> ! {
        let p = p as *mut Pair;
        loop {
            // No TLS here: FS may point at a dummy. (Nothing but this read and the switch.)
            unsafe {
                (*p).seen[0] = read_fs();
                (*p).count += 1;
                switch_fs(&raw mut (*p).co, &raw const (*p).root);
            }
        }
    }

    extern "C" fn read_fs_and_return_plain(p: usize) -> ! {
        let p = p as *mut Pair;
        loop {
            unsafe {
                (*p).seen[0] = read_fs();
                switch(&raw mut (*p).co, &raw const (*p).root);
            }
        }
    }

    #[test]
    fn fs_switched_when_asked() {
        let stack = Stack::new(16 * 1024);
        let mut p = Pair::new();
        let pp: *mut Pair = &mut *p;
        let dummy_tls = Box::new([0u64; 64]);
        let fake_fs = dummy_tls.as_ptr() as usize;
        let mine = read_fs();
        unsafe {
            p.co = Context::new(stack.top(), read_fs_and_return, pp as usize, fake_fs);
            for i in 1..=3 {
                switch_fs(&raw mut (*pp).root, &raw const (*pp).co);
                assert_eq!(read_fs(), mine, "the root's FS not restored");
                assert_eq!(p.seen[0], fake_fs, "round {i}");
                assert_eq!(p.co.fs(), fake_fs, "the coroutine's FS not saved");
            }
        }
        assert_eq!(p.root.fs(), mine);
    }

    #[test]
    fn fs_untouched_when_not() {
        let stack = Stack::new(16 * 1024);
        let mut p = Pair::new();
        let pp: *mut Pair = &mut *p;
        let mine = read_fs();
        unsafe {
            // A recorded FS that `switch` must ignore.
            p.co = Context::new(stack.top(), read_fs_and_return_plain, pp as usize, 0xdead_0000);
            switch(&raw mut (*pp).root, &raw const (*pp).co);
        }
        assert_eq!(p.seen[0], mine);
        assert_eq!(read_fs(), mine);
    }

    // Registers start: land in a naked function that stores what it was given, then go back.
    static mut LANDED: [u64; 17] = [0; 17];
    static mut BACK: *mut Pair = core::ptr::null_mut();

    extern "C" fn back_to_root() -> ! {
        unsafe {
            let p = BACK;
            switch(&raw mut (*p).co, &raw const (*p).root);
        }
        unreachable!()
    }

    #[unsafe(naked)]
    extern "C" fn landing() -> ! {
        core::arch::naked_asm!(
            "lea r11, [rip + {out}]",
            "mov [r11], rax",
            "mov [r11 + 8], rbx",
            "mov [r11 + 16], rcx",
            "mov [r11 + 24], rdx",
            "mov [r11 + 32], rsi",
            "mov [r11 + 40], rdi",
            "mov [r11 + 48], rbp",
            "mov [r11 + 56], rsp",
            "mov [r11 + 64], r8",
            "mov [r11 + 72], r9",
            "mov [r11 + 80], r10",
            "mov [r11 + 96], r12",
            "mov [r11 + 104], r13",
            "mov [r11 + 112], r14",
            "mov [r11 + 120], r15",
            // As if called: rsp % 16 == 8 at a function's entry.
            "jmp {back}",
            out = sym LANDED,
            back = sym back_to_root,
        )
    }

    #[test]
    fn start_from_registers() {
        let control = Stack::new(16 * 1024);
        let program = Stack::new(16 * 1024);
        let mut p = Pair::new();
        let pp: *mut Pair = &mut *p;
        let mut regs = Registers::default();
        let vals = [0u64, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 0, 13, 14, 15, 16];
        // rax = 0, as a clone's child; the rest distinct.
        regs.rax = vals[0];
        regs.rbx = vals[1];
        regs.rcx = vals[2];
        regs.rdx = vals[3];
        regs.rsi = vals[4];
        regs.rdi = vals[5];
        regs.rbp = vals[6];
        regs.rsp = (program.top() & !15) as u64 - 8;
        regs.r8 = vals[8];
        regs.r9 = vals[9];
        regs.r10 = vals[10];
        regs.r12 = vals[12];
        regs.r13 = vals[13];
        regs.r14 = vals[14];
        regs.r15 = vals[15];
        regs.rip = landing as *const () as u64;
        unsafe {
            BACK = pp;
            p.co = Context::with_registers(control.top(), &regs, 0);
            regs = Registers::default(); // the copy on the control stack is what counts
            let _ = regs;
            switch(&raw mut (*pp).root, &raw const (*pp).co);
            let got = LANDED;
            for i in [0usize, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15] {
                assert_eq!(got[i], vals[i], "register #{i}");
            }
            assert_eq!(got[7], (program.top() & !15) as u64 - 8, "rsp");
        }
    }

    unsafe extern "C" fn jump_from_depth(buf: usize) {
        unsafe extern "C" fn deeper(buf: usize) {
            unsafe { jump(buf as *const JmpBuf, 42) }
        }
        unsafe { deeper(buf) }
    }

    unsafe extern "C" fn just_return(_: usize) {}

    #[test]
    fn jump_back_round_trips() {
        let mut buf = JmpBuf::new();
        for _ in 0..1000 {
            let b = &raw mut buf;
            assert_eq!(unsafe { call_with_jump_back(b, jump_from_depth, b as usize) }, 42);
            assert_eq!(unsafe { call_with_jump_back(b, just_return, 0) }, 0);
        }
    }
}
