# Applies the measurement counters (stats.rs) to the scratch copy of the tree given as argv[1].
import sys
T = sys.argv[1]


def edit(path, pairs):
    p = T + '/' + path
    s = open(p).read()
    for a, b, *n in pairs:
        cnt = n[0] if n else 1
        assert s.count(a) == cnt, (path, a, s.count(a))
        s = s.replace(a, b)
    open(p, 'w').write(s)


edit('native/rt/src/lib.rs', [("pub mod futex;\n", "pub mod futex;\npub mod stats;\n")])
edit('native/rt/Cargo.toml', [("[dev-dependencies]", "[features]\nstats = []\n\n[dev-dependencies]")])
edit('native/exobox/Cargo.toml', [('tokio = ["dep:tokio"]', 'tokio = ["dep:tokio"]\nstats = ["exobox-rt/stats"]')])

edit('native/rt/src/par.rs', [
    ("fn poke(id: u16) {\n    let _ = trap::eventfd_write",
     "fn poke(id: u16) {\n    crate::stats::count(crate::stats::K::Poke, 0);\n    let _ = trap::eventfd_write"),
    ("fn wait_token(id: u16) {\n",
     "fn wait_token(id: u16) {\n    if PAR.owner.load(Ordering::Acquire) == id as u32 {\n        return;\n    }\n    let t = crate::stats::tsc();\n    wait_token_counted(id);\n    crate::stats::count(crate::stats::K::WaitToken, crate::stats::tsc() - t);\n    crate::stats::handed();\n}\n\nfn wait_token_counted(id: u16) {\n"),
])
p = T + '/native/rt/src/par.rs'
s = open(p).read()
s = s.replace("PAR.owner.store(", "set_owner(")
s = s.replace("fn lock() {", "fn set_owner(v: u32, o: Ordering) {\n    crate::stats::owner_change(PAR.owner.load(Ordering::Relaxed), v, KERNEL as u32);\n    PAR.owner.store(v, o);\n}\n\nfn lock() {", 1)
open(p, 'w').write(s)
edit('native/rt/src/par.rs', [
    ("        unlock(); // already held (e.g. the main thread between setup syscalls)\n        return;\n    }\n    if o == NONE_SLOT {",
     "        unlock(); // already held (e.g. the main thread between setup syscalls)\n        crate::stats::count(crate::stats::K::AcqHeld, 0);\n        return;\n    }\n    if o == NONE_SLOT {\n        crate::stats::count(crate::stats::K::AcqFree, 0);"),
    ("    unlock();\n    poke(owner);\n    wait_token(id);\n}",
     "    unlock();\n    let t = crate::stats::tsc();\n    poke(owner);\n    wait_token(id);\n    crate::stats::count(crate::stats::K::AcqContended, crate::stats::tsc() - t);\n    if owner == KERNEL {\n        crate::stats::count(crate::stats::K::AcqFromKernel, 0);\n    }\n    LAST_WAIT.store(crate::stats::tsc() - t, Ordering::Relaxed);\n}\n\n/// The last contended acquire's wait (cycles), for the dispatcher's per-call account.\npub static LAST_WAIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);"),
    ("            give(id, true);\n            wait_token(id);",
     "            crate::stats::count(crate::stats::K::SchedIdle, 0);\n            give(id, true);\n            wait_token(id);"),
    ("        if trap::ppoll_fds(&mut fds[..n], ts.as_ref()).is_ok_and(|r| r > 0) {",
     "        let t = crate::stats::tsc();\n        let polled = trap::ppoll_fds(&mut fds[..n], ts.as_ref());\n        crate::stats::count(crate::stats::K::KernelPpoll, crate::stats::tsc() - t);\n        if polled.is_ok_and(|r| r > 0) {"),
])

edit('native/rt/src/guest.rs', [
    # per-syscall: threaded
    ("        let id = par::enter();\n        served(uc, nr, a);\n        par::leave(id);\n        return;",
     "        let t = crate::stats::tsc();\n        par::LAST_WAIT.store(0, core::sync::atomic::Ordering::Relaxed);\n        let id = par::enter();\n        let w = par::LAST_WAIT.load(core::sync::atomic::Ordering::Relaxed);\n        served(uc, nr, a);\n        par::leave(id);\n        crate::stats::syscall(nr, crate::stats::tsc() - t, w);\n        return;"),
    # coroutine
    ("    served(uc, nr, a);\n    // No preemption here",
     "    let t = crate::stats::tsc();\n    served(uc, nr, a);\n    crate::stats::syscall(nr, crate::stats::tsc() - t, 0);\n    // No preemption here"),
    ("    let mut p = a.map(|v| v as c_long);\n    // SAFETY: the kernel runs; the arguments are the program's (LKL reads its pointers) or ours.\n    unsafe { l::lkl_syscall(nr, p.as_mut_ptr()) as isize }",
     "    let mut p = a.map(|v| v as c_long);\n    let t = crate::stats::tsc();\n    // SAFETY: the kernel runs; the arguments are the program's (LKL reads its pointers) or ours.\n    let r = unsafe { l::lkl_syscall(nr, p.as_mut_ptr()) as isize };\n    crate::stats::count(crate::stats::K::Lkl, crate::stats::tsc() - t);\n    r"),
    ("fn finish(code: i32) -> ! {\n",
     "fn finish(code: i32) -> ! {\n    if crate::stats::ENABLED {\n        if S.phase.get() == Phase::Program {\n            let st = with_arena(|ar, _| ar.stats());\n            let hw = alloc::format!(\"EXOBOX_STATS arena high_water={} mapped={} extents={}\\n\", st.high_water, st.mapped, st.extents);\n            let _ = trap::write(2, hw.as_bytes());\n        }\n        crate::stats::report(SCHED.now(), &|b| {\n            let _ = trap::write(2, b);\n        });\n    }\n"),
])
# exec
p = T + '/native/rt/src/guest.rs'
s = open(p).read()
i = s.index("fn load(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], replace: bool) -> Result<Registers, Errno> {")
s = s[:i] + "fn load(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], replace: bool) -> Result<Registers, Errno> {\n    let t = crate::stats::tsc();\n    let r = load_inner(path, argv, envp, replace);\n    crate::stats::count(crate::stats::K::Exec, crate::stats::tsc() - t);\n    r\n}\n\nfn load_inner(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], replace: bool) -> Result<Registers, Errno> {" + s[i + len("fn load(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], replace: bool) -> Result<Registers, Errno> {"):]
open(p, 'w').write(s)

edit('native/rt/src/arena.rs', [
    ("unsafe fn zero_nonzero(addr: usize, len: usize) -> usize {\n    let mut written = 0;",
     "unsafe fn zero_nonzero(addr: usize, len: usize) -> usize {\n    let t = crate::stats::tsc();\n    let w = unsafe { zero_nonzero_inner(addr, len) };\n    crate::stats::count(crate::stats::K::Zero, crate::stats::tsc() - t);\n    crate::stats::bytes(crate::stats::K::Zero, w as u64);\n    w\n}\n\nunsafe fn zero_nonzero_inner(addr: usize, len: usize) -> usize {\n    let mut written = 0;"),
    ("unsafe fn copy_nonzero(dst: usize, src: usize, len: usize) {\n",
     "unsafe fn copy_nonzero(dst: usize, src: usize, len: usize) {\n    let _t = crate::stats::tsc();\n    crate::stats::bytes(crate::stats::K::MremapCopy, len as u64);\n    let _g = Defer(move || crate::stats::count(crate::stats::K::MremapCopy, crate::stats::tsc() - _t));\n"),
    ("    fn fill<B: Backing>(b: &mut B, f: FileMap, lo: usize, len: usize) -> Result<()> {\n        let mut done = 0;",
     "    fn fill<B: Backing>(b: &mut B, f: FileMap, lo: usize, len: usize) -> Result<()> {\n        let _t = crate::stats::tsc();\n        crate::stats::bytes(crate::stats::K::FileCopy, len as u64);\n        let _g = Defer(move || crate::stats::count(crate::stats::K::FileCopy, crate::stats::tsc() - _t));\n        let mut done = 0;"),
])
p = T + '/native/rt/src/arena.rs'
s = open(p).read()
s += "\nstruct Defer<F: FnMut()>(F);\nimpl<F: FnMut()> Drop for Defer<F> {\n    fn drop(&mut self) {\n        (self.0)()\n    }\n}\n"
open(p, 'w').write(s)

edit('native/rt/src/sched.rs', [
    ("        self.current.set(next);\n        let from = self.slots[prev as usize].ctx.get();",
     "        self.current.set(next);\n        crate::stats::count(crate::stats::K::Switch, 0);\n        let from = self.slots[prev as usize].ctx.get();"),
])
edit('native/rt/src/guest.rs', [
    ("        SCHED.init(Config { stacks: b.stacks, switch_fs: true, host: &SYS }).map_err(err(\"coroutine stacks\"))?;\n",
     "        SCHED.init(Config { stacks: b.stacks, switch_fs: true, host: &SYS }).map_err(err(\"coroutine stacks\"))?;\n        crate::stats::start(SCHED.now());\n"),
])
if len(sys.argv) > 2:
    # EXPERIMENT: sched_getaffinity reports this mask (the shipped runtime reports one CPU).
    edit('native/rt/src/guest.rs', [
        ("ret(write_user(a[2], 1u64).map(|_| 8))", "ret(write_user(a[2], %su64).map(|_| 8))" % sys.argv[2]),
    ])
edit('native/rt/src/par.rs', [
    ("    // SAFETY: the caller's.\n    unsafe { fork_trampoline(stack_top, flags, frame) }",
     "    let t = crate::stats::tsc();\n    // SAFETY: the caller's.\n    let r = unsafe { fork_trampoline(stack_top, flags, frame) };\n    if r > 0 {\n        crate::stats::count(crate::stats::K::Fork, crate::stats::tsc() - t);\n    }\n    r"),
])
print("ok")
