# EXPERIMENT (measurement only): a token waiter spins (pause loop, up to SPIN_CYCLES of the TSC)
# watching the owner before it blocks on its eventfd. The wait loop re-checks the owner after
# every read, so a hand-off seen while spinning leaves a stale eventfd count, which only makes a
# later read return at once. argv[1]: the tree; argv[2]: cycles (default 60000, ~20 us at 3 GHz).
import sys
p = sys.argv[1] + '/native/rt/src/par.rs'
cyc = sys.argv[2] if len(sys.argv) > 2 else '60000'
s = open(p).read()
a = """fn wait_token_inner(id: u16) {
    while PAR.owner.load(Ordering::Acquire) != id as u32 {"""
assert s.count(a) == 1
s = s.replace(a, """fn wait_token_inner(id: u16) {
    // SAFETY: rdtsc has no preconditions.
    let t0 = unsafe { core::arch::x86_64::_rdtsc() };
    while PAR.owner.load(Ordering::Acquire) != id as u32 {
        if unsafe { core::arch::x86_64::_rdtsc() } - t0 > %s {
            break;
        }
        core::hint::spin_loop();
    }
    while PAR.owner.load(Ordering::Acquire) != id as u32 {""" % cyc)
open(p, 'w').write(s)
print('ok')
