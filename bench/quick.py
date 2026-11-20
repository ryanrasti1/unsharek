#!/usr/bin/env python3
"""The vs-native suite: where each mode stands against native, in seconds.

Not correctness (cargo xtask test) and not perf.rs's budgets (cargo xtask perf): each workload that matters for
parallel builds, scaled down until a run takes a fraction of a second, run natively and in each
mode, reported as the ratio to native with a pass/fail against a target ratio (the goal: builds
within 5% of native). The full-size measurements are bench/run's (bench/PERF.md); the
small versions here were checked to show the same ratios (PERF.md, "The vs-native suite").

  cargo xtask vs-native                       every workload, threaded and fork mode
  cargo xtask vs-native --modes fork --work make,micro
  cargo xtask vs-native --unsharek PATH         another unsharek binary (an experiment's)
  cargo xtask vs-native --modes fork,fork:old --variant old=PATH   before and after, interleaved
  cargo xtask vs-native --modes fork,fork:stats --variant stats     the runtime's counters' build

Workloads: rustc (a generated crate, -C codegen-units=16 --emit=obj: rustc's threads),
rustmake (4 generated crates and a binary by rustc under make -j4: processes and threads), make
(make -j4 of 12 C files and a link), xz (xz -T4 on 8 MB), micro (syscall_bench's getppid,
futex and pipe ping-pongs; exec_bench's fork+exec+wait of `true`, fork mode). Exit status 1 if a
ratio is over its target (`--no-fail` to only report).
"""

import argparse
import glob
import os
import shutil
import statistics
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_bench as bb  # noqa: E402

# Target ratios to native. Builds: the goal. Micro costs: what a build at the goal can afford
# (a call ~1 µs, a futex round trip and a process within 2x of native).
TARGET = {'rustc': 1.05, 'rustmake': 1.05, 'make': 1.05, 'xz': 1.05,
          'getppid': 20.0, 'futex': 2.0, 'pingpong': 3.0, 'forkexec': 2.0}
SINGLE = {'rustc', 'xz', 'micro'}  # one process: every mode; the rest need fork mode


def fixtures():
    """The fixtures' bin directory (the newest build's)."""
    dirs = glob.glob(os.path.join(bb.TARGET, 'release', 'build', 'unsharek-fixtures-*', 'out', 'bin'))
    dirs = [d for d in dirs if os.path.exists(os.path.join(d, 'exec_bench'))]
    if not dirs:
        sys.exit('no fixtures with exec_bench under target/release: build first (bench/quick does)')
    return max(dirs, key=os.path.getmtime)


def gen_crate(d, name, k, deps=()):
    os.makedirs(os.path.join(d, 'src'), exist_ok=True)
    body = ''.join(
        f'pub fn f{i}(v: &[u64]) -> u64 {{ v.iter().enumerate().map(|(j, x)| x.wrapping_mul(j as u64 ^ {i}))'
        f'.fold(0, |a, b| a.rotate_left(3) ^ b) }}\n'
        f'#[derive(Debug, Clone, PartialEq)] pub struct S{i} {{ pub a: Vec<String>, pub b: std::collections::HashMap<u32, u64> }}\n'
        f'impl S{i} {{ pub fn new() -> Self {{ S{i} {{ a: (0..{i}).map(|j| format!("{{j}}")).collect(), b: (0..{i} as u32).map(|j| (j, j as u64)).collect() }} }} }}\n'
        for i in range(k))
    open(os.path.join(d, 'src', 'lib.rs'), 'w').write(body)


FLAGS = '--edition 2021 -C opt-level=3 -C codegen-units=16 -C debuginfo=0'


def setup(tmp, fx):
    rc = bb.rustc_real()
    bash, make, gcc = os.environ['UNSHAREK_TEST_BASH'], os.environ['UNSHAREK_TEST_MAKE'], os.environ['UNSHAREK_TEST_GCC']
    cu = os.environ['UNSHAREK_TEST_COREUTILS']
    xz = os.environ['UNSHAREK_TEST_XZ']
    w = {}
    # rustc: one crate.
    src = os.path.join(tmp, 'rustc-src')
    if not os.path.exists(src):
        gen_crate(src, 'q', 40)
    args = FLAGS.split() + ['--crate-type', 'lib', '--crate-name', 'q', '--emit=obj', os.path.join(src, 'src', 'lib.rs')]
    nat = os.path.join(tmp, 'rustc-out')

    def rustc_native(nat=nat):
        shutil.rmtree(nat, ignore_errors=True)
        os.makedirs(nat)
        return [rc] + args + ['--out-dir', nat]
    w['rustc'] = (rustc_native, lambda: [rc] + args + ['--out-dir', '/tmp'], [src], None)
    # rustmake: 4 crates in a chain of two, a binary, rustc under make -j4.
    src = os.path.join(tmp, 'rustmake-src')
    if not os.path.exists(src):
        crates = [f'c{i}' for i in range(4)]
        rules = []
        for i, c in enumerate(crates):
            gen_crate(os.path.join(src, c), c, 15)
            deps = [f'c{j}' for j in range(i) if j >= i - 2]
            ext = ' '.join(f'--extern {d}=lib{d}.rlib' for d in deps)
            rules.append(f'lib{c}.rlib: {c}/src/lib.rs {" ".join(f"lib{d}.rlib" for d in deps)}\n'
                         f'\t+$(RUSTC) {FLAGS} --crate-type rlib --crate-name {c} {ext} -L . -o $@ $<\n')
        os.makedirs(os.path.join(src, 'app'))
        open(os.path.join(src, 'app', 'main.rs'), 'w').write(
            'fn main() { println!("{}", ' + ' ^ '.join(f'{c}::f1(&[1, 2, 3])' for c in crates) + '); }\n')
        ext = ' '.join(f'--extern {c}=lib{c}.rlib' for c in crates)
        open(os.path.join(src, 'Makefile'), 'w').write(
            f'app-bin: app/main.rs {" ".join(f"lib{c}.rlib" for c in crates)}\n'
            f'\t+$(RUSTC) {FLAGS} --crate-type bin --crate-name app {ext} -L . -o $@ $<\n' + ''.join(rules))
    env = bb.tools_env([os.path.dirname(rc), gcc, make, os.path.join(cu, 'bin')])

    def rm_script(work, src=src):
        return f'set -e; rm -rf {work}; cp -r {src} {work}; cd {work}; make -s -j4 RUSTC={rc}; ./app-bin >/dev/null'
    allow = [bb.store_path(p) for p in (bash, make, rc, gcc, cu)] + [src]
    w['rustmake'] = (lambda: [bash, '-c', rm_script(os.path.join(tmp, 'rustmake-native'))],
                     lambda: [bash, '-c', rm_script('/tmp/build')], allow, env)
    # make: 12 C files and a link.
    src = os.path.join(tmp, 'make-src')
    if not os.path.exists(src):
        os.makedirs(src)
        objs = []
        for i in range(12):
            body = ''.join(
                f'static int g{i}_{j}[64];\nint f{i}_{j}(int x) {{ int s = 0; for (int k = 0; k < x; k++) '
                f's += (k * {j}) ^ {i} ^ g{i}_{j}[k & 63]; return s; }}\n' for j in range(40))
            open(os.path.join(src, f'f{i}.c'), 'w').write('#include <stdio.h>\n#include <string.h>\n' + body)
            objs.append(f'f{i}.o')
        open(os.path.join(src, 'main.c'), 'w').write('int main(void) { return 0; }\n')
        open(os.path.join(src, 'Makefile'), 'w').write(
            f'prog: main.o {" ".join(objs)}\n\t$(CC) -o $@ $^\n%.o: %.c\n\t$(CC) -O2 -c -o $@ $<\n')
    menv = bb.tools_env([gcc, make, os.path.join(cu, 'bin')])

    def mk_script(work, src=src):
        return f'set -e; rm -rf {work}; cp -r {src} {work}; make -s -C {work} -j4 CC=gcc; {work}/prog'
    allow = [bb.store_path(p) for p in (bash, make, gcc, cu)] + [src]
    w['make'] = (lambda: [bash, '-c', mk_script(os.path.join(tmp, 'make-native'))],
                 lambda: [bash, '-c', mk_script('/tmp/build')], allow, menv)
    # xz: 8 MB, eight 1 MiB blocks.
    inp = os.path.join(tmp, 'xz', 'input.txt')
    if not os.path.exists(inp):
        full = bb.xz_input(os.path.join(tmp, 'xz-full'))
        with open(full, 'rb') as f:
            data = f.read(8 << 20)
        os.makedirs(os.path.dirname(inp), exist_ok=True)
        open(inp + '.tmp', 'wb').write(data)
        os.replace(inp + '.tmp', inp)
        os.unlink(full)
    xargv = [xz, '-T4', '-3', '--block-size=1MiB', '-c', inp]
    w['xz'] = (lambda: xargv, lambda: xargv, [bb.store_path(xz), os.path.dirname(inp)], None)
    # micro: syscall_bench, and exec_bench of coreutils' true.
    true = os.path.join(cu, 'bin', 'true')
    sb = [os.path.join(fx, 'syscall_bench'), '5000']
    eb = [os.path.join(fx, 'exec_bench'), '20', true]
    w['micro'] = (sb, eb, [fx, cu])
    return w


def parse_micro(out):
    r = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) == 2 and f[0] in TARGET:
            r[f[0]] = float(f[1])
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--work', default='rustc,rustmake,make,xz,micro')
    ap.add_argument('--modes', default='threaded,fork')
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--cpus', default=os.environ.get('BENCH_CPUS', '0-7'))
    ap.add_argument('--unsharek', default=os.path.join(bb.TARGET, 'release', 'unsharek'))
    ap.add_argument('--variant', action='append', default=[], metavar='NAME=PATH',
                    help='another unsharek binary; a mode MODE:NAME runs it (before/after in one run); '
                    '`stats` alone: the counters\' build')
    ap.add_argument('--timeout', type=float, default=60)
    ap.add_argument('--no-fail', action='store_true', help='report only: exit 0 whatever the ratios')
    ap.add_argument('--tmp', default=os.path.join(bb.TARGET, 'vs-native'))
    a = ap.parse_args()
    os.makedirs(a.tmp, exist_ok=True)
    works = [w for w in a.work.split(',') if w]
    modes = [m for m in a.modes.split(',') if m]
    variants = bb.parse_variants(a.variant)

    def mode_of(m):
        return m.partition(':')[0]

    def exe_of(m):
        var = m.partition(':')[2]
        return variants[var] if var else a.unsharek
    fx = fixtures()
    setups = setup(a.tmp, fx)
    cpus = a.cpus or None
    walls = {}   # (work, mode) -> [s]
    micro = {}   # (op, mode) -> [value]
    failed = []
    counters = {}  # what -> the last run's UNSHAREK_STATS (the `stats` build's)

    def go(cmd, env, what):
        st, wall, _, _, out, err, _ = bb.run(cmd, a.timeout, env=env, cpus=cpus)
        stats = bb.parse_stats(err)
        if stats['k']:
            counters[what] = (stats, wall)
        if st != 0:
            failed.append(f'{what}: status {st}: {err.strip()[-300:]}')
            return None, out
        return wall, out

    def sandboxed_env(env):
        return dict(env, PATH=env['PATH'] + ':' + os.environ.get('PATH', '')) if env else None
    for _ in range(a.reps):
        for w in works:
            if w == 'micro':
                sb, eb, allow = setups[w]
                for m in ['native'] + modes:
                    for cmd, ops in ((sb, ('getppid', 'futex', 'pingpong')), (eb, ('forkexec',))):
                        if cmd is eb and mode_of(m) not in ('native', 'fork'):
                            continue
                        c = cmd if m == 'native' else bb.sandboxed(exe_of(m), mode_of(m), allow, cmd)
                        _, out = go(c, None, f'micro {m}')
                        for op, v in parse_micro(out).items():
                            if op in ops:
                                micro.setdefault((op, m), []).append(v)
                continue
            native, sb, allow, env = setups[w]
            wall, _ = go(native(), env, f'{w} native')
            if wall:
                walls.setdefault((w, 'native'), []).append(wall)
            for m in modes:
                if w not in SINGLE and mode_of(m) != 'fork':
                    continue
                wall, _ = go(bb.sandboxed(exe_of(m), mode_of(m), allow, sb(), max_procs=32 if mode_of(m) == 'fork' else None),
                             sandboxed_env(env), f'{w} {m}')
                if wall:
                    walls.setdefault((w, m), []).append(wall)
    print(f'{"":10} {"native":>10} ' + ' '.join(f'{m:>18}' for m in modes) + '   target')
    over = []

    def row(name, nat, per_mode, unit, best=min):
        cells = []
        for m in modes:
            v = per_mode.get(m)
            if not v or not nat:
                cells.append(f'{"-":>18}')
                continue
            r = best(v) / best(nat)
            ok = r <= TARGET[name]
            if not ok:
                over.append(f'{name} {m} {r:.2f}x')
            cells.append(f'{best(v):8.{2 if unit == "s" else 0}f} {r:5.2f}x {"ok  " if ok else "FAIL"}')
        n = f'{best(nat):8.{2 if unit == "s" else 0}f} {unit:2}' if nat else f'{"-":>10}'
        print(f'{name:10} {n} ' + ' '.join(cells) + f'   {TARGET[name]}x')
    for w in works:
        if w == 'micro':
            for op, unit in (('getppid', 'ns'), ('futex', 'ns'), ('pingpong', 'ns'), ('forkexec', 'us')):
                row(op, micro.get((op, 'native')), {m: micro.get((op, m)) for m in modes}, unit, best=statistics.median)
            continue
        row(w, walls.get((w, 'native')), {m: walls.get((w, m)) for m in modes}, 's')
    print(f'(best of {a.reps}: builds by wall time, micro costs by median; pinned to CPUs {a.cpus})')
    for what, (stats, wall) in counters.items():
        print(f'\n{what}: counters of the last run')
        bb.summarize(stats, wall)
    for f in failed:
        print('RUN FAILED: ' + f)
    if failed or (over and not a.no_fail):
        print('over target: ' + ', '.join(over) if over else '')
        sys.exit(1)


if __name__ == '__main__':
    main()
