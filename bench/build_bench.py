#!/usr/bin/env python3
"""Build benchmarks: native against each unsharek mode, wall and CPU time, interleaved reps.

Run through `bench/run` (it enters the devshell and builds release). Every run is bounded
by a timeout; a run that fails or times out is reported, not retried. See bench/PERF.md for what
the numbers mean and how they were taken.

Workloads (`--work`, comma-separated):
  rustc   rustc -C opt-level=3 -C codegen-units=16 --emit=obj of regex-syntax (58k lines, no
          deps, no link): one process, a frontend thread then LLVM codegen threads. rustc sizes
          its codegen parallelism from sched_getaffinity unless given a jobserver.
  xz      xz -T4 -3 --block-size=2MiB on 16 MB of text (perf.rs's input): four compressing threads.
  make    make -j4 of 32 generated C files and a link, from bash (fork mode only).
  cargo   cargo build -j4 --offline of a generated 6-crate workspace (fork mode only).
  rustmake  the same workspace's crates by rustc under make -jN, cargo's release flags, linked by
          cc: cargo's work without cargo (fork mode only).

Modes (`--modes`): native, coroutine, threaded, fork; MODE:NAME runs the `--variant NAME=PATH`
binary (an experiment's build) in that mode, for A/B comparisons in one interleaved run. Each rep
runs every mode once, in order, so load from other processes on the machine hits all of them
alike; min, median and the paired (same-rep) ratio to native are reported.

`--unsharek PATH` runs another unsharek binary. `--variant stats` (no path) is the runtime's counters
(the cargo feature `stats`, built by bench/run): its `UNSHAREK_STATS` lines (stderr) are kept
in the log and summarised.
"""

import argparse
import glob
import json
import os
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# cargo's target directory (CARGO_TARGET_DIR, else the tree's target/)
TARGET = os.environ.get('CARGO_TARGET_DIR') or os.path.join(ROOT, 'target')
TASKSET = shutil.which('taskset') or 'taskset'


def store_path(p):
    p = os.path.realpath(p)
    parts = p.split('/')
    return '/'.join(parts[:4]) if p.startswith('/nix/store/') else p


def run(cmd, timeout, env=None, cwd=None, cpus=None, perf=None):
    """Runs cmd; returns (status, wall s, user s, sys s, stdout, stderr, perf counters). User and
    sys are the children's rusage via wait4, which misses processes nobody waited for: fork mode's
    (init reaps them with SA_NOCLDWAIT). With `perf`, `perf stat` counts every descendant
    (task-clock: CPU ms, user and kernel), the number to compare across modes."""
    pfile = None
    if perf:
        pfile = tempfile.NamedTemporaryFile(suffix='.perf', delete=False).name
        cmd = [perf, 'stat', '-x,', '-o', pfile, '-e', 'task-clock,context-switches,cpu-migrations,page-faults', '--'] + cmd
    if cpus:
        cmd = [TASKSET, '-c', cpus] + cmd
    out = tempfile.TemporaryFile()
    err = tempfile.TemporaryFile()
    t = time.monotonic()
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, cwd=cwd,
                         start_new_session=True)
    deadline = t + timeout
    status = None
    while True:
        pid, st, ru = os.wait4(p.pid, os.WNOHANG)
        if pid:
            status = os.waitstatus_to_exitcode(st)
            break
        if time.monotonic() > deadline:
            os.killpg(p.pid, signal.SIGKILL)
            pid, st, ru = os.wait4(p.pid, 0)
            status = 'timeout'
            break
        time.sleep(0.005)
    wall = time.monotonic() - t
    out.seek(0)
    err.seek(0)
    pc = {}
    if pfile:
        for line in open(pfile):
            f = line.strip().split(',')
            if len(f) > 2 and f[0] and f[0][0].isdigit():
                pc[f[2].split(':')[0]] = float(f[0])
        os.unlink(pfile)
    return status, wall, ru.ru_utime, ru.ru_stime, out.read().decode(errors='replace'), err.read().decode(errors='replace'), pc


def sandboxed(unsharek, mode, allow, argv, max_procs=None):
    cmd = [unsharek, '--mode', mode, '--env', 'PATH', '--env', 'HOME']
    for a in allow:
        # A store path: its closure. A host directory: shown live, and the store paths it uses.
        cmd += ['--mount', a + ':closure'] if os.path.realpath(a).startswith('/nix/store/') else ['--mount', a + ':ro', '--mount', a + ':closure']
    if max_procs:
        cmd += ['--max-procs', str(max_procs)]
    return cmd + ['--'] + argv


# ---- workloads: each returns (native argv, sandboxed argv builder, allowed paths, env, cleanup) ----

def find_regex_syntax(arg):
    if arg:
        return arg
    hits = sorted(glob.glob(os.path.expanduser('~/.cargo/registry/src/*/regex-syntax-0.8.*')))
    if not hits:
        sys.exit('regex-syntax 0.8 not in ~/.cargo/registry: pass --crate-src DIR')
    return hits[-1]


def rustc_real():
    # The devshell's rustc is a wrapper script; run the compiler itself (its sysroot is its store
    # path, so the closure brings it).
    w = shutil.which('rustc')
    sysroot = subprocess.check_output([w, '--print', 'sysroot'], text=True).strip()
    return os.path.join(sysroot, 'bin', 'rustc')


def w_rustc(a, tmp):
    src = find_regex_syntax(a.crate_src)
    feats = ['std', 'unicode', 'unicode-age', 'unicode-bool', 'unicode-case', 'unicode-gencat', 'unicode-perl',
             'unicode-script', 'unicode-segment']
    args = ['--edition', '2021', '--crate-type', 'lib', '--crate-name', 'regex_syntax', '-C', 'opt-level=3',
            '-C', f'codegen-units={a.cgu}', '--emit=obj']
    for f in feats:
        args += ['--cfg', f'feature="{f}"']
    args.append(os.path.join(src, 'src', 'lib.rs'))
    rc = rustc_real()
    nat_out = os.path.join(tmp, 'rustc-native')

    def native():
        shutil.rmtree(nat_out, ignore_errors=True)
        os.makedirs(nat_out)
        return [rc] + args + ['--out-dir', nat_out]
    return native, lambda: [rc] + args + ['--out-dir', '/tmp'], [src], None


def xz_input(tmp):
    f = os.path.join(tmp, 'xz', 'input.txt')
    if os.path.exists(f):
        return f
    os.makedirs(os.path.dirname(f), exist_ok=True)
    words = [b'sandbox', b'kernel', b'seccomp', b'arena', b'coroutine', b'thread', b'fork', b'store', b'\n']
    x = 0x9e3779b97f4a7c15
    m = (1 << 64) - 1
    out = bytearray()
    while len(out) < 16 << 20:
        x ^= (x << 13) & m
        x ^= x >> 7
        x ^= (x << 17) & m
        out += words[x % len(words)] + b' '
    with open(f, 'wb') as fh:
        fh.write(out)
    return f


def w_xz(a, tmp):
    xz = os.environ.get('UNSHAREK_TEST_XZ') or shutil.which('xz')
    inp = xz_input(tmp)
    argv = [xz, '-T4', '-3', '--block-size=2MiB', '-c', inp]
    return lambda: argv, lambda: argv, [store_path(xz), os.path.dirname(inp)], None


def tools_env(tools):
    path = ':'.join(os.path.dirname(t) if os.path.isfile(t) else t for t in tools)
    env = {'PATH': path, 'HOME': '/tmp', 'LANG': 'C'}
    return env


def w_make(a, tmp):
    bash, make, gcc = os.environ['UNSHAREK_TEST_BASH'], os.environ['UNSHAREK_TEST_MAKE'], os.environ['UNSHAREK_TEST_GCC']
    cu = os.environ['UNSHAREK_TEST_COREUTILS']
    src = os.path.join(tmp, 'make-src')
    if not os.path.exists(src):
        os.makedirs(src)
        objs = []
        for i in range(32):
            body = ''.join(
                f'static int g{i}_{j}[64];\nint f{i}_{j}(int x) {{ int s = 0; for (int k = 0; k < x; k++) '
                f's += (k * {j}) ^ {i} ^ g{i}_{j}[k & 63]; return s; }}\n' for j in range(60))
            open(os.path.join(src, f'f{i}.c'), 'w').write('#include <stdio.h>\n#include <string.h>\n' + body)
            objs.append(f'f{i}.o')
        open(os.path.join(src, 'main.c'), 'w').write('int main(void) { return 0; }\n')
        open(os.path.join(src, 'Makefile'), 'w').write(
            f'prog: main.o {" ".join(objs)}\n\t$(CC) -o $@ $^\n%.o: %.c\n\t$(CC) -O2 -c -o $@ $<\n')
    env = tools_env([gcc, make, os.path.join(cu, 'bin')])

    def script(work):
        return f'set -e; rm -rf {work}; cp -r {src} {work}; make -s -C {work} -j{a.jobs} CC=gcc; {work}/prog'
    nat = os.path.join(tmp, 'make-native')
    allow = [store_path(p) for p in (bash, make, gcc, cu)] + [src]
    return lambda: [bash, '-c', script(nat)], lambda: [bash, '-c', script('/tmp/build')], allow, env


def w_cargo(a, tmp):
    bash, cu = os.environ['UNSHAREK_TEST_BASH'], os.environ['UNSHAREK_TEST_COREUTILS']
    cargo = shutil.which('cargo')
    rustc = shutil.which('rustc')
    cc = os.environ['UNSHAREK_TEST_GCC']
    src = os.path.join(tmp, 'cargo-src')
    if not os.path.exists(src):
        os.makedirs(src)
        crates = [f'c{i}' for i in range(6)]
        open(os.path.join(src, 'Cargo.toml'), 'w').write(
            '[workspace]\nresolver = "2"\nmembers = [' + ', '.join(f'"{c}"' for c in crates + ['app']) + ']\n')
        for i, c in enumerate(crates):
            d = os.path.join(src, c, 'src')
            os.makedirs(d)
            deps = ''.join(f'c{j} = {{ path = "../c{j}" }}\n' for j in range(i) if j >= i - 2)
            open(os.path.join(src, c, 'Cargo.toml'), 'w').write(
                f'[package]\nname = "{c}"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n{deps}')
            body = ''.join(
                f'pub fn f{k}(v: &[u64]) -> u64 {{ v.iter().enumerate().map(|(i, x)| x.wrapping_mul(i as u64 ^ {k}))'
                f'.fold(0, |a, b| a.rotate_left(3) ^ b) }}\n'
                f'#[derive(Debug, Clone, PartialEq)] pub struct S{k} {{ pub a: Vec<String>, pub b: std::collections::HashMap<u32, u64> }}\n'
                f'impl S{k} {{ pub fn new() -> Self {{ S{k} {{ a: (0..{k}).map(|i| format!("{{i}}")).collect(), b: (0..{k} as u32).map(|i| (i, i as u64)).collect() }} }} }}\n'
                for k in range(80))
            open(os.path.join(d, 'lib.rs'), 'w').write(body)
        os.makedirs(os.path.join(src, 'app', 'src'))
        open(os.path.join(src, 'app', 'Cargo.toml'), 'w').write(
            '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n'
            + ''.join(f'{c} = {{ path = "../{c}" }}\n' for c in crates))
        open(os.path.join(src, 'app', 'src', 'main.rs'), 'w').write(
            'fn main() { println!("{}", ' + ' ^ '.join(f'{c}::f1(&[1, 2, 3])' for c in crates) + '); }\n')
        # A lockfile, so --offline never looks for a registry.
        subprocess.run([cargo, 'generate-lockfile', '--offline', '--manifest-path', os.path.join(src, 'Cargo.toml')],
                       check=True, capture_output=True)
        # The same DAG as rustc invocations under make (the `rustmake` workload): cargo's release
        # flags, make's jobserver passed on (`+`), the binary linked by cc.
        rules = []
        for i, c in enumerate(crates):
            deps = [f'c{j}' for j in range(i) if j >= i - 2]
            ext = ' '.join(f'--extern {d}=lib{d}.rlib' for d in deps)
            rules.append(f'lib{c}.rlib: {c}/src/lib.rs {" ".join(f"lib{d}.rlib" for d in deps)}\n'
                         f'\t+$(RUSTC) $(FLAGS) --crate-type rlib --crate-name {c} {ext} -L . -o $@ $<\n')
        ext = ' '.join(f'--extern {c}=lib{c}.rlib' for c in crates)
        open(os.path.join(src, 'rust.mk'), 'w').write(
            'FLAGS = --edition 2021 -C opt-level=3 -C codegen-units=16 -C debuginfo=0\n'
            f'app-bin: app/src/main.rs {" ".join(f"lib{c}.rlib" for c in crates)}\n'
            f'\t+$(RUSTC) $(FLAGS) --crate-type bin --crate-name app {ext} -L . -o $@ $<\n' + ''.join(rules))
    tools = [os.path.dirname(cargo), os.path.dirname(rustc), os.path.dirname(cc), os.path.join(cu, 'bin')]
    env = tools_env(tools)
    env['CARGO_HOME'] = '/tmp/cargo-home'

    def script(work):
        return (f'set -e; rm -rf {work}; cp -r {src} {work}; cd {work}; '
                f'cargo build -j{a.jobs} --offline --release -q; ./target/release/app')
    nat = os.path.join(tmp, 'cargo-native')
    allow = [store_path(p) for p in (bash, cargo, rustc, rustc_real(), cc, cu)] + [src]

    def native():
        e = dict(env)
        e['CARGO_HOME'] = os.path.join(tmp, 'cargo-home')
        return [bash, '-c', script(nat)]
    return native, lambda: [bash, '-c', script('/tmp/build')], allow, env


def w_rustmake(a, tmp):
    """cargo's work without cargo (made while cargo crashed the sandbox; kept: no cargo in it): the workspace's
    crates compiled by rustc under make -jN, the binary linked by cc."""
    w_cargo(a, tmp)  # generates the sources and rust.mk
    bash, make, cu = os.environ['UNSHAREK_TEST_BASH'], os.environ['UNSHAREK_TEST_MAKE'], os.environ['UNSHAREK_TEST_COREUTILS']
    cc = os.environ['UNSHAREK_TEST_GCC']
    rc = rustc_real()
    src = os.path.join(tmp, 'cargo-src')
    env = tools_env([os.path.dirname(rc), cc, make, os.path.join(cu, 'bin')])

    def script(work):
        return (f'set -e; rm -rf {work}; cp -r {src} {work}; cd {work}; '
                f'make -s -f rust.mk -j{a.jobs} RUSTC={rc}; ./app-bin')
    nat = os.path.join(tmp, 'rustmake-native')
    allow = [store_path(p) for p in (bash, make, rc, cc, cu)] + [src]
    return lambda: [bash, '-c', script(nat)], lambda: [bash, '-c', script('/tmp/build')], allow, env


WORK = {'rustc': w_rustc, 'xz': w_xz, 'make': w_make, 'cargo': w_cargo, 'rustmake': w_rustmake}
FORK_ONLY = {'make', 'cargo', 'rustmake'}


def parse_stats(err):
    """UNSHAREK_STATS lines (the `stats` build's) into a dict."""
    st = {'k': {}, 'sys': {}}
    for line in err.splitlines():
        if not line.startswith('UNSHAREK_STATS '):
            continue
        f = line.split()[1:]
        kv = {x.split('=')[0]: float(x.split('=')[1]) for x in f if '=' in x}
        if f[0] == 'k':
            st['k'][f[1]] = kv
        elif f[0] == 'sys':
            st['sys'][int(f[1])] = kv
        else:
            st.setdefault('top', {}).update(kv)
    return st


def parse_variants(vs):
    """`--variant NAME=PATH`s into {NAME: PATH}. A NAME alone is target/release/unsharek-NAME: `stats`,
    the runtime's counters (the cargo feature `stats`), which bench/run builds there."""
    return {n: p or os.path.join(TARGET, 'release', 'unsharek-' + n) for n, _, p in (v.partition('=') for v in vs)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--work', default='rustc,xz')
    ap.add_argument('--modes', default='native,threaded')
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--cpus', default=os.environ.get('BENCH_CPUS', '0-7'),
                    help='taskset CPU list for every run (default: 0-7, this machine\'s P-cores); "" for none')
    ap.add_argument('--unsharek', default=os.path.join(TARGET, 'release', 'unsharek'))
    ap.add_argument('--variant', action='append', default=[], metavar='NAME=PATH',
                    help='another unsharek binary; a mode MODE:NAME runs it (A/B runs, interleaved)')
    ap.add_argument('--crate-src', default=None)
    ap.add_argument('--cgu', type=int, default=16)
    ap.add_argument('--jobs', type=int, default=4)
    ap.add_argument('--timeout', type=float, default=300)
    ap.add_argument('--perf', default=shutil.which('perf'),
                    help='perf, for CPU time across every process (default: perf on PATH; "" for none)')
    ap.add_argument('--log', default=None, help='JSON lines, one per run')
    ap.add_argument('--tmp', default=None, help='work directory (default: a fresh one)')
    a = ap.parse_args()
    variants = parse_variants(a.variant)
    tmp = a.tmp or tempfile.mkdtemp(prefix='unsharek-bench-')
    os.makedirs(tmp, exist_ok=True)
    log = open(a.log, 'a') if a.log else None
    results = {}
    works = [w for w in a.work.split(',') if w]
    modes = [m for m in a.modes.split(',') if m]
    setups = {w: WORK[w](a, tmp) for w in works}
    for rep in range(a.reps):
        for w in works:
            native, sb, allow, env = setups[w]
            for m in modes:
                if m == 'native':
                    e = env
                    if env and w == 'cargo':
                        e = dict(env, CARGO_HOME=os.path.join(tmp, 'cargo-home'))
                    cmd = native()
                else:
                    # unsharek itself needs the host's PATH (nix-store, for the closures); the
                    # program sees the tools first.
                    e = dict(env, PATH=env['PATH'] + ':' + os.environ.get('PATH', '')) if env else None
                    mode, _, var = m.partition(':')
                    exe = variants[var] if var else a.unsharek
                    if mode not in ('fork',) and w in FORK_ONLY:
                        continue
                    cmd = sandboxed(exe, mode, allow, sb(), max_procs=32 if mode == 'fork' else None)
                load = os.getloadavg()[0]
                st, wall, ut, stime, out, err, pc = run(cmd, a.timeout, env=e, cpus=a.cpus or None, perf=a.perf)
                stats = parse_stats(err)
                rec = {'work': w, 'mode': m, 'rep': rep, 'status': st, 'wall': wall, 'user': ut, 'sys': stime,
                       'cpu': pc.get('task-clock', (ut + stime) * 1e3) / 1e3, 'perf': pc,
                       'load': load, 'stats': stats if stats['k'] else None}
                if st != 0:
                    rec['stderr'] = err[-2000:]
                if log:
                    log.write(json.dumps(rec) + '\n')
                    log.flush()
                results.setdefault((w, m), []).append(rec)
                tag = 'ok' if st == 0 else f'FAILED ({st})'
                print(f'rep {rep} {w:6} {m:22} wall {wall:7.3f} s  cpu {rec["cpu"]:7.3f} s  load {load:5.1f}  {tag}',
                      flush=True)
                if st != 0:
                    print('   ' + err.strip().replace('\n', '\n   ')[-1500:])
    print()
    print("x native: best against best; paired: the median over reps of each rep's ratio to its native run")
    print(f'{"work":6} {"mode":22} {"n":>2} {"wall min":>9} {"median":>9} {"x native":>9} {"paired":>7} '
          f'{"cpu s":>8} {"cpu/wall":>8} {"ctxsw":>8}')
    for w in works:
        natr = {r['rep']: r['wall'] for r in results.get((w, 'native'), []) if r['status'] == 0}
        nmin = min(natr.values()) if natr else None
        for m in modes:
            rs = [r for r in results.get((w, m), []) if r['status'] == 0]
            if not rs:
                if (w, m) in results:
                    print(f'{w:6} {m:22}  all runs failed')
                continue
            walls = [r['wall'] for r in rs]
            best = min(rs, key=lambda r: r['wall'])
            ratio = f'{min(walls) / nmin:8.2f}x' if nmin else '        -'
            pr = [r['wall'] / natr[r['rep']] for r in rs if r['rep'] in natr]
            paired = f'{statistics.median(pr):6.2f}x' if pr else '      -'
            cs = best['perf'].get('context-switches', 0)
            print(f'{w:6} {m:22} {len(rs):2} {min(walls):9.3f} {statistics.median(walls):9.3f} {ratio} {paired} '
                  f'{best["cpu"]:8.3f} {best["cpu"] / best["wall"]:8.2f} {cs:8.0f}')
    for (w, m), rs in results.items():
        for r in rs:
            if r['stats'] and r is min(rs, key=lambda r: r['wall']):
                print(f'\n{w} {m}: counters of the fastest run')
                summarize(r['stats'], r['wall'])


SYSNAMES = {0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat', 5: 'fstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
            10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction', 14: 'rt_sigprocmask', 16: 'ioctl',
            17: 'pread64', 20: 'writev', 21: 'access', 22: 'pipe', 24: 'sched_yield', 25: 'mremap', 28: 'madvise',
            32: 'dup', 33: 'dup2', 39: 'getpid', 41: 'socket', 56: 'clone', 57: 'fork', 59: 'execve', 60: 'exit',
            61: 'wait4', 62: 'kill', 63: 'uname', 72: 'fcntl', 79: 'getcwd', 80: 'chdir', 83: 'mkdir', 87: 'unlink',
            89: 'readlink', 96: 'gettimeofday', 102: 'getuid', 110: 'getppid', 131: 'sigaltstack', 157: 'prctl',
            158: 'arch_prctl', 186: 'gettid', 202: 'futex', 204: 'sched_getaffinity', 217: 'getdents64',
            218: 'set_tid_address', 228: 'clock_gettime', 230: 'clock_nanosleep', 231: 'exit_group', 257: 'openat',
            262: 'newfstatat', 263: 'unlinkat', 273: 'set_robust_list', 293: 'pipe2', 302: 'prlimit64',
            318: 'getrandom', 332: 'statx', 334: 'rseq', 435: 'clone3', 439: 'faccessat2'}


def summarize(st, wall):
    k = st['k']
    g = lambda n, f='us': k.get(n, {}).get(f, 0)
    wall_us = st.get('top', {}).get('wall_us', wall * 1e6)
    # The idler's ppoll is inside its hold when it sleeps holding the token (the shipped runtime),
    # outside it when it doesn't: clamp.
    hk = max(0.0, g('held_kernel') - g('kernel_ppoll'))
    held = g('held_program') + hk
    print(f'  token held by program threads {g("held_program") / 1e3:.1f} ms, by the idler awake {hk / 1e3:.1f} ms: '
          f'{100 * held / wall_us:.1f}% of wall; waits for it {g("wait_token", "n"):.0f}, {g("wait_token") / 1e3:.1f} ms')
    print(f'  of the held time, hand-off latency (assigned to a sleeping thread, not yet running): '
          f'{g("handoff", "n"):.0f} hand-offs, {g("handoff") / 1e3:.1f} ms; host forks {g("fork", "n"):.0f} in {g("fork") / 1e3:.1f} ms')
    print(f'  acquires: free {g("acq_free", "n"):.0f}, contended {g("acq_contended", "n"):.0f} '
          f'(from the idler {g("acq_from_kernel", "n"):.0f}; {g("acq_contended") / 1e3:.1f} ms waited), '
          f'hand-offs {g("poke", "n"):.0f}')
    print(f'  inside LKL: {g("lkl", "n"):.0f} calls, {g("lkl") / 1e3:.1f} ms (incl. blocking); '
          f'context switches {g("switch", "n"):.0f}')
    print(f'  arena: zeroed {g("zero", "bytes") / 2**20:.0f} MiB in {g("zero") / 1e3:.1f} ms; '
          f'file maps copied {g("file_copy", "bytes") / 2**20:.0f} MiB in {g("file_copy") / 1e3:.1f} ms; '
          f'mremap copied {g("mremap_copy", "bytes") / 2**20:.0f} MiB in {g("mremap_copy") / 1e3:.1f} ms; '
          f'exec loads {g("exec", "n"):.0f} in {g("exec") / 1e3:.1f} ms')
    tot = sum(v['n'] for v in st['sys'].values())
    print(f'  trapped syscalls: {tot:.0f} ({tot / (wall_us / 1e6):.0f}/s). Top by time in the dispatcher:')
    for nr, v in sorted(st['sys'].items(), key=lambda x: -x[1]['us'])[:12]:
        print(f'    {SYSNAMES.get(nr, nr)!s:18} n={v["n"]:8.0f}  {v["us"] / 1e3:9.1f} ms  '
              f'({v["us"] / v["n"]:7.2f} us/call; token wait {v.get("token_wait_us", 0) / 1e3:.1f} ms)')


if __name__ == '__main__':
    main()
