//! What each x86-64 syscall number gets: the table the SIGSYS handler dispatches on.
//!
//! LKL is built with the asm-generic table (`include/uapi/asm-generic/unistd.h`), not x86-64's:
//! the numbers differ, the x86-only calls (`open`, `stat`, `pipe`, `poll`, `fork`, ...) don't
//! exist there, and a few structs differ (`xabi`). So every number gets one `Route`: LKL's call
//! of the same name, a rewrite into another LKL call, the runtime's own emulation, or a refusal.
//! The classification is capnix tier A's audit (`docs/syscalls.md` there: every number called
//! once in a sandbox), with one change of design: signals are the guest kernel's in every mode
//! (the kernel series' item 8), so `kill`, the `rt_sig*` calls, `sigaltstack`, `pause`, the
//! sleeps, `alarm` and the itimers, and `getpid`/`gettid`/`getppid`, are LKL's everywhere.
//!
//! The table is checked mechanically (the tests): every name against the kernel's x86-64 `.tbl`,
//! every LKL number against the generic header by name, every class against the suite's
//! `sysaudit` lists. At compile time: every x86-64 number has exactly one route.

/// Numbers below this have a route; the rest (including the x32 numbers, bit 30 set) are ENOSYS.
pub const NR: usize = 470;

/// What a number gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// LKL's call of the same name and arguments, by its generic number.
    Lkl(u16),
    /// An x86-only call (or one whose struct differs) made through another LKL call.
    Rewrite(Rewrite),
    /// The runtime's own: memory, threads, exec, the thread pointer.
    Emulate(Emulate),
    /// Refused without a call.
    Errno(Errno),
}

/// A refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    /// `EPERM`: administration of a machine, refused as to an unprivileged user.
    Perm,
    /// `ENOSYS`: not in the guest kernel, not emulated yet, or not in Linux either.
    Nosys,
}

impl Errno {
    /// The negative errno a syscall returns.
    pub const fn ret(self) -> isize {
        match self {
            Errno::Perm => -1,
            Errno::Nosys => -38,
        }
    }
}

/// The three outcomes `docs/syscalls.md` (and the suite's `sysaudit` case) classify by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Served,
    Eperm,
    Enosys,
}

impl Route {
    pub const fn class(self) -> Class {
        match self {
            Route::Errno(Errno::Perm) => Class::Eperm,
            Route::Errno(Errno::Nosys) => Class::Enosys,
            _ => Class::Served,
        }
    }
}

/// An argument of a pure rewrite: the program's argument `X(i)` or a constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arg {
    X(u8),
    K(i32),
}

/// A rewrite that only reorders arguments and adds constants: LKL's call `lkl` with `args`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Args {
    pub lkl: u16,
    pub args: [Arg; 6],
}

impl Args {
    /// LKL's six arguments from the program's six (constants sign-extended, as the kernel reads
    /// an `int` such as `AT_FDCWD` from a register).
    pub const fn apply(&self, a: &[usize; 6]) -> [usize; 6] {
        let mut out = [0; 6];
        let mut i = 0;
        while i < 6 {
            out[i] = match self.args[i] {
                Arg::X(j) => a[j as usize],
                Arg::K(k) => k as isize as usize,
            };
            i += 1;
        }
        out
    }
}

/// How `stat` and friends reach LKL's `newfstatat`/`fstat`; the result, a generic `struct stat`
/// in the runtime's memory, goes to the program's buffer as x86-64's (`xabi::stat_to_x86`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatForm {
    /// `stat(path, buf)` → `newfstatat(AT_FDCWD, path, &tmp, 0)`.
    Path,
    /// `lstat(path, buf)` → `newfstatat(AT_FDCWD, path, &tmp, AT_SYMLINK_NOFOLLOW)`.
    Lpath,
    /// `fstat(fd, buf)` → `fstat(fd, &tmp)`.
    Fd,
    /// `newfstatat(dfd, path, buf, flags)` → `newfstatat(dfd, path, &tmp, flags)`.
    At,
}

/// The rewrites that need more than `Args`. Each says what the dispatcher calls (generic numbers
/// in `lkl`) and what it does around the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rewrite {
    /// Arguments reordered, constants added (`open` → `openat(AT_FDCWD, ...)` and the like).
    Args(&'static Args),
    /// See `StatForm`.
    Stat(StatForm),
    /// `poll(fds, n, ms)` → `ppoll(fds, n, ts, NULL, 8)`, `ts` from `xabi::poll_timeout` (NULL
    /// when `ms < 0`). Unlike poll, a ppoll interrupted by a handled signal isn't restarted with
    /// the time left (`EINTR` either way when a handler ran, which is what programs see).
    Poll,
    /// `select(n, r, w, e, tv)` → `pselect6(n, r, w, e, ts, NULL)`, `ts` from
    /// `xabi::select_timeout` (NULL tv: NULL ts); afterwards the time left is written back to
    /// `tv` (`xabi::select_remaining`), as Linux's select does and programs rely on.
    Select,
    /// `dup2(old, new)`: when `old == new`, check `old` is open (`fcntl(old, F_GETFD)`, its error
    /// returned, `EBADF`) and return `new` without a call, since `dup3` refuses equal fds with
    /// `EINVAL`; otherwise `dup3(old, new, 0)`.
    Dup2,
    /// `epoll_create(size)`: `EINVAL` if `size <= 0` (as an `int`), as Linux checks; otherwise
    /// `epoll_create1(0)`.
    EpollCreate,
    /// `time(t)`: `clock_gettime(CLOCK_REALTIME, &ts)`, `ts.tv_sec` stored to `t` if non-NULL and
    /// returned. (Glibc's comes from the vDSO; this is for direct callers.)
    Time,
    /// `utime(path, ub)` → `utimensat(AT_FDCWD, path, ts, 0)`, `ts` from
    /// `xabi::utimbuf_to_timespecs` (NULL ub: NULL, now).
    Utime,
    /// `utimes(path, tv)` → `utimensat(AT_FDCWD, path, ts, 0)`, `ts` from
    /// `xabi::utimes_to_timespecs` (`EINVAL` if it refuses; NULL tv: NULL).
    Utimes,
    /// `futimesat(dfd, path, tv)` → `utimensat(dfd, path, ts, 0)`, as `Utimes`.
    Futimesat,
    /// `alarm(secs)` → `setitimer(ITIMER_REAL, {0, {secs as u32, 0}}, &old)`, returning
    /// `xabi::alarm_remaining(&old)`. (LKL's alarm would be the same; the generic table has
    /// none.)
    Alarm,
    /// `pause()` → `ppoll(NULL, 0, NULL, NULL, 0)`: sleeps until a signal, then `EINTR`
    /// (`ERESTARTNOHAND` inside, as pause's).
    Pause,
    /// `uname(buf)` → `uname(buf)`, then `machine` is `"x86_64"` (`xabi::uts_set_machine`): LKL
    /// says `"lkl"`, and programs choose code and downloads by it.
    Uname,
    /// `rt_sigaction(sig, act, old, size)` → LKL's with `xabi::LklSigaction`s (no `sa_restorer`
    /// there); the runtime keeps each signal's restorer for delivery and for `old`
    /// (`xabi::sigaction_to_lkl`, `xabi::sigaction_to_x86`).
    SigAction,
    /// `statx(dfd, path, flags, mask, buf)` → LKL's, with `&tmp` for `buf` (copied out after, or
    /// `EFAULT`), once `path` is checked to be the program's string (`EFAULT`; NULL only in the
    /// form the kernel takes without reading it: an fd, `AT_EMPTY_PATH`). LKL reads a bad pointer
    /// with no MMU to fault in, so the program's NULL was the sandbox's SIGSEGV, and Rust's std
    /// probes statx with `statx(0, NULL, 0, STATX_ALL, NULL)` expecting `EFAULT` (cargo, at its
    /// first missing config file).
    Statx,
    /// `fork()`, `vfork()`: the runtime's `clone` (`Emulate::Clone`) with `(SIGCHLD, 0, 0, 0, 0)`.
    /// vfork is a fork: its child can't share the parent's memory across host processes, and
    /// POSIX allows it (the parent just doesn't wait for the exec).
    Fork,
}

/// The runtime's own calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emulate {
    // Memory: the program's memory is the host's arena, not the kernel's (no host mmap after
    // lockdown).
    Mmap,
    Munmap,
    Mremap,
    Mprotect,
    Madvise,
    Msync,
    Brk,
    /// `mincore`: every arena page resident.
    Mincore,
    /// Returns 0: `mlock`, `munlock`, `mlockall`, `munlockall`, `mlock2` (the arena is never
    /// swapped) and `fadvise64` (advice; the guest kernel has no `ADVISE_SYSCALLS`).
    NoOp,
    // Threads: each program thread is a host thread (or coroutine) the runtime made.
    Clone,
    Exit,
    ExitGroup,
    SetRobustList,
    SetTidAddress,
    Futex,
    SchedYield,
    /// One CPU (or the pool's).
    SchedGetaffinity,
    /// 0: any set is the one CPU.
    SchedSetaffinity,
    /// CPU 0, node 0.
    Getcpu,
    /// The thread pointer (FS) is the program's, kept by the runtime per thread.
    ArchPrctl,
    // Exec maps the image in the arena; its kernel half (fds, handlers, name) is one operation.
    Execve,
    Execveat,
    /// Returning from a handler the runtime ran on the program's stack (kernel series item 8).
    SigReturn,
    /// Options about the thread's memory or CPU (`PR_SET_VMA`, `PR_SET_MM`, `PR_SET_TSC`, ...)
    /// are the runtime's; the rest go to LKL's `prctl` (`lkl::PRCTL`).
    Prctl,
}

/// Generic (LKL) numbers the rewrites call, checked by name against the header in the tests.
pub mod lkl {
    pub const DUP3: u16 = 24;
    pub const EPOLL_CREATE1: u16 = 20;
    pub const EPOLL_PWAIT: u16 = 22;
    pub const EVENTFD2: u16 = 19;
    pub const FACCESSAT: u16 = 48;
    pub const FCHMODAT: u16 = 53;
    pub const FCHOWNAT: u16 = 54;
    pub const FCNTL: u16 = 25;
    pub const FSTAT: u16 = 80;
    pub const GETPGID: u16 = 155;
    pub const LINKAT: u16 = 37;
    pub const MKDIRAT: u16 = 34;
    pub const MKNODAT: u16 = 33;
    pub const NEWFSTATAT: u16 = 79;
    pub const OPENAT: u16 = 56;
    pub const PIPE2: u16 = 59;
    pub const PPOLL: u16 = 73;
    pub const PRCTL: u16 = 167;
    pub const PSELECT6: u16 = 72;
    pub const READLINKAT: u16 = 78;
    pub const RENAMEAT: u16 = 38;
    pub const RT_SIGACTION: u16 = 134;
    pub const SETITIMER: u16 = 103;
    pub const SYMLINKAT: u16 = 36;
    pub const UNAME: u16 = 160;
    pub const UNLINKAT: u16 = 35;
    pub const UTIMENSAT: u16 = 88;
    pub const CLOCK_GETTIME: u16 = 113;
    pub const STATX: u16 = 291;
}

/// Constants the rewrites pass (the same values on x86-64 and asm-generic).
pub mod k {
    pub const AT_FDCWD: i32 = -100;
    pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    pub const AT_REMOVEDIR: i32 = 0x200;
    pub const AT_EMPTY_PATH: i32 = 0x1000;
    pub const AT_NO_AUTOMOUNT: i32 = 0x800;
    pub const AT_STATX_SYNC_TYPE: i32 = 0x6000;
    /// `creat`'s flags: `O_CREAT | O_WRONLY | O_TRUNC`.
    pub const CREAT_FLAGS: i32 = 0o100 | 0o1 | 0o1000;
    pub const SIGCHLD: i32 = 17;
    pub const F_GETFD: i32 = 1;
    pub const CLOCK_REALTIME: i32 = 0;
    pub const ITIMER_REAL: i32 = 0;
    /// The kernel's sigset size (64 signals).
    pub const SIGSETSIZE: i32 = 8;
}

use Arg::{K, X};
const AT: Arg = K(k::AT_FDCWD);
const Z: Arg = K(0);

const fn a(lkl: u16, args: [Arg; 6]) -> Args {
    Args { lkl, args }
}
// The x86-only path calls are their *at forms from the current directory.
const OPEN: Args = a(lkl::OPENAT, [AT, X(0), X(1), X(2), Z, Z]);
const CREAT: Args = a(lkl::OPENAT, [AT, X(0), K(k::CREAT_FLAGS), X(1), Z, Z]);
const ACCESS: Args = a(lkl::FACCESSAT, [AT, X(0), X(1), Z, Z, Z]);
const MKDIR: Args = a(lkl::MKDIRAT, [AT, X(0), X(1), Z, Z, Z]);
const RMDIR: Args = a(lkl::UNLINKAT, [AT, X(0), K(k::AT_REMOVEDIR), Z, Z, Z]);
const UNLINK: Args = a(lkl::UNLINKAT, [AT, X(0), Z, Z, Z, Z]);
const RENAME: Args = a(lkl::RENAMEAT, [AT, X(0), AT, X(1), Z, Z]);
const LINK: Args = a(lkl::LINKAT, [AT, X(0), AT, X(1), Z, Z]);
const SYMLINK: Args = a(lkl::SYMLINKAT, [X(0), AT, X(1), Z, Z, Z]);
const READLINK: Args = a(lkl::READLINKAT, [AT, X(0), X(1), X(2), Z, Z]);
const CHMOD: Args = a(lkl::FCHMODAT, [AT, X(0), X(1), Z, Z, Z]);
const CHOWN: Args = a(lkl::FCHOWNAT, [AT, X(0), X(1), X(2), Z, Z]);
const LCHOWN: Args = a(lkl::FCHOWNAT, [AT, X(0), X(1), X(2), K(k::AT_SYMLINK_NOFOLLOW), Z]);
const MKNOD: Args = a(lkl::MKNODAT, [AT, X(0), X(1), X(2), Z, Z]);
// The flagless forms are the flagged ones with no flags.
const PIPE: Args = a(lkl::PIPE2, [X(0), Z, Z, Z, Z, Z]);
const EVENTFD: Args = a(lkl::EVENTFD2, [X(0), Z, Z, Z, Z, Z]);
const EPOLL_WAIT: Args = a(lkl::EPOLL_PWAIT, [X(0), X(1), X(2), X(3), Z, K(k::SIGSETSIZE)]);
const GETPGRP: Args = a(lkl::GETPGID, [Z, Z, Z, Z, Z, Z]);

macro_rules! table {
    ($($nr:literal $name:ident $route:expr;)*) => {
        /// Every assigned route and its x86-64 name; `assert!` makes a number assigned twice a
        /// compile error.
        #[allow(clippy::large_const_arrays)]
        const BUILT: ([Option<Route>; NR], [&str; NR]) = {
            let mut t: [Option<Route>; NR] = [None; NR];
            let mut n: [&str; NR] = [""; NR];
            $(
                assert!(t[$nr].is_none(), concat!("two routes for ", stringify!($name)));
                t[$nr] = Some($route);
                n[$nr] = stringify!($name);
            )*
            (t, n)
        };
    };
}

use Emulate as E;
use Errno::{Nosys, Perm};
use Rewrite as R;
use Route::{Emulate as Em, Errno as Er, Lkl, Rewrite as Rw};

table! {
    // ---- LKL, by name: the same call and arguments, LKL's number ---------------------------
    0 read Lkl(63);
    1 write Lkl(64);
    3 close Lkl(57);
    8 lseek Lkl(62);
    14 rt_sigprocmask Lkl(135);
    16 ioctl Lkl(29);
    17 pread64 Lkl(67);
    18 pwrite64 Lkl(68);
    19 readv Lkl(65);
    20 writev Lkl(66);
    32 dup Lkl(23);
    35 nanosleep Lkl(101);
    36 getitimer Lkl(102);
    38 setitimer Lkl(103);
    39 getpid Lkl(172);
    40 sendfile Lkl(71);
    41 socket Lkl(198);
    42 connect Lkl(203);
    43 accept Lkl(202);
    44 sendto Lkl(206);
    45 recvfrom Lkl(207);
    46 sendmsg Lkl(211);
    47 recvmsg Lkl(212);
    48 shutdown Lkl(210);
    49 bind Lkl(200);
    50 listen Lkl(201);
    51 getsockname Lkl(204);
    52 getpeername Lkl(205);
    53 socketpair Lkl(199);
    54 setsockopt Lkl(208);
    55 getsockopt Lkl(209);
    61 wait4 Lkl(260);
    62 kill Lkl(129);
    72 fcntl Lkl(25);
    73 flock Lkl(32);
    74 fsync Lkl(82);
    75 fdatasync Lkl(83);
    76 truncate Lkl(45);
    77 ftruncate Lkl(46);
    79 getcwd Lkl(17);
    80 chdir Lkl(49);
    81 fchdir Lkl(50);
    91 fchmod Lkl(52);
    93 fchown Lkl(55);
    95 umask Lkl(166);
    // (capnix made it from clock_gettime; LKL's is the same call with the same 64-bit timeval.)
    96 gettimeofday Lkl(169);
    97 getrlimit Lkl(163);
    98 getrusage Lkl(165);
    // (MemTotal is the program's arena: the kernel series' item 13.)
    99 sysinfo Lkl(179);
    100 times Lkl(153);
    102 getuid Lkl(174);
    104 getgid Lkl(176);
    105 setuid Lkl(146);
    106 setgid Lkl(144);
    107 geteuid Lkl(175);
    108 getegid Lkl(177);
    109 setpgid Lkl(154);
    110 getppid Lkl(173);
    112 setsid Lkl(157);
    113 setreuid Lkl(145);
    114 setregid Lkl(143);
    115 getgroups Lkl(158);
    116 setgroups Lkl(159);
    117 setresuid Lkl(147);
    118 getresuid Lkl(148);
    119 setresgid Lkl(149);
    120 getresgid Lkl(150);
    121 getpgid Lkl(155);
    122 setfsuid Lkl(151);
    123 setfsgid Lkl(152);
    124 getsid Lkl(156);
    125 capget Lkl(90);
    126 capset Lkl(91);
    127 rt_sigpending Lkl(136);
    128 rt_sigtimedwait Lkl(137);
    129 rt_sigqueueinfo Lkl(138);
    130 rt_sigsuspend Lkl(133);
    131 sigaltstack Lkl(132);
    135 personality Lkl(92);
    137 statfs Lkl(43);
    138 fstatfs Lkl(44);
    140 getpriority Lkl(141);
    141 setpriority Lkl(140);
    142 sched_setparam Lkl(118);
    143 sched_getparam Lkl(121);
    144 sched_setscheduler Lkl(119);
    145 sched_getscheduler Lkl(120);
    146 sched_get_priority_max Lkl(125);
    147 sched_get_priority_min Lkl(126);
    148 sched_rr_get_interval Lkl(127);
    160 setrlimit Lkl(164);
    162 sync Lkl(81);
    // The mount family is the guest kernel's: it isn't the sandbox's boundary (the host filter
    // is), and the setup closure run before exec (`exobox::Guest::run`) and in-guest inits
    // (capnix's) mount with plain syscalls.
    155 pivot_root Lkl(41);
    161 chroot Lkl(51);
    165 mount Lkl(40);
    166 umount2 Lkl(39);
    186 gettid Lkl(178);
    187 readahead Lkl(213);
    188 setxattr Lkl(5);
    189 lsetxattr Lkl(6);
    190 fsetxattr Lkl(7);
    191 getxattr Lkl(8);
    192 lgetxattr Lkl(9);
    193 fgetxattr Lkl(10);
    194 listxattr Lkl(11);
    195 llistxattr Lkl(12);
    196 flistxattr Lkl(13);
    197 removexattr Lkl(14);
    198 lremovexattr Lkl(15);
    199 fremovexattr Lkl(16);
    200 tkill Lkl(130);
    217 getdents64 Lkl(61);
    219 restart_syscall Lkl(128);
    222 timer_create Lkl(107);
    223 timer_settime Lkl(110);
    224 timer_gettime Lkl(108);
    225 timer_getoverrun Lkl(109);
    226 timer_delete Lkl(111);
    228 clock_gettime Lkl(113);
    229 clock_getres Lkl(114);
    230 clock_nanosleep Lkl(115);
    233 epoll_ctl Lkl(21);
    234 tgkill Lkl(131);
    247 waitid Lkl(95);
    257 openat Lkl(56);
    258 mkdirat Lkl(34);
    259 mknodat Lkl(33);
    260 fchownat Lkl(54);
    263 unlinkat Lkl(35);
    264 renameat Lkl(38);
    265 linkat Lkl(37);
    266 symlinkat Lkl(36);
    267 readlinkat Lkl(78);
    268 fchmodat Lkl(53);
    269 faccessat Lkl(48);
    270 pselect6 Lkl(72);
    271 ppoll Lkl(73);
    275 splice Lkl(76);
    276 tee Lkl(77);
    277 sync_file_range Lkl(84);
    278 vmsplice Lkl(75);
    280 utimensat Lkl(88);
    281 epoll_pwait Lkl(22);
    285 fallocate Lkl(47);
    288 accept4 Lkl(242);
    290 eventfd2 Lkl(19);
    291 epoll_create1 Lkl(20);
    292 dup3 Lkl(24);
    293 pipe2 Lkl(59);
    295 preadv Lkl(69);
    296 pwritev Lkl(70);
    297 rt_tgsigqueueinfo Lkl(240);
    299 recvmmsg Lkl(243);
    302 prlimit64 Lkl(261);
    306 syncfs Lkl(267);
    307 sendmmsg Lkl(269);
    314 sched_setattr Lkl(274);
    315 sched_getattr Lkl(275);
    316 renameat2 Lkl(276);
    318 getrandom Lkl(278);
    326 copy_file_range Lkl(285);
    327 preadv2 Lkl(286);
    328 pwritev2 Lkl(287);
    424 pidfd_send_signal Lkl(424);
    434 pidfd_open Lkl(434);
    436 close_range Lkl(436);
    437 openat2 Lkl(437);
    439 faccessat2 Lkl(439);
    441 epoll_pwait2 Lkl(441);
    452 fchmodat2 Lkl(452);

    // ---- LKL, rewritten: x86-only forms, or a struct that differs (xabi) --------------------
    2 open Rw(R::Args(&OPEN));
    4 stat Rw(R::Stat(StatForm::Path));
    5 fstat Rw(R::Stat(StatForm::Fd));
    6 lstat Rw(R::Stat(StatForm::Lpath));
    7 poll Rw(R::Poll);
    13 rt_sigaction Rw(R::SigAction);
    21 access Rw(R::Args(&ACCESS));
    22 pipe Rw(R::Args(&PIPE));
    23 select Rw(R::Select);
    33 dup2 Rw(R::Dup2);
    34 pause Rw(R::Pause);
    37 alarm Rw(R::Alarm);
    57 fork Rw(R::Fork);
    58 vfork Rw(R::Fork);
    63 uname Rw(R::Uname);
    82 rename Rw(R::Args(&RENAME));
    83 mkdir Rw(R::Args(&MKDIR));
    84 rmdir Rw(R::Args(&RMDIR));
    85 creat Rw(R::Args(&CREAT));
    86 link Rw(R::Args(&LINK));
    87 unlink Rw(R::Args(&UNLINK));
    88 symlink Rw(R::Args(&SYMLINK));
    89 readlink Rw(R::Args(&READLINK));
    90 chmod Rw(R::Args(&CHMOD));
    92 chown Rw(R::Args(&CHOWN));
    94 lchown Rw(R::Args(&LCHOWN));
    111 getpgrp Rw(R::Args(&GETPGRP));
    132 utime Rw(R::Utime);
    133 mknod Rw(R::Args(&MKNOD));
    201 time Rw(R::Time);
    213 epoll_create Rw(R::EpollCreate);
    232 epoll_wait Rw(R::Args(&EPOLL_WAIT));
    235 utimes Rw(R::Utimes);
    261 futimesat Rw(R::Futimesat);
    262 newfstatat Rw(R::Stat(StatForm::At));
    332 statx Rw(R::Statx);
    284 eventfd Rw(R::Args(&EVENTFD));

    // ---- Emulated in the runtime -----------------------------------------------------------
    9 mmap Em(E::Mmap);
    10 mprotect Em(E::Mprotect);
    11 munmap Em(E::Munmap);
    12 brk Em(E::Brk);
    15 rt_sigreturn Em(E::SigReturn);
    24 sched_yield Em(E::SchedYield);
    25 mremap Em(E::Mremap);
    26 msync Em(E::Msync);
    27 mincore Em(E::Mincore);
    28 madvise Em(E::Madvise);
    56 clone Em(E::Clone);
    59 execve Em(E::Execve);
    60 exit Em(E::Exit);
    149 mlock Em(E::NoOp);
    150 munlock Em(E::NoOp);
    151 mlockall Em(E::NoOp);
    152 munlockall Em(E::NoOp);
    157 prctl Em(E::Prctl);
    158 arch_prctl Em(E::ArchPrctl);
    202 futex Em(E::Futex);
    203 sched_setaffinity Em(E::SchedSetaffinity);
    204 sched_getaffinity Em(E::SchedGetaffinity);
    218 set_tid_address Em(E::SetTidAddress);
    221 fadvise64 Em(E::NoOp);
    231 exit_group Em(E::ExitGroup);
    273 set_robust_list Em(E::SetRobustList);
    309 getcpu Em(E::Getcpu);
    322 execveat Em(E::Execveat);
    325 mlock2 Em(E::NoOp);

    // ---- EPERM: administration of a machine, which the guest kernel is not. Programs treat
    // EPERM here as "not allowed", which is what it is. -------------------------------------
    103 syslog Er(Perm);
    153 vhangup Er(Perm);
    159 adjtimex Er(Perm);
    163 acct Er(Perm);
    164 settimeofday Er(Perm);
    167 swapon Er(Perm);
    168 swapoff Er(Perm);
    // (Not in the audit, which skips it; the same reason as the rest. capnix gave ENOSYS.)
    169 reboot Er(Perm);
    170 sethostname Er(Perm);
    171 setdomainname Er(Perm);
    172 iopl Er(Perm);
    173 ioperm Er(Perm);
    175 init_module Er(Perm);
    176 delete_module Er(Perm);
    179 quotactl Er(Perm);
    227 clock_settime Er(Perm);
    246 kexec_load Er(Perm);
    272 unshare Er(Perm);
    305 clock_adjtime Er(Perm);
    308 setns Er(Perm);
    313 finit_module Er(Perm);
    320 kexec_file_load Er(Perm);
    443 quotactl_fd Er(Perm);

    // ---- ENOSYS: not in the guest kernel (the defconfig leaves it out for size; turning one on
    // is a config line plus a route here) ----------------------------------------------------
    29 shmget Er(Nosys); // SYSVIPC
    30 shmat Er(Nosys);
    31 shmctl Er(Nosys);
    64 semget Er(Nosys);
    65 semop Er(Nosys);
    66 semctl Er(Nosys);
    67 shmdt Er(Nosys);
    68 msgget Er(Nosys);
    69 msgsnd Er(Nosys);
    70 msgrcv Er(Nosys);
    71 msgctl Er(Nosys);
    220 semtimedop Er(Nosys);
    240 mq_open Er(Nosys); // POSIX_MQUEUE
    241 mq_unlink Er(Nosys);
    242 mq_timedsend Er(Nosys);
    243 mq_timedreceive Er(Nosys);
    244 mq_notify Er(Nosys);
    245 mq_getsetattr Er(Nosys);
    206 io_setup Er(Nosys); // AIO
    207 io_destroy Er(Nosys);
    208 io_getevents Er(Nosys);
    209 io_submit Er(Nosys);
    210 io_cancel Er(Nosys);
    333 io_pgetevents Er(Nosys);
    425 io_uring_setup Er(Nosys); // IO_URING
    426 io_uring_enter Er(Nosys);
    427 io_uring_register Er(Nosys);
    253 inotify_init Er(Nosys); // INOTIFY_USER
    254 inotify_add_watch Er(Nosys);
    255 inotify_rm_watch Er(Nosys);
    294 inotify_init1 Er(Nosys);
    300 fanotify_init Er(Nosys); // FANOTIFY
    301 fanotify_mark Er(Nosys);
    282 signalfd Er(Nosys); // SIGNALFD
    289 signalfd4 Er(Nosys);
    283 timerfd_create Er(Nosys); // TIMERFD
    286 timerfd_settime Er(Nosys);
    287 timerfd_gettime Er(Nosys);
    319 memfd_create Er(Nosys); // MEMFD_CREATE
    303 name_to_handle_at Er(Nosys); // FHANDLE
    304 open_by_handle_at Er(Nosys);
    // (capnix's kernel had no block layer. exobox's has one, for erofs (kernel series item 12),
    // so LKL could serve these; kept ENOSYS with the spec and the suite until they move.)
    251 ioprio_set Er(Nosys);
    252 ioprio_get Er(Nosys);
    248 add_key Er(Nosys); // KEYS
    249 request_key Er(Nosys);
    250 keyctl Er(Nosys);
    321 bpf Er(Nosys);
    298 perf_event_open Er(Nosys);
    323 userfaultfd Er(Nosys);
    444 landlock_create_ruleset Er(Nosys);
    445 landlock_add_rule Er(Nosys);
    446 landlock_restrict_self Er(Nosys);
    459 lsm_get_self_attr Er(Nosys);
    460 lsm_set_self_attr Er(Nosys);
    461 lsm_list_modules Er(Nosys);
    451 cachestat Er(Nosys);
    // (Not in the audit. LKL has a ptrace, but its register requests are lkl's, not x86-64's,
    // and a tracee is a host thread it can't stop: refused, as capnix did.)
    101 ptrace Er(Nosys);
    // (Not in the audit. The sandbox's filter is the host's; a guest filter would need
    // SECCOMP_FILTER in the guest and to be checked by the runtime. Programs fall back on
    // ENOSYS (as capnix gave).)
    317 seccomp Er(Nosys);

    // ---- ENOSYS: the runtime's to emulate, not done yet --------------------------------------
    324 membarrier Er(Nosys); // runtimes fall back
    334 rseq Er(Nosys); // glibc falls back
    274 get_robust_list Er(Nosys);
    449 futex_waitv Er(Nosys); // the futex2 calls; glibc uses futex
    454 futex_wake Er(Nosys);
    455 futex_wait Er(Nosys);
    456 futex_requeue Er(Nosys);
    447 memfd_secret Er(Nosys);
    329 pkey_mprotect Er(Nosys);
    330 pkey_alloc Er(Nosys);
    331 pkey_free Er(Nosys);
    453 map_shadow_stack Er(Nosys);
    462 mseal Er(Nosys);
    // clone3's struct is in memory, where the filter can't check its flags: glibc falls back to
    // clone, whose flags are a register.
    435 clone3 Er(Nosys);

    // ---- ENOSYS: another process's memory (fork mode's processes are separate host processes)
    310 process_vm_readv Er(Nosys);
    311 process_vm_writev Er(Nosys);
    440 process_madvise Er(Nosys);
    448 process_mrelease Er(Nosys);
    438 pidfd_getfd Er(Nosys);
    312 kcmp Er(Nosys);
    216 remap_file_pages Er(Nosys);

    // ---- ENOSYS: NUMA ------------------------------------------------------------------------
    237 mbind Er(Nosys);
    238 set_mempolicy Er(Nosys);
    239 get_mempolicy Er(Nosys);
    256 migrate_pages Er(Nosys);
    279 move_pages Er(Nosys);
    450 set_mempolicy_home_node Er(Nosys);

    // ---- ENOSYS: newer than the kernel (6.12) ------------------------------------------------
    463 setxattrat Er(Nosys);
    464 getxattrat Er(Nosys);
    465 listxattrat Er(Nosys);
    466 removexattrat Er(Nosys);
    467 open_tree_attr Er(Nosys);
    468 file_getattr Er(Nosys);
    469 file_setattr Er(Nosys);

    // ---- ENOSYS: the new mount API ------------------------------------------------------------
    428 open_tree Er(Nosys);
    429 move_mount Er(Nosys);
    430 fsopen Er(Nosys);
    431 fsconfig Er(Nosys);
    432 fsmount Er(Nosys);
    433 fspick Er(Nosys);
    442 mount_setattr Er(Nosys);
    457 statmount Er(Nosys);
    458 listmount Er(Nosys);

    // ---- ENOSYS: obsolete or never implemented by Linux (ENOSYS there too) -------------------
    78 getdents Er(Nosys); // glibc uses getdents64
    134 uselib Er(Nosys);
    136 ustat Er(Nosys);
    139 sysfs Er(Nosys);
    156 _sysctl Er(Nosys);
    174 create_module Er(Nosys);
    177 get_kernel_syms Er(Nosys);
    178 query_module Er(Nosys);
    180 nfsservctl Er(Nosys);
    181 getpmsg Er(Nosys);
    182 putpmsg Er(Nosys);
    183 afs_syscall Er(Nosys);
    184 tuxcall Er(Nosys);
    185 security Er(Nosys);
    236 vserver Er(Nosys);
    212 lookup_dcookie Er(Nosys);
    214 epoll_ctl_old Er(Nosys);
    215 epoll_wait_old Er(Nosys);
    // (Not in the audit: x86-64's uprobe return trampoline, meaningful only from the kernel's
    // own trampoline page, which the guest has none of.)
    335 uretprobe Er(Nosys);

    // ---- ENOSYS: x86 segment and TLS descriptors (the runtime owns FS: arch_prctl) -----------
    154 modify_ldt Er(Nosys);
    205 set_thread_area Er(Nosys);
    211 get_thread_area Er(Nosys);
}

/// The first and last numbers with no x86-64 call (between `uretprobe` and `pidfd_send_signal`,
/// where the 32-bit-only time64 calls are on other arches).
const HOLE: core::ops::RangeInclusive<usize> = 336..=423;

/// The route for each number below `NR`; holes are ENOSYS, as Linux's are.
static TABLE: [Route; NR] = {
    let built = BUILT.0;
    let mut r = [Route::Errno(Errno::Nosys); NR];
    let mut i = 0;
    while i < NR {
        match built[i] {
            Some(x) => r[i] = x,
            None => assert!(*HOLE.start() <= i && i <= *HOLE.end(), "an x86-64 number without a route"),
        }
        i += 1;
    }
    r
};

/// What x86-64 syscall `nr` gets. Anything at or past `NR` (unassigned, or x32's numbers with
/// bit 30 set, which a 64-bit program doesn't make) is ENOSYS.
#[inline]
pub fn route(nr: usize) -> Route {
    match TABLE.get(nr) {
        Some(&r) => r,
        None => Route::Errno(Errno::Nosys),
    }
}

/// The x86-64 name of `nr` (for diagnostics), if it has one.
pub fn name(nr: usize) -> Option<&'static str> {
    NAMES.get(nr).copied().filter(|n| !n.is_empty())
}

static NAMES: [&str; NR] = BUILT.1;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// The kernel tree the tables are checked against (stock LKL, read-only).
    fn kernel() -> Option<PathBuf> {
        let p = PathBuf::from(std::env::var_os("EXOBOX_LKL_SRC").unwrap_or("/home/ryan/src/lkl-stock".into()));
        if p.join("include/uapi/asm-generic/unistd.h").exists() {
            Some(p)
        } else {
            eprintln!("skipped: no kernel tree at {} (set EXOBOX_LKL_SRC)", p.display());
            None
        }
    }

    /// x86-64's numbers by name, from the `.tbl` (common and 64-bit ABIs; not x32).
    fn x86_table(k: &Path) -> HashMap<usize, String> {
        let t = std::fs::read_to_string(k.join("arch/x86/entry/syscalls/syscall_64.tbl")).unwrap();
        t.lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let f: Vec<_> = l.split_whitespace().collect();
                (f.len() >= 3 && f[1] != "x32").then(|| (f[0].parse().unwrap(), f[2].to_string()))
            })
            .collect()
    }

    /// The generic numbers by name, from the header as LKL (64-bit) sees it: `__NR_x N`, plus
    /// the `__NR3264_x` names under their 64-bit aliases. The header's only conditional numbers
    /// that a 64-bit build lacks are the time64 calls (403-423), which no x86-64 name maps to.
    fn generic_table(k: &Path) -> HashMap<String, u16> {
        let h = std::fs::read_to_string(k.join("include/uapi/asm-generic/unistd.h")).unwrap();
        let mut m = HashMap::new();
        for l in h.lines() {
            let f: Vec<_> = l.split_whitespace().collect();
            if f.len() == 3
                && f[0] == "#define"
                && let Ok(n) = f[2].parse::<u16>()
                && let Some(name) = f[1].strip_prefix("__NR_").or_else(|| f[1].strip_prefix("__NR3264_"))
            {
                m.insert(name.to_string(), n);
            }
        }
        // `#define __NR_newfstatat __NR3264_fstatat` (64-bit): the only alias whose name changes.
        let fstatat = m["fstatat"];
        m.insert("newfstatat".into(), fstatat);
        m
    }

    #[test]
    fn names_are_the_kernels() {
        let Some(k) = kernel() else { return };
        let x86 = x86_table(&k);
        for nr in 0..NR {
            match x86.get(&nr) {
                Some(n) => assert_eq!(name(nr), Some(n.as_str()), "x86-64 {nr}"),
                // Numbers past the 6.12 table: named from newer kernels, all ENOSYS.
                None if nr > 462 => assert_eq!(route(nr), Route::Errno(Errno::Nosys), "{nr}"),
                None => assert_eq!(name(nr), None, "{nr} isn't an x86-64 number"),
            }
        }
    }

    #[test]
    fn lkl_targets_are_the_same_call() {
        let Some(k) = kernel() else { return };
        let g = generic_table(&k);
        let mut n = 0;
        for nr in 0..NR {
            if let Route::Lkl(l) = route(nr) {
                let x = name(nr).unwrap();
                assert_eq!(g.get(x), Some(&l), "x86-64 {x} ({nr}) → generic {l}");
                n += 1;
            }
        }
        assert!(n > 150);
        // The numbers the rewrites call, by name.
        let named = [
            ("dup3", lkl::DUP3),
            ("epoll_create1", lkl::EPOLL_CREATE1),
            ("epoll_pwait", lkl::EPOLL_PWAIT),
            ("eventfd2", lkl::EVENTFD2),
            ("faccessat", lkl::FACCESSAT),
            ("fchmodat", lkl::FCHMODAT),
            ("fchownat", lkl::FCHOWNAT),
            ("fcntl", lkl::FCNTL),
            ("fstat", lkl::FSTAT),
            ("getpgid", lkl::GETPGID),
            ("linkat", lkl::LINKAT),
            ("mkdirat", lkl::MKDIRAT),
            ("mknodat", lkl::MKNODAT),
            ("newfstatat", lkl::NEWFSTATAT),
            ("openat", lkl::OPENAT),
            ("pipe2", lkl::PIPE2),
            ("ppoll", lkl::PPOLL),
            ("prctl", lkl::PRCTL),
            ("pselect6", lkl::PSELECT6),
            ("readlinkat", lkl::READLINKAT),
            ("renameat", lkl::RENAMEAT),
            ("rt_sigaction", lkl::RT_SIGACTION),
            ("setitimer", lkl::SETITIMER),
            ("symlinkat", lkl::SYMLINKAT),
            ("uname", lkl::UNAME),
            ("unlinkat", lkl::UNLINKAT),
            ("utimensat", lkl::UTIMENSAT),
            ("clock_gettime", lkl::CLOCK_GETTIME),
            ("statx", lkl::STATX),
        ];
        for (x, l) in named {
            assert_eq!(g.get(x), Some(&l), "lkl::{x}");
        }
    }

    /// Each pure rewrite calls the *at (or flagged) form it should.
    #[test]
    fn args_rewrites_target() {
        let want: HashMap<&str, u16> = [
            ("open", lkl::OPENAT),
            ("creat", lkl::OPENAT),
            ("access", lkl::FACCESSAT),
            ("pipe", lkl::PIPE2),
            ("rename", lkl::RENAMEAT),
            ("mkdir", lkl::MKDIRAT),
            ("rmdir", lkl::UNLINKAT),
            ("link", lkl::LINKAT),
            ("unlink", lkl::UNLINKAT),
            ("symlink", lkl::SYMLINKAT),
            ("readlink", lkl::READLINKAT),
            ("chmod", lkl::FCHMODAT),
            ("chown", lkl::FCHOWNAT),
            ("lchown", lkl::FCHOWNAT),
            ("getpgrp", lkl::GETPGID),
            ("mknod", lkl::MKNODAT),
            ("epoll_wait", lkl::EPOLL_PWAIT),
            ("eventfd", lkl::EVENTFD2),
        ]
        .into();
        let mut seen = 0;
        for nr in 0..NR {
            if let Route::Rewrite(Rewrite::Args(a)) = route(nr) {
                assert_eq!(want.get(name(nr).unwrap()), Some(&a.lkl), "{:?}", name(nr));
                seen += 1;
            }
        }
        assert_eq!(seen, want.len());
        let p = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000];
        let at = -100isize as usize;
        assert_eq!(OPEN.apply(&p), [at, 0x1000, 0x2000, 0x3000, 0, 0]);
        assert_eq!(RENAME.apply(&p), [at, 0x1000, at, 0x2000, 0, 0]);
        assert_eq!(SYMLINK.apply(&p), [0x1000, at, 0x2000, 0, 0, 0]);
        assert_eq!(LCHOWN.apply(&p), [at, 0x1000, 0x2000, 0x3000, 0x100, 0]);
        assert_eq!(CREAT.apply(&p)[2], (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize);
    }

    /// The constants are x86-64's (and asm-generic's: the same headers).
    #[test]
    fn constants_are_libcs() {
        assert_eq!(k::AT_FDCWD, libc::AT_FDCWD);
        assert_eq!(k::AT_SYMLINK_NOFOLLOW, libc::AT_SYMLINK_NOFOLLOW);
        assert_eq!(k::AT_REMOVEDIR, libc::AT_REMOVEDIR);
        assert_eq!(k::AT_EMPTY_PATH, libc::AT_EMPTY_PATH);
        assert_eq!(k::AT_NO_AUTOMOUNT, libc::AT_NO_AUTOMOUNT);
        assert_eq!(k::AT_STATX_SYNC_TYPE, libc::AT_STATX_SYNC_TYPE);
        assert_eq!(k::SIGCHLD, libc::SIGCHLD);
        assert_eq!(k::F_GETFD, libc::F_GETFD);
        assert_eq!(k::CLOCK_REALTIME, libc::CLOCK_REALTIME);
        assert_eq!(k::ITIMER_REAL, libc::ITIMER_REAL);
        assert_eq!(Errno::Perm.ret(), -libc::EPERM as isize);
        assert_eq!(Errno::Nosys.ret(), -libc::ENOSYS as isize);
    }

    /// A `const NAME: &[..] = &[ ... ];` list from the suite's source.
    fn suite_list(src: &str, decl: &str) -> Vec<String> {
        let start = src.find(decl).unwrap_or_else(|| panic!("{decl} not in suite.rs")) + decl.len();
        let body = &src[start..start + src[start..].find("];").unwrap()];
        body.split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect()
    }

    /// Every number's class is docs/syscalls.md's, as the suite's `sysaudit_check` encodes it
    /// (its lists are read from its source, so the two can't drift): its EPERM and ENOSYS lists,
    /// everything else served. The numbers the audit skips are classified here.
    #[test]
    fn classes_are_the_specs() {
        let suite = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../exobox/tests/suite.rs")).unwrap();
        let eperm = suite_list(&suite, "const EPERM: &[&str] = &[");
        let enosys = suite_list(&suite, "const ENOSYS: &[&str] = &[");
        let enosys_nr: Vec<usize> =
            suite_list(&suite, "const ENOSYS_NR: &[i64] = &[").iter().map(|s| s.parse().unwrap()).collect();
        let names: Vec<_> = (0..NR).filter_map(name).collect();
        for n in eperm.iter().chain(&enosys) {
            assert!(names.contains(&n.as_str()), "suite.rs names {n}, which isn't an x86-64 call");
        }
        // sysaudit's `skipped()`: classified by this table, not by the audit.
        let skipped = [
            ("exit", Class::Served),
            ("exit_group", Class::Served),
            ("fork", Class::Served),
            ("vfork", Class::Served),
            ("clone", Class::Served),
            ("clone3", Class::Enosys),
            ("execve", Class::Served),
            ("execveat", Class::Served),
            ("rt_sigreturn", Class::Served),
            ("reboot", Class::Eperm),
            ("pause", Class::Served),
            ("rt_sigsuspend", Class::Served),
            ("ptrace", Class::Enosys),
            ("kill", Class::Served),
            ("tkill", Class::Served),
            ("tgkill", Class::Served),
            ("munmap", Class::Served),
            ("mremap", Class::Served),
            ("brk", Class::Served),
            ("arch_prctl", Class::Served),
            ("set_tid_address", Class::Served),
            ("seccomp", Class::Enosys),
            ("restart_syscall", Class::Served),
        ];
        let mut counts = HashMap::new();
        for nr in (0..=334).chain(424..NR) {
            let n = name(nr).unwrap();
            let want = if let Some(&(_, c)) = skipped.iter().find(|s| s.0 == n) {
                c
            } else if eperm.iter().any(|e| e == n) {
                Class::Eperm
            } else if enosys.iter().any(|e| e == n) || enosys_nr.contains(&nr) {
                Class::Enosys
            } else {
                Class::Served
            };
            assert_eq!(route(nr).class(), want, "{n} ({nr}): {:?}", route(nr));
            *counts.entry(want).or_insert(0) += 1;
        }
        eprintln!("{counts:?}");
        // The doc's 381 numbers (0-334, 424-469).
        assert_eq!(counts.values().sum::<usize>(), 381);
    }

    #[test]
    fn holes_and_out_of_range_are_enosys() {
        for nr in HOLE.chain([335, NR, 0x4000_0000, usize::MAX]) {
            assert_eq!(route(nr), Route::Errno(Errno::Nosys), "{nr}");
        }
        assert_eq!(name(NR), None);
        assert_eq!(name(400), None);
        assert_eq!(route(0), Route::Lkl(63));
        assert_eq!(name(0), Some("read"));
    }

    /// The design's fixed points: signals and the process ids are LKL's in every mode.
    #[test]
    fn signals_are_the_kernels() {
        for n in [
            "kill", "tkill", "tgkill", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
            "rt_tgsigqueueinfo", "rt_sigsuspend", "sigaltstack", "nanosleep", "clock_nanosleep", "getitimer",
            "setitimer", "getpid", "gettid", "getppid",
        ] {
            let nr = (0..NR).find(|&nr| name(nr) == Some(n)).unwrap();
            assert!(matches!(route(nr), Route::Lkl(_)), "{n}: {:?}", route(nr));
        }
        // rt_sigaction (struct), pause and alarm (no generic call) reach LKL through rewrites.
        for (nr, r) in [(13, Rewrite::SigAction), (34, Rewrite::Pause), (37, Rewrite::Alarm)] {
            assert_eq!(route(nr), Route::Rewrite(r));
        }
    }
}
