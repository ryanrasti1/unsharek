//! Where the x86-64 ABI the program was built for and LKL's (asm-generic, 64-bit) differ in the
//! structs syscalls pass, and the pure translations between them. `sysmap` says which calls need
//! them.
//!
//! Every struct a call in `sysmap` passes was checked against both kernels' UAPI headers (LKL's
//! `arch/lkl` uses the asm-generic ones; x86-64 overrides a few in `arch/x86/include/uapi/asm`).
//! Findings, for the 64-bit ABI (both have `__BITS_PER_LONG == 64`):
//! - **`struct stat` differs** (`X86Stat`, 144 bytes, vs `LklStat`, 128): x86-64 has `st_nlink`
//!   before `st_mode` and as a long, `st_blksize` as a long, and three spare longs. `stat`, `lstat`,
//!   `fstat` and `newfstatat` are translated (`stat_to_x86`).
//! - **`struct sigaction` (the kernel's, for `rt_sigaction`) differs** (`X86Sigaction`, 32 bytes,
//!   vs `LklSigaction`, 24): LKL defines no `SA_RESTORER` (asm-generic `signal.h` declares
//!   `sa_restorer` only `#ifdef SA_RESTORER`, and so `__ARCH_HAS_SA_RESTORER` is unset in
//!   `linux/signal_types.h`), so it has no `sa_restorer` field and its `do_sigaction` clears the
//!   `SA_RESTORER` flag bit (`UAPI_SA_FLAGS` leaves it out). The runtime keeps each signal's
//!   restorer itself: it is where a handler returns to (glibc's `__restore_rt`, which makes
//!   `rt_sigreturn`), and it is given back, flag and all, by the old-action half.
//! - **`struct epoll_event` is the same** (`EpollEvent`, 12 bytes, packed): `linux/eventpoll.h`
//!   packs it `#ifdef __x86_64__`, which the host compiler defines when it builds LKL
//!   (`arch/lkl/Makefile` doesn't undefine it). It would differ only for an LKL cross-built for
//!   another architecture.
//! - **`struct statfs` is the same** (`Statfs`, 120 bytes): x86-64's `asm/statfs.h` includes
//!   asm-generic's, whose `__statfs_word` is `long` on 64-bit; only the 32-bit compat struct is
//!   packed differently.
//! - **`struct statx` is the same**: `linux/stat.h`, fixed-width fields, no arch part.
//! - **`struct new_utsname` is the same layout**, but LKL's `machine` is `"lkl"`: `uname` rewrites
//!   it to `"x86_64"` (`UTS_MACHINE`), as programs pick code paths and download URLs from it.
//! - The same on both (asm-generic on x86-64 too, or fixed-width): `timespec`, `timeval`,
//!   `itimerval`, `rlimit`, `rusage`, `sysinfo`, `tms`, `stack_t` (`sigaltstack`), `siginfo_t`
//!   (x86 changes it only for x32), `sigset_t` (64 signals, one word), `pollfd`, `flock`, `iovec`,
//!   `msghdr`/`cmsghdr`, `sockaddr*`, `linux_dirent64`, `sched_param`/`sched_attr`, `sigevent`,
//!   `open_how`, `clone_args`; the flag and constant spaces too (`O_*`, `AT_*`, `SA_*`, signal
//!   numbers, `ioctl` numbers, `SO_*`), since x86-64 has no `fcntl.h`, `socket.h`, `ioctls.h`
//!   or `termbits.h` of its own. `clone`'s argument order is the same: neither selects
//!   `CLONE_BACKWARDS*`.
//! - x86-64's own (`mman.h`'s `MAP_32BIT`, `ldt.h`, `prctl.h`'s `ARCH_*`, `sigcontext`/`ucontext`,
//!   the SysV IPC structs) belong to calls the runtime emulates or refuses (`sysmap`), never
//!   passed to LKL.

/// x86-64's `struct stat` (`arch/x86/include/uapi/asm/stat.h`, `!__i386__`). Glibc's is the same.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: u64,
    pub st_atime_nsec: u64,
    pub st_mtime: u64,
    pub st_mtime_nsec: u64,
    pub st_ctime: u64,
    pub st_ctime_nsec: u64,
    pub unused: [i64; 3],
}
const _: () = assert!(size_of::<X86Stat>() == 144);

/// LKL's `struct stat` (`include/uapi/asm-generic/stat.h`, 64-bit), what its `newfstatat` and
/// `fstat` write.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LklStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub unused4: u32,
    pub unused5: u32,
}
const _: () = assert!(size_of::<LklStat>() == 128);

/// LKL's stat as x86-64's. Padding is zeroed (the kernel's `INIT_STRUCT_STAT_PADDING`), so nothing
/// of the runtime's stack reaches the program. Times are the same bits in both (x86-64 declares
/// them unsigned; a time before 1970 is negative in both).
pub fn stat_to_x86(s: &LklStat) -> X86Stat {
    X86Stat {
        st_dev: s.st_dev,
        st_ino: s.st_ino,
        st_nlink: s.st_nlink as u64,
        st_mode: s.st_mode,
        st_uid: s.st_uid,
        st_gid: s.st_gid,
        pad0: 0,
        st_rdev: s.st_rdev,
        st_size: s.st_size,
        st_blksize: s.st_blksize as i64,
        st_blocks: s.st_blocks,
        st_atime: s.st_atime as u64,
        st_atime_nsec: s.st_atime_nsec,
        st_mtime: s.st_mtime as u64,
        st_mtime_nsec: s.st_mtime_nsec,
        st_ctime: s.st_ctime as u64,
        st_ctime_nsec: s.st_ctime_nsec,
        unused: [0; 3],
    }
}

/// `SA_RESTORER` (`asm-generic/signal-defs.h`; x86-64 defines it, LKL doesn't).
pub const SA_RESTORER: u64 = 0x0400_0000;

/// x86-64's kernel `struct sigaction` for `rt_sigaction` (`linux/signal_types.h` with
/// `__ARCH_HAS_SA_RESTORER`). Not glibc's `struct sigaction`, whose mask is 128 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86Sigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}
const _: () = assert!(size_of::<X86Sigaction>() == 32);

/// LKL's kernel `struct sigaction`: no `sa_restorer` (see the module comment).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LklSigaction {
    pub handler: usize,
    pub flags: u64,
    pub mask: u64,
}
const _: () = assert!(size_of::<LklSigaction>() == 24);

/// The program's new action for LKL, and the restorer the runtime keeps for that signal (0 when
/// `SA_RESTORER` isn't set: then the program has none, and a handler can't return).
pub fn sigaction_to_lkl(x: &X86Sigaction) -> (LklSigaction, usize) {
    let restorer = if x.flags & SA_RESTORER != 0 { x.restorer } else { 0 };
    (LklSigaction { handler: x.handler, flags: x.flags & !SA_RESTORER, mask: x.mask }, restorer)
}

/// LKL's old action for the program, with the restorer the runtime kept for that signal: what
/// x86-64's kernel would have given back.
pub fn sigaction_to_x86(l: &LklSigaction, restorer: usize) -> X86Sigaction {
    X86Sigaction {
        handler: l.handler,
        flags: if restorer != 0 { l.flags | SA_RESTORER } else { l.flags },
        restorer,
        mask: l.mask,
    }
}

/// `struct epoll_event`, the same on both (see the module comment); declared for the size check.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}
const _: () = assert!(size_of::<EpollEvent>() == 12);

/// `struct statfs`, the same on both (see the module comment); declared for the size check.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Statfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: i64,
    pub f_bfree: i64,
    pub f_bavail: i64,
    pub f_files: i64,
    pub f_ffree: i64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}
const _: () = assert!(size_of::<Statfs>() == 120);

/// `struct new_utsname`'s `machine`: the fifth of six 65-byte fields.
pub const UTS_MACHINE: core::ops::Range<usize> = 4 * 65..5 * 65;
/// `struct new_utsname`'s size.
pub const UTS_SIZE: usize = 6 * 65;

/// Makes a `struct new_utsname` from LKL say `x86_64`, NUL-padded as the kernel's is.
pub fn uts_set_machine(uts: &mut [u8; UTS_SIZE]) {
    let m = &mut uts[UTS_MACHINE];
    m.fill(0);
    m[..6].copy_from_slice(b"x86_64");
}

/// `struct timespec` (64-bit: two longs on both).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct timeval` (64-bit: two longs on both).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `struct itimerval`, for `alarm` (as `setitimer(ITIMER_REAL)`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

/// `poll`'s timeout in milliseconds as `ppoll`'s: negative waits forever (no timespec), as
/// `do_sys_poll` takes it.
pub fn poll_timeout(ms: i32) -> Option<Timespec> {
    (ms >= 0).then(|| Timespec { tv_sec: (ms / 1000) as i64, tv_nsec: (ms % 1000) as i64 * 1_000_000 })
}

/// `select`'s timeout as `pselect6`'s. Normalised as `kern_select` does (microseconds past a
/// second carry over), so what select accepts pselect6 accepts; a negative one stays invalid,
/// and pselect6 refuses it with `EINVAL` as select would.
pub fn select_timeout(tv: &Timeval) -> Timespec {
    Timespec {
        tv_sec: tv.tv_sec.saturating_add(tv.tv_usec / 1_000_000),
        tv_nsec: (tv.tv_usec % 1_000_000) * 1000,
    }
}

/// `pselect6`'s remaining time, written back as `select`'s (Linux updates select's timeout;
/// programs loop on it). Truncated to microseconds as `poll_select_finish` does.
pub fn select_remaining(ts: &Timespec) -> Timeval {
    Timeval { tv_sec: ts.tv_sec, tv_usec: ts.tv_nsec / 1000 }
}

/// `utimes`/`futimesat`'s two timevals as `utimensat`'s timespecs; `None` (`EINVAL`) for a
/// microsecond count out of range, which `do_futimesat` refuses before converting.
pub fn utimes_to_timespecs(tv: &[Timeval; 2]) -> Option<[Timespec; 2]> {
    let one = |t: &Timeval| {
        (0..1_000_000).contains(&t.tv_usec).then_some(Timespec { tv_sec: t.tv_sec, tv_nsec: t.tv_usec * 1000 })
    };
    Some([one(&tv[0])?, one(&tv[1])?])
}

/// `utime`'s `struct utimbuf` (access and modification seconds) as `utimensat`'s timespecs.
pub fn utimbuf_to_timespecs(actime: i64, modtime: i64) -> [Timespec; 2] {
    [Timespec { tv_sec: actime, tv_nsec: 0 }, Timespec { tv_sec: modtime, tv_nsec: 0 }]
}

/// `alarm`'s result from the old `ITIMER_REAL` value: whole seconds left, rounded as
/// `alarm_setitimer` does (half a second or more up, and never 0 while one is pending).
pub fn alarm_remaining(old: &Itimerval) -> u64 {
    let v = old.it_value;
    let mut s = v.tv_sec as u64;
    if (v.tv_sec == 0 && v.tv_usec != 0) || v.tv_usec >= 500_000 {
        s += 1;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    /// Our x86-64 stat is glibc's, field for field (libc's x86_64 `stat` is the kernel's).
    #[test]
    fn x86_stat_is_libcs() {
        assert_eq!(size_of::<X86Stat>(), size_of::<libc::stat>());
        macro_rules! same {
            ($($f:ident)*) => { $(assert_eq!(offset_of!(X86Stat, $f), offset_of!(libc::stat, $f), stringify!($f));)* };
        }
        same!(st_dev st_ino st_nlink st_mode st_uid st_gid st_rdev st_size st_blksize st_blocks
              st_atime st_atime_nsec st_mtime st_mtime_nsec st_ctime st_ctime_nsec);
    }

    /// The generic layout's offsets, from asm-generic/stat.h (libc has no arch with it here).
    #[test]
    fn lkl_stat_offsets() {
        let o = [
            offset_of!(LklStat, st_mode),
            offset_of!(LklStat, st_nlink),
            offset_of!(LklStat, st_rdev),
            offset_of!(LklStat, st_size),
            offset_of!(LklStat, st_blksize),
            offset_of!(LklStat, st_blocks),
            offset_of!(LklStat, st_atime),
            offset_of!(LklStat, st_ctime_nsec),
            offset_of!(LklStat, unused4),
        ];
        assert_eq!(o, [16, 20, 32, 48, 56, 64, 72, 112, 120]);
    }

    /// Every field arrives, each a distinct value, sign-extended where it widens.
    #[test]
    fn stat_translation_keeps_every_field() {
        let l = LklStat {
            st_dev: 1,
            st_ino: 2,
            st_mode: 0o100644,
            st_nlink: 4,
            st_uid: 5,
            st_gid: 6,
            st_rdev: 7,
            pad1: 0xdead,
            st_size: 8,
            st_blksize: 4096,
            pad2: 0xbeef,
            st_blocks: 10,
            st_atime: -11,
            st_atime_nsec: 12,
            st_mtime: 13,
            st_mtime_nsec: 14,
            st_ctime: 15,
            st_ctime_nsec: 16,
            unused4: 0xfeed,
            unused5: 0xface,
        };
        let x = stat_to_x86(&l);
        assert_eq!(
            x,
            X86Stat {
                st_dev: 1,
                st_ino: 2,
                st_nlink: 4,
                st_mode: 0o100644,
                st_uid: 5,
                st_gid: 6,
                pad0: 0,
                st_rdev: 7,
                st_size: 8,
                st_blksize: 4096,
                st_blocks: 10,
                st_atime: -11i64 as u64,
                st_atime_nsec: 12,
                st_mtime: 13,
                st_mtime_nsec: 14,
                st_ctime: 15,
                st_ctime_nsec: 16,
                unused: [0; 3],
            }
        );
        // And as glibc reads it.
        let g: libc::stat = unsafe { core::mem::transmute(x) };
        assert_eq!((g.st_nlink, g.st_mode, g.st_blksize, g.st_atime, g.st_ctime_nsec), (4, 0o100644, 4096, -11, 16));
    }

    #[test]
    fn sigaction_round_trips() {
        let x = X86Sigaction { handler: 0x1000, flags: 4 | SA_RESTORER, restorer: 0x2000, mask: 1 << 9 };
        let (l, r) = sigaction_to_lkl(&x);
        assert_eq!(l, LklSigaction { handler: 0x1000, flags: 4, mask: 1 << 9 });
        assert_eq!(r, 0x2000);
        assert_eq!(sigaction_to_x86(&l, r), x);
        // Without SA_RESTORER, whatever is in the field isn't a restorer.
        let (l, r) = sigaction_to_lkl(&X86Sigaction { flags: 4, restorer: 0x2000, ..x });
        assert_eq!(r, 0);
        assert_eq!(sigaction_to_x86(&l, r), X86Sigaction { flags: 4, restorer: 0, ..x });
    }

    #[test]
    fn same_layouts_as_libc() {
        assert_eq!(size_of::<EpollEvent>(), size_of::<libc::epoll_event>());
        assert_eq!(size_of::<Statfs>(), size_of::<libc::statfs>());
        assert_eq!(offset_of!(Statfs, f_fsid), offset_of!(libc::statfs, f_fsid));
        assert_eq!(offset_of!(Statfs, f_frsize), offset_of!(libc::statfs, f_frsize));
        assert_eq!(size_of::<libc::utsname>(), UTS_SIZE);
        assert_eq!(offset_of!(libc::utsname, machine), UTS_MACHINE.start);
        assert_eq!(size_of::<Itimerval>(), size_of::<libc::itimerval>());
    }

    #[test]
    fn uname_machine() {
        let mut u = [b'x'; UTS_SIZE];
        u[UTS_MACHINE][..4].copy_from_slice(b"lkl\0");
        uts_set_machine(&mut u);
        assert_eq!(&u[UTS_MACHINE.start..UTS_MACHINE.start + 7], b"x86_64\0");
        assert!(u[UTS_MACHINE].iter().skip(6).all(|&b| b == 0));
        assert_eq!(u[UTS_MACHINE.end], b'x');
    }

    #[test]
    fn time_conversions() {
        assert_eq!(poll_timeout(-1), None);
        assert_eq!(poll_timeout(0), Some(Timespec { tv_sec: 0, tv_nsec: 0 }));
        assert_eq!(poll_timeout(2500), Some(Timespec { tv_sec: 2, tv_nsec: 500_000_000 }));
        assert_eq!(select_timeout(&Timeval { tv_sec: 1, tv_usec: 2_500_000 }), Timespec { tv_sec: 3, tv_nsec: 500_000_000 });
        assert!(select_timeout(&Timeval { tv_sec: 1, tv_usec: -1 }).tv_nsec < 0); // pselect6: EINVAL
        assert_eq!(select_remaining(&Timespec { tv_sec: 1, tv_nsec: 999_999 }), Timeval { tv_sec: 1, tv_usec: 999 });
        let tv = [Timeval { tv_sec: 1, tv_usec: 2 }, Timeval { tv_sec: 3, tv_usec: 999_999 }];
        assert_eq!(
            utimes_to_timespecs(&tv),
            Some([Timespec { tv_sec: 1, tv_nsec: 2000 }, Timespec { tv_sec: 3, tv_nsec: 999_999_000 }])
        );
        assert_eq!(utimes_to_timespecs(&[tv[0], Timeval { tv_sec: 0, tv_usec: 1_000_000 }]), None);
        assert_eq!(utimbuf_to_timespecs(5, 6)[1], Timespec { tv_sec: 6, tv_nsec: 0 });
        let it = |s, us| Itimerval { it_interval: Timeval::default(), it_value: Timeval { tv_sec: s, tv_usec: us } };
        assert_eq!(alarm_remaining(&it(0, 0)), 0);
        assert_eq!(alarm_remaining(&it(0, 1)), 1);
        assert_eq!(alarm_remaining(&it(3, 499_999)), 3);
        assert_eq!(alarm_remaining(&it(3, 500_000)), 4);
    }
}
