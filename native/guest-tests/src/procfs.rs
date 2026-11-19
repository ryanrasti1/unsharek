//! What a program reads about itself and its machine (stdio_meminfo.c's memory part, /proc/self).

use std::fs;

/// The memory size is the program's, not the guest kernel's pool: sysinfo and /proc/meminfo both
/// say at least 256 MB (it was 16 MB: V8 picked its smallest heap).
pub fn meminfo() {
    let min_kb = 256 * 1024;
    // SAFETY: a zeroed out-struct.
    let si = unsafe {
        let mut si: libc::sysinfo = std::mem::zeroed();
        assert_eq!(libc::sysinfo(&mut si), 0);
        si
    };
    let total_kb = si.totalram * si.mem_unit as u64 / 1024;
    assert!(total_kb >= min_kb, "sysinfo totalram {total_kb} KB");
    let m = fs::read_to_string("/proc/meminfo").unwrap();
    let line = m.lines().find(|l| l.starts_with("MemTotal:")).expect("a MemTotal line");
    let kb: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(kb >= min_kb, "{line}");
}

/// /proc/self: the executable, the mapping of it, the threads (libtest's main and this one), the
/// open fds.
pub fn proc_self() {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(fs::read_link("/proc/self/exe").unwrap(), exe);
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    // In the guest /proc/self/maps is empty: LKL has no MMU, and the program's memory is the
    // runtime's arena, which the kernel doesn't map. (Anything reading its own maps, as some
    // runtimes and sanitizers do, finds nothing.)
    if crate::mode() == "native" {
        assert!(maps.contains(exe.to_str().unwrap()), "the executable isn't in /proc/self/maps:\n{maps}");
    } else {
        assert!(maps.is_empty(), "/proc/self/maps in the guest has something now:\n{maps}");
    }
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let threads: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .expect("a Threads line")
        .trim()
        .parse()
        .unwrap();
    assert!(threads >= 2, "{threads} threads: libtest's main and the test's at least");
    let fds: Vec<String> =
        fs::read_dir("/proc/self/fd").unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    for fd in ["0", "1", "2"] {
        assert!(fds.iter().any(|f| f == fd), "fd {fd} not in /proc/self/fd: {fds:?}");
    }
    assert_eq!(fs::read_to_string("/proc/self/comm").unwrap().trim_end().len() <= 15, true);
}

pub fn uname() {
    // SAFETY: a zeroed out-struct; its fields are NUL-terminated.
    let u = unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        assert_eq!(libc::uname(&mut u), 0);
        u
    };
    let s = |f: &[libc::c_char]| unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }.to_string_lossy().into_owned();
    assert_eq!(s(&u.sysname), "Linux");
    assert_eq!(s(&u.machine), "x86_64");
    println!("uname: {} {} {}", s(&u.sysname), s(&u.release), s(&u.nodename));
}
