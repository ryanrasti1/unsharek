//! The host memory a guest is made of, mapped before lockdown: the arena, the kernel's memory and
//! stacks, the images, and fork mode's shared section. Not the TCB: unsharek-tcb's lockdown checks
//! every mapping of the process (`/proc/self/maps`) whatever made it, so nothing here is trusted
//! to have mapped only what it says. All of it is private but fork mode's, which is shared
//! anonymous memory (the kernel's, among the sandbox's own processes).

use std::io;
use std::os::fd::RawFd;

const PAGE: usize = 4096;

fn check(p: *mut libc::c_void) -> io::Result<usize> {
    if p == libc::MAP_FAILED { Err(io::Error::last_os_error()) } else { Ok(p as usize) }
}

/// Anonymous memory, `MAP_NORESERVE` (it costs what is touched): at `at` if it's free (0:
/// anywhere), else anywhere.
pub(crate) fn reserve(at: usize, len: usize, prot: i32, shared: bool) -> io::Result<usize> {
    let share = if shared { libc::MAP_SHARED } else { libc::MAP_PRIVATE };
    let flags = share | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
    // A fresh anonymous mapping; FIXED_NOREPLACE never replaces one.
    let fixed = if at != 0 { libc::MAP_FIXED_NOREPLACE } else { 0 };
    // SAFETY: a fresh mapping, nobody else's.
    match check(unsafe { libc::mmap(at as *mut _, len, prot, flags | fixed, -1, 0) }) {
        // SAFETY: as above.
        Err(_) if at != 0 => check(unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, -1, 0) }),
        r => r,
    }
}

/// `fd`'s first `len` bytes mapped read-only and private, for the process's life: an image.
pub(crate) fn map_image(fd: RawFd, len: usize) -> io::Result<&'static [u8]> {
    // SAFETY: a fresh private mapping of the caller's fd.
    let p = check(unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, fd, 0) })?;
    // SAFETY: mapped above, readable, never unmapped.
    Ok(unsafe { std::slice::from_raw_parts(p as *const u8, len) })
}

/// `fd`'s first `len` bytes mapped read-only and private over `at`, inside a mapping of the
/// caller's (an immutable image's file blocks: `unsharek::Guest::map_image_over`), for the
/// process's life.
pub(crate) fn map_over(at: usize, fd: RawFd, len: usize) -> io::Result<()> {
    // SAFETY: over pages of the caller's own read-only image mapping, which nothing uses yet.
    check(unsafe { libc::mmap(at as *mut _, len, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_FIXED, fd, 0) }).map(|_| ())
}

/// `fd`'s first `len` bytes mapped again, private, readable and executable, over `at` in the
/// arena's image zone. On failure the zone's range is anonymous memory again, as reserved.
pub(crate) fn map_image_at(at: usize, fd: RawFd, len: usize) -> io::Result<()> {
    let rx = libc::PROT_READ | libc::PROT_EXEC;
    // SAFETY: over the arena's own reservation, where nothing is mapped yet.
    if let Err(e) = check(unsafe { libc::mmap(at as *mut _, len, rx, libc::MAP_PRIVATE | libc::MAP_FIXED, fd, 0) }) {
        // A failed MAP_FIXED may have unmapped the range: the reservation's zeros back.
        let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED;
        // SAFETY: as above.
        check(unsafe { libc::mmap(at as *mut _, len.next_multiple_of(PAGE), rwx, flags, -1, 0) }).expect("the image zone lost a range");
        return Err(e);
    }
    Ok(())
}

/// Fork mode: the kernel's and the runtime's statics (`unsharek_rt::share::section`, whole pages)
/// mapped shared, their contents kept, so a host fork from now on shares them. All-zero pages
/// aren't copied (they cost nothing until written).
///
/// # Safety
/// Before the runtime is used, on the only thread (nothing writes the section meanwhile).
pub(crate) unsafe fn share_section() -> io::Result<()> {
    let (lo, hi) = unsharek_rt::share::section();
    if !lo.is_multiple_of(PAGE) || !hi.is_multiple_of(PAGE) || hi <= lo {
        // The link didn't make it whole pages: sharing would take in its neighbours.
        return Err(io::Error::from_raw_os_error(libc::ENOEXEC));
    }
    let len = hi - lo;
    let tmp = reserve(0, len, libc::PROT_READ | libc::PROT_WRITE, true)?;
    for p in (lo..hi).step_by(PAGE) {
        // SAFETY: the section is mapped and readable; `tmp` is its size.
        unsafe {
            let page = std::slice::from_raw_parts(p as *const u64, PAGE / 8);
            if page.iter().any(|&w| w != 0) {
                std::ptr::copy_nonoverlapping(p as *const u8, (tmp + (p - lo)) as *mut u8, PAGE);
            }
        }
    }
    // Over the section, atomically: nothing runs in between that could see it unmapped.
    // SAFETY: moves the fresh mapping over the section, whose contents it now has.
    let r = unsafe { libc::mremap(tmp as *mut _, len, len, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED, lo as *mut libc::c_void) };
    if r == libc::MAP_FAILED {
        let e = io::Error::last_os_error();
        // SAFETY: the fresh mapping, unused.
        unsafe { libc::munmap(tmp as *mut _, len) };
        return Err(e);
    }
    Ok(())
}
