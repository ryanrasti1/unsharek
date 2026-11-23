//! Host directories in the guest, through virtio-fs (unsharek-fs): a device per directory, its
//! FUSE requests served in this process by unsharek-fs's passthrough, whose host calls are
//! unsharek-tcb's fs plugin's rows (`unsharek_tcb::plugin::Files`, which the caller passes to
//! lockdown with the directories as its roots: without it the first request after lockdown is
//! killed). The guest mounts it with `mount -t virtiofs <tag> <dir>`. Host code, after
//! `Guest::boot` and before lockdown.

use std::io;
use std::path::Path;

use unsharek_fs::Host;
use unsharek_rt::nr as l;
use unsharek_rt::{guest, host};

static SYS: unsharek_fs::passthrough::Sys = unsharek_fs::passthrough::Sys { call: host::device_sys };

/// Add a virtio-fs device `tag` serving host directory `dir` (absolute and canonical: the
/// passthrough's paths start with it), read-write if `writable`. `shared`: fork mode's (the
/// passthrough's nodes are then mapped shared, for every process the guest forks).
pub fn add(tag: &str, dir: &Path, writable: bool, shared: bool) -> io::Result<()> {
    unsharek_fs::install(&host::FS_DEVICES);
    unsharek_fs::passthrough::install(&SYS);
    host::set_iomem(unsharek_fs::ioremap, unsharek_fs::iomem_access);
    let len = unsharek_fs::passthrough::ROOT_SIZE.next_multiple_of(4096);
    // Anonymous and NORESERVE: its untouched pages (most of the node table) cost nothing.
    let mem = crate::memory::reserve(0, len, libc::PROT_READ | libc::PROT_WRITE, shared)?;
    // SAFETY: fresh, zeroed, as large as ROOT_SIZE, the root's alone, never unmapped.
    let state = unsafe { unsharek_fs::passthrough::root(mem as *mut u8, dir.as_os_str().as_encoded_bytes(), writable) }
        .ok_or_else(|| io::Error::other(format!("{}: not an absolute path", dir.display())))?;
    let irq = host::free_irq();
    if irq < 0 {
        return Err(io::Error::from_raw_os_error(-irq));
    }
    let h = Host { trigger_irq: host::trigger_irq, rpc: unsharek_fs::passthrough::serve };
    let (base, size) = unsharek_fs::add(tag, irq as u32, state, h).ok_or_else(|| io::Error::other("too many host directories"))?;
    let r = guest::syscall(l::__lkl__NR_virtio_mmio_device_add as _, [base, size, irq as usize, 0, 0, 0]);
    if r < 0 {
        return Err(io::Error::from_raw_os_error(-r as i32));
    }
    Ok(())
}

/// Mount device `tag` at `at` (made if missing): in a setup closure (`g.run`), where this
/// thread's calls are the guest's.
pub fn mount(tag: &str, at: &Path) -> io::Result<()> {
    std::fs::create_dir_all(at)?;
    let c = |b: &[u8]| std::ffi::CString::new(b).map_err(|_| io::Error::other("a NUL in a path"));
    let (src, dir, ty) = (c(tag.as_bytes())?, c(at.as_os_str().as_encoded_bytes())?, c(b"virtiofs")?);
    // SAFETY: NUL-terminated strings, live for the call.
    if unsafe { libc::mount(src.as_ptr(), dir.as_ptr(), ty.as_ptr(), 0, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
