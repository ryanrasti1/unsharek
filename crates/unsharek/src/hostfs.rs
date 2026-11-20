//! Host directories in the guest, through virtio-fs (unsharek-fs): a device per directory, whose
//! FUSE requests go to its server over a socket (the server is another process: the
//! `unsharek-fs-server` plugin, or anything speaking unsharek-fs's `wire`). The guest mounts it
//! with `mount -t virtiofs <tag> <dir>`. Host code, after `Guest::boot` and before lockdown; the
//! socket must then be granted (`s.grant(fd)`), since the device reads and writes it after.

use std::io;
use std::os::fd::RawFd;

use unsharek_fs::Host;
use unsharek_rt::nr as l;
use unsharek_rt::{guest, host};

/// Add a virtio-fs device `tag` whose server is on socket `fd` (a unix stream: unsharek-fs's
/// `wire`).
pub fn add(tag: &str, fd: RawFd) -> io::Result<()> {
    unsharek_fs::install(&host::FS_DEVICES);
    host::set_iomem(unsharek_fs::ioremap, unsharek_fs::iomem_access);
    let irq = host::free_irq();
    if irq < 0 {
        return Err(io::Error::from_raw_os_error(-irq));
    }
    let h = Host { trigger_irq: host::trigger_irq, rpc: host::device_rpc };
    let (base, size) = unsharek_fs::add(tag, irq as u32, fd, h).ok_or_else(|| io::Error::other("too many host directories"))?;
    let r = guest::syscall(l::__lkl__NR_virtio_mmio_device_add as _, [base, size, irq as usize, 0, 0, 0]);
    if r < 0 {
        return Err(io::Error::from_raw_os_error(-r as i32));
    }
    Ok(())
}

/// Mount device `tag` at `at` (made if missing): in a setup closure (`g.run`), where this
/// thread's calls are the guest's.
pub fn mount(tag: &str, at: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(at)?;
    let c = |b: &[u8]| std::ffi::CString::new(b).map_err(|_| io::Error::other("a NUL in a path"));
    let (src, dir, ty) = (c(tag.as_bytes())?, c(at.as_os_str().as_encoded_bytes())?, c(b"virtiofs")?);
    // SAFETY: NUL-terminated strings, live for the call.
    if unsafe { libc::mount(src.as_ptr(), dir.as_ptr(), ty.as_ptr(), 0, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
