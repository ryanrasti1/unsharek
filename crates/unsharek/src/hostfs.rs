//! Host directories in the guest, through virtio-fs (unsharek-fs): a device per directory, whose
//! FUSE requests its backend answers. The guest mounts it with `mount -t virtiofs <tag> <dir>`.
//! Host code, after `Guest::boot` and before lockdown (the backend's calls are the host's:
//! in-process, it doesn't survive the filter yet).

use std::io;

use unsharek_fs::{Backend, Host, VirtioFs};
use unsharek_rt::nr as l;
use unsharek_rt::{guest, host};

/// Add a virtio-fs device `tag` answered by `backend`.
pub fn add(tag: &str, backend: Box<dyn Backend>) -> io::Result<()> {
    host::set_iomem(unsharek_fs::ioremap, unsharek_fs::iomem_access);
    let irq = host::free_irq();
    if irq < 0 {
        return Err(io::Error::from_raw_os_error(-irq));
    }
    let h = Host { trigger_irq: host::trigger_irq, host_calls: guest::host_calls };
    let (base, size) = VirtioFs::new(tag, irq as u32, h, backend).add();
    let r = guest::syscall(l::__lkl__NR_virtio_mmio_device_add as _, [base, size, irq as usize, 0, 0, 0]);
    if r < 0 {
        return Err(io::Error::from_raw_os_error(-r as i32));
    }
    Ok(())
}
