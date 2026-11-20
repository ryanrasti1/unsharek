//! Spike: a host directory in the guest through virtio-fs (unsharek-fs's device, virtiofsd's
//! passthrough file system). `virtiofs_spike <host dir> [rw]`: mounts it at /mnt in the guest and
//! stats, lists, reads, writes (rw), and times a write+read loop, before lockdown.

use std::io::{Read, Write};
use std::time::Instant;

use unsharek::{Guest, GuestConfig, Mode};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).cloned().expect("usage: virtiofs_spike <host dir> [rw]");
    let rw = args.get(2).is_some_and(|a| a == "rw");
    let mut g = Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() }).unwrap();
    let backend = unsharek_fs::passthrough::Passthrough::new(&dir, rw).expect("passthrough");
    unsharek::hostfs::add("host", Box::new(backend)).expect("virtio-fs device");
    let out = g
        .run(move || -> std::io::Result<Vec<String>> {
            let mut log = vec![];
            std::fs::create_dir_all("/mnt")?;
            let c = |s: &str| std::ffi::CString::new(s).unwrap();
            let (src, at, ty) = (c("host"), c("/mnt"), c("virtiofs"));
            // SAFETY: NUL-terminated strings, live for the call.
            let r = unsafe { libc::mount(src.as_ptr(), at.as_ptr(), ty.as_ptr(), 0, std::ptr::null()) };
            if r != 0 {
                return Err(std::io::Error::last_os_error());
            }
            log.push("mount: ok".into());
            let md = std::fs::metadata("/mnt")?;
            log.push(format!("stat /mnt: dir={} mode={:o}", md.is_dir(), std::os::unix::fs::PermissionsExt::mode(&md.permissions())));
            let mut names: Vec<String> = std::fs::read_dir("/mnt")?.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            log.push(format!("ls /mnt: {names:?}"));
            if let Ok(s) = std::fs::read_to_string("/mnt/hello.txt") {
                log.push(format!("read hello.txt: {s:?}"));
            }
            let w = std::fs::write("/mnt/from-guest.txt", "written in the guest\n");
            log.push(format!("write from-guest.txt: {:?}", w.as_ref().map_err(|e| e.to_string())));
            if w.is_ok() {
                // a write+read loop: 64 MiB in 1 MiB writes, fsync, read back
                let buf = vec![7u8; 1 << 20];
                let t = Instant::now();
                let mut f = std::fs::File::create("/mnt/big.bin")?;
                for _ in 0..64 {
                    f.write_all(&buf)?;
                }
                f.sync_all()?;
                drop(f);
                let wt = t.elapsed();
                // drop the guest's page cache so the read goes to the host
                let _ = std::fs::write("/proc/sys/vm/drop_caches", "3");
                let t = Instant::now();
                let mut f = std::fs::File::open("/mnt/big.bin")?;
                let mut rb = vec![0u8; 1 << 20];
                let mut n = 0;
                loop {
                    let k = f.read(&mut rb)?;
                    if k == 0 {
                        break;
                    }
                    n += k;
                }
                let rt = t.elapsed();
                log.push(format!("64 MiB: write+fsync {wt:?}, read {rt:?} ({n} bytes)"));
                std::fs::remove_file("/mnt/big.bin")?;
            }
            Ok(log)
        })
        .unwrap();
    match out {
        Ok(log) => {
            for l in log {
                println!("{l}");
            }
        }
        Err(e) => println!("guest: {e}"),
    }
    // a host change, seen live by the guest?
    std::fs::write(format!("{dir}/hello.txt"), "changed on the host, longer than before\n").unwrap();
    let seen = g.run(|| std::fs::read_to_string("/mnt/hello.txt").map_err(|e| e.to_string())).unwrap();
    println!("after a host change, the guest reads hello.txt: {seen:?}");
    std::fs::write(format!("{dir}/hello.txt"), "hello from host\n").unwrap();
    // native, same loop, on the host directory
    if rw {
        let buf = vec![7u8; 1 << 20];
        let p = format!("{dir}/big-native.bin");
        let t = Instant::now();
        let mut f = std::fs::File::create(&p).unwrap();
        for _ in 0..64 {
            f.write_all(&buf).unwrap();
        }
        f.sync_all().unwrap();
        drop(f);
        let wt = t.elapsed();
        let t = Instant::now();
        let n = std::fs::read(&p).unwrap().len();
        println!("native 64 MiB: write+fsync {wt:?}, read {:?} ({n} bytes, host page cache)", t.elapsed());
        std::fs::remove_file(&p).unwrap();
    }
    std::process::exit(0);
}
