//! The server's filter: the host calls its file system (fuse-backend-rs's passthrough) and its
//! loop make, nothing else. A plain Rust function, compiled by seccomp-fn and proven equal to its
//! program by seccomp-fn-verify (`cargo xtask prove`), like the sandbox's.
//!
//! Its arguments aren't pinned: Landlock confines what the file calls reach (the directory), so
//! the filter's job is the kernel surface: no sockets, no exec, no ptrace, no namespaces, no
//! mounts, no new processes or threads, no credential changes (the server runs as itself: the
//! requests' uid and gid are zeroed, so fuse-backend-rs never switches), no Landlock or seccomp
//! changes. The list is what a run of every FUSE operation the guest's driver sends, under strace,
//! called (see each row).
#![allow(non_upper_case_globals)] // libc's syscall names, as patterns

use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, seccomp_data, sock_filter};
use libc::{
    SYS_brk, SYS_capget, SYS_close, SYS_copy_file_range, SYS_dup, SYS_exit_group, SYS_fallocate, SYS_fchmod, SYS_fchmodat,
    SYS_fchownat, SYS_fcntl, SYS_fdatasync, SYS_fgetxattr, SYS_flistxattr, SYS_fremovexattr, SYS_fsetxattr, SYS_fstat,
    SYS_fstatfs, SYS_fsync, SYS_ftruncate, SYS_getdents64, SYS_linkat, SYS_lseek, SYS_madvise,
    SYS_mkdirat, SYS_mknodat, SYS_mmap, SYS_mremap, SYS_munmap, SYS_newfstatat, SYS_openat, SYS_pread64, SYS_preadv,
    SYS_pwrite64, SYS_pwritev, SYS_read, SYS_readlinkat, SYS_renameat2, SYS_statx, SYS_symlinkat,
    SYS_umask, SYS_unlinkat, SYS_utimensat, SYS_write, SYS_writev,
};

/// include/uapi/linux/audit.h (libc lacks it for x86_64): EM_X86_64 | 64-bit | little-endian.
const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | 0x8000_0000 | 0x4000_0000;
/// `__X32_SYSCALL_BIT` (arch/x86/include/uapi/asm/unistd.h).
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The server's verdict on a call `d`: allowed, or the server killed.
pub fn policy() -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        // Another ABI: the rows are x86-64's numbers.
        if d.arch != AUDIT_ARCH_X86_64 || d.nr as u32 >= X32_SYSCALL_BIT {
            return SECCOMP_RET_KILL_PROCESS;
        }
        match d.nr as i64 {
            // The loop: the socket, and the memfd its replies are written to and read back from.
            SYS_read | SYS_write | SYS_writev | SYS_lseek | SYS_pread64 => SECCOMP_RET_ALLOW,
            // Lookups, attributes, directories, links (FUSE's LOOKUP, GETATTR, READDIR, READLINK,
            // STATFS, OPEN through /proc/self/fd, RELEASE, FORGET's closes; its inodes' fds dup'd).
            SYS_openat | SYS_close | SYS_dup | SYS_newfstatat | SYS_fstat | SYS_statx | SYS_fstatfs
            | SYS_getdents64 | SYS_readlinkat | SYS_fcntl => SECCOMP_RET_ALLOW,
            // Data (READ, WRITE: preadv and pwritev into its buffers; FSYNC, FALLOCATE,
            // COPY_FILE_RANGE).
            SYS_preadv | SYS_pwrite64 | SYS_pwritev | SYS_fsync | SYS_fdatasync | SYS_fallocate | SYS_copy_file_range => {
                SECCOMP_RET_ALLOW
            }
            // Changes (CREATE, MKDIR, MKNOD, SYMLINK, LINK, UNLINK, RMDIR, RENAME2, SETATTR; umask:
            // CREATE's and MKDIR's, the request's).
            SYS_mkdirat | SYS_mknodat | SYS_symlinkat | SYS_linkat | SYS_unlinkat | SYS_renameat2 | SYS_fchmod
            | SYS_fchmodat | SYS_fchownat | SYS_ftruncate | SYS_utimensat | SYS_umask => SECCOMP_RET_ALLOW,
            // Extended attributes (off in its config; a request for them is still answered).
            SYS_fgetxattr | SYS_fsetxattr | SYS_flistxattr | SYS_fremovexattr => SECCOMP_RET_ALLOW,
            // Memory (its allocator), and capget (the caps crate: whether it holds CAP_FSETID, on
            // a write that clears setuid bits).
            SYS_brk | SYS_mmap | SYS_munmap | SYS_mremap | SYS_madvise | SYS_capget => SECCOMP_RET_ALLOW,
            // The end: the sandbox's end of the socket closed.
            SYS_exit_group => SECCOMP_RET_ALLOW,
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

seccomp_fn_verify::policy!(policy, filter_of, unwind = 200);

fn filter_of() -> Vec<sock_filter> {
    seccomp_fn::compile!(policy())
}

/// The server's filter: [`policy`]'s program.
pub fn filter() -> Vec<sock_filter> {
    filter_of()
}
