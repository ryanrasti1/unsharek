//! The kernel: LKL (Linux as a library), built from `lkl/` by build.rs and linked in, and bindgen's
//! declarations of its entry points.
//!
//! - `lkl_init(ops)`, `lkl_start_kernel(cmdline, ...)`, `lkl_cleanup()`, `lkl_is_running()`
//! - `lkl_syscall(nr, params)` with the generic syscall numbers `__lkl__NR_*` (asm-generic's, not
//!   x86_64's), and `lkl_sys_halt()`
//! - `lkl_host_operations`, the table of host operations the kernel calls (with `lkl_jmp_buf` and
//!   `lkl_thread_t`, which it names)
//!
//! Only the kernel object is linked, not tools/lkl/lib: the host operations are the binary's to
//! provide, and so are the two functions shim.c's `lkl_printf` and `lkl_bug` (variadic, so in C)
//! hand their formatted message to:
//!
//! ```ignore
//! #[unsafe(no_mangle)]
//! extern "C" fn exobox_lkl_print(s: *const c_char, len: c_ulong) { /* write it */ }
//! #[unsafe(no_mangle)]
//! extern "C" fn exobox_lkl_panic() -> ! { /* lkl_bug: the kernel can't go on */ }
//! ```
#![no_std]

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::all,
    clippy::pedantic
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;
