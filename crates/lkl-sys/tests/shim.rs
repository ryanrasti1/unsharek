//! shim.c's lkl_printf, as the kernel calls it: formatted in C, handed to the binary's
//! `exobox_lkl_print`. No posix host here, so shim.c's definitions are the ones linked.

use core::ffi::{c_char, c_ulong};
use std::sync::Mutex;

use lkl_sys::lkl_printf;

static PRINTED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

#[unsafe(no_mangle)]
extern "C" fn exobox_lkl_print(s: *const c_char, len: c_ulong) {
    // SAFETY: shim.c passes its buffer and the length it formatted.
    let bytes = unsafe { core::slice::from_raw_parts(s.cast::<u8>(), len as usize) };
    PRINTED.lock().unwrap().extend_from_slice(bytes);
}

#[unsafe(no_mangle)]
extern "C" fn exobox_lkl_panic() -> ! {
    std::process::abort()
}

#[test]
fn printf_formats_and_hands_over() {
    // SAFETY: the format's arguments match it.
    let n = unsafe { lkl_printf(c"%s: %d\n".as_ptr(), c"lkl_sys_open /dev".as_ptr(), -2) };
    assert_eq!(&*PRINTED.lock().unwrap(), b"lkl_sys_open /dev: -2\n");
    assert_eq!(n, 22);

    // Longer than shim.c's buffer: cut to 511 bytes, the full length returned.
    PRINTED.lock().unwrap().clear();
    let long = std::ffi::CString::new("x".repeat(600)).unwrap();
    // SAFETY: as above.
    let n = unsafe { lkl_printf(c"%s".as_ptr(), long.as_ptr()) };
    assert_eq!(n, 600);
    assert_eq!(PRINTED.lock().unwrap().len(), 511);
}
