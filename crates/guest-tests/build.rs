//! The C the tests need where Rust can't go: c/longjmp.c (sigsetjmp and a handler's siglongjmp).
fn main() {
    println!("cargo:rerun-if-changed=c/longjmp.c");
    // -O2: the devshell's _FORTIFY_SOURCE warns without optimization.
    cc::Build::new().file("c/longjmp.c").opt_level(2).warnings(true).compile("guest_tests_c");
}
