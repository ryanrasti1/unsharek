//! Builds the kernel (lkl/Makefile, incrementally), links its object, and generates the bindings.
//!
//! The kernel's source is a checkout named by `EXOBOX_LKL_SRC` (default: the exobox/native
//! worktree). Its build lives in `<target>/lkl`, shared by every profile and by clippy: the kernel
//! doesn't depend on Rust's build settings.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_SRC: &str = "/home/ryan/src/lkl-exobox";

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lkl_dir = manifest.join("../../lkl").canonicalize().unwrap();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // OUT_DIR is <target>/<profile>/build/lkl-sys-<hash>/out.
    let kout = out_dir.ancestors().nth(4).unwrap().join("lkl");
    let src = PathBuf::from(env::var("EXOBOX_LKL_SRC").unwrap_or_else(|_| DEFAULT_SRC.into()));

    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_SRC");
    println!(
        "cargo:rerun-if-changed={}",
        lkl_dir.join("Makefile").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        lkl_dir.join("defconfig").display()
    );
    println!("cargo:rerun-if-changed=wrapper.h");
    // The whole checkout, so a kernel change is rebuilt by the next `./test`. cargo compares the
    // newest mtime under it with the last run: a walk of the whole tree, yet a no-op `cargo build`
    // stays ~0.1 s. kbuild then decides what to recompile.
    println!("cargo:rerun-if-changed={}", src.display());

    make(&lkl_dir, &src, &kout);

    println!("cargo:rustc-link-search=native={}", kout.display());
    // lkl.o alone (lkl/Makefile). It needs nothing from libc: only lkl_printf and lkl_bug, from
    // shim.c below. Built so that no linker can mis-relax it and with its stack note (both in
    // lkl/Makefile): a binary links it with no special flags.
    println!("cargo:rustc-link-lib=static=lkl-kernel");
    // For tests/boot.rs's relocation check.
    println!(
        "cargo:rustc-env=LKL_KERNEL_OBJ={}",
        kout.join("lkl.o").display()
    );

    println!("cargo:rerun-if-changed=shim.c");
    cc::Build::new()
        .file("shim.c")
        // Always optimized: glibc's _FORTIFY_SOURCE (the devshell's hardening) wants -O.
        .opt_level(2)
        .warnings(true)
        .compile("lkl-shim");

    bindings(&manifest, &src, &kout, &out_dir);
}

fn make(lkl_dir: &Path, src: &Path, kout: &Path) {
    let mut cmd = Command::new("timeout");
    // Bounded like everything else: a cold build is well under a minute on 24 cores.
    cmd.args(["600", "make", "-C"]).arg(lkl_dir);
    cmd.arg(format!("EXOBOX_LKL_SRC={}", src.display()));
    cmd.arg(format!("KOUT={}", kout.display()));
    // cargo's jobserver, so the kernel shares the machine with the crates building beside it.
    if let Some(flags) = env::var_os("CARGO_MAKEFLAGS") {
        cmd.env("MAKEFLAGS", flags);
    }
    // kbuild's progress goes to the build script's log (target/.../output), not cargo's output.
    let status = cmd.status().expect("make (lkl/Makefile)");
    assert!(status.success(), "the kernel build failed: {status}");
}

fn bindings(manifest: &Path, src: &Path, kout: &Path, out_dir: &Path) {
    #[derive(Debug)]
    struct SyscallNumbersAreLong;
    impl bindgen::callbacks::ParseCallbacks for SyscallNumbersAreLong {
        // lkl_syscall takes the number as a `long`.
        fn int_macro(&self, name: &str, _: i64) -> Option<bindgen::callbacks::IntKind> {
            name.starts_with("__lkl__NR_")
                .then_some(bindgen::callbacks::IntKind::Long)
        }
    }

    let bindings = bindgen::Builder::default()
        .header(manifest.join("wrapper.h").to_str().unwrap())
        // The generated headers (lkl/, lkl_autoconf.h) are in the build; lkl.h is in the source.
        .clang_arg(format!("-I{}", kout.join("tools/lkl/include").display()))
        .clang_arg(format!("-I{}", src.join("tools/lkl/include").display()))
        .use_core()
        .rust_edition(bindgen::RustEdition::Edition2024)
        // What lkl.o defines and the host-operations table, nothing of the uapi beyond them.
        .allowlist_function(
            "lkl_(init|start_kernel|cleanup|is_running|syscall|sys_halt|printf|bug)",
        )
        .allowlist_type("lkl_host_operations|lkl_jmp_buf|lkl_thread_t")
        .allowlist_var("__lkl__NR_.*")
        .parse_callbacks(Box::new(SyscallNumbersAreLong))
        .generate()
        .expect("bindgen: lkl.h");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("bindings.rs");
}
