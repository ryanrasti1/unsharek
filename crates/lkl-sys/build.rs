//! Builds the kernel (crates/lkl-sys/Makefile, incrementally), links its object, and generates the bindings.
//!
//! The kernel's source is the submodule crates/lkl-sys/linux, as it is on disk (the one `nix build` links), or
//! another checkout named by `EXOBOX_LKL_SRC` (a worktree's, whose own submodule isn't checked out).
//! It is configured by crates/lkl-sys/defconfig and, after it, the fragment `EXOBOX_LKL_CONFIG`
//! names (a file of config lines; relative to the workspace's root, or absolute). Its build lives in
//! `<target>/lkl`, shared by every profile and by clippy: the kernel doesn't depend on Rust's build
//! settings.
//!
//! `EXOBOX_LKL_PREBUILT=<dir>` instead takes a finished kernel build (crates/lkl-sys/Makefile's `install`;
//! flake.nix's `lib.exoboxKernel`) and runs no make: the Nix build makes the kernel once, as its
//! own derivation, and the Rust build only links it.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a kernel build is, for the link and for bindgen.
struct Kernel {
    /// liblkl-kernel.a, liblkl-posix.a (tests/boot.rs) and lkl.o.
    lib: PathBuf,
    /// bindgen's -I directories: lkl.h's and the generated headers'.
    include: Vec<PathBuf>,
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_PREBUILT");
    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_SRC");
    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_CONFIG");
    println!("cargo:rerun-if-changed=wrapper.h");
    let kernel = match env::var_os("EXOBOX_LKL_PREBUILT").filter(|d| !d.is_empty()) {
        Some(dir) => prebuilt(PathBuf::from(dir)),
        None => build(&manifest, &out_dir),
    };

    println!("cargo:rustc-link-search=native={}", kernel.lib.display());
    // lkl.o alone (crates/lkl-sys/Makefile). It needs nothing from libc: only lkl_printf and lkl_bug, from
    // shim.c below. Built so that no linker can mis-relax it and with its stack note (both in
    // crates/lkl-sys/Makefile): a binary links it with no special flags.
    println!("cargo:rustc-link-lib=static=lkl-kernel");
    // For tests/boot.rs's relocation check.
    println!(
        "cargo:rustc-env=LKL_KERNEL_OBJ={}",
        kernel.lib.join("lkl.o").display()
    );

    println!("cargo:rerun-if-changed=shim.c");
    cc::Build::new()
        .file("shim.c")
        // Always optimized: glibc's _FORTIFY_SOURCE (the devshell's hardening) wants -O.
        .opt_level(2)
        .warnings(true)
        .compile("lkl-shim");

    bindings(&manifest, &kernel.include, &out_dir);
}

/// A kernel built elsewhere, in crates/lkl-sys/Makefile's `install` layout: the archives and lkl.o at the top,
/// lkl.h and the generated headers merged in include/.
fn prebuilt(dir: PathBuf) -> Kernel {
    // Its config is the one it was built with: a fragment here would be silently ignored.
    assert!(
        env::var_os("EXOBOX_LKL_CONFIG").is_none_or(|c| c.is_empty()),
        "EXOBOX_LKL_CONFIG configures a kernel build; EXOBOX_LKL_PREBUILT is one already made"
    );
    assert!(
        dir.join("liblkl-kernel.a").is_file(),
        "EXOBOX_LKL_PREBUILT={}: no liblkl-kernel.a (made by `make -C crates/lkl-sys install PREFIX=...`)",
        dir.display()
    );
    println!("cargo:rerun-if-changed={}", dir.display());
    Kernel {
        include: vec![dir.join("include")],
        lib: dir,
    }
}

/// The kernel built here, by crates/lkl-sys/Makefile: incremental, into `<target>/lkl`.
fn build(manifest: &Path, out_dir: &Path) -> Kernel {
    let root = manifest.join("../..").canonicalize().unwrap();
    // the Makefile, the defconfig and the submodule linux/ are this package's
    let lkl_dir = manifest.to_path_buf();
    // OUT_DIR is <target>/<profile>/build/lkl-sys-<hash>/out.
    let kout = out_dir.ancestors().nth(4).unwrap().join("lkl");
    let src = env::var_os("EXOBOX_LKL_SRC")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| lkl_dir.join("linux"));
    // Relative to the workspace's root, where `./test` and cargo are run from (build.rs runs in
    // the package's directory and the Makefile in lkl/: neither is the caller's).
    let config = env::var_os("EXOBOX_LKL_CONFIG")
        .filter(|c| !c.is_empty())
        .map(|c| root.join(c));

    println!(
        "cargo:rerun-if-changed={}",
        lkl_dir.join("Makefile").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        lkl_dir.join("defconfig").display()
    );
    // Its content: the Makefile's stamp hashes it, so an edit reconfigures the kernel.
    if let Some(config) = &config {
        println!("cargo:rerun-if-changed={}", config.display());
    }
    // The whole checkout, so a kernel change (a submodule bump, or work in it) is rebuilt by the
    // next `./test`. cargo compares the newest mtime under it with the last run: a walk of the
    // whole tree, yet a no-op `cargo build` stays ~0.1 s. kbuild then decides what to recompile.
    println!("cargo:rerun-if-changed={}", src.display());

    make(&lkl_dir, &src, config.as_deref(), &kout);
    // <target>/lkl is shared by every lkl-sys build script (each profile, and `-p lkl-sys` alone
    // has another hash than the workspace's), which keeps its bindings in its own OUT_DIR. When
    // one builds the kernel from another source or config, the others must run again, or they
    // would link that kernel with their old bindings. crates/lkl-sys/Makefile writes these stamps only when
    // they change (so after a change each script runs once more, finding nothing to do).
    for stamp in [kout.join(".exobox_defconfig.sha256"), kout.join(".exobox_lkl_src")] {
        println!("cargo:rerun-if-changed={}", stamp.display());
    }
    Kernel {
        // The generated headers (lkl/, lkl_autoconf.h) are in the build; lkl.h is in the source.
        include: vec![kout.join("tools/lkl/include"), src.join("tools/lkl/include")],
        lib: kout,
    }
}

fn make(lkl_dir: &Path, src: &Path, config: Option<&Path>, kout: &Path) {
    let mut cmd = Command::new("timeout");
    // Bounded like everything else: a cold build is well under a minute on 24 cores.
    cmd.args(["600", "make", "-C"]).arg(lkl_dir);
    cmd.arg(format!("EXOBOX_LKL_SRC={}", src.display()));
    cmd.arg(format!("KOUT={}", kout.display()));
    if let Some(config) = config {
        cmd.arg(format!("EXOBOX_LKL_CONFIG={}", config.display()));
    }
    // cargo's jobserver, so the kernel shares the machine with the crates building beside it.
    if let Some(flags) = env::var_os("CARGO_MAKEFLAGS") {
        cmd.env("MAKEFLAGS", flags);
    }
    // kbuild's progress goes to the build script's log (target/.../output), not cargo's output.
    let status = cmd.status().expect("make (crates/lkl-sys/Makefile)");
    assert!(status.success(), "the kernel build failed: {status}");
}

fn bindings(manifest: &Path, include: &[PathBuf], out_dir: &Path) {
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
        .clang_args(include.iter().map(|i| format!("-I{}", i.display())))
        .use_core()
        .rust_edition(bindgen::RustEdition::Edition2024)
        // What lkl.o defines and the host-operations table, nothing of the uapi beyond them.
        .allowlist_function(
            // lkl_net_*: the host's calls for networking (tsi.c); lkl_hostfd_ready: a host fd's
            // readiness for its guest file's pollers (hostfd.c)
            "lkl_(init|start_kernel|cleanup|is_running|syscall|sys_halt|printf|bug|net_.*|hostfd_ready)",
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
