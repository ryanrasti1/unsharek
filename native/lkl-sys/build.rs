//! Builds the kernel (lkl/Makefile, incrementally), links its object, and generates the bindings.
//!
//! The kernel's source is the commit flake.lock pins for the `linux` input (the one `nix build`
//! links), or the one `EXOBOX_LKL_REF` names, in the repository `EXOBOX_LKL_REPO` (default
//! /home/ryan/src/lkl-linux), which lkl/Makefile extracts into `<target>/lkl-src`; or, for work on
//! the kernel, a checkout named by `EXOBOX_LKL_SRC`, as it is on disk. It is configured by lkl/defconfig and, after it, the fragment `EXOBOX_LKL_CONFIG`
//! names (a file of config lines; relative to the workspace's root, or absolute). Its build lives in
//! `<target>/lkl`, shared by every profile and by clippy: the kernel doesn't depend on Rust's build
//! settings.
//!
//! `EXOBOX_LKL_PREBUILT=<dir>` instead takes a finished kernel build (lkl/Makefile's `install`;
//! flake.nix's `lib.exoboxKernel`) and runs no make: the Nix build makes the kernel once, as its
//! own derivation, and the Rust build only links it.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// lkl/Makefile's default EXOBOX_LKL_REPO (needed here only to watch its refs, for
/// EXOBOX_LKL_REF).
const DEFAULT_REPO: &str = "/home/ryan/src/lkl-linux";

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
    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_REPO");
    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_REF");
    println!("cargo:rerun-if-env-changed=EXOBOX_LKL_CONFIG");
    println!("cargo:rerun-if-changed=wrapper.h");
    let kernel = match env::var_os("EXOBOX_LKL_PREBUILT").filter(|d| !d.is_empty()) {
        Some(dir) => prebuilt(PathBuf::from(dir)),
        None => build(&manifest, &out_dir),
    };

    println!("cargo:rustc-link-search=native={}", kernel.lib.display());
    // lkl.o alone (lkl/Makefile). It needs nothing from libc: only lkl_printf and lkl_bug, from
    // shim.c below. Built so that no linker can mis-relax it and with its stack note (both in
    // lkl/Makefile): a binary links it with no special flags.
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

/// A kernel built elsewhere, in lkl/Makefile's `install` layout: the archives and lkl.o at the top,
/// lkl.h and the generated headers merged in include/.
fn prebuilt(dir: PathBuf) -> Kernel {
    // Its config is the one it was built with: a fragment here would be silently ignored.
    assert!(
        env::var_os("EXOBOX_LKL_CONFIG").is_none_or(|c| c.is_empty()),
        "EXOBOX_LKL_CONFIG configures a kernel build; EXOBOX_LKL_PREBUILT is one already made"
    );
    assert!(
        dir.join("liblkl-kernel.a").is_file(),
        "EXOBOX_LKL_PREBUILT={}: no liblkl-kernel.a (made by `make -C lkl install PREFIX=...`)",
        dir.display()
    );
    println!("cargo:rerun-if-changed={}", dir.display());
    Kernel {
        include: vec![dir.join("include")],
        lib: dir,
    }
}

/// The kernel built here, by lkl/Makefile: incremental, into `<target>/lkl`.
fn build(manifest: &Path, out_dir: &Path) -> Kernel {
    let root = manifest.join("../..").canonicalize().unwrap();
    let lkl_dir = root.join("lkl");
    // OUT_DIR is <target>/<profile>/build/lkl-sys-<hash>/out.
    let kout = out_dir.ancestors().nth(4).unwrap().join("lkl");
    let checkout = env::var_os("EXOBOX_LKL_SRC")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
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
    let src = match &checkout {
        // The whole checkout, so a kernel change is rebuilt by the next `./test`. cargo compares
        // the newest mtime under it with the last run: a walk of the whole tree, yet a no-op
        // `cargo build` stays ~0.1 s. kbuild then decides what to recompile.
        Some(src) => {
            println!("cargo:rerun-if-changed={}", src.display());
            src.clone()
        }
        // The commit flake.lock pins: it changes only with flake.lock (a kernel bump).
        None if env::var_os("EXOBOX_LKL_REF").is_none_or(|r| r.is_empty()) => {
            println!("cargo:rerun-if-changed={}", root.join("flake.lock").display());
            // lkl/Makefile's $(KOUT)-src.
            kout.with_file_name("lkl-src")
        }
        // A ref, followed while working on the kernel: its moving is seen as a change under the
        // repository's refs/ or packed-refs (any ref's: then the make, finding the same commit, is
        // a no-op of ~3.5 s). Where they are is asked of git (a non-bare repository keeps them in
        // .git, a worktree in its common dir).
        None => {
            let repo = env::var_os("EXOBOX_LKL_REPO").unwrap_or(DEFAULT_REPO.into());
            let out = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
                .output()
                .expect("git");
            assert!(
                out.status.success(),
                "EXOBOX_LKL_REPO={}: not a git repository",
                Path::new(&repo).display()
            );
            let git_dir = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
            println!("cargo:rerun-if-changed={}", git_dir.join("refs").display());
            if git_dir.join("packed-refs").exists() {
                println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());
            }
            // lkl/Makefile's $(KOUT)-src.
            kout.with_file_name("lkl-src")
        }
    };

    make(&lkl_dir, checkout.as_deref(), config.as_deref(), &kout);
    // <target>/lkl is shared by every lkl-sys build script (each profile, and `-p lkl-sys` alone
    // has another hash than the workspace's), which keeps its bindings in its own OUT_DIR. When
    // one builds the kernel from another source or config, the others must run again, or they
    // would link that kernel with their old bindings. lkl/Makefile writes these stamps only when
    // they change (so after a change each script runs once more, finding nothing to do).
    let mut stamps = vec![
        kout.join(".exobox_defconfig.sha256"),
        kout.join(".exobox_lkl_src"),
    ];
    if checkout.is_none() {
        stamps.push(kout.with_file_name("lkl-src.commit"));
    }
    for stamp in stamps {
        println!("cargo:rerun-if-changed={}", stamp.display());
    }
    Kernel {
        // The generated headers (lkl/, lkl_autoconf.h) are in the build; lkl.h is in the source.
        include: vec![kout.join("tools/lkl/include"), src.join("tools/lkl/include")],
        lib: kout,
    }
}

/// EXOBOX_LKL_REPO and EXOBOX_LKL_REF reach the Makefile from the environment.
fn make(lkl_dir: &Path, checkout: Option<&Path>, config: Option<&Path>, kout: &Path) {
    let mut cmd = Command::new("timeout");
    // Bounded like everything else: a cold build is well under a minute on 24 cores.
    cmd.args(["600", "make", "-C"]).arg(lkl_dir);
    if let Some(src) = checkout {
        cmd.arg(format!("EXOBOX_LKL_SRC={}", src.display()));
    }
    cmd.arg(format!("KOUT={}", kout.display()));
    if let Some(config) = config {
        cmd.arg(format!("EXOBOX_LKL_CONFIG={}", config.display()));
    }
    // cargo's jobserver, so the kernel shares the machine with the crates building beside it.
    if let Some(flags) = env::var_os("CARGO_MAKEFLAGS") {
        cmd.env("MAKEFLAGS", flags);
    }
    // kbuild's progress goes to the build script's log (target/.../output), not cargo's output.
    let status = cmd.status().expect("make (lkl/Makefile)");
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
