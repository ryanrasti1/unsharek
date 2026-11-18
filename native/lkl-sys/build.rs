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
    // lkl.o alone (lkl/Makefile): it needs nothing from libc, only lkl_printf and lkl_bug, which
    // the host side defines (tools/lkl/lib/utils.c does, for the posix host).
    println!("cargo:rustc-link-lib=static=lkl-kernel");
    // lkl.o has no .note.GNU-stack, which to ld means "needs an executable stack". rustc links with
    // `-z noexecstack`, so a Rust binary's stack stays RW; a C program linking it must say so too.

    // GCC 16 emits `push sym@GOTPCREL(%rip)` (a function pointer passed on the stack) with an
    // R_X86_64_GOTPCRELX relocation, and ld 2.46 relaxes that `ff /6` as if it were an indirect
    // call, into `addr32 call sym`: the kernel calls the function instead of passing it. Four
    // sites in LKL (udp_setsockopt, which Go's resolver reaches; inet_ehashfn passed in the TCP
    // lookups: inet_lhash2_lookup, __inet_lookup_listener, tcp_v4_rcv). Found in capnix tier A.
    // `rustc-link-arg` only reaches this package's own links (the smoke test); a binary linking
    // lkl-sys forwards DEP_LKL_LINK_ARGS from its build.rs, and runs the same check (tests/boot.rs).
    // The cost, GOT loads instead of lea for global addresses, did not show in tier A's benchmark.
    // On stock LKL (d0f76a77e) with the devshell's toolchain the four GOT pushes are in lkl.o but
    // ld leaves them alone (`push GOT(%rip)` in a PIE, `push $imm` without), with or without
    // --no-relax; kept until the tier A case is understood, the check costs half a second.
    println!("cargo:rustc-link-arg=-Wl,--no-relax");
    println!("cargo:link_args=-Wl,--no-relax");

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
        .allowlist_function("lkl_(init|start_kernel|cleanup|is_running|syscall|sys_halt)")
        .allowlist_type("lkl_host_operations|lkl_jmp_buf|lkl_thread_t")
        .allowlist_var("__lkl__NR_.*")
        .parse_callbacks(Box::new(SyscallNumbersAreLong))
        .generate()
        .expect("bindgen: lkl.h");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("bindings.rs");
}
