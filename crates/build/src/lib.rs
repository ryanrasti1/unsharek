//! For a binary that embeds exobox: its build script links it the way the `exobox` CLI is linked,
//! as a position-dependent executable (`ET_EXEC`) at a fixed address far above the sandbox's
//! arena. One call from `build.rs`:
//!
//! ```no_run
//! // build.rs of a crate whose binaries embed exobox (with `exobox-build` a build-dependency),
//! // in its `fn main()`:
//! exobox_build::link_fixed_address();
//! ```
//!
//! **Why.** As a PIE, ld.so writes ~17,900 relative relocations into the binary's writable
//! segment at every start (the kernel's ops tables and GOT, Rust's vtables): 400 KB of pages
//! copied and dirtied in each sandbox (of an idle one's ~4.7 MB), where a fixed address leaves
//! them the file's, shared by every sandbox. Nothing is lost to the program inside: it shares
//! the address space with the runtime anyway, and the boundary is the filter, not where the
//! runtime sits.
//!
//! **How.** The code stays position-independent (rustc's default `pic`; the kernel object is too),
//! only the link changes: `-no-pie` at [`TEXT_AT`]. `-no-pie` alone would bring GCC's non-PIE
//! start files, whose `crtbegin.o` holds 32-bit absolute addresses that can't reach `TEXT_AT`; the
//! PIE ones (`Scrt1.o`, `crtbeginS.o`, `crtendS.o`) are position-independent and work at any
//! address, so they are named instead (`-nostartfiles`). If the compiler can't name them, the
//! binaries are linked as PIEs, as they would be without this (a cargo warning says so).
//!
//! It applies to the crate's binaries (`cargo:rustc-link-arg-bins`), not its tests or examples.

use std::path::PathBuf;
use std::process::Command;

/// Where the binary's first segment goes: above the arena and its image zone (tens of GiB from
/// 2 MiB: exobox's `ARENA_AT`), below where the kernel puts mappings and the stack (near 128 TiB).
pub const TEXT_AT: &str = "0x500000000000";

/// Print the link arguments for the calling build script's crate's binaries (module comment).
pub fn link_fixed_address() {
    let cc = cc::Build::new().cargo_metadata(false).get_compiler();
    let find = |name: &str| -> Option<PathBuf> {
        let out = Command::new(cc.path()).arg(format!("-print-file-name={name}")).output().ok()?;
        let p = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
        // An unknown file is printed back as given.
        p.is_absolute().then_some(p)
    };
    let first = ["Scrt1.o", "crti.o", "crtbeginS.o"];
    let last = ["crtendS.o", "crtn.o"];
    let (Some(first), Some(last)) = (
        first.iter().map(|n| find(n)).collect::<Option<Vec<_>>>(),
        last.iter().map(|n| find(n)).collect::<Option<Vec<_>>>(),
    ) else {
        println!("cargo:warning=no PIE start files from {}: linked as a PIE", cc.path().display());
        return;
    };
    for arg in ["-no-pie", "-nostartfiles", &format!("-Wl,-Ttext-segment={TEXT_AT}")] {
        println!("cargo:rustc-link-arg-bins={arg}");
    }
    // rustc puts these after its own objects: crti/crtn's .init halves still bracket every other
    // .init piece (Rust and the kernel have none), and the start files' order among themselves
    // is the driver's.
    for f in first.iter().chain(&last) {
        println!("cargo:rustc-link-arg-bins={}", f.display());
    }
}
