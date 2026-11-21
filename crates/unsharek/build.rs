//! Links the `unsharek` binary as a position-dependent executable at a fixed address far above the
//! arena (`lib.rs`'s `ARENA_AT`, with the images' zone after it): `unsharek-build`'s
//! `link_fixed_address`, which says why and how (and which an embedder's build script calls too).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    unsharek_build::link_fixed_address();
    pty_init();
}

/// src/pty_init.c, the guest's init on a terminal (src/pty.rs, which embeds it): no libc, a
/// static PIE with nothing to relocate.
fn pty_init() {
    println!("cargo:rerun-if-changed=src/pty_init.c");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("pty_init");
    let cc = cc::Build::new().get_compiler();
    let status = cc
        .to_command()
        .args(["-O2", "-nostdlib", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-static-pie", "-fPIE", "-o"])
        .arg(&out)
        .arg("src/pty_init.c")
        .status()
        .expect("the C compiler");
    assert!(status.success(), "src/pty_init.c didn't build");
}
