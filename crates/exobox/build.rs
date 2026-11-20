//! Links the `exobox` binary as a position-dependent executable at a fixed address far above the
//! arena (`lib.rs`'s `ARENA_AT`, with the images' zone after it): `exobox-build`'s
//! `link_fixed_address`, which says why and how (and which an embedder's build script calls too).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    exobox_build::link_fixed_address();
}
