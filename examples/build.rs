//! Compiles c/*.c into $OUT_DIR/bin (the examples' own guest programs), with the compiler `cc`
//! finds (the devshell's gcc, whose glibc is a store path: the program's closure comes with it).

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bin");
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("c");
    fs::create_dir_all(&out).unwrap();
    println!("cargo:rerun-if-changed=c");
    println!("cargo:rustc-env=EXOBOX_EXAMPLES_C={}", out.display());
    let cc = cc::Build::new().get_compiler();
    for e in fs::read_dir(&src).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "c") {
            let dst = out.join(p.file_stem().unwrap());
            let o = cc.to_command().args(["-O2", "-Wall", "-o"]).arg(&dst).arg(&p).output().unwrap();
            assert!(o.status.success(), "{}: {}", p.display(), String::from_utf8_lossy(&o.stderr));
        }
    }
}
