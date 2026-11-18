//! Compiles c/*.c into $OUT_DIR/bin, one program each, in parallel, with the compiler `cc` finds
//! (the devshell's gcc). A few need their own link: the hostile loader tests' interpreter and
//! constructor library, and the library dlopen_test loads from inside and outside the allowed
//! paths ($OUT_DIR/denied is outside them).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, thread};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("c");
    let bin = out.join("bin");
    let denied = out.join("denied");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&denied).unwrap();
    println!("cargo:rerun-if-changed=c");
    println!("cargo:rustc-env=EXOBOX_FIXTURES={}", out.display());

    let cc = cc::Build::new().get_compiler();
    let common = ["-O2", "-g", "-Wall", "-pthread"];
    let interp = bin.join("evil_interp");

    // The libraries first: programs link against them.
    let libs: Vec<(String, PathBuf, Vec<String>)> = vec![
        // -ffreestanding: no library calls substituted for loops (GCC turns a strlen loop into a call to
        // strlen, through a PLT that nothing relocates here).
        ("evil_interp".into(), interp.clone(), args(&["-nostdlib", "-ffreestanding", "-shared", "-fPIC", "-fno-stack-protector", "-Wl,-e,_start"])),
        ("ctor_escape".into(), bin.join("libctor_escape.so"), args(&["-shared", "-fPIC"])),
        ("plug".into(), bin.join("libplug.so"), args(&["-shared", "-fPIC"])),
    ];
    run_all(&cc, &src, &common, libs);
    fs::copy(bin.join("libplug.so"), denied.join("libplug.so")).unwrap();

    let special = ["evil_interp", "ctor_escape", "plug"];
    let programs = fs::read_dir(&src)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            let stem = p.file_stem()?.to_str()?.to_owned();
            (p.extension()? == "c" && !special.contains(&stem.as_str())).then_some(stem)
        })
        .map(|name| {
            let extra = match name.as_str() {
                "interp_victim" => vec![format!("-Wl,--dynamic-linker={}", interp.display())],
                "ctor_victim" => vec![
                    format!("-L{}", bin.display()),
                    "-lctor_escape".into(),
                    "-Wl,-rpath,$ORIGIN".into(),
                ],
                _ => vec![],
            };
            let dst = bin.join(&name);
            (name, dst, extra)
        })
        .collect();
    run_all(&cc, &src, &common, programs);
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn run_all(cc: &cc::Tool, src: &Path, common: &[&str], jobs: Vec<(String, PathBuf, Vec<String>)>) {
    thread::scope(|s| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|(name, dst, extra)| {
                s.spawn(move || {
                    let mut cmd: Command = cc.to_command();
                    cmd.args(common).arg("-o").arg(&dst).arg(src.join(format!("{name}.c")));
                    // Link options after the source, so -l finds what the source needs.
                    cmd.args(&extra);
                    let o = cmd.output().unwrap_or_else(|e| panic!("{name}: {e}"));
                    if !o.status.success() {
                        panic!("{name}: {}\n{}", o.status, String::from_utf8_lossy(&o.stderr));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}
