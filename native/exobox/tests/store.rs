//! The store's host side (src/store.rs): closures from Nix, and the image cache. Store images
//! are cached in one directory for the whole test run (`shared_cache`), so only the first test
//! to need an image pays for it; tests about building use caches of their own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Barrier;
use std::{env, fs, thread};

use exobox::store::{self, Cache, Closure, Error};
use exobox_fixtures as fx;

fn bash() -> PathBuf {
    env::var_os("EXOBOX_TEST_BASH").expect("EXOBOX_TEST_BASH (run in the devshell: ./test)").into()
}

/// The store path a path is in: `/nix/store/<hash>-<name>`.
fn store_path(p: &Path) -> PathBuf {
    p.ancestors().find(|a| a.parent() == Some(Path::new(store::STORE_DIR))).unwrap().to_owned()
}

/// The glibc store path: the one with `lib/libc.so.6`.
fn glibc(set: &BTreeSet<PathBuf>) -> Option<&PathBuf> {
    set.iter().find(|p| p.to_string_lossy().contains("-glibc-") && p.join("lib/libc.so.6").exists())
}

fn shared_cache() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("image-cache")
}

/// fsck.erofs (erofs-utils, in the devshell) accepts the image.
fn fsck(image: &Path) {
    let out = Command::new("fsck.erofs").arg(image).output().expect("fsck.erofs (devshell)");
    assert!(out.status.success(), "fsck.erofs {}: {}", image.display(), String::from_utf8_lossy(&out.stderr));
}

#[test]
fn bash_closure_has_bash_and_glibc() {
    let c = store::closure(&bash(), &[]).unwrap();
    assert!(c.store.contains(&store_path(&bash())), "{c:?}");
    assert!(glibc(&c.store).is_some(), "no glibc in {c:?}");
    assert!(c.host.is_empty());
}

#[test]
fn fixture_closure_has_its_glibc_and_its_dir() {
    // hello is outside the store: its references come from scanning the allowed directory (its
    // PT_INTERP and RUNPATH name glibc's store path).
    let c = store::closure(&fx::bin("hello"), &[fx::bin_dir()]).unwrap();
    assert!(glibc(&c.store).is_some(), "no glibc in {c:?}");
    let dir = fs::canonicalize(fx::bin_dir()).unwrap();
    assert_eq!(c.host, BTreeSet::from([dir.clone()]));

    let config = exobox::Config {
        argv: vec![fx::bin("hello").into()],
        allow_paths: vec![fx::bin_dir()],
        image_cache: Some(shared_cache()),
        ..Default::default()
    };
    let s = exobox::store(&config).unwrap();
    let own = s.mounts.iter().find(|m| m.guest == dir).expect("the fixtures dir's image");
    fsck(&own.image);
    let layout = fs::read_to_string(&own.layout).unwrap();
    assert!(layout.lines().any(|l| l.ends_with(" elf hello")), "{layout}");
    assert_eq!(s.mounts.len(), c.store.len() + 1);
}

#[test]
fn second_call_builds_nothing() {
    let c = store::closure(&bash(), &[]).unwrap();
    let first = Cache::new(&shared_cache()).images(&c).unwrap();
    let mtimes = |s: &store::Store| -> Vec<_> {
        s.mounts.iter().map(|m| fs::metadata(&m.image).unwrap().modified().unwrap()).collect()
    };
    let before = mtimes(&first);
    let cache = Cache::new(&shared_cache());
    let second = cache.images(&c).unwrap();
    assert_eq!(cache.builds(), 0);
    assert_eq!(first, second);
    assert_eq!(before, mtimes(&second));
    let bash_mount = second.mounts.iter().find(|m| m.guest == store_path(&bash())).unwrap();
    assert!(bash_mount.layout.exists());
}

#[test]
fn editing_a_host_dir_rebuilds_only_its_image() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    for d in [&a, &b] {
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("sub/f"), "one").unwrap();
    }
    let closure = Closure { store: BTreeSet::new(), host: BTreeSet::from([a.clone(), b.clone()]) };
    let cache_dir = tmp.path().join("cache");
    let images = |builds: usize| {
        let cache = Cache::new(&cache_dir);
        let s = cache.images(&closure).unwrap();
        assert_eq!(cache.builds(), builds);
        s
    };
    let first = images(2);
    assert_eq!(images(0), first);
    fs::write(a.join("sub/f"), "two!").unwrap();
    let edited = images(1);
    assert_ne!(edited.mounts[0].image, first.mounts[0].image, "a's image rebuilt under a new key");
    assert_eq!(edited.mounts[1], first.mounts[1], "b's image kept");
    fsck(&edited.mounts[0].image);
}

#[test]
fn racing_builders_agree() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = store_path(&bash());
    let barrier = Barrier::new(2);
    let mounts: Vec<_> = thread::scope(|s| {
        let racers: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    let cache = Cache::new(tmp.path());
                    barrier.wait();
                    cache.store_image(&sp).unwrap()
                })
            })
            .collect();
        racers.into_iter().map(|r| r.join().unwrap()).collect()
    });
    assert_eq!(mounts[0], mounts[1]);
    fsck(&mounts[0].image);
    // No temporary files left behind, whoever won.
    let dir = mounts[0].image.parent().unwrap();
    let left: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(left.len(), 2, "{left:?}");
}

#[test]
fn missing_paths_are_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope");
    assert!(matches!(store::closure(&missing, &[]), Err(Error::Io { .. })));
    assert!(matches!(store::closure(&bash(), &[missing]), Err(Error::Io { .. })));
    // A well-formed store path that isn't there.
    let fake = PathBuf::from("/nix/store/00000000000000000000000000000000-nope/bin/nope");
    assert!(matches!(store::closure(&fake, &[]), Err(Error::Io { .. })));
}

#[test]
fn a_program_outside_the_store_needs_an_allowed_dir() {
    assert!(matches!(store::closure(&fx::bin("hello"), &[]), Err(Error::ProgramNotAllowed(_))));
    assert!(matches!(store::closure(&bash(), &["/nix".into()]), Err(Error::WholeStore(_))));
}

