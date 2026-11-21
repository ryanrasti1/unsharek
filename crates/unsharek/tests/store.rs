//! The store's host side (src/store.rs): closures from Nix, and the image cache. Store images
//! are cached in one directory for the whole test run (`shared_cache`), so only the first test
//! to need an image pays for it; tests about building use caches of their own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Barrier;
use std::{env, fs, thread};

use unsharek::store::{self, Cache, Closure, Error};
use unsharek_fixtures as fx;

fn bash() -> PathBuf {
    env::var_os("UNSHAREK_TEST_BASH").expect("UNSHAREK_TEST_BASH (run in the devshell: cargo xtask test)").into()
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

    let s = store::Cache::new(&shared_cache()).closures(&[fx::bin_dir()]).unwrap();
    let own = s.mounts.iter().find(|m| m.guest == dir).expect("the fixtures dir's image");
    fsck(&own.image);
    let layout = fs::read_to_string(&own.layout).unwrap();
    assert!(layout.lines().any(|l| l.ends_with(" elf hello")), "{layout}");
    assert_eq!(s.mounts.len(), c.store.len() + 1);
    // The CLI's --closure of the directory: the store paths it references, and no image of its
    // own (the directory is --ro's to show, live).
    let config = unsharek::Config { closures: vec![fx::bin_dir()], image_cache: Some(shared_cache()), ..Default::default() };
    let refs = unsharek::store(&config).unwrap();
    assert!(refs.mounts.iter().all(|m| m.guest != dir), "the directory imaged");
    assert_eq!(refs.mounts.len(), c.store.len());
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

/// `Cache::closure` answers from its lists once made: a store query per set of roots, a scan per
/// state of a host tree. Shown by editing the lists by hand: the edit is what comes back, until
/// the tree changes (a new key) or a list is cut short (made again).
#[test]
fn closures_are_cached() {
    let tmp = tempfile::tempdir().unwrap();
    let xz = store_path(&PathBuf::from(env::var_os("UNSHAREK_TEST_XZ").expect("UNSHAREK_TEST_XZ (devshell)")));
    let tree = tmp.path().join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("script"), format!("#!/bin/sh\nexec {}/bin/xz\n", xz.display())).unwrap();
    let allow = std::slice::from_ref(&tree);
    let cache = Cache::new(&tmp.path().join("cache"));
    let first = cache.closure(&bash(), allow).unwrap();
    assert_eq!(first, store::closure(&bash(), allow).unwrap());
    assert!(first.store.contains(&xz), "{first:?}");

    let list = |sub: &str| -> PathBuf {
        let dir = tmp.path().join(format!("cache/v{}/{sub}", unsharek_erofs::FORMAT_VERSION));
        let mut v: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        v.retain(|p| sub != "host" || p.to_string_lossy().ends_with(".refs"));
        assert_eq!(v.len(), 1, "{v:?}");
        v.pop().unwrap()
    };
    let (requisites, refs) = (list("requisites"), list("host"));
    const EMPTY: &str = "unsharek list v1\nend\n";
    // The tree's references emptied: xz is no root any more (and those roots aren't cached).
    let refs_text = fs::read_to_string(&refs).unwrap();
    fs::write(&refs, EMPTY).unwrap();
    assert!(!cache.closure(&bash(), allow).unwrap().store.contains(&xz));
    // The first roots' list with glibc taken out: what the first roots get.
    fs::write(&refs, &refs_text).unwrap();
    let text = fs::read_to_string(&requisites).unwrap();
    let edited: String = text.lines().filter(|l| !l.contains("-glibc-")).map(|l| format!("{l}\n")).collect();
    fs::write(&requisites, &edited).unwrap();
    assert!(glibc(&cache.closure(&bash(), allow).unwrap().store).is_none());
    // Cut short (no `end`), it is made again.
    fs::write(&requisites, &text[..text.len() - 4]).unwrap();
    assert_eq!(cache.closure(&bash(), allow).unwrap(), first);
    // A tree that changed is scanned again, whatever its old list said.
    fs::write(&refs, EMPTY).unwrap();
    fs::write(tree.join("other"), "x").unwrap();
    assert_eq!(cache.closure(&bash(), allow).unwrap().store, first.store);
}

