//! The test programs build.rs compiled: `bin(name)` is one, `denied_dir()` holds a library outside
//! every allowed path.

use std::path::PathBuf;

const DIR: &str = env!("EXOBOX_FIXTURES");

/// The directory of every program and library; the suite's allowed path.
pub fn bin_dir() -> PathBuf {
    PathBuf::from(DIR).join("bin")
}

pub fn bin(name: &str) -> PathBuf {
    bin_dir().join(name)
}

pub fn denied_dir() -> PathBuf {
    PathBuf::from(DIR).join("denied")
}
