//! The program on a terminal of the guest's own: for a CLI whose stdin is a terminal
//! ([`Config::tty`](crate::Config::tty)). The host terminal can't be asked anything after
//! lockdown (no `ioctl` through the filter), so the program's stdio is the slave of a pty from
//! the guest's devpts instead, its session's controlling terminal, at the host terminal's size:
//! the guest kernel's tty layer does echo, line editing, job control and ^C. The guest's init is
//! a small program of unsharek's (`pty_init.c`) that makes the pty, starts the program on it and
//! copies between the host's stdio (fds 0 and 1, read and written as granted) and the master,
//! until the program's end, whose status it ends with.
//!
//! Fork mode only: the program is a process of its own (init's child), a session leader. The
//! host terminal in raw mode, and back afterwards, is the CLI's (`cli/tty.rs`), outside the
//! sandbox.

use std::ffi::OsString;
use std::path::Path;

/// A terminal's size, as the host's reported it before lockdown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

/// The guest's init on a terminal, built by build.rs.
const PTY_INIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pty_init"));

/// Where in the guest it is put: the guest's own `/dev` (its tmpfs), nothing of the host's.
const AT: &str = "/dev/.unsharek-pty-init";

/// In a setup closure (the guest's init, before lockdown): the helper put in the guest.
pub fn install() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(AT, PTY_INIT)?;
    std::fs::set_permissions(AT, std::fs::Permissions::from_mode(0o755))
}

/// The argv that runs `argv` on a pty of `size`: the helper's, `argv` after it.
pub fn argv(argv: &[OsString], size: Size) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![Path::new(AT).into(), size.rows.to_string().into(), size.cols.to_string().into()];
    a.extend(argv.iter().cloned());
    a
}
