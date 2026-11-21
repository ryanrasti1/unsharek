//! **An interactive terminal.** When the CLI's stdin is a terminal: the sandbox runs as a child,
//! and this process stays outside it as its supervisor, because the sandbox can make no `ioctl`
//! of the host terminal after lockdown. The supervisor puts the terminal in raw mode (the guest's
//! own pty does echo, editing and signals: `unsharek::pty`), waits for the sandbox, puts the
//! terminal back as it was, and ends as the sandbox ended (its status, or its signal again).
//! ^C, ^Z and ^\ are bytes for the guest while the terminal is raw; the supervisor ignores the
//! signals they'd raise besides.
//!
//! The size is the terminal's at the start; a resize later isn't passed on (yet).

use std::os::fd::RawFd;

const STDIN: RawFd = 0;

/// Whether stdin is a terminal.
pub fn is_tty() -> bool {
    // SAFETY: isatty of fd 0.
    unsafe { libc::isatty(STDIN) == 1 }
}

/// Fork: the child returns the terminal's size, to become the sandbox; the parent supervises
/// and never returns. Before the sandbox boots (this process has one thread).
pub fn supervise() -> unsharek::pty::Size {
    // SAFETY: the terminal's settings and size into locals; fork with one thread; the parent's
    // calls are on the terminal and its child only.
    unsafe {
        let mut saved: libc::termios = std::mem::zeroed();
        let have = libc::tcgetattr(STDIN, &mut saved) == 0;
        let mut ws: libc::winsize = std::mem::zeroed();
        libc::ioctl(STDIN, libc::TIOCGWINSZ, &mut ws);
        let size = unsharek::pty::Size { rows: ws.ws_row, cols: ws.ws_col };
        let pid = libc::fork();
        if pid < 0 {
            // No supervisor: the sandbox runs on the terminal as it is.
            return size;
        }
        if pid == 0 {
            return size;
        }
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTOU, libc::SIGTTIN] {
            libc::signal(sig, libc::SIG_IGN);
        }
        if have {
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(STDIN, libc::TCSANOW, &raw);
        }
        let mut st = 0;
        while libc::waitpid(pid, &mut st, 0) < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {}
        if have {
            libc::tcsetattr(STDIN, libc::TCSANOW, &saved);
        }
        if libc::WIFSIGNALED(st) {
            let sig = libc::WTERMSIG(st);
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        libc::_exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 125 });
    }
}
