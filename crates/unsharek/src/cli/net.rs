//! **Plugin (experimental): the network, through a provider process.** `--net public|all` and
//! `--publish [IP:]HOST_PORT:GUEST_PORT`: a provider forked before the sandbox boots
//! (unsharek-net: it dials under its policy, listens on the published ports, and passes each
//! connection in over a control socket; its own lockdown and proven filter). The sandbox gains
//! the control socket and, in its filter, `recvmsg` on it and `close` of what arrives on it
//! (unsharek-tcb's `Config::recv_fds`). The hooks that call the provider are the library's
//! (`unsharek::provider`).

use std::os::fd::{OwnedFd, RawFd};

use unsharek::provider::{NetConfig, Policy, Publish};

/// The flags' values.
pub struct Args {
    pub policy: Option<Policy>,
    pub publish: Vec<Publish>,
}

/// The plugin, between its spawn and the sandbox's lockdown.
pub struct Net {
    /// Ours until the guest holds it (the same number: `fd`).
    ctl: std::cell::Cell<Option<OwnedFd>>,
    fd: RawFd,
    dials: bool,
}

/// The provider, if the flags ask for a network (before the sandbox boots: this process has one
/// thread).
pub fn spawn(args: &Args) -> Result<Option<Net>, unsharek::Error> {
    let net = NetConfig { policy: args.policy, publish: args.publish.clone() };
    if !net.enabled() {
        return Ok(None);
    }
    let ctl = unsharek::provider::spawn(&net)?;
    Ok(Some(Net { fd: std::os::fd::AsRawFd::as_raw_fd(&ctl), ctl: std::cell::Cell::new(Some(ctl)), dials: args.policy.is_some() }))
}

impl Net {
    /// The hooks, on the booted guest: the control socket held, connects and resolves (with
    /// `--net`) and listens through the provider.
    pub fn install(&self, g: &mut unsharek::Guest) -> Result<(), unsharek::Error> {
        if let Some(ctl) = self.ctl.take() {
            unsharek::provider::install(g, ctl, self.dials)?;
        }
        Ok(())
    }

    /// Lockdown's part: the control socket, `recvmsg`'s one fd.
    pub fn grant(&self, c: unsharek::SandboxConfig) -> unsharek::SandboxConfig {
        c.grant([self.fd]).recv_fds(self.fd)
    }
}
