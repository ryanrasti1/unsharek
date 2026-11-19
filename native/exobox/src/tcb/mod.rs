//! The trusted computing base: the only code that protects the host. `TCB.md` (beside this
//! crate's Cargo.toml) says what is in it, what isn't and why, and how to review it.
//!
//! - [`inventory`]: every host resource the sandbox keeps past lockdown, made and recorded here;
//! - [`filter`]: the security filter, built from the inventory, compiled by seccompiler;
//! - [`lockdown`]: threads checked, fds closed, filters installed (TSYNC), in that order.
//!
//! The rest of exobox (the API in `lib.rs`, the runtime, the guest kernel, the hooks, the store)
//! runs in the program's address space after lockdown, and a compromised program can corrupt it:
//! none of it is trusted to protect the host.

pub(crate) mod filter;
pub(crate) mod inventory;
pub(crate) mod lockdown;
