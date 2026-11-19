//! Links the examples' binaries at a fixed address (`exobox_build::link_fixed_address`), as the
//! exobox CLI is: not a PIE (exobox-build says why).

fn main() {
    exobox_build::link_fixed_address();
}
