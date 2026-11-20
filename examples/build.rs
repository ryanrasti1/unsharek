//! Links the examples' binaries at a fixed address (`unsharek_build::link_fixed_address`), as the
//! unsharek CLI is: not a PIE (unsharek-build says why).

fn main() {
    unsharek_build::link_fixed_address();
}
