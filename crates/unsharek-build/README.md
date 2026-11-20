# unsharek-build

For the `build.rs` of a binary that embeds unsharek: `link_fixed_address()` links it at a fixed
address, as the CLI is. A position-independent binary's relocations would be written into each
sandbox's copy of its data, about 400 KB a sandbox.
