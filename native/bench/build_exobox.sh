# Sourced by native/bench/run and native/bench/quick (in the devshell, at the tree's root):
# `build_exobox ARGS...` builds exobox release, and with `--variant stats` among ARGS (a variant
# without a path) the runtime's counters too: the cargo feature `stats`, as
# target/release/exobox-stats. The plain binary is built last, so target/release/exobox stays it.
build_exobox() {
  local prev= a want_stats=
  for a in "$@"; do
    if [[ "$a" == --variant=stats || ( "$prev" == --variant && "$a" == stats ) ]]; then
      want_stats=1
    fi
    prev=$a
  done
  if [[ -n "$want_stats" ]]; then
    cargo build --release -q -p exobox --bin exobox --features exobox/stats
    cp target/release/exobox target/release/exobox-stats
  fi
  cargo build --release -q -p exobox --bin exobox
}
