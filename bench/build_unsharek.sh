# Sourced by bench/run and bench/quick (in the devshell, at the tree's root):
# `build_unsharek ARGS...` builds unsharek release, and with `--variant stats` among ARGS (a variant
# without a path) the runtime's counters too: the cargo feature `stats`, as
# target/release/unsharek-stats. The plain binary is built last, so target/release/unsharek stays it.
build_unsharek() {
  local prev= a want_stats=
  for a in "$@"; do
    if [[ "$a" == --variant=stats || ( "$prev" == --variant && "$a" == stats ) ]]; then
      want_stats=1
    fi
    prev=$a
  done
  if [[ -n "$want_stats" ]]; then
    cargo build --release -q -p unsharek --bin unsharek --features unsharek/stats
    cp target/release/unsharek target/release/unsharek-stats
  fi
  cargo build --release -q -p unsharek --bin unsharek
}
