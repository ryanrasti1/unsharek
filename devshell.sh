# Sourced by ./test: enter the devshell without `nix develop`, which copies the tree into the store
# on every change. The environment depends only on flake.nix, flake.lock and the test programs it
# builds (nix/test-programs.nix, nix/goprobe), and Kani (seccomp-fn/flake.nix), so `nix print-dev-env` is
# cached in .cache/, keyed on those files. Delete .cache/ to refresh by hand.
#
# The cache is a GC root (`--profile`, .cache/devshell-<key>): its environment names store paths
# (the test programs, Kani, glibc's static archives) that nothing else roots. Unrooted, a
# `nix-collect-garbage` deleted them under a cache that still named them: the suite's busybox and
# Go cases failed ("No such file or directory"), and one during a run killed it mid-test (the
# devshell's own tools gone). A cache without its root (from before) is remade.
if [[ -z "${UNSHAREK_DEVSHELL:-}" ]]; then
  _unsharek_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  _unsharek_key="$(cat "$_unsharek_root/flake.nix" "$_unsharek_root/flake.lock" "$_unsharek_root/nix/test-programs.nix" \
  "$_unsharek_root/seccomp-fn/flake.nix" \
  "$_unsharek_root"/nix/goprobe/* 2>/dev/null | sha256sum | cut -c1-16)"
  _unsharek_env="$_unsharek_root/.cache/devshell-$_unsharek_key.sh"
  if [[ ! -s "$_unsharek_env" || ! -e "$_unsharek_root/.cache/devshell-$_unsharek_key" ]]; then
    mkdir -p "$_unsharek_root/.cache"
    nix print-dev-env --profile "$_unsharek_root/.cache/devshell-$_unsharek_key" "$_unsharek_root" >"$_unsharek_env.tmp"
    mv "$_unsharek_env.tmp" "$_unsharek_env"
  fi
  # print-dev-env's script sets the shell's options and traps; keep the caller's. ($(set +o)
  # runs in a subshell, where bash turns errexit off, so it is kept from $- instead: without it
  # ./test went on past a failed build and exited with the last command's status.)
  _unsharek_opts="$(set +o)"
  [[ $- == *e* ]] && _unsharek_opts+=$'\nset -e'
  # shellcheck disable=SC1090
  source "$_unsharek_env"
  eval "$_unsharek_opts"
  trap - EXIT
  export UNSHAREK_DEVSHELL=1
  unset _unsharek_root _unsharek_key _unsharek_env _unsharek_opts
fi
