# Sourced by ./test: enter the devshell without `nix develop`, which copies the tree into the store
# on every change. The environment depends only on flake.nix, flake.lock and the test programs it
# builds (nix/test-programs.nix, nix/goprobe), so `nix print-dev-env` is cached in .cache/, keyed
# on those files. Delete .cache/ to refresh by hand.
if [[ -z "${EXOBOX_DEVSHELL:-}" ]]; then
  _exobox_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  _exobox_key="$(cat "$_exobox_root/flake.nix" "$_exobox_root/flake.lock" "$_exobox_root/nix/test-programs.nix" \
  "$_exobox_root"/nix/goprobe/* 2>/dev/null | sha256sum | cut -c1-16)"
  _exobox_env="$_exobox_root/.cache/devshell-$_exobox_key.sh"
  if [[ ! -s "$_exobox_env" ]]; then
    mkdir -p "$_exobox_root/.cache"
    nix print-dev-env "$_exobox_root" >"$_exobox_env.tmp"
    mv "$_exobox_env.tmp" "$_exobox_env"
  fi
  # print-dev-env's script sets the shell's options and traps; keep the caller's.
  _exobox_opts="$(set +o)"
  # shellcheck disable=SC1090
  source "$_exobox_env"
  eval "$_exobox_opts"
  trap - EXIT
  export EXOBOX_DEVSHELL=1
  unset _exobox_root _exobox_key _exobox_env _exobox_opts
fi
