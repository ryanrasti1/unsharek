#!/usr/bin/env bash
# unsharek inside bubblewrap: bwrap decides what exists (its mount namespace: the store, one work
# directory, nothing of home), unsharek what the host kernel is asked (its filter: a few calls,
# each argument pinned). A live mount's paths are confined twice: by bwrap's view, and by
# unsharek's Landlock ruleset (--no-landlock leaves it to bwrap).
#
#   examples/bwrap/run.sh WORKDIR PROGRAM [ARGS...]
#
# PROGRAM is a static program in the store (its store path is mapped: `closure` would need
# nix-store's database, which bwrap's view hasn't); WORKDIR is the program's /work, read-write.
# The image cache is the host's (bound in): unsharek builds the mapped directory's image there.
set -euo pipefail
work=$(realpath "$1")
prog=$(realpath "$2")
shift 2
unsharek=${UNSHAREK:-$(command -v unsharek)}
store=$(echo "$prog" | cut -d/ -f1-4)
cache=${UNSHAREK_IMAGE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/unsharek/images}
mkdir -p "$cache"
exec bwrap \
  --unshare-all --die-with-parent --new-session \
  --ro-bind /nix/store /nix/store \
  --ro-bind "$unsharek" /unsharek \
  --bind "$work" /work \
  --bind "$cache" "$cache" --setenv UNSHAREK_IMAGE_CACHE "$cache" \
  --dev /dev --proc /proc --tmpfs /tmp \
  -- /unsharek --mode fork --mount "$store:map" --mount /work:rw -- "$prog" "$@"
