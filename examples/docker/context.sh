#!/usr/bin/env bash
# The Docker build context for examples/docker/Dockerfile, in DIR: the unsharek binary
# (UNSHAREK, default the one on PATH) and the Nix store paths it links, at their own paths
# under DIR/nix/store.
#
#   examples/docker/context.sh DIR
set -euo pipefail
dir=$1
unsharek=$(realpath "${UNSHAREK:-$(command -v unsharek)}")
mkdir -p "$dir/nix/store"
cp "$unsharek" "$dir/unsharek"
# The store paths of its interpreter and libraries, and theirs.
paths=$(ldd "$unsharek" | grep -o '/nix/store/[^/]*' | sort -u)
for p in $(nix-store -qR $paths); do
  [ -e "$dir$p" ] || cp -a "$p" "$dir/nix/store/"
done
# Writable copies (the store's are read-only), so the context can be removed.
chmod -R u+w "$dir/nix"
