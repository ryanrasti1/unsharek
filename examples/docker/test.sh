#!/usr/bin/env bash
# `cargo xtask test-docker`: the image of examples/docker/Dockerfile built, then unsharek run in
# it under Docker's default seccomp profile, each case's output checked:
#   map             the Dockerfile's CMD: the image's busybox, mapped, reads /data
#   ro              a live read-only mount, Landlock's ruleset over it
#   ro-no-landlock  the same with --no-landlock (Docker's mount namespace confines it alone)
#   net             --net host: a connect to a server in the container (outside the sandbox)
# Skipped, with a message, if there's no Docker daemon. The image is removed at the end.
set -euo pipefail
cd "$(dirname "$0")/../.."
if ! docker info >/dev/null 2>&1; then
  echo "test-docker: skipped: no Docker daemon"
  exit 0
fi
image=unsharek-example-test
ctx=target/docker-context
UNSHAREK=${UNSHAREK:-target/debug/unsharek}
cargo build -q -p unsharek
[ -d "$ctx" ] && chmod -R u+w "$ctx"
rm -rf "$ctx"
UNSHAREK=$UNSHAREK examples/docker/context.sh "$ctx"
trap 'docker rmi -f "$image" >/dev/null 2>&1 || true; rm -rf "$ctx"' EXIT
docker build -q -t "$image" -f examples/docker/Dockerfile "$ctx" >/dev/null

fail=0
check() { # NAME WANT -- docker run args...
  local name=$1 want=$2
  shift 3
  local out
  out=$(timeout 60 docker run --rm "$@" 2>&1) || true
  if grep -qF -- "$want" <<<"$out"; then
    echo "test-docker: $name: ok"
  else
    echo "test-docker: $name: FAIL (wanted '$want')"
    sed 's/^/  | /' <<<"$out"
    fail=1
  fi
}
base=(unsharek --mode fork --mount /bin:map --mount /lib:map)
check map "hello from the image" -- "$image"
check ro "hello from the image" -- "$image" "${base[@]}" --mount /data:ro -- /bin/busybox cat /data/hello.txt
check ro-no-landlock "hello from the image" -- "$image" "${base[@]}" --no-landlock --mount /data:ro -- /bin/busybox cat /data/hello.txt
# A seccomp profile that hides Landlock (older Docker defaults did): an ro mount is refused,
# and the error names the way out.
profile=$(mktemp)
echo '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["landlock_create_ruleset"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]}' >"$profile"
check no-landlock-profile "--no-landlock (where file access is already scoped), or a \`map\` mount" -- --security-opt seccomp="$profile" \
  "$image" "${base[@]}" --mount /data:ro -- /bin/busybox cat /data/hello.txt
unlink "$profile"
# A server in the container, outside the sandbox, on the container's own address (the guest's
# 127.0.0.1 is its own loopback).
check net "hello from the image" -- "$image" sh -c \
  'ip=$(hostname -i | cut -d" " -f1); nc -l -p 8080 < /data/hello.txt & sleep 0.3; '"${base[*]}"' --net host -- /bin/busybox nc $ip 8080 </dev/null'
exit $fail
