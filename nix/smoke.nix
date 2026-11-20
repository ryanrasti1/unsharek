# The release smoke test (the flake's checks.<system>.smoke): the release `unsharek` runs real
# programs in all three modes inside Nix's build sandbox, each output checked. What the sandbox
# changes for unsharek, and how it's met:
# - No Nix database: unsharek finds a program's closure with `nix-store --query --requisites`. The
#   programs' closure is registered in a database of the build's own (closureInfo's
#   registration, loaded with `nix-store --load-db` under NIX_STATE_DIR), which unsharek's
#   nix-store then reads.
# - No $HOME: the image cache is $UNSHAREK_IMAGE_CACHE, in the build's $TMPDIR.
# - Nix's own seccomp filter is under unsharek's (filters stack: the strictest answer wins), and
#   /dev and /proc are the sandbox's: unsharek's guest has its own of both.
{ pkgs, unsharek, tp }:
let
  programs = {
    hello = pkgs.hello;
    python = pkgs.python3;
    bash = pkgs.bash;
    coreutils = pkgs.coreutils;
    inherit (tp) goprobe httpbin busybox;
  };
  closure = pkgs.closureInfo { rootPaths = builtins.attrValues programs; };
in
pkgs.runCommand "unsharek-smoke"
  {
    nativeBuildInputs = [ unsharek pkgs.nix ];
    env = {
      HELLO = "${programs.hello}/bin/hello";
      PYTHON = "${programs.python}/bin/python3";
      BASH_ = "${programs.bash}/bin/bash";
      COREUTILS = "${programs.coreutils}";
      GOPROBE = "${programs.goprobe}/bin/goprobe";
      HTTPBIN = "${programs.httpbin}/bin/go-httpbin";
      BUSYBOX = "${programs.busybox}/bin/busybox";
    };
  }
  ''
    export NIX_STATE_DIR=$TMPDIR/nix-state NIX_REMOTE=
    nix-store --load-db < ${closure}/registration
    export UNSHAREK_IMAGE_CACHE=$TMPDIR/unsharek-images

    fails=0
    # check NAME MODE WANT -- PROGRAM ARGS...: the run exits 0 within 60 s and its stdout has WANT.
    # Its stdin is $IN.
    check() {
      local name=$1 mode=$2 want=$3; shift 4
      local t0=$EPOCHREALTIME out st=0
      out=$(timeout 60 unsharek run --mode "$mode" --allow-path "$COREUTILS" --allow-path "''${HTTPBIN%/bin/*}" \
        -- "$@" 2>"$TMPDIR/err" <<<"''${IN:-}") || st=$?
      local ms=$(( (''${EPOCHREALTIME/./} - ''${t0/./}) / 1000 ))
      if [[ $st == 0 && $out == *"$want"* ]]; then
        echo "ok   $name ($mode) ''${ms} ms"
      else
        echo "FAIL $name ($mode): status $st, wanted '$want' in:"; echo "$out" | tail -5; tail -5 "$TMPDIR/err"
        fails=$((fails + 1))
      fi
    }

    for m in coroutine threaded fork; do
      check hello $m "Hello, world!" -- "$HELLO"
      check python $m 42 -- "$PYTHON" -c 'print(6*7)'
      check go $m GOPROBE_OK -- "$GOPROBE"
      IN=$'c\nb\na' check busybox-sort $m $'a\nb\nc' -- "$BUSYBOX" sort
      check busybox-sh $m "42 ok" -- "$BUSYBOX" sh -c 'x=$((6*7)); echo $x ok'
      check busybox-ls $m proc -- "$BUSYBOX" ls /
    done
    # Pipelines need processes: fork mode's (coroutine and threaded mode have one).
    check bash-pipeline fork "n=3 sub=ok" -- "$BASH_" -c \
      'n=$(printf "a\nb\nc\n" | $COREUTILS/bin/sort -r | $COREUTILS/bin/wc -l); echo n=$n sub=$(echo ok)'
    for m in coroutine threaded; do
      check bash $m "42 sub=ok" -- "$BASH_" -c 'x=$((6*7)); echo $x sub=ok'
    done
    check busybox-pipeline fork "3" -- "$BUSYBOX" sh -c \
      'b='"$BUSYBOX"'; printf "3\n1\n2\n" | $b sort | $b wc -l'
    check go-exec fork "exec ok" -- "$GOPROBE" preempt exec
    check go-httpbin fork HTTPBIN_OK -- "$BUSYBOX" sh -c '
      b='"$BUSYBOX"'; u=http://127.0.0.1:18080
      '"$HTTPBIN"' -host 127.0.0.1 -port 18080 >/dev/null 2>&1 &
      pid=$!
      i=0; until $b wget -q -O /dev/null $u/status/200 2>/dev/null; do
        i=$((i+1)); [ $i -gt 250 ] && exit 1; $b usleep 20000; done
      $b wget -q -O - "$u/get?x=42" | $b grep -q "\"42\"" && { kill $pid; wait $pid; echo HTTPBIN_OK; }'

    if [[ $fails != 0 ]]; then echo "$fails failed"; exit 1; fi
    echo "all passed" > $out
  ''
