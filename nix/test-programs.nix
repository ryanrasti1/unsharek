# Programs from nixpkgs (and one built here) that the suite runs in the sandbox, as the devshell's
# EXOBOX_TEST_* variables (flake.nix), and that the flake's smoke check runs against the release
# binary. Static ones first: exobox claims to run static binaries, so the suite runs real ones,
# each from a different toolchain.
{ pkgs }:
{
  # Go's runtime, CGO off (a static ELF with no interpreter): small-stack syscalls, many threads,
  # SIGURG preemption, timers, the netpoller over loopback, fork+exec by clone(CLONE_VFORK|CLONE_VM).
  # Built here: no nixpkgs program does all of that in one process, which coroutine and threaded
  # mode need (they have no processes). A derivation, not a test-time build: seconds, once.
  goprobe = pkgs.stdenv.mkDerivation {
    name = "exobox-goprobe";
    src = ./goprobe;
    nativeBuildInputs = [ pkgs.go ];
    env.CGO_ENABLED = "0";
    env.GO111MODULE = "off";
    buildPhase = ''
      export HOME=$TMPDIR GOCACHE=$TMPDIR/go-cache
      go build -trimpath -o goprobe main.go
    '';
    installPhase = "install -Dm755 goprobe $out/bin/goprobe";
    dontPatchELF = true;
  };
  # A real Go server from nixpkgs, static (CGO off in its derivation): fork mode's case runs it
  # with busybox's wget as its client.
  httpbin = pkgs.go-httpbin;
  # musl, static (not PIE): one binary, many applets.
  busybox = pkgs.pkgsStatic.busybox;
}
