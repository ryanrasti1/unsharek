# What `cargo xtask calls` reads of mainline Linux (the host's syscalls, which the filter judges;
# not LKL's, the guest's): v7.0's x86-64 syscall table and every C file with a SYSCALL_DEFINE,
# extracted from the release tarball (pinned by its hash), the rest of the tree dropped.
{ pkgs }:
pkgs.runCommand "linux-7.0-syscalls" {
  src = pkgs.fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz";
    sha256 = "1w4i705i0nl1xqv7fdhdbhy7j3xrzhl31fabs6vmgiw7nf06szxv";
  };
} ''
  mkdir -p $out
  tar -xJf $src --strip-components=1 -C $out --wildcards 'linux-7.0/arch/x86/entry/syscalls/syscall_64.tbl' '*.c'
  # Only the files that define a syscall (grep -L's status is 1 when every file has one).
  find $out -name '*.c' -type f -exec grep -L 'SYSCALL_DEFINE' {} + > drop || true
  xargs -r rm -f < drop
  find $out -depth -type d -empty -delete
''
