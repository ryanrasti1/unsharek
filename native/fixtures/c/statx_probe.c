// statx with bad pointers is EFAULT, not a crash. Rust's std probes for statx at its first failed
// one (library/std/src/sys/fs/unix.rs, try_statx) with `statx(0, NULL, 0, STATX_ALL, NULL)` and
// expects EFAULT; the call went to LKL as is, whose getname() reads the path with no MMU to fault
// in (asm-generic access_ok is true everywhere), so it dereferenced NULL and the sandbox died of
// SIGSEGV. cargo did that at startup, looking for `/.cargo/config.toml`: every cargo in every mode.
#include "exobox_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sx(int dfd, const void *path, int flags, unsigned mask, void *buf)
{
	long r = syscall(SYS_statx, dfd, path, flags, mask, buf);
	return r < 0 ? -errno : r;
}

int main(void)
{
	struct statx st;
	long r;
	// Rust's probe, exactly.
	r = sx(0, NULL, 0, STATX_ALL, NULL);
	CHECK(r == -EFAULT, "probe: %ld", r);
	// What std does after a failed statx with EFAULT: its own path missing, ENOENT.
	r = sx(AT_FDCWD, "/statx_probe_missing", AT_STATX_SYNC_AS_STAT, STATX_ALL, &st);
	CHECK(r == -ENOENT, "missing: %ld", r);
	// A path the program doesn't have. (NULL with AT_EMPTY_PATH at AT_FDCWD depends on the kernel:
	// EFAULT in the guest's 6.12, the cwd's stat in newer hosts'.)
	r = sx(AT_FDCWD, (const void *)8, 0, STATX_ALL, &st);
	CHECK(r == -EFAULT, "bad path: %ld", r);
	// A bad buffer: the lookup's own error first, else EFAULT.
	r = sx(AT_FDCWD, "/", 0, STATX_ALL, NULL);
	CHECK(r == -EFAULT, "NULL buffer: %ld", r);
	r = sx(AT_FDCWD, "/statx_probe_missing", 0, STATX_ALL, NULL);
	CHECK(r == -ENOENT, "missing, NULL buffer: %ld", r);
	// What works: a path, and an fd with a NULL or empty path (Linux 6.11's NULL form).
	memset(&st, 0, sizeof(st));
	r = sx(AT_FDCWD, "/", 0, STATX_BASIC_STATS, &st);
	CHECK(r == 0 && S_ISDIR(st.stx_mode) && (st.stx_mask & STATX_TYPE), "/: %ld mode %o", r, st.stx_mode);
	int fd = open("/", O_RDONLY | O_DIRECTORY);
	CHECK(fd >= 0, "open /");
	memset(&st, 0, sizeof(st));
	r = sx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &st);
	CHECK(r == 0 && S_ISDIR(st.stx_mode), "fd, \"\": %ld", r);
	memset(&st, 0, sizeof(st));
	r = sx(fd, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &st);
	CHECK(r == 0 && S_ISDIR(st.stx_mode), "fd, NULL: %ld", r);
	printf("STATX_PROBE_OK\n");
	return 0;
}
