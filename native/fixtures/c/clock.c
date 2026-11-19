// The guest kernel's clock against the host's: a file made now has today's mtime, and the
// kernel's CLOCK_REALTIME (a raw syscall, which the sandbox serves from the guest kernel) is the
// vDSO's (the host's). The guest's realtime started at the host's uptime (its clock is the host's
// CLOCK_MONOTONIC), so files got 1970 mtimes while `date` said today, and autoconf stopped:
// "newly created file is older than distributed files" (capnix building nixpkgs' hello). In fork
// mode a forked child checks the same.
#include "exobox_test.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double secs(struct timespec t) { return t.tv_sec + t.tv_nsec / 1e9; }

static void check(const char *who)
{
	struct timespec vdso, raw;
	CHECK(clock_gettime(CLOCK_REALTIME, &vdso) == 0, "clock_gettime");
	CHECK(syscall(SYS_clock_gettime, CLOCK_REALTIME, &raw) == 0, "SYS_clock_gettime");
	printf("%s: vdso %.3f kernel %.3f\n", who, secs(vdso), secs(raw));
	CHECK(secs(raw) - secs(vdso) < 1 && secs(vdso) - secs(raw) < 1,
	      "%s: the kernel's realtime is %.3f s off the host's", who, secs(raw) - secs(vdso));
	// The guest's /tmp; natively the suite's TMPDIR, as the environment's TMPDIR is the host's.
	const char *dir = mode_is("native") ? getenv("TMPDIR") : NULL;
	char path[4096];
	snprintf(path, sizeof(path), "%s/clock-%d", dir && *dir ? dir : "/tmp", getpid());
	int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0, "open %s", path);
	CHECK(write(fd, "x", 1) == 1, "write");
	struct stat st;
	CHECK(fstat(fd, &st) == 0, "fstat");
	close(fd);
	unlink(path);
	double d = st.st_mtim.tv_sec + st.st_mtim.tv_nsec / 1e9 - secs(vdso);
	printf("%s: mtime %ld (%+.3f s)\n", who, (long)st.st_mtim.tv_sec, d);
	CHECK(d > -3 && d < 3, "%s: a new file's mtime is %.3f s off the host's time", who, d);
}

int main(void)
{
	check("init");
	if (mode_is("fork") || mode_is("native")) {
		pid_t c = fork();
		CHECK(c >= 0, "fork");
		if (c == 0) {
			check("child");
			fflush(stdout);
			_exit(0);
		}
		int st;
		CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child's checks");
	}
	printf("CLOCK_OK\n");
	return 0;
}
