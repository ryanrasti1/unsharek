// The guest's device nodes are usable by a user that isn't root, as on any Linux: setup made
// them with mknod, whose mode goes through the umask, so they were 0644 (crw-r--r--) and a build
// user (capnix's, after setresuid in a guard) couldn't write /dev/null. In the sandbox the program
// is root, so it drops to uid/gid 1000 first; natively it runs as whoever runs the suite.
#include "exobox_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
	if (geteuid() == 0)
		CHECK(setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0, "dropping to 1000");
	printf("uid %d\n", getuid());
	const char *nodes[] = {"/dev/null", "/dev/zero",    "/dev/full", "/dev/random",
			       "/dev/urandom", "/dev/tty", "/dev/ptmx"};
	for (size_t i = 0; i < sizeof(nodes) / sizeof(*nodes); i++) {
		struct stat st;
		CHECK(stat(nodes[i], &st) == 0, "stat %s", nodes[i]);
		CHECK(S_ISCHR(st.st_mode) && (st.st_mode & 0777) == 0666, "%s: mode %o", nodes[i], st.st_mode);
	}
	int fd = open("/dev/null", O_WRONLY);
	CHECK(fd >= 0 && write(fd, "x", 1) == 1, "writing /dev/null: %s", strerror(errno));
	close(fd);
	fd = open("/dev/full", O_WRONLY);
	CHECK(fd >= 0 && write(fd, "x", 1) == -1 && errno == ENOSPC, "writing /dev/full: %s", strerror(errno));
	close(fd);
	const char *reads[] = {"/dev/zero", "/dev/urandom", "/dev/random"};
	for (size_t i = 0; i < 3; i++) {
		char b[16];
		fd = open(reads[i], O_RDONLY);
		CHECK(fd >= 0 && read(fd, b, sizeof(b)) == sizeof(b), "reading %s: %s", reads[i], strerror(errno));
		close(fd);
	}
	printf("DEVNODES_OK\n");
	return 0;
}
