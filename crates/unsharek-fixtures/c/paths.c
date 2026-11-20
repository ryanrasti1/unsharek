// What each path argument is, for the library's tests (tests/guest.rs): store paths that are a
// file or a symlink had no image ("not a directory (an image's root is one)"), which Nix builds hit
// constantly (setup hooks' scripts, source tarballs are single-file store paths); now a file is
// bind-mounted from its image and a symlink made. Prints, per path, `PATH <path> file <bytes>
// <mode> ro` (its first bytes, its permission bits, and a write refused with EROFS), `PATH <path>
// link <target> <bytes>` (the bytes read through it) or `PATH <path> dir`, then PATHS_OK.
#include "unsharek_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static void head(const char *path, char *b, size_t n)
{
	int fd = open(path, O_RDONLY);
	CHECK(fd >= 0, "open %s: %s", path, strerror(errno));
	ssize_t r = read(fd, b, n - 1);
	CHECK(r >= 0, "read %s", path);
	b[r] = 0;
	for (ssize_t i = 0; i < r; i++)
		if (b[i] == '\n')
			b[i] = '_';
	close(fd);
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		struct stat st;
		CHECK(lstat(argv[i], &st) == 0, "lstat %s: %s", argv[i], strerror(errno));
		char b[64];
		if (S_ISREG(st.st_mode)) {
			head(argv[i], b, sizeof(b));
			int fd = open(argv[i], O_WRONLY);
			int ro = fd < 0 && (errno == EROFS || errno == EACCES);
			printf("PATH %s file %s %o %s\n", argv[i], b, st.st_mode & 07777, ro ? "ro" : "rw");
		} else if (S_ISLNK(st.st_mode)) {
			char t[4096];
			ssize_t n = readlink(argv[i], t, sizeof(t) - 1);
			CHECK(n >= 0, "readlink %s", argv[i]);
			t[n] = 0;
			head(argv[i], b, sizeof(b));
			printf("PATH %s link %s %s\n", argv[i], t, b);
		} else if (S_ISDIR(st.st_mode)) {
			printf("PATH %s dir\n", argv[i]);
		} else {
			printf("PATH %s other\n", argv[i]);
		}
	}
	printf("PATHS_OK\n");
	return 0;
}
