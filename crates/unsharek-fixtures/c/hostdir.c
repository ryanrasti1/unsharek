// A host directory served live (the CLI's `--mount DIR:ro` and `DIR:rw`: virtio-fs, served in
// process by unsharek-fs's passthrough). `hostdir <op> <path> [<path>]`, each op ending in HOSTDIR_OK:
//   write DIR       (an rw mount) create, rename, mkdir, symlink, truncate, chmod, unlink, rmdir:
//                   each seen back, and a hard link refused (EPERM: the fs plugin has no linkat
//                   row); then DIR/created-by-the-program, the suite's marker, checked on the host
//   ro FILE         (FILE in an ro mount) every change refused: an O_WRONLY or O_TRUNC
//                   open, a create, mkdir, unlink, rename, truncate, chmod, a symlink and a link
//   escape DIR OUT  (an rw mount; OUT a host file outside it) a symlink and a hard link to OUT from
//                   inside DIR don't reach it: the guest resolves the link in its own tree, where
//                   OUT isn't
//   big DIR         a 16 MiB file written in odd-sized pieces and read back, checked
//   par DIR         4 threads (and in fork mode 4 processes) each writing and reading back files of
//                   their own at once: the device's requests from several host threads and
//                   processes
#include "unsharek_test.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void path(char *out, const char *dir, const char *name) { snprintf(out, 4096, "%s/%s", dir, name); }

static void put(const char *p, const char *s)
{
	int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0, "create %s: %s", p, strerror(errno));
	CHECK(write(fd, s, strlen(s)) == (ssize_t)strlen(s), "write %s: %s", p, strerror(errno));
	CHECK(close(fd) == 0, "close %s", p);
}

static void get(const char *p, char *out, size_t n)
{
	int fd = open(p, O_RDONLY);
	CHECK(fd >= 0, "open %s: %s", p, strerror(errno));
	ssize_t k = read(fd, out, n - 1);
	CHECK(k >= 0, "read %s: %s", p, strerror(errno));
	out[k] = 0;
	close(fd);
}

static void op_write(const char *dir)
{
	char a[4096], b[4096], s[4096], h[4096], sub[4096], buf[64];
	path(a, dir, "a"), path(b, dir, "b"), path(s, dir, "s"), path(h, dir, "h"), path(sub, dir, "sub");
	put(a, "from the guest\n");
	CHECK(rename(a, b) == 0, "rename: %s", strerror(errno));
	get(b, buf, sizeof buf);
	CHECK(!strcmp(buf, "from the guest\n"), "read back %s", buf);
	CHECK(mkdir(sub, 0755) == 0, "mkdir: %s", strerror(errno));
	CHECK(symlink("b", s) == 0, "symlink: %s", strerror(errno));
	CHECK(readlink(s, buf, sizeof buf) == 1 && buf[0] == 'b', "readlink");
	// Natively a hard link is made (and removed); in the sandbox it is refused.
	const char *mode = getenv("UNSHAREK_TEST_MODE");
	int native = mode && !strcmp(mode, "native");
	int l = link(b, h);
	CHECK(native ? l == 0 : l < 0 && errno == EPERM, "link: %d, %s", l, strerror(errno));
	if (native)
		CHECK(unlink(h) == 0, "unlink the hard link: %s", strerror(errno));
	struct stat st;
	CHECK(stat(b, &st) == 0 && st.st_nlink == 1, "nlink %ld", (long)st.st_nlink);
	CHECK(truncate(b, 4) == 0 && stat(b, &st) == 0 && st.st_size == 4, "truncate");
	CHECK(chmod(b, 0600) == 0 && stat(b, &st) == 0 && (st.st_mode & 0777) == 0600, "chmod");
	CHECK(unlink(s) == 0 && unlink(b) == 0, "unlink: %s", strerror(errno));
	CHECK(rmdir(sub) == 0, "rmdir: %s", strerror(errno));
	CHECK(access(b, F_OK) != 0, "b still there");
	path(a, dir, "created-by-the-program");
	put(a, "marker\n");
	printf("HOSTDIR_WRITE\n");
}

// A change to a read-only directory: refused, as EROFS (the server's early refusal) or EACCES
// (Landlock's).
#define REFUSED(call, what)                                                                        \
	do {                                                                                       \
		errno = 0;                                                                         \
		int r_ = (call);                                                                   \
		CHECK(r_ < 0 && (errno == EROFS || errno == EACCES), "%s: %d, %s", what, r_,       \
		      strerror(errno));                                                            \
	} while (0)

static void op_ro(const char *file)
{
	char dir[4096], p[4096];
	snprintf(dir, sizeof dir, "%s", file);
	*strrchr(dir, '/') = 0;
	REFUSED(open(file, O_WRONLY), "open O_WRONLY");
	REFUSED(open(file, O_RDWR), "open O_RDWR");
	REFUSED(open(file, O_RDONLY | O_TRUNC), "open O_TRUNC");
	path(p, dir, "new");
	REFUSED(open(p, O_WRONLY | O_CREAT, 0644), "create");
	REFUSED(mkdir(p, 0755), "mkdir");
	REFUSED(symlink("x", p), "symlink");
	REFUSED(link(file, p), "link");
	REFUSED(rename(file, p), "rename");
	REFUSED(unlink(file), "unlink");
	REFUSED(truncate(file, 0), "truncate");
	REFUSED(chmod(file, 0777), "chmod");
	CHECK(access(file, R_OK) == 0, "the file isn't readable");
	printf("HOSTDIR_RO\n");
}

static void op_escape(const char *dir, const char *out)
{
	char s[4096], h[4096], buf[64];
	path(s, dir, "out-link"), path(h, dir, "out-hard");
	CHECK(symlink(out, s) == 0, "symlink: %s", strerror(errno));
	int fd = open(s, O_RDONLY);
	CHECK(fd < 0 && errno == ENOENT, "the symlink reached %s", out);
	// A relative one, out of the directory: .. is the guest's, above its mount point.
	unlink(s);
	CHECK(symlink("../../../../../../../../../../etc/passwd", s) == 0, "symlink: %s", strerror(errno));
	fd = open(s, O_RDONLY);
	if (fd >= 0) {
		// The guest's own /etc/passwd, if it has one: not the host's.
		ssize_t k = read(fd, buf, sizeof buf);
		CHECK(k <= 0 || !strstr(buf, "root:x:0:0"), "the host's /etc/passwd");
		close(fd);
	}
	unlink(s);
	CHECK(link(out, h) < 0, "a hard link to %s", out);
	CHECK(rename(out, h) < 0, "a rename of %s", out);
	CHECK(access(h, F_OK) != 0, "%s exists", h);
	printf("HOSTDIR_ESCAPE\n");
}

static void op_big(const char *dir)
{
	char p[4096];
	path(p, dir, "big");
	size_t total = 16 << 20, chunk = 100003;
	unsigned char *buf = malloc(chunk);
	int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0, "create: %s", strerror(errno));
	for (size_t off = 0; off < total; off += chunk) {
		size_t n = total - off < chunk ? total - off : chunk;
		for (size_t i = 0; i < n; i++)
			buf[i] = (unsigned char)((off + i) * 7 + 3);
		CHECK(write(fd, buf, n) == (ssize_t)n, "write at %zu: %s", off, strerror(errno));
	}
	CHECK(fsync(fd) == 0 && close(fd) == 0, "fsync");
	fd = open(p, O_RDONLY);
	size_t off = 0;
	for (;;) {
		ssize_t k = read(fd, buf, chunk);
		CHECK(k >= 0, "read: %s", strerror(errno));
		if (k == 0)
			break;
		for (ssize_t i = 0; i < k; i++)
			CHECK(buf[i] == (unsigned char)((off + i) * 7 + 3), "byte %zu", off + i);
		off += k;
	}
	CHECK(off == total, "read %zu of %zu", off, total);
	close(fd);
	CHECK(unlink(p) == 0, "unlink");
	printf("HOSTDIR_BIG\n");
}

static const char *par_dir;

static void *worker(void *arg)
{
	long id = (long)arg;
	char p[4096], want[64], got[64];
	for (int i = 0; i < 50; i++) {
		snprintf(p, sizeof p, "%s/w%ld-%d", par_dir, id, i);
		snprintf(want, sizeof want, "worker %ld, file %d\n", id, i);
		put(p, want);
		get(p, got, sizeof got);
		CHECK(!strcmp(got, want), "%s: %s", p, got);
		CHECK(unlink(p) == 0, "unlink %s", p);
	}
	return NULL;
}

static void op_par(const char *dir)
{
	par_dir = dir;
	pthread_t t[4];
	for (long i = 0; i < 4; i++)
		CHECK(pthread_create(&t[i], NULL, worker, (void *)i) == 0, "pthread_create");
	pid_t kids[4] = {0};
	if (mode_is("fork") || mode_is("native")) {
		for (long i = 0; i < 4; i++) {
			kids[i] = fork();
			CHECK(kids[i] >= 0, "fork");
			if (kids[i] == 0) {
				worker((void *)(10 + i));
				_exit(0);
			}
		}
	}
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	for (int i = 0; i < 4; i++) {
		if (!kids[i])
			continue;
		int st;
		CHECK(waitpid(kids[i], &st, 0) == kids[i] && WIFEXITED(st) && WEXITSTATUS(st) == 0, "child %d", i);
	}
	printf("HOSTDIR_PAR\n");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc >= 3, "usage: hostdir <op> <path> [<path>]");
	const char *op = argv[1];
	if (!strcmp(op, "write"))
		op_write(argv[2]);
	else if (!strcmp(op, "ro"))
		op_ro(argv[2]);
	else if (!strcmp(op, "escape") && argc == 4)
		op_escape(argv[2], argv[3]);
	else if (!strcmp(op, "big"))
		op_big(argv[2]);
	else if (!strcmp(op, "par"))
		op_par(argv[2]);
	else
		CHECK(0, "unknown op %s", op);
	printf("HOSTDIR_OK\n");
	return 0;
}
