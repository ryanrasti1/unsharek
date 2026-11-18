// Fork mode: guest fork, pipes between processes, wait statuses, separate memory.
// Prints one line per check and FORK_OK at the end; exits nonzero on the first failure.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int counter = 100;

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); return 1; } } while (0)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	pid_t me = getpid();
	printf("parent pid=%d\n", me);

	/* 1. A child writes to a pipe and exits with a status. */
	int p[2];
	CHECK(pipe(p) == 0, "pipe");
	pid_t c = fork();
	CHECK(c >= 0, "fork: %d (%s)", c, strerror(errno));
	if (c == 0) {
		close(p[0]);
		counter++;	/* the child's own copy */
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "child pid=%d ppid=%d counter=%d", getpid(), getppid(), counter);
		if (write(p[1], msg, n) != n)
			_exit(99);
		_exit(7);
	}
	close(p[1]);
	char buf[128] = {0};
	ssize_t n = read(p[0], buf, sizeof(buf) - 1);
	CHECK(n > 0, "read from child: %zd", n);
	printf("got: %s\n", buf);
	int st = 0;
	pid_t w = waitpid(c, &st, 0);
	CHECK(w == c, "waitpid returned %d, wanted %d", w, c);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7, "status %#x", st);
	CHECK(counter == 100, "parent's counter changed: %d", counter);
	printf("1 ok: child %d exited 7, parent's memory untouched\n", c);

	/* 2. Several children at once, reaped in any order. */
	enum { N = 4 };
	pid_t kids[N];
	for (int i = 0; i < N; i++) {
		kids[i] = fork();
		CHECK(kids[i] >= 0, "fork %d", i);
		if (kids[i] == 0) {
			volatile unsigned long x = 0;
			for (unsigned long k = 0; k < 2000000UL * (N - i); k++)
				x += k;
			_exit(10 + i);
		}
	}
	int seen = 0;
	for (int i = 0; i < N; i++) {
		w = wait(&st);
		CHECK(w > 0 && WIFEXITED(st), "wait: %d %#x", w, st);
		int idx = -1;
		for (int j = 0; j < N; j++)
			if (kids[j] == w)
				idx = j;
		CHECK(idx >= 0 && WEXITSTATUS(st) == 10 + idx, "pid %d status %d", w, WEXITSTATUS(st));
		seen |= 1 << idx;
	}
	CHECK(seen == (1 << N) - 1, "seen %#x", seen);
	CHECK(wait(&st) == -1, "a fifth child?");
	printf("2 ok: %d children reaped\n", N);

	/* 3. A grandchild: the child forks, waits, and passes its status on. */
	c = fork();
	if (c == 0) {
		pid_t g = fork();
		if (g == 0)
			_exit(3);
		int gs;
		if (waitpid(g, &gs, 0) != g || !WIFEXITED(gs))
			_exit(98);
		_exit(WEXITSTATUS(gs) + 20);
	}
	CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 23, "nested %#x", st);
	printf("3 ok: grandchild's status through the child\n");

	/* 4. A child that outlives a while: the parent blocks in read until it writes. */
	CHECK(pipe(p) == 0, "pipe");
	c = fork();
	if (c == 0) {
		close(p[0]);
		usleep(50000);
		if (write(p[1], "late", 4) != 4)
			_exit(97);
		_exit(0);
	}
	close(p[1]);
	memset(buf, 0, sizeof(buf));
	CHECK(read(p[0], buf, 4) == 4 && !strcmp(buf, "late"), "late read: %s", buf);
	CHECK(read(p[0], buf, 4) == 0, "EOF after the child's exit");
	CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0, "late status %#x", st);
	printf("4 ok: blocked read woken by another process\n");

	printf("FORK_OK\n");
	return 0;
}
