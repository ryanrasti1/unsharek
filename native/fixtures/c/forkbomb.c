// Fork mode's process bound (--max-procs, EXOBOX_TEST_MAX_PROCS): forking without end stops at the
// bound with EAGAIN; the children are then killed and reaped, and their slots come back.
// Prints FORKBOMB_OK.
#include "exobox_test.h"
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	const char *w = getenv("EXOBOX_TEST_MAX_PROCS");
	CHECK(w, "EXOBOX_TEST_MAX_PROCS unset");
	int want = atoi(w);
	pid_t kids[256];
	int n = 0, err = 0;
	while (n < 256) {
		pid_t c = fork();
		if (c == 0) {
			for (;;)
				pause();
		}
		if (c < 0) {
			err = errno;
			break;
		}
		kids[n++] = c;
	}
	printf("forked %d, then: %s\n", n, strerror(err));
	for (int i = 0; i < n; i++)
		kill(kids[i], SIGKILL);
	int reaped = 0, st;
	while (wait(&st) > 0)
		reaped++;
	/* The bound counts every process, this one included. */
	CHECK(n == want - 1 && err == EAGAIN && reaped == n, "wanted %d then EAGAIN, reaped %d", want - 1,
	      reaped);
	pid_t c = fork();
	if (c == 0)
		_exit(5);
	CHECK(c > 0 && waitpid(c, &st, 0) == c && WEXITSTATUS(st) == 5, "no fork after the reaping");
	printf("FORKBOMB_OK\n");
	return 0;
}
