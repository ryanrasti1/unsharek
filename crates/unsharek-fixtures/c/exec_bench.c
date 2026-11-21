// What a process costs, for the vs-native suite (bench/quick): argv[1] rounds of fork, exec
// argv[2] (argv[3..] its arguments) and wait. One line: "forkexec <us per round>".
#include "unsharek_test.h"
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	CHECK(argc >= 3, "usage: exec_bench N PROGRAM [ARGS...]");
	long n = atol(argv[1]);
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	for (long i = 0; i < n; i++) {
		pid_t p = fork();
		CHECK(p >= 0, "fork");
		if (p == 0) {
			execv(argv[2], argv + 2);
			_exit(127);
		}
		int st;
		CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0, "round %ld: status %#x", i, st);
	}
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("forkexec %.0f\n", ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / 1e3 / n);
	return 0;
}
