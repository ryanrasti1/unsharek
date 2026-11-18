// A thread making syscalls while another sleeps in short poll timeouts (curl's threaded resolver
// pattern: the main thread polls a socketpair with a timeout while the resolver thread works, then
// writes to wake it). A new thread's first syscall makes its LKL task as a thread of init's process;
// that used to take init's task over from the caller's host thread (switch_to_host_task), so a later
// switch to init handed the CPU to the wrong thread: "lkl_cpu_put: unbalanced put".
// Prints THREADPOLL_OK.
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static int sv[2], what, iters;

static void *work(void *a)
{
	(void)a;
	for (int i = 0; i < iters; i++) {
		if (what == 1) {
			int fd = open("/", O_RDONLY);
			close(fd);
		} else if (what == 2) {
			char b;
			int p[2];
			if (pipe(p) == 0) {
				if (write(p[1], "x", 1) == 1 && read(p[0], &b, 1) == 1)
					;
				close(p[0]);
				close(p[1]);
			}
		}
	}
	if (write(sv[1], "x", 1) != 1)
		return (void *)1;
	return NULL;
}

int main(void)
{
	static const struct { int what, iters, timeout; } runs[] = {
		{0, 0, 1}, {1, 1000, 1}, {2, 1000, 1}, {1, 1000, 10}, {2, 200, 0},
	};
	for (unsigned r = 0; r < sizeof(runs) / sizeof(runs[0]); r++) {
		what = runs[r].what;
		iters = runs[r].iters;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
			return 1;
		pthread_t t;
		pthread_create(&t, NULL, work, NULL);
		struct pollfd p = {.fd = sv[0], .events = POLLIN};
		int n = 0;
		while (poll(&p, 1, runs[r].timeout) == 0)
			n++;
		void *ret;
		pthread_join(t, &ret);
		char b;
		if (ret || read(sv[0], &b, 1) != 1) {
			printf("FAIL: run %u\n", r);
			return 1;
		}
		close(sv[0]);
		close(sv[1]);
		printf("run %u ok: %d syscalls of kind %d on a thread, %d polls of %d ms meanwhile\n", r,
		       iters, what, n, runs[r].timeout);
	}
	printf("THREADPOLL_OK\n");
	return 0;
}
