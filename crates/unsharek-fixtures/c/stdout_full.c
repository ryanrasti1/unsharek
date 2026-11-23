// Writes to a full stdout pipe: the suite holds off reading the program's stdout for its first
// first 300 ms (`Case::stdout_delay`), so the pipe fills at once and stays full while the threads
// write. Threaded and fork mode hung here (xz -T2 ... | cat, 4 runs in 6; the perf suite's
// xz::threaded): a write to a nonblocking host fd is EAGAIN and the fd is watched, but only
// coroutine mode's idle wait polled the watched fds; threaded mode's idler waited on its eventfd
// alone, so nothing ever saw stdout become writable, and the program's poll waited for good, every
// thread parked waiting for the CPU token. And a blocking write that the host pipe couldn't take
// whole blocked in the host's write(2) holding the token: every other thread stopped with it.
// argv[1]:
//   nonblock  stdout O_NONBLOCK (as xz makes it); 4 threads write 256 KiB each in 8 KiB writes,
//             polling for POLLOUT at each EAGAIN
//   block     one thread writes 1 MiB in a single blocking write(2) while the main thread makes a
//             syscall every millisecond: none may wait long (the CPU is free while the write
//             waits for the reader)
//   exit      a thread blocked in that write, the process exits 100 ms in: it ends (the reader
//             starts after it), printing STDOUT_FULL_EXIT on stderr
//   signal    a thread blocked in that write gets a signal 100 ms in: the write returns what
//             it wrote
// With `child` before nonblock or block (fork mode), a forked process does it: init's process,
// whose kernel thread is the idler, polls the fds the child's threads wait for.
// Prints STDOUT_FULL_OK after its data, exits 0.
#include "unsharek_test.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 4
#define PER_THREAD (256 << 10)
#define CHUNK (8 << 10)
#define BIG (1 << 20)

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// All of buf to stdout, waiting for POLLOUT at each EAGAIN; returns the EAGAINs seen.
static long write_all(const char *buf, size_t len)
{
	long again = 0;
	while (len > 0) {
		ssize_t n = write(1, buf, len);
		if (n < 0 && errno == EAGAIN) {
			again++;
			struct pollfd p = {.fd = 1, .events = POLLOUT};
			CHECK(poll(&p, 1, -1) == 1, "poll: %s", strerror(errno));
			continue;
		}
		CHECK(n > 0, "write: %s", strerror(errno));
		buf += n;
		len -= n;
	}
	return again;
}

static void *nonblock_writer(void *arg)
{
	static char bufs[THREADS][CHUNK];
	long id = (long)arg, again = 0;
	char *b = bufs[id];
	memset(b, 'a' + id, CHUNK);
	b[CHUNK - 1] = '\n';
	for (int i = 0; i < PER_THREAD / CHUNK; i++)
		again += write_all(b, CHUNK);
	return (void *)again;
}

static atomic_int big_done;

static void *big_writer(void *arg)
{
	(void)arg;
	static char b[BIG];
	memset(b, 'b', BIG);
	b[BIG - 1] = '\n';
	ssize_t n = write(1, b, BIG);
	// A blocking write is whole unless a signal cut it short (none here).
	CHECK(n == BIG, "write of %d: %zd (%s)", BIG, n, n < 0 ? strerror(errno) : "short");
	atomic_store(&big_done, 1);
	return NULL;
}

static void nonblock(void)
{
	int fl = fcntl(1, F_GETFL);
	CHECK(fl >= 0 && fcntl(1, F_SETFL, fl | O_NONBLOCK) == 0, "O_NONBLOCK: %s", strerror(errno));
	pthread_t t[THREADS];
	for (long i = 0; i < THREADS; i++)
		CHECK(pthread_create(&t[i], NULL, nonblock_writer, (void *)i) == 0, "pthread_create");
	long again = 0;
	for (int i = 0; i < THREADS; i++) {
		void *r;
		pthread_join(t[i], &r);
		again += (long)r;
	}
	// The pipe was full: some write must have been EAGAIN, else this tested nothing.
	CHECK(again > 0, "no write was EAGAIN: the pipe never filled");
	CHECK(fcntl(1, F_SETFL, fl) == 0, "fcntl");
}

static void block(void)
{
	pthread_t t;
	CHECK(pthread_create(&t, NULL, big_writer, NULL) == 0, "pthread_create");
	long worst = 0, last = now_ms(), start = last;
	while (!atomic_load(&big_done)) {
		struct timespec ms = {0, 1000000};
		nanosleep(&ms, NULL);
		getppid();
		long t = now_ms();
		if (t - last > worst)
			worst = t - last;
		last = t;
	}
	pthread_join(t, NULL);
	dprintf(2, "write took %ld ms, the longest syscall gap %ld ms\n", last - start, worst);
	// The reader starts 300 ms after the run (less the sandbox's start): the write waits, the other
	// thread doesn't.
	CHECK(last - start >= 100, "the write didn't wait for the reader (%ld ms)", last - start);
	CHECK(worst < 150, "a syscall waited %ld ms while the write waited for the reader", worst);
}

static void on_usr1(int sig) { (void)sig; }

static void *cut_writer(void *arg)
{
	static char b[BIG];
	memset(b, 'c', BIG);
	*(ssize_t *)arg = write(1, b, BIG);
	return NULL;
}

// A blocking write waiting for the reader, ended by the process's exit, or cut short by a signal
// (no SA_RESTART): it returns what it wrote, as a pipe's write (natively, the pipe's 64 KiB).
static void cut(int by_exit)
{
	struct sigaction sa = {.sa_handler = on_usr1};
	struct timespec ms100 = {0, 100000000};
	ssize_t n = -2;
	pthread_t t;
	CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
	CHECK(pthread_create(&t, NULL, cut_writer, &n) == 0, "pthread_create");
	nanosleep(&ms100, NULL);
	if (by_exit) {
		// (on stderr: stdout is full)
		dprintf(2, "STDOUT_FULL_EXIT\n");
		exit(0);
	}
	CHECK(pthread_kill(t, SIGUSR1) == 0, "pthread_kill");
	pthread_join(t, NULL);
	dprintf(2, "the write of %d, interrupted: %zd\n", BIG, n);
	CHECK(n > 0 && n < BIG, "the interrupted write: %zd (%s)", n, n < 0 ? strerror(errno) : "");
}

int main(int argc, char **argv)
{
	const char *usage = "usage: stdout_full [child] nonblock|block|exit|signal";
	CHECK(argc == 2 || argc == 3, "%s", usage);
	const char *what = argv[argc - 1];
	if (argc == 2 && (!strcmp(what, "exit") || !strcmp(what, "signal"))) {
		cut(!strcmp(what, "exit"));
		printf("STDOUT_FULL_OK\n");
		fflush(stdout);
		return 0;
	}
	CHECK(!strcmp(what, "nonblock") || !strcmp(what, "block"), "%s", usage);
	pid_t pid = 0;
	if (argc == 3) {
		CHECK(!strcmp(argv[1], "child"), "%s", usage);
		pid = fork();
		CHECK(pid >= 0, "fork: %s", strerror(errno));
	}
	if (pid == 0) {
		if (!strcmp(what, "nonblock"))
			nonblock();
		else
			block();
		if (argc == 3) {
			fflush(stdout);
			_exit(0);
		}
	} else {
		int st;
		CHECK(waitpid(pid, &st, 0) == pid, "waitpid: %s", strerror(errno));
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child: status %#x", st);
	}
	printf("STDOUT_FULL_OK\n");
	fflush(stdout);
	return 0;
}
