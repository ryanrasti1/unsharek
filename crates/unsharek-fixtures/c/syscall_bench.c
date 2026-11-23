// What the sandbox's own paths cost, one line per operation: "<op> <ns per op>".
//   getppid      a syscall the guest kernel serves
//   sigprocmask  block and unblock a signal (the guest kernel's in every mode)
//   signal       kill(self) and its handler's run, the round trip
//   pingpong     one byte there and back between two threads over pipes
//   futex        a turn there and back between two threads through a futex word (wait, wake)
// argv[1]: iterations (default 20000).
#include "unsharek_test.h"
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long n;
static int ab[2], ba[2];
static volatile sig_atomic_t got;

static double now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e9 + t.tv_nsec;
}

static _Atomic int turn;

static void fx_wait(int v) { syscall(SYS_futex, &turn, FUTEX_WAIT_PRIVATE, v, NULL, NULL, 0); }
static void fx_wake(void) { syscall(SYS_futex, &turn, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0); }

/* The futex ping-pong's other side: waits for turn 1, passes it back as 0. */
static void *fx_peer(void *a)
{
	(void)a;
	for (long i = 0; i < n; i++) {
		while (atomic_load(&turn) != 1)
			fx_wait(0);
		atomic_store(&turn, 0);
		fx_wake();
	}
	return NULL;
}

static void on_usr1(int s) { (void)s; got++; }

static void *echo(void *a)
{
	(void)a;
	char c;
	for (long i = 0; i < n; i++)
		if (read(ab[0], &c, 1) != 1 || write(ba[1], &c, 1) != 1)
			return (void *)1;
	return NULL;
}

int main(int argc, char **argv)
{
	n = argc > 1 ? atol(argv[1]) : 20000;
	double t = now_ns();
	for (long i = 0; i < n; i++)
		syscall(SYS_getppid);
	printf("getppid %.0f\n", (now_ns() - t) / n);

	sigset_t m;
	sigemptyset(&m);
	sigaddset(&m, SIGUSR1);
	t = now_ns();
	for (long i = 0; i < n; i++) {
		sigprocmask(SIG_BLOCK, &m, NULL);
		sigprocmask(SIG_UNBLOCK, &m, NULL);
	}
	printf("sigprocmask %.0f\n", (now_ns() - t) / (2 * n));

	signal(SIGUSR1, on_usr1);
	pid_t me = getpid();
	t = now_ns();
	for (long i = 0; i < n; i++)
		kill(me, SIGUSR1);
	CHECK(got == n, "%d of %ld signals handled", (int)got, n);
	printf("signal %.0f\n", (now_ns() - t) / n);

	CHECK(pipe(ab) == 0 && pipe(ba) == 0, "pipe");
	pthread_t th;
	CHECK(pthread_create(&th, NULL, echo, NULL) == 0, "pthread_create");
	char c = 'x';
	t = now_ns();
	for (long i = 0; i < n; i++)
		CHECK(write(ab[1], &c, 1) == 1 && read(ba[0], &c, 1) == 1, "pingpong %ld", i);
	printf("pingpong %.0f\n", (now_ns() - t) / n);
	void *r;
	pthread_join(th, &r);
	CHECK(!r, "echo thread");

	CHECK(pthread_create(&th, NULL, fx_peer, NULL) == 0, "pthread_create");
	t = now_ns();
	for (long i = 0; i < n; i++) {
		atomic_store(&turn, 1);
		fx_wake();
		while (atomic_load(&turn) != 0)
			fx_wait(1);
	}
	printf("futex %.0f\n", (now_ns() - t) / n);
	pthread_join(th, NULL);
	printf("SYSCALL_BENCH_OK\n");
	return 0;
}
