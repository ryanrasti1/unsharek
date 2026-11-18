// Fork mode's signals: LKL's dispositions, masks, delivery and default actions.
// Prints one line per check and SIGNALS_OK at the end; exits nonzero on the first failure.
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); return 1; } } while (0)

static volatile sig_atomic_t got, got_sig, chld;
static volatile int info_pid;
static sigjmp_buf jb;
static void on_usr1(int s) { got++; got_sig = s; }
static void on_info(int s, siginfo_t *si, void *uc) { (void)s; (void)uc; info_pid = si->si_pid; }
static void on_chld(int s) { (void)s; chld++; }
static void on_jump(int s) { siglongjmp(jb, s); }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	/* 1. A handler, delivered at the kill's return. */
	signal(SIGUSR1, on_usr1);
	CHECK(kill(getpid(), SIGUSR1) == 0 && got == 1 && got_sig == SIGUSR1, "got=%d", got);
	printf("1 ok: handler ran\n");

	/* 2. Blocked: pending until unblocked. */
	sigset_t m, old;
	sigemptyset(&m);
	sigaddset(&m, SIGUSR1);
	sigprocmask(SIG_BLOCK, &m, &old);
	raise(SIGUSR1);
	sigset_t pend;
	sigpending(&pend);
	CHECK(got == 1 && sigismember(&pend, SIGUSR1), "blocked signal delivered or not pending");
	sigprocmask(SIG_SETMASK, &old, NULL);
	CHECK(got == 2, "not delivered once unblocked: got=%d", got);
	printf("2 ok: blocked, pending, delivered on unblock\n");

	/* 3. SA_SIGINFO from another process, and SIGCHLD when it exits. */
	struct sigaction sa = {0};
	sa.sa_sigaction = on_info;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGUSR2, &sa, NULL);
	signal(SIGCHLD, on_chld);
	pid_t parent = getpid(), c = fork();
	if (c == 0) {
		kill(parent, SIGUSR2);
		_exit(0);
	}
	int st;
	while (waitpid(c, &st, 0) < 0 && errno == EINTR)
		;
	CHECK(info_pid == c, "si_pid %d, wanted %d", info_pid, c);
	CHECK(chld >= 1, "no SIGCHLD");
	printf("3 ok: siginfo from pid %d, SIGCHLD\n", c);

	/* 4. A default action ends a child; its parent sees the signal in wait. */
	c = fork();
	if (c == 0) {
		for (;;)
			pause();
	}
	usleep(20000);
	kill(c, SIGTERM);
	while (waitpid(c, &st, 0) < 0 && errno == EINTR)
		;
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM, "status %#x", st);
	printf("4 ok: child killed by SIGTERM\n");

	/* 5. A sleep interrupted by a signal: EINTR. */
	signal(SIGALRM, on_usr1);
	alarm(1);
	struct timespec ts = {5, 0};
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	int r = nanosleep(&ts, NULL);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	CHECK(r == -1 && errno == EINTR && t1.tv_sec - t0.tv_sec < 3, "nanosleep %d errno %d", r, errno);
	printf("5 ok: nanosleep interrupted by SIGALRM\n");

	/* 6. siglongjmp out of a handler, then syscalls still work (and again). */
	signal(SIGUSR1, on_jump);
	for (int i = 0; i < 50; i++) {
		if (sigsetjmp(jb, 1) == 0) {
			kill(getpid(), SIGUSR1);
			CHECK(0, "returned from a handler that jumps");
		}
	}
	CHECK(getpid() == parent && write(1, "", 0) == 0, "syscalls after longjmp");
	printf("6 ok: 50 siglongjmps out of handlers\n");

	/* 7. A fatal signal to a child running a sleep. */
	c = fork();
	if (c == 0) {
		sleep(30);
		_exit(0);
	}
	usleep(20000);
	kill(c, SIGINT);
	while (waitpid(c, &st, 0) < 0 && errno == EINTR)
		;
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGINT, "status %#x", st);
	printf("7 ok: sleeping child killed by SIGINT\n");

	printf("SIGNALS_OK\n");
	return 0;
}
