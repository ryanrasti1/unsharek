// Signals: the guest kernel's dispositions, masks, delivery and default actions, and handlers the
// runtime runs as the program (the kernel series' item 8). Every mode runs the checks without a
// fork; fork mode (and natively) the ones with a child too. Before the runtime ran handlers, a
// handler was recorded and never run, and a fatal default action was faked as exit 128 + it.
// Prints one line per check and SIGNALS_OK at the end; exits nonzero on the first failure.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); exit(1); } } while (0)

/* glibc declares its calls leaf functions: the compiler may keep a handler-written struct in
 * registers across them. */
#define BARRIER() __asm__ volatile("" ::: "memory")

static volatile sig_atomic_t got, got_sig, chld, nested, alrm;
static volatile int info_pid;
static siginfo_t info_copy;
static volatile int info_blocked, uc_has_it;
static volatile uintptr_t handler_sp;
static sigjmp_buf jb;
static int restart_pipe[2];

static void on_usr1(int s) { got++; got_sig = s; }
static void on_chld(int s) { (void)s; chld++; }
static void on_jump(int s) { siglongjmp(jb, s); }
static void on_alrm(int s) { (void)s; alrm++; }

static void on_info(int s, siginfo_t *si, void *ucv)
{
	ucontext_t *uc = ucv;
	sigset_t now;
	info_copy = *si;
	info_pid = si->si_pid;
	sigprocmask(SIG_BLOCK, NULL, &now);
	info_blocked = sigismember(&now, s);
	uc_has_it = sigismember(&uc->uc_sigmask, s);
}

static void on_stack(int s)
{
	(void)s;
	int here;
	handler_sp = (uintptr_t)&here;
}

/* SA_RESTART's read: the handler makes the byte the interrupted read then gets. */
static void on_restart(int s)
{
	(void)s;
	char c = 'r';
	if (write(restart_pipe[1], &c, 1) != 1)
		_exit(9);
}

static void on_outer(int s)
{
	(void)s;
	raise(SIGUSR2); /* delivered inside this handler, at raise's return */
	nested = nested * 10 + 1;
}

static void on_inner(int s) { (void)s; nested = nested * 10 + 2; }

/* A handler that clobbers the vector registers: the interrupted code's must come back. */
static void on_clobber(int s)
{
	(void)s;
	__asm__ volatile("pcmpeqd %%xmm8, %%xmm8\n\txorps %%xmm9, %%xmm9" ::: "xmm8", "xmm9");
}

/* A Go-style handler: every signal, SA_SIGINFO | SA_ONSTACK | SA_RESTART. */
static volatile sig_atomic_t go_count[65];
static void go_handler(int s, siginfo_t *si, void *uc)
{
	(void)si;
	(void)uc;
	go_count[s]++;
}

static void ms(long n)
{
	struct timespec t = {n / 1000, (n % 1000) * 1000000};
	while (nanosleep(&t, &t) < 0 && errno == EINTR)
		;
}

/* An itimer firing once after `ms` milliseconds (SIGALRM). */
static void itimer_ms(long n)
{
	struct itimerval it = {{0, 0}, {n / 1000, (n % 1000) * 1000}};
	CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0, "setitimer");
}

static void set(int sig, void (*h)(int), int flags)
{
	struct sigaction sa = {0};
	sa.sa_handler = h;
	sa.sa_flags = flags;
	CHECK(sigaction(sig, &sa, NULL) == 0, "sigaction(%d)", sig);
}

/* A thread blocked in a futex wait (pthread_cond_wait) or a pipe read, and a signal for it. */
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static volatile int go_on, thread_got;
static int thread_pipe[2];
static void on_thread(int s) { (void)s; thread_got++; }

static void *cond_waiter(void *a)
{
	(void)a;
	pthread_mutex_lock(&mu);
	while (!go_on)
		pthread_cond_wait(&cv, &mu);
	pthread_mutex_unlock(&mu);
	return NULL;
}

static void *pipe_reader(void *a)
{
	(void)a;
	char c;
	ssize_t r = read(thread_pipe[0], &c, 1);
	return (void *)(intptr_t)(r < 0 ? errno : 0);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *mode = getenv("EXOBOX_TEST_MODE");
	int forks = !mode || !strcmp(mode, "native") || !strcmp(mode, "fork");
	pid_t parent = getpid();

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

	/* 3. SA_SIGINFO: the siginfo of a kill and of a tgkill; the signal blocked in the handler and
	 * not in uc_sigmask. */
	struct sigaction sa = {0};
	sa.sa_sigaction = on_info;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGUSR2, &sa, NULL);
	kill(getpid(), SIGUSR2);
	BARRIER();
	CHECK(info_copy.si_signo == SIGUSR2 && info_copy.si_code == SI_USER && info_copy.si_pid == getpid() &&
		      info_copy.si_uid == getuid(),
	      "kill's siginfo: signo %d code %d pid %d uid %d", info_copy.si_signo, info_copy.si_code,
	      info_copy.si_pid, info_copy.si_uid);
	CHECK(info_blocked && !uc_has_it, "in the handler: blocked %d, in uc_sigmask %d", info_blocked, uc_has_it);
	syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2);
	BARRIER();
	CHECK(info_copy.si_code == SI_TKILL && info_copy.si_pid == getpid(), "tgkill's siginfo: code %d (want %d) pid %d getpid %d",
	      info_copy.si_code, SI_TKILL, info_copy.si_pid, getpid());
	union sigval v = {.sival_int = 42};
	CHECK(sigqueue(getpid(), SIGUSR2, v) == 0, "sigqueue");
	BARRIER();
	CHECK(info_copy.si_code == SI_QUEUE && info_copy.si_value.sival_int == 42, "sigqueue's siginfo: code %d value %d",
	      info_copy.si_code, info_copy.si_value.sival_int);
	printf("3 ok: SA_SIGINFO handler's siginfo and masks\n");

	/* 4. SA_ONSTACK: the handler runs on the alternate stack; without it, on the thread's. */
	static char alt[64 * 1024];
	stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt, .ss_flags = 0};
	CHECK(sigaltstack(&ss, NULL) == 0, "sigaltstack");
	set(SIGURG, on_stack, SA_ONSTACK);
	raise(SIGURG);
	CHECK(handler_sp >= (uintptr_t)alt && handler_sp < (uintptr_t)alt + sizeof alt, "SA_ONSTACK handler at %#lx",
	      (unsigned long)handler_sp);
	set(SIGURG, on_stack, 0);
	raise(SIGURG);
	CHECK(!(handler_sp >= (uintptr_t)alt && handler_sp < (uintptr_t)alt + sizeof alt), "no SA_ONSTACK, on the altstack");
	stack_t cur;
	CHECK(sigaltstack(NULL, &cur) == 0 && cur.ss_sp == alt && !(cur.ss_flags & SS_ONSTACK), "altstack after");
	printf("4 ok: SA_ONSTACK on the alternate stack\n");

	/* 5. A sleep interrupted by a signal: EINTR, the time left. */
	set(SIGALRM, on_alrm, 0);
	itimer_ms(20);
	struct timespec ts = {5, 0}, left = {0, 0}, t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	int r = nanosleep(&ts, &left);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	CHECK(r == -1 && errno == EINTR && alrm == 1 && t1.tv_sec - t0.tv_sec < 3 && left.tv_sec >= 3,
	      "nanosleep %d errno %d alrm %d left %ld", r, errno, (int)alrm, (long)left.tv_sec);
	printf("5 ok: nanosleep interrupted by SIGALRM\n");

	/* 6. SA_RESTART: a pipe read the handler's signal interrupted runs again (and gets the byte the
	 * handler wrote); without it, EINTR. */
	CHECK(pipe(restart_pipe) == 0, "pipe");
	set(SIGALRM, on_restart, SA_RESTART);
	itimer_ms(20);
	char c = 0;
	r = read(restart_pipe[0], &c, 1);
	CHECK(r == 1 && c == 'r', "SA_RESTART read %d errno %d", r, errno);
	set(SIGALRM, on_alrm, 0);
	itimer_ms(20);
	r = read(restart_pipe[0], &c, 1);
	CHECK(r == -1 && errno == EINTR, "read without SA_RESTART %d errno %d", r, errno);
	printf("6 ok: SA_RESTART restarts a read, else EINTR\n");

	/* 7. siglongjmp out of a handler, then syscalls still work (and again). */
	signal(SIGUSR1, on_jump);
	for (int i = 0; i < 50; i++) {
		if (sigsetjmp(jb, 1) == 0) {
			kill(getpid(), SIGUSR1);
			CHECK(0, "returned from a handler that jumps");
		}
	}
	CHECK(getpid() == parent && write(1, "", 0) == 0, "syscalls after longjmp");
	sigprocmask(SIG_BLOCK, NULL, &m);
	CHECK(!sigismember(&m, SIGUSR1), "siglongjmp(jb, 1) kept SIGUSR1 blocked");
	printf("7 ok: 50 siglongjmps out of handlers\n");

	/* 8. A signal delivered inside a handler (raise there), and the vector registers of the
	 * interrupted code restored after a handler clobbers them. */
	set(SIGUSR1, on_outer, SA_NODEFER);
	set(SIGUSR2, on_inner, 0);
	raise(SIGUSR1);
	CHECK(nested == 21, "nested %d", (int)nested);
	set(SIGUSR1, on_clobber, 0);
	uint64_t want = 0x0123456789abcdefull, got8 = 0;
	long ret;
	__asm__ volatile("movq %[w], %%xmm8\n\t"
			 "syscall\n\t"
			 "movq %%xmm8, %[g]"
			 : [g] "=r"(got8), "=a"(ret)
			 : [w] "r"(want), "1"((long)SYS_kill), "D"((long)getpid()), "S"((long)SIGUSR1)
			 : "rcx", "r11", "xmm8", "xmm9", "memory");
	CHECK(ret == 0 && got8 == want, "xmm8 after a handler: %#lx", (unsigned long)got8);
	printf("8 ok: nested handlers, vector registers restored\n");

	/* 9. A signal for a thread blocked in a futex wait, and for one in a pipe read: the handler
	 * runs on that thread, the read is EINTR, the condition wait carries on. */
	set(SIGUSR1, on_thread, 0);
	CHECK(pipe(thread_pipe) == 0, "pipe");
	pthread_t tc, tp;
	CHECK(pthread_create(&tc, NULL, cond_waiter, NULL) == 0, "pthread_create");
	CHECK(pthread_create(&tp, NULL, pipe_reader, NULL) == 0, "pthread_create");
	ms(20);
	pthread_kill(tc, SIGUSR1);
	pthread_kill(tp, SIGUSR1);
	for (int i = 0; i < 200 && thread_got < 2; i++)
		ms(5);
	CHECK(thread_got == 2, "thread handlers %d", (int)thread_got);
	void *res;
	CHECK(pthread_join(tp, &res) == 0 && (intptr_t)res == EINTR, "pipe reader: %ld", (long)(intptr_t)res);
	pthread_mutex_lock(&mu);
	go_on = 1;
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mu);
	CHECK(pthread_join(tc, NULL) == 0, "cond waiter");
	printf("9 ok: signals for threads in a futex wait and a pipe read\n");

	/* 10. A Go-style runtime: a handler for every signal (SIGSYS among them), on an alternate
	 * stack; then the sandbox still serves calls and threads, and handlers run. */
	struct sigaction g = {0};
	g.sa_sigaction = go_handler;
	g.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigfillset(&g.sa_mask);
	int installed = 0;
	for (int s = 1; s < 65; s++) {
		if (s == SIGKILL || s == SIGSTOP || (s >= 32 && s < SIGRTMIN))
			continue;
		CHECK(sigaction(s, &g, NULL) == 0, "sigaction(%d) for every signal", s);
		installed++;
	}
	for (int i = 0; i < 100; i++)
		CHECK(getppid() >= 0 && write(1, "", 0) == 0, "syscalls under every handler");
	CHECK(pthread_create(&tc, NULL, pipe_reader, NULL) == 0, "a thread under every handler");
	c = 'x';
	CHECK(write(thread_pipe[1], &c, 1) == 1 && pthread_join(tc, &res) == 0 && res == NULL, "thread read");
	int sigs[] = {SIGURG, SIGWINCH, SIGUSR1, SIGSYS, SIGRTMIN + 1};
	for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++) {
		raise(sigs[i]);
		CHECK(go_count[sigs[i]] == 1, "go handler for %d: %d", sigs[i], (int)go_count[sigs[i]]);
	}
	printf("10 ok: a handler for each of %d signals; calls, threads and delivery work\n", installed);
	for (int s = 1; s < 65; s++)
		if (s != SIGKILL && s != SIGSTOP && !(s >= 32 && s < SIGRTMIN))
			signal(s, SIG_DFL);

	if (forks) {
		/* 11. SA_SIGINFO from another process, and SIGCHLD when it exits. */
		info_pid = 0;
		sigaction(SIGUSR2, &sa, NULL);
		signal(SIGCHLD, on_chld);
		pid_t c = fork();
		if (c == 0) {
			kill(parent, SIGUSR2);
			_exit(0);
		}
		int st;
		while (waitpid(c, &st, 0) < 0 && errno == EINTR)
			;
		CHECK(info_pid == c, "si_pid %d, wanted %d", info_pid, c);
		CHECK(chld >= 1, "no SIGCHLD");
		printf("11 ok: siginfo from pid %d, SIGCHLD\n", c);

		/* 12. A default action ends a child; its parent sees the signal in wait. */
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
		printf("12 ok: child killed by SIGTERM\n");

		/* 13. A fatal signal to a child running a sleep. */
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
		printf("13 ok: sleeping child killed by SIGINT\n");
	}

	printf("SIGNALS_OK\n");
	return 0;
}
