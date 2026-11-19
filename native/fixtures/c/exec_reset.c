// An exec's kernel half (the kernel series' item 10): what the new image sees of the old one's
// kernel state. The runtime's exec loaded the new image but kept the rest: close-on-exec fds
// stayed open, caught signals' handlers (addresses in the old image) stayed installed, the old
// image's other threads kept running in the new one.
//   exec_reset [threads]  set up the state (with `threads`: two more threads, one waiting in a
//                         futex and one reading a pipe, and the exec made from a third), then exec
//                         itself as `exec_reset check <cloexec fd> <plain fd> <pid>`
//   exec_reset check <cloexec fd> <plain fd> <pid> <tasks before>  the new image: the close-on-exec fd closed, the plain one open, SIGUSR1's
//                         handler reset to the default, SIGUSR2 still ignored, SIGHUP still
//                         blocked, no alternate stack, one thread, the same pid, named after the
//                         file, /proc/self/exe the file
// Prints EXEC_RESET_OK.
#include "exobox_test.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void on_usr1(int s) { (void)s; }

/* The process's live tasks (not zombies: after an exec from another thread the old leader stays
 * one, as the kernel's new_exec leaves it). In the sandbox init's process also has the kernel's
 * parked host0, so the new image compares with the count before anything was started. */
static int threads_of_self(void)
{
	DIR *d = opendir("/proc/self/task");
	CHECK(d, "opendir /proc/self/task: %d", errno);
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		char path[64], buf[512];
		snprintf(path, sizeof path, "/proc/self/task/%s/stat", e->d_name);
		int fd = open(path, O_RDONLY);
		ssize_t k = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
		if (fd >= 0)
			close(fd);
		if (k <= 0)
			continue;
		buf[k] = 0;
		char *st = strrchr(buf, ')');
		n += !(st && st[1] == ' ' && st[2] == 'Z');
	}
	closedir(d);
	return n;
}

static int check(char **argv)
{
	int cloexec = atoi(argv[2]), plain = atoi(argv[3]);
	CHECK(fcntl(cloexec, F_GETFD) == -1 && errno == EBADF, "close-on-exec fd %d still open", cloexec);
	CHECK(fcntl(plain, F_GETFD) == 0, "plain fd %d: %d", plain, errno);
	struct sigaction sa;
	CHECK(sigaction(SIGUSR1, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL, "SIGUSR1's handler not reset: %p",
	      (void *)sa.sa_handler);
	CHECK(sigaction(SIGUSR2, NULL, &sa) == 0 && sa.sa_handler == SIG_IGN, "SIGUSR2 not ignored any more");
	sigset_t m;
	sigprocmask(SIG_BLOCK, NULL, &m);
	CHECK(sigismember(&m, SIGHUP), "SIGHUP no longer blocked");
	stack_t ss;
	CHECK(sigaltstack(NULL, &ss) == 0 && (ss.ss_flags & SS_DISABLE), "an alternate stack after exec");
	CHECK(getpid() == atoi(argv[4]), "pid %d, was %s", getpid(), argv[4]);
	CHECK(threads_of_self() == atoi(argv[5]), "%d live tasks after exec, %s before", threads_of_self(), argv[5]);
	char comm[32] = {0};
	CHECK(prctl(PR_GET_NAME, comm) == 0 && !strcmp(comm, "exec_reset"), "name %s", comm);
	char exe[4096];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	CHECK(n > 0, "readlink /proc/self/exe: %d", errno);
	exe[n] = 0;
	CHECK(n >= 11 && !strcmp(exe + n - 11, "/exec_reset"), "/proc/self/exe is %s", exe);
	printf("the new image: close-on-exec fd closed, handler reset, ignored and blocked kept, one thread\n");
	printf("EXEC_RESET_OK\n");
	return 0;
}

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int pipe_fds[2];
static char *exec_argv[7];

static void *cond_waiter(void *a)
{
	(void)a;
	pthread_mutex_lock(&mu);
	for (;;)
		pthread_cond_wait(&cv, &mu);
	return NULL;
}

static void *pipe_reader(void *a)
{
	(void)a;
	char c;
	if (read(pipe_fds[0], &c, 1) >= 0)
		printf("FAIL: the pipe reader read\n");
	return NULL;
}

static void *execer(void *a)
{
	(void)a;
	execv(exec_argv[0], exec_argv);
	printf("FAIL: execv from a thread: %d\n", errno);
	exit(1);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc >= 6 && !strcmp(argv[1], "check"))
		return check(argv);
	int threads = argc >= 2 && !strcmp(argv[1], "threads");

	int a[2], b[2];
	CHECK(pipe2(a, O_CLOEXEC) == 0 && pipe(b) == 0, "pipes");
	signal(SIGUSR1, on_usr1);
	signal(SIGUSR2, SIG_IGN);
	sigset_t m;
	sigemptyset(&m);
	sigaddset(&m, SIGHUP);
	sigprocmask(SIG_BLOCK, &m, NULL);
	static char alt[16384];
	stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt};
	CHECK(sigaltstack(&ss, NULL) == 0, "sigaltstack");
	prctl(PR_SET_NAME, "before-exec");

	static char fa[16], fb[16], pid[16], tasks[16];
	snprintf(tasks, sizeof tasks, "%d", threads_of_self());
	snprintf(fa, sizeof fa, "%d", a[0]);
	snprintf(fb, sizeof fb, "%d", b[0]);
	snprintf(pid, sizeof pid, "%d", getpid());
	exec_argv[0] = argv[0];
	exec_argv[1] = "check";
	exec_argv[2] = fa;
	exec_argv[3] = fb;
	exec_argv[4] = pid;
	exec_argv[5] = tasks;
	printf("exec%s, close-on-exec fd %d, plain fd %d\n", threads ? " from a thread of three" : "", a[0], b[0]);
	if (!threads) {
		execv(argv[0], exec_argv);
		CHECK(0, "execv: %d", errno);
	}
	CHECK(pipe(pipe_fds) == 0, "pipe");
	pthread_t t;
	CHECK(pthread_create(&t, NULL, cond_waiter, NULL) == 0, "pthread_create");
	CHECK(pthread_create(&t, NULL, pipe_reader, NULL) == 0, "pthread_create");
	struct timespec ts = {0, 20 * 1000 * 1000};
	nanosleep(&ts, NULL);
	CHECK(pthread_create(&t, NULL, execer, NULL) == 0, "pthread_create");
	for (;;)
		pause();
}
