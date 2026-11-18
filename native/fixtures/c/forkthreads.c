// Threads in a forked process (fork mode, src/fork.c "threads"): a child makes 4 threads that share
// a counter under a mutex and wait on a condition variable, joins them, checks their tids are its
// process's (getpid, distinct gettid, tgkill to one), and a second child exits with a thread still
// waiting (exit_group reaches it). Threads made and joined one after another return their values
// (pthread_join waits for each, so the next reuses a finished thread's stack). Prints FORKTHREADS_OK.
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int count, go;
static pid_t tids[4];
static volatile int got_usr1;

static void on_usr1(int s) { (void)s; got_usr1 = 1; }

static void *worker(void *p)
{
	int i = (int)(long)p;
	tids[i] = syscall(SYS_gettid);
	pthread_mutex_lock(&mu);
	while (!go)
		pthread_cond_wait(&cv, &mu);
	pthread_mutex_unlock(&mu);
	for (int k = 0; k < 1000; k++) {
		pthread_mutex_lock(&mu);
		count++;
		pthread_mutex_unlock(&mu);
		if (k % 100 == 0)
			sched_yield();
	}
	if (getpid() != (pid_t)syscall(SYS_getpid))
		return (void *)1;
	return NULL;
}

static void *sleeper(void *p)
{
	(void)p;
	pthread_mutex_lock(&mu);
	for (;;)
		pthread_cond_wait(&cv, &mu);	/* never signalled: the process exits around it */
	return NULL;
}

static void *ret_arg(void *p) { return p; }

/* Create and join, one after another: each join waits for its thread and gets its value. */
static int one_after_another(const char *who)
{
	for (long i = 1; i <= 4; i++) {
		pthread_t t;
		void *r = NULL;
		if (pthread_create(&t, NULL, ret_arg, (void *)i) || pthread_join(t, &r) || r != (void *)i) {
			printf("%s: thread %ld joined with %p\n", who, i, r);
			return 1;
		}
	}
	return 0;
}

static int child_threads(void)
{
	if (one_after_another("forked process"))
		return 1;
	pthread_t t[4];
	for (long i = 0; i < 4; i++)
		if (pthread_create(&t[i], NULL, worker, (void *)i)) {
			printf("pthread_create failed\n");
			return 1;
		}
	sleep(0);
	pthread_mutex_lock(&mu);
	go = 1;
	pthread_cond_broadcast(&cv);
	pthread_mutex_unlock(&mu);
	for (int i = 0; i < 4; i++) {
		void *r;
		pthread_join(t[i], &r);
		if (r) {
			printf("worker %d saw another pid\n", i);
			return 1;
		}
	}
	if (count != 4000) {
		printf("count %d, not 4000\n", count);
		return 1;
	}
	pid_t me = getpid(), main_tid = syscall(SYS_gettid);
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < i; j++)
			if (tids[i] == tids[j] || tids[i] == main_tid || tids[i] <= 0) {
				printf("tids not distinct: %d %d %d\n", tids[i], tids[j], main_tid);
				return 1;
			}
	/* A signal to one thread of this process, by its tid. */
	signal(SIGUSR1, on_usr1);
	pthread_t s;
	pthread_create(&s, NULL, worker, (void *)0);
	pthread_join(s, NULL);
	if (syscall(SYS_tgkill, me, main_tid, SIGUSR1) || !got_usr1) {
		printf("tgkill to the main thread: %d\n", got_usr1);
		return 1;
	}
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (one_after_another("first process"))
		return 1;
	pid_t pid = fork();
	if (pid == 0)
		_exit(child_threads());
	int st;
	if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) {
		printf("threads child: status %x\n", st);
		return 1;
	}
	pid = fork();
	if (pid == 0) {
		pthread_t s;
		pthread_create(&s, NULL, sleeper, NULL);
		usleep(10000);
		exit(7);		/* exit_group with the sleeper waiting */
	}
	if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 7) {
		printf("exit child: status %x\n", st);
		return 1;
	}
	printf("FORKTHREADS_OK\n");
	return 0;
}
