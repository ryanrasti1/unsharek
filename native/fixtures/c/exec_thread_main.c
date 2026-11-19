// An exec from a thread other than the main one, while the main thread waits, and then a new
// image that makes threads of its own (Rust's libtest does all of this: its main thread waits in
// a timed futex for the test thread, which execs; the new image runs the test on a thread again).
// Threaded and fork mode panicked in the runtime ("attempt to subtract with overflow" in
// `Context::new`, a stack top of 0) at the new image's first thread, and then hung: the main
// thread's end (the exec ends it) freed its host slot's coroutines, one of them the scheduler's
// root, which has no stack of its own (it ran on the host thread's), onto the free list; the new
// thread's scheduler coroutine was made in it, on a stack at 0 (sched.rs's `free_slot`). How the main thread waits
// doesn't matter (a futex, timed or not, pause, a join all did it); that the new image makes a
// thread does: exec_reset.c's `threads` variant execs from a thread too, and its new image
// makes none, so it passed.
//   exec_thread_main timed|pause  start a thread that execs this program as `exec_thread_main
//                                 after`, the main thread meanwhile waiting in a timed futex
//                                 (libtest's wait) or in pause (exec_reset.c's)
//   exec_thread_main after        the new image: makes threads (each makes one more, so the
//                                 slots the old image's threads left are taken several times
//                                 over), joins them
// Prints EXEC_THREAD_MAIN_OK.
#include "exobox_test.h"
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static char *self;
static uint32_t word;

static void *execer(void *a)
{
	(void)a;
	// Let the main thread get into its wait.
	struct timespec ts = {0, 20 * 1000 * 1000};
	nanosleep(&ts, NULL);
	char *argv[] = {self, "after", NULL};
	execv(self, argv);
	printf("FAIL: execv from a thread: %d\n", errno);
	exit(1);
}

static void *leaf(void *a) { return a; }

static void *inner(void *a)
{
	pthread_t t;
	void *r;
	CHECK(pthread_create(&t, NULL, leaf, a) == 0, "pthread_create (inner)");
	CHECK(pthread_join(t, &r) == 0 && r == a, "pthread_join (inner)");
	return a;
}

static int after(void)
{
	for (intptr_t i = 1; i <= 8; i++) {
		pthread_t t;
		void *r;
		CHECK(pthread_create(&t, NULL, inner, (void *)i) == 0, "pthread_create %ld", (long)i);
		CHECK(pthread_join(t, &r) == 0 && r == (void *)i, "pthread_join %ld", (long)i);
	}
	printf("the new image made and joined its threads\n");
	printf("EXEC_THREAD_MAIN_OK\n");
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	self = argv[0];
	CHECK(argc == 2, "usage: exec_thread_main timed|pause|after");
	if (!strcmp(argv[1], "after"))
		return after();
	const char *how = argv[1];
	printf("exec from a thread, the main thread waiting by %s\n", how);
	pthread_t t;
	CHECK(pthread_create(&t, NULL, execer, NULL) == 0, "pthread_create");
	for (;;) {
		if (!strcmp(how, "timed")) {
			struct timespec ts = {60, 0};
			syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
		} else if (!strcmp(how, "pause")) {
			pause();
		} else {
			CHECK(0, "no such wait: %s", how);
		}
	}
}
