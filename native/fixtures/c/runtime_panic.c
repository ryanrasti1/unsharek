// A panic in the runtime ends the sandbox, at once and by SIGABRT, in every mode. It hung in
// threaded and fork mode: std's panic wrote its message and made its abort's tgkill as guest
// calls, served by the runtime that had panicked (mid-call, holding the CPU token). When the
// panic had left the guest mid-change (a thread's guest task made, its host thread not: the panic
// exec_thread_main.c found), the guest's SIGABRT ended the panicking thread's task but never the
// process, whose other task never runs; that host thread exited and the idler polled for good.
//   runtime_panic main    the runtime's test hook (a call debug builds panic on: guest.rs's
//                         TEST_PANIC), from the main thread
//   runtime_panic thread  the same from a second thread, the main one waiting in a timed futex
//   runtime_panic clone   the hook armed for the next thread's clone, which a second thread
//                         makes while the main one waits in a timed futex: the guest mid-change
// Natively the call is ENOSYS: prints RUNTIME_PANIC_OK. In the sandbox the expected end is
// SIGABRT before that line.
#include "exobox_test.h"
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TEST_PANIC 0x4558

static uint32_t word;
static int in_clone;

static void *leaf(void *a) { return a; }

static void *panicker(void *a)
{
	(void)a;
	long r = syscall(TEST_PANIC, in_clone);
	// (arming it returns 0 in the sandbox)
	CHECK((r == -1 && errno == ENOSYS) || (in_clone && r == 0), "the test call: %ld, %d", r, errno);
	if (in_clone) {
		pthread_t t;
		CHECK(pthread_create(&t, NULL, leaf, NULL) == 0, "pthread_create");
		CHECK(pthread_join(t, NULL) == 0, "pthread_join");
	}
	printf("RUNTIME_PANIC_OK\n");
	exit(0);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 2, "usage: runtime_panic main|thread|clone");
	printf("the runtime's test panic: %s\n", argv[1]);
	in_clone = !strcmp(argv[1], "clone");
	if (!strcmp(argv[1], "main"))
		panicker(NULL);
	pthread_t t;
	CHECK(pthread_create(&t, NULL, panicker, NULL) == 0, "pthread_create");
	for (;;) {
		struct timespec ts = {60, 0};
		syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
	}
}
