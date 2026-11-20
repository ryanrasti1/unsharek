// A thread kept busy, in user code (argv[1] "user") or in calls (argv[1] "calls"), mustn't keep
// another thread's sleep from ending. With one guest CPU passed between host threads (threaded
// and fork mode before SMP), main's 10 ms nanosleep never ended: its timer wasn't serviced while
// the other thread ran (found writing smp_scale). Prints BUSY_SLEEP_OK.
#include "unsharek_test.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_int done;
static int calls;

static void *busy(void *a)
{
	(void)a;
	while (!atomic_load(&done))
		if (calls)
			syscall(SYS_getppid);
	return NULL;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 2, "usage: busy_sleep user|calls");
	calls = !strcmp(argv[1], "calls");
	pthread_t t;
	CHECK(pthread_create(&t, NULL, busy, NULL) == 0, "pthread_create");
	for (int i = 0; i < 5; i++) {
		struct timespec d = {0, 10 * 1000 * 1000};
		CHECK(nanosleep(&d, NULL) == 0, "nanosleep");
	}
	atomic_store(&done, 1);
	pthread_join(t, NULL);
	printf("BUSY_SLEEP_OK\n");
	return 0;
}
