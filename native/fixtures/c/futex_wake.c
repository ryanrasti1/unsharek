// FUTEX_WAKE wakes a waiter on that address, not another one waiting at the same time. 32 threads
// wait on 32 adjacent words (any wait-queue hash puts several in one slot); each word is then woken
// on its own and its thread must finish. (capnix tier A: an emulated wake could take a waiter on a
// different address in the same hash slot; the intended waiter slept on, and this test hangs.)
// Prints FUTEX_WAKE_OK.
#include "exobox_test.h"
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { N = 32 };
static _Atomic int words[N], waiting;

static long futex(_Atomic int *w, int op, int v)
{
	return syscall(SYS_futex, w, op | FUTEX_PRIVATE_FLAG, v, NULL, NULL, 0);
}

static void *waiter(void *a)
{
	_Atomic int *w = &words[(long)a];
	atomic_fetch_add(&waiting, 1);
	while (atomic_load(w) == 0)
		futex(w, FUTEX_WAIT, 0);
	return NULL;
}

int main(void)
{
	pthread_t t[N];
	for (long i = 0; i < N; i++)
		CHECK(pthread_create(&t[i], NULL, waiter, (void *)i) == 0, "pthread_create %ld", i);
	while (atomic_load(&waiting) < N)
		usleep(1000);
	usleep(20000); /* (all of them in FUTEX_WAIT, most likely) */
	for (int i = N - 1; i >= 0; i--) {
		atomic_store(&words[i], 1);
		futex(&words[i], FUTEX_WAKE, 1);
		pthread_join(t[i], NULL);
	}
	printf("%d waiters, each woken by its own address\n", N);
	printf("FUTEX_WAKE_OK\n");
	return 0;
}
