// CPU-bound threads with no syscalls in the loop: argv[1] threads each run argv[2] iterations of
// xorshift. Prints "wall_ms <ms>". Threads that are host threads run in parallel; coroutines
// don't.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long iters;
static volatile uint64_t sink[64];

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void *work(void *p)
{
	uint64_t x = 88172645463325252ULL + (uintptr_t)p;
	for (long i = 0; i < iters; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	sink[(uintptr_t)p] = x;
	return NULL;
}

int main(int argc, char **argv)
{
	int threads = argc > 1 ? atoi(argv[1]) : 1;
	iters = argc > 2 ? atol(argv[2]) : 100000000L;
	if (threads < 1 || threads > 64)
		return 2;
	pthread_t th[64];
	double t0 = now();
	for (int i = 0; i < threads; i++)
		if (pthread_create(&th[i], NULL, work, (void *)(uintptr_t)i))
			return 1;
	for (int i = 0; i < threads; i++)
		pthread_join(th[i], NULL);
	printf("wall_ms %.1f\n", (now() - t0) * 1e3);
	return 0;
}
