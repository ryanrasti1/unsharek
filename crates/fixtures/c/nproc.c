// The CPUs a program is told it has: sched_getaffinity, as nproc, std's available_parallelism and
// glibc's pthread_getaffinity_np read it. Prints "NPROC <count>". The sandbox reported one CPU in
// every mode, so rustc ran its codegen units one at a time in threaded and fork mode, whose
// threads run in parallel on the host's CPUs (bench/PERF.md: rustc at 2.8x native).
#define _GNU_SOURCE
#include "exobox_test.h"
#include <sched.h>

int main(void)
{
	cpu_set_t s;
	CHECK(sched_getaffinity(0, sizeof s, &s) == 0, "sched_getaffinity");
	int n = CPU_COUNT(&s);
	CHECK(n >= 1, "no CPU");
	// A buffer too small for the mask is refused, as the kernel does (a 1-byte one always is).
	unsigned char tiny;
	CHECK(sched_getaffinity(0, 1, (cpu_set_t *)&tiny) == -1, "a 1-byte mask was accepted");
	printf("NPROC %d\n", n);
	return 0;
}
