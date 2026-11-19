// The GS base is the program's: set by arch_prctl(ARCH_SET_GS) and, with FSGSBASE, by wrgsbase
// (no syscall: no filter sees it), it survives syscalls, a thread's creation and join, and the
// sandbox keeps working. Threaded mode kept each host thread's runtime record at the GS base, so
// a program that set GS clobbered it (the next trap read the program's value as the record).
// A new thread starts with its creator's GS base, as Linux's clone copies it. Prints GSBASE_OK.
#include "exobox_test.h"
#include <asm/prctl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE (1 << 1)
#endif

static char area[2][64];

static unsigned long rdgs(void)
{
	unsigned long v;
	__asm__ volatile("rdgsbase %0" : "=r"(v));
	return v;
}

static void wrgs(unsigned long v) { __asm__ volatile("wrgsbase %0" ::"r"(v)); }

static unsigned long get_gs(void)
{
	unsigned long v = 0;
	CHECK(syscall(SYS_arch_prctl, ARCH_GET_GS, &v) == 0, "arch_prctl(ARCH_GET_GS)");
	return v;
}

static void *thread(void *want)
{
	char buf[16];
	// Syscalls of this thread's own, then its GS base: its creator's.
	for (int i = 0; i < 100; i++)
		if (getppid() < 0 || write(1, buf, 0) != 0)
			return (void *)1;
	return (void *)(get_gs() == (unsigned long)want ? 0L : 2L);
}

static void syscalls_and_threads(unsigned long want, int fsgsbase, const char *how)
{
	for (int i = 0; i < 1000; i++)
		CHECK(getppid() >= 0, "getppid");
	CHECK(get_gs() == want, "%s: ARCH_GET_GS %#lx, wanted %#lx", how, get_gs(), want);
	if (fsgsbase)
		CHECK(rdgs() == want, "%s: rdgsbase %#lx, wanted %#lx", how, rdgs(), want);
	pthread_t t[4];
	for (int i = 0; i < 4; i++)
		CHECK(pthread_create(&t[i], NULL, thread, (void *)want) == 0, "pthread_create");
	for (int i = 0; i < 4; i++) {
		void *r;
		CHECK(pthread_join(t[i], &r) == 0 && r == NULL, "%s: thread %d: %ld", how, i, (long)r);
	}
	CHECK(get_gs() == want, "%s: after the threads, %#lx", how, get_gs());
	printf("%s: GS base %#lx kept across syscalls and threads\n", how, want);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int fsgsbase = (getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE) != 0;

	unsigned long a = (unsigned long)area[0];
	CHECK(syscall(SYS_arch_prctl, ARCH_SET_GS, a) == 0, "arch_prctl(ARCH_SET_GS)");
	syscalls_and_threads(a, fsgsbase, "arch_prctl");

	if (fsgsbase) {
		unsigned long b = (unsigned long)area[1];
		wrgs(b);
		syscalls_and_threads(b, 1, "wrgsbase");
	} else {
		printf("no FSGSBASE: wrgsbase skipped\n");
	}
	printf("GSBASE_OK\n");
	return 0;
}
