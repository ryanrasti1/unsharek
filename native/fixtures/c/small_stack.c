// A syscall writes nothing below the caller's stack pointer. Go makes raw syscalls on goroutine
// stacks with as little as ~128 bytes to spare; a sandbox that leaves its trap's signal frame
// (siginfo, ucontext, xsave: ~2 KB) on the app's stack overwrites the next goroutine's (capnix
// tier A: "unexpected return pc" in parallel mode). Each syscall here runs with the stack pointer
// in the middle of a poisoned buffer, and the whole buffer below it must be intact afterwards.
// Prints SMALL_STACK_OK.
#include "exobox_test.h"
#include <stdint.h>
#include <sys/syscall.h>

#define POISON 0xab
static unsigned char stack[64 << 10] __attribute__((aligned(64)));

static long syscall_on(unsigned char *sp, long nr, long a0, long a1, long a2)
{
	long r;
	register long r10 __asm__("r10") = 0;
	__asm__ volatile("mov %%rsp, %%r12\n\t"
			 "mov %[sp], %%rsp\n\t"
			 "syscall\n\t"
			 "mov %%r12, %%rsp"
			 : "=a"(r)
			 : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), [sp] "r"(sp)
			 : "rcx", "r11", "r12", "memory");
	return r;
}

int main(void)
{
	static const struct { const char *what; long nr, a0, a1, a2; } calls[] = {
		{"getppid (the guest's)", SYS_getppid, 0, 0, 0},
		{"write(1, \"\", 0) (stdio)", SYS_write, 1, (long)"", 0},
		{"clock_gettime", SYS_clock_gettime, 1, (long)(stack + sizeof(stack) - 64), 0},
		{"sched_yield", SYS_sched_yield, 0, 0, 0},
	};
	unsigned char *sp = stack + sizeof(stack) / 2;
	for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
		memset(stack, POISON, sizeof(stack) / 2);
		long r = syscall_on(sp, calls[i].nr, calls[i].a0, calls[i].a1, calls[i].a2);
		CHECK(r >= 0, "%s -> %ld", calls[i].what, r);
		size_t dirty = 0;
		for (unsigned char *p = stack; p < sp; p++)
			dirty += *p != POISON;
		CHECK(!dirty, "%s wrote %zu bytes below the stack pointer", calls[i].what, dirty);
		printf("%s: nothing written below sp\n", calls[i].what);
	}
	printf("SMALL_STACK_OK\n");
	return 0;
}
