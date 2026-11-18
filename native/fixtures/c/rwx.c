// Generated code runs: writable and executable memory, by mmap and by mprotect (JITs: V8, the JVM,
// LuaJIT). The sandbox's boundary is the host filter, not W^X, which would be hardening of the
// program itself; so every mode allows it, with no flag. Prints RWX_OK.
#include "exobox_test.h"
#include <errno.h>
#include <sys/mman.h>

static void emit_and_run(unsigned char *p, int want)
{
	p[0] = 0xb8; p[1] = want; p[2] = p[3] = p[4] = 0; p[5] = 0xc3; /* mov $want, %eax; ret */
	int r = ((int (*)(void))p)();
	CHECK(r == want, "generated code returned %d, wanted %d", r, want);
}

int main(void)
{
	unsigned char *p =
		mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED, "RWX mmap: %s", strerror(errno));
	emit_and_run(p, 42);
	printf("mmap(RWX): generated code ran\n");

	unsigned char *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(q != MAP_FAILED, "mmap: %s", strerror(errno));
	q[0] = 0;
	CHECK(mprotect(q, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "mprotect(+X): %s", strerror(errno));
	emit_and_run(q, 7);
	printf("mprotect(+X): generated code ran\n");
	printf("RWX_OK\n");
	return 0;
}
