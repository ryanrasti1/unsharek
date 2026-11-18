// W^X unless the run opts out (--jit, or fork mode, whose exec maps programs into the arena):
// mmap and mprotect with PROT_EXEC are refused. EXOBOX_TEST_RWX=1 says the run allows it.
// Prints WX_OK.
#include "exobox_test.h"
#include <errno.h>
#include <sys/mman.h>

int main(void)
{
	int rwx = getenv("EXOBOX_TEST_RWX") != NULL;
	unsigned char *p =
		mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rwx) {
		CHECK(p != MAP_FAILED, "RWX mmap refused: %s", strerror(errno));
		p[0] = 0xb8; p[1] = 42; p[2] = p[3] = p[4] = 0; p[5] = 0xc3; /* mov $42, %eax; ret */
		int r = ((int (*)(void))p)();
		CHECK(r == 42, "generated code returned %d", r);
		printf("rwx: generated code ran\n");
	} else {
		CHECK(p == MAP_FAILED, "RWX mmap allowed");
		unsigned char *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		CHECK(q != MAP_FAILED, "mmap: %s", strerror(errno));
		CHECK(mprotect(q, 4096, PROT_READ | PROT_EXEC) != 0, "mprotect(PROT_EXEC) allowed");
		printf("w^x: PROT_EXEC refused by mmap and mprotect\n");
	}
	printf("WX_OK\n");
	return 0;
}
