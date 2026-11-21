// The default deny action: a refused host syscall kills the sandbox (SIGSYS), no EPERM to probe
// with. The suite expects death by SIGSYS before ESCAPE_KILL_SURVIVED.
#include "unsharek_test.h"
#include <fcntl.h>
#include <sys/syscall.h>

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	gate_fn gate = unsharek_gate();
	CHECK(gate, "no gate in the auxiliary vector: not sandboxed");
	long r = gate(SYS_openat, AT_FDCWD, (long)"/", O_RDONLY, 0, 0, 0);
	printf("ESCAPE_KILL_SURVIVED %ld\n", r);
	return 1;
}
