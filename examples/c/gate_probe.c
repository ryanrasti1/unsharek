// A hostile program for the `escape` example. It finds exobox's own syscall instruction (the
// "gate": the one place host syscalls are allowed from, which exobox puts in the auxiliary vector
// for its tests) and calls through it, as a compromised program that had found it would. What it
// gets is the host filter's answer, not the guest kernel's.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EXOBOX_AT_GATE 0x4558
typedef long (*gate_fn)(long, long, long, long, long, long, long);

static void show(const char *what, long r)
{
	if (r < 0)
		printf("  %-38s -> %s\n", what, strerror((int)-r));
	else
		printf("  %-38s -> %ld\n", what, r);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	gate_fn gate = (gate_fn)getauxval(EXOBOX_AT_GATE);
	if (!gate) {
		printf("  not sandboxed: no gate\n");
		return 2;
	}
	// An ordinary call traps and is the guest kernel's: init's parent, 0.
	show("getppid(), trapped: the guest's", getppid());
	// The same number through the gate is a host syscall: the filter decides.
	show("getppid() via the gate: the host's", gate(SYS_getppid, 0, 0, 0, 0, 0, 0));
	show("openat(\"/etc/passwd\") via the gate", gate(SYS_openat, AT_FDCWD, (long)"/etc/passwd", O_RDONLY, 0, 0, 0));
	printf("  survived\n");
	return 0;
}
