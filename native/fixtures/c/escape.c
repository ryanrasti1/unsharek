// Attempts to reach the host from a sandbox, through libc and through the runtime's own syscall
// instruction. Every attempt must be refused (run with --deny=errno so refusals return EPERM).
// The secret file (argv[1]) exists on the host, not in the guest. Prints ESCAPE_OK.
#include "exobox_test.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 2, "usage: escape <host file>");
	gate_fn gate = exobox_gate();
	CHECK(gate, "no gate in the auxiliary vector: not sandboxed");

	/* A host file through libc: the syscall traps and lands in the guest kernel, which hasn't it. */
	int fd = open(argv[1], O_RDONLY);
	CHECK(fd < 0 && errno == ENOENT, "open(host file) via libc -> %d (%s)", fd, strerror(errno));
	printf("open(host file) via libc -> ENOENT\n");

	/* The same through the gate: refused by the filter. */
	long r = gate(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0, 0, 0);
	CHECK(r == -EPERM, "openat via gate -> %ld", r);
	r = gate(SYS_socket, 2, 1, 0, 0, 0, 0);
	CHECK(r == -EPERM, "socket via gate -> %ld", r);
	/* An fd nobody was given (the low ones are the guest's CPU-token eventfds in threaded and
	 * fork mode: kernel-numbered at lockdown, 3 and up). */
	r = gate(SYS_write, 4001, (long)"x", 1, 0, 0, 0);
	CHECK(r == -EPERM, "write(4001) via gate -> %ld", r);
	printf("openat, socket, write(4001) via gate -> EPERM\n");

	/* A new host process from anywhere: guest fork in fork mode, refused otherwise. */
	if (!mode_is("fork")) {
		r = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
		CHECK(r < 0, "clone(SIGCHLD) -> %ld: forked", r);
		printf("clone(SIGCHLD) -> %s\n", strerror(errno));
	}

	/* execve of a host program: the guest has none at that path. */
	char *args[] = {argv[1], NULL};
	execv(argv[1], args);
	CHECK(errno == ENOENT, "execve(host file) -> %s", strerror(errno));
	printf("execve(host file) -> ENOENT\n");

	printf("ESCAPE_OK\n");
	return 0;
}
