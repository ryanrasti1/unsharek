// Attempts to reach the host from a sandbox through libc: each is trapped and served by the guest
// kernel, which has no host file and makes no host process. The secret file (argv[1]) exists on
// the host, not in the guest. Prints ESCAPE_OK. (Through the gate, each refused call kills the
// sandbox: escape_gate.c, one probe a run.)
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

	/* read and write from the gate are allowed on any fd, and reach only the open ones: an fd
	 * nobody was given is closed (lockdown closed it, and nothing can open one), so EBADF. In
	 * threaded and fork mode the low numbers are the guest's CPU-token eventfds; 4000 is open
	 * nowhere. */
	long r = gate(SYS_write, 4000, (long)"x", 1, 0, 0, 0);
	CHECK(r == -EBADF, "write(4000) via gate -> %ld", r);
	char c;
	r = gate(SYS_read, 4000, (long)&c, 1, 0, 0, 0);
	CHECK(r == -EBADF, "read(4000) via gate -> %ld", r);
	printf("read, write(4000) via gate -> EBADF\n");
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
