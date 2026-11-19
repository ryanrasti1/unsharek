// How fork mode's processes end besides their own exit (guest/fork.rs, "Ends").
//
//   fork_ends init_exit    init (this process) exits 0 while its child waits in pause(): init's
//                          end is the sandbox's, as a pid namespace's init's, and the child must
//                          not outlive it on the host (it held the sandbox's stdout open, and the
//                          run never ended: every forked process waits for the CPU on an eventfd
//                          nobody writes any more). Prints FORK_ENDS_OK first.
//   fork_ends child_killed a child calls through the gate with a call the filter kills: its host
//                          process dies of SIGSYS, which the guest kernel never sees (the child
//                          may have held the CPU, the kernel's shared state half-updated), so the
//                          sandbox dies of it too, and the parent never gets to say it survived.
#include "exobox_test.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 2, "usage: fork_ends init_exit|child_killed");
	if (!strcmp(argv[1], "init_exit")) {
		pid_t c = fork();
		CHECK(c >= 0, "fork");
		if (c == 0) {
			for (;;)
				pause();
		}
		usleep(20000);
		printf("FORK_ENDS_OK\n");
		return 0;
	}
	gate_fn gate = exobox_gate();
	CHECK(gate, "no gate in the auxiliary vector: not sandboxed");
	pid_t c = fork();
	CHECK(c >= 0, "fork");
	if (c == 0) {
		gate(SYS_openat, AT_FDCWD, (long)"/", O_RDONLY, 0, 0, 0);
		_exit(0);
	}
	int st;
	waitpid(c, &st, 0);
	sleep(3);
	printf("FORK_ENDS_SURVIVED %#x\n", st);
	return 1;
}
