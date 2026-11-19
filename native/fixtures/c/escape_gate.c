// One forbidden host call through the runtime's own syscall instruction (the gate, found in the
// auxiliary vector, as a compromised program that found it would call it): argv[1] names it. The
// filter must kill the sandbox (SIGSYS) before ESCAPE_GATE_SURVIVED prints. Every number's
// verdict is checked against the filter's model in exobox-tcb (tests/filter.rs); these are the
// installed filter, in a real sandbox, for the calls an escape would try.
#include "exobox_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* A host thread's exact clone flags (exobox-tcb's CLONE_THREAD_FLAGS). */
#define T (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID)

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 2, "usage: escape_gate <probe>");
	gate_fn gate = exobox_gate();
	CHECK(gate, "no gate in the auxiliary vector: not sandboxed");
	const char *p = argv[1];
	const char *t = getenv("EXOBOX_TEST_TARGET");
	long target = t ? atol(t) : 1;
	char buf[64];
	char *heap = malloc(1 << 20);
	long page = ((long)heap + 4095) & ~4095L;
	struct { const char *name; long nr, a0, a1, a2; } probes[] = {
		{"openat", SYS_openat, AT_FDCWD, (long)"/etc/passwd", O_RDONLY},
		{"socket", SYS_socket, AF_INET, SOCK_STREAM, 0},
		{"getppid", SYS_getppid, 0, 0, 0},
		/* Fds nobody was given: 4000 is open nowhere (the guest's token eventfds are 3 and up);
		 * stdout is granted for write only. */
		{"write_4000", SYS_write, 4000, (long)"x", 1},
		{"read_stdout", SYS_read, 1, (long)buf, 1},
		{"writev_stderr", SYS_writev, 2, 0, 0},
		/* Signals to another process; the sandbox's own pid only, and kill only. */
		{"kill_other", SYS_kill, target, 0, 0},
		{"tgkill_other", SYS_tgkill, target, target, 0},
		/* No memory call: the arena's own pages, and the host's vDSO. */
		{"madvise_arena", SYS_madvise, page, 4096, MADV_DONTNEED},
		{"madvise_vdso", SYS_madvise, (long)getauxval(AT_SYSINFO_EHDR) & ~4095L, 4096, MADV_DONTNEED},
		{"mmap", SYS_mmap, 0, 4096, PROT_READ},
		/* A host process or thread with flags other than the mode's exact sets. */
		{"clone_vm_sigchld", SYS_clone, CLONE_VM | SIGCHLD, 0, 0},
		{"clone_newuser", SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0},
		{"clone_sigchld_stack", SYS_clone, SIGCHLD, (long)buf, 0},
		{"clone_thread_settls", SYS_clone, T | CLONE_SETTLS, (long)buf, 0},
		{"clone_thread_high_bit", SYS_clone, T | (1L << 32), (long)buf, 0},
		{"clone3", SYS_clone3, 0, 0, 0},
		{"exit_1", SYS_exit, 1, 0, 0},
		{"sigaltstack", SYS_sigaltstack, 0, 0, 0},
		{"prctl", SYS_prctl, PR_SET_DUMPABLE, 1, 0},
		{"seccomp", SYS_seccomp, 0, 0, 0},
	};
	for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		if (strcmp(probes[i].name, p) == 0) {
			long r = gate(probes[i].nr, probes[i].a0, probes[i].a1, probes[i].a2, 0, 0, 0);
			printf("ESCAPE_GATE_SURVIVED %s -> %ld\n", p, r);
			return 1;
		}
	}
	CHECK(0, "unknown probe %s", p);
}
