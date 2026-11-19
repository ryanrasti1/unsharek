// The filter itself: call every x86-64 syscall number through the runtime's gate instruction (the
// one a compromised app would jump to) and check each is refused. Then probe argument checks
// every mode shares (tests/guest.rs runs it under a restriction too: it changes none of this). Run with
// --deny=errno so refusals return EPERM. EXOBOX_TEST_TARGET: a pid outside the sandbox.
// Prints ESCAPE_GATE_OK.
#include "exobox_test.h"
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fails;

static void expect(const char *what, long got, int want_ok)
{
	int ok = want_ok ? got >= 0 : got == -EPERM;
	printf("%-50s -> %ld %s\n", what, got, ok ? "ok" : "FAIL");
	fails += !ok;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	gate_fn gate = exobox_gate();
	CHECK(gate, "no gate in the auxiliary vector: not sandboxed");
	const char *t = getenv("EXOBOX_TEST_TARGET");
	CHECK(t, "EXOBOX_TEST_TARGET unset");
	long target = atol(t);
	int fork_mode = mode_is("fork"), threads = fork_mode || mode_is("threaded");

	/* 1. Every number with zero arguments. Skipped: rt_sigreturn (allowed: through the gate it
	 * would unwind a frame that isn't there), exit_group (allowed: would end the test), ppoll
	 * (allowed: a NULL timeout blocks), read (stdin, fd 0, is the host's in every mode: filter::HOST),
	 * exit where threads are host threads
	 * (exit(0) is allowed: it would end this thread), and the unassigned 335-423 gap
	 * (this host kernel raises SIGILL for those, even natively). An allowed number that takes an
	 * fd or address still refuses here, since fd 0 and address 0 are outside every rule. */
	int refused = 0, leaked = 0;
	for (long nr = 0; nr < 470; nr++) {
		if (nr == SYS_rt_sigreturn || nr == SYS_exit_group || nr == SYS_ppoll ||
		    nr == SYS_read || (threads && nr == SYS_exit) || (nr > 334 && nr < 424))
			continue;
		long r = gate(nr, 0, 0, 0, 0, 0, 0);
		if (r == -EPERM) {
			refused++;
		} else {
			printf("  nr %ld via gate -> %ld (not refused)\n", nr, r);
			leaked++;
		}
	}
	printf("%-50s -> refused=%d leaked=%d %s\n", "every number via gate, zero args", refused, leaked,
	       leaked ? "FAIL" : "ok");
	fails += leaked != 0;

	/* 2. Signals to another process. */
	char buf[96];
	snprintf(buf, sizeof(buf), "tgkill(%ld, %ld, 0) via gate", target, target);
	expect(buf, gate(SYS_tgkill, target, target, 0, 0, 0, 0), 0);
	snprintf(buf, sizeof(buf), "kill(%ld, 0) via gate", target);
	expect(buf, gate(SYS_kill, target, 0, 0, 0, 0, 0), 0);
	long r = syscall(SYS_kill, target, 0);
	snprintf(buf, sizeof(buf), "kill(%ld, 0) via libc", target);
	printf("%-50s -> %ld %s\n", buf, r < 0 ? -errno : r, r < 0 ? "ok" : "FAIL");
	fails += r >= 0;

	/* 3. A host process: in fork mode clone(SIGCHLD) with no stack, and nothing more. */
	if (fork_mode) {
		expect("clone(SIGCHLD | CLONE_VM) via gate", gate(SYS_clone, SIGCHLD | CLONE_VM, 0, 0, 0, 0, 0), 0);
		expect("clone(SIGCHLD, stack) via gate", gate(SYS_clone, SIGCHLD, (long)buf, 0, 0, 0, 0), 0);
		expect("clone(CLONE_NEWUSER | SIGCHLD) via gate",
		       gate(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0, 0), 0);
	}

	/* 4. A host thread is clone with exactly one flag set: a bit more or less, a namespace, or
	 * garbage in the high half is refused. (The exact set itself is allowed; not probed, as its
	 * child would run this code with no stack of its own.) */
	if (threads) {
		const long T = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
			       CLONE_SYSVSEM | CLONE_CHILD_CLEARTID;
		static const struct { const char *what; long flags; } cl[] = {
			{"clone(thread set & ~CLONE_CHILD_CLEARTID)", T & ~CLONE_CHILD_CLEARTID},
			{"clone(thread set & ~CLONE_THREAD)", T & ~CLONE_THREAD},
			{"clone(thread set & ~CLONE_VM)", T & ~CLONE_VM},
			{"clone(thread set | CLONE_SETTLS)", T | CLONE_SETTLS},
			{"clone(thread set | CLONE_PTRACE)", T | CLONE_PTRACE},
			{"clone(thread set | CLONE_NEWNS)", T | CLONE_NEWNS},
			{"clone(thread set | CLONE_NEWUSER)", T | CLONE_NEWUSER},
			{"clone(thread set | CLONE_NEWPID)", T | CLONE_NEWPID},
			{"clone(thread set | CLONE_NEWNET)", T | CLONE_NEWNET},
			{"clone(thread set | CLONE_PIDFD)", T | CLONE_PIDFD},
			{"clone(thread set | CLONE_VFORK)", T | CLONE_VFORK},
			{"clone(thread set | 1 << 32)", T | (1L << 32)},
			{"clone(CLONE_VM | SIGCHLD)", CLONE_VM | SIGCHLD},
			{"clone(0)", 0},
		};
		for (size_t i = 0; i < sizeof(cl) / sizeof(cl[0]); i++) {
			snprintf(buf, sizeof(buf), "%s via gate", cl[i].what);
			expect(buf, gate(SYS_clone, cl[i].flags, (long)buf, 0, 0, 0, 0), 0);
		}
		expect("clone3 via gate", gate(SYS_clone3, 0, 0, 0, 0, 0, 0), 0);
		expect("exit(1) via gate", gate(SYS_exit, 1, 0, 0, 0, 0, 0), 0);
		expect("sigaltstack via gate", gate(SYS_sigaltstack, 0, 0, 0, 0, 0, 0), 0);
	}

	/* 5. Memory outside the arena; fds nobody was given. */
	/* No madvise in any mode, the arena included (coroutine mode had DONTNEED there, a MiB at a
	 * time): a heap page of the program's, which must keep its byte. And the host's vDSO. */
	char *heap = malloc(1 << 20);
	char *page = (char *)(((long)heap + 4095) & ~4095L);
	*page = 7;
	expect("madvise(arena page, DONTNEED) via gate", gate(SYS_madvise, (long)page, 4096, MADV_DONTNEED, 0, 0, 0), 0);
	if (*page != 7) {
		printf("madvise via gate zeroed an arena page: FAIL\n");
		fails++;
	}
	expect("madvise(vDSO page, DONTNEED) via gate",
	       gate(SYS_madvise, (long)getauxval(AT_SYSINFO_EHDR) & ~4095L, 4096, MADV_DONTNEED, 0, 0, 0), 0);
	expect("write(1, \"\") via gate", gate(SYS_write, 1, (long)"", 0, 0, 0, 0), 1);
	expect("read(1) via gate", gate(SYS_read, 1, (long)buf, 1, 0, 0, 0), 0);
	expect("write(5) via gate", gate(SYS_write, 5, (long)"x", 1, 0, 0, 0), 0);
	expect("write(1099) via gate", gate(SYS_write, 1099, (long)"x", 1, 0, 0, 0), 0);
	expect("writev(2) via gate", gate(SYS_writev, 2, 0, 0, 0, 0, 0), 0);

	CHECK(!fails, "%d probes not refused", fails);
	printf("ESCAPE_GATE_OK\n");
	return 0;
}
