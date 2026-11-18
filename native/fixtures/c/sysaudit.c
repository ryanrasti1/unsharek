// sysaudit: every x86-64 syscall number, once, each argument the address of a zeroed buffer (as an
// fd or a size it is out of range; as a path an empty string), in a forked child under alarm(2),
// printing "nr result" (result -errno; "signalN" if the child was killed, "hang" if it never
// answered, e.g. it crashed on the host; "skip" for the ones not safe to call this way). Run in a fork-mode sandbox; docs/syscalls.md
// classifies the output. With args, only those numbers.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>

static char zbuf[65536] __attribute__((aligned(4096)));

static int skipped(long nr)
{
	switch (nr) {
	case SYS_exit: case SYS_exit_group: case SYS_fork: case SYS_vfork: case SYS_clone:
	case SYS_clone3: case SYS_execve: case SYS_execveat: case SYS_rt_sigreturn: case SYS_reboot:
	case SYS_pause: case SYS_rt_sigsuspend: case SYS_ptrace: case SYS_kill: case SYS_tkill:
	case SYS_tgkill: case SYS_munmap: case SYS_mremap: case SYS_brk: case SYS_arch_prctl:
	case SYS_set_tid_address: case SYS_seccomp: case SYS_restart_syscall:
		return 1;
	}
	return 0;
}

static void one(long nr)
{
	if (skipped(nr)) {
		printf("%ld skip\n", nr);
		return;
	}
	int p[2];
	if (pipe(p))
		exit(1);
	pid_t pid = fork();
	if (pid == 0) {
		close(p[0]);
		alarm(2);
		long z = (long)zbuf;
		long r = syscall(nr, z, z, z, z, z, z);
		long e = r == -1 ? -errno : r;
		write(p[1], &e, sizeof(e));
		_exit(0);
	}
	close(p[1]);
	long e;
	int st;
	struct pollfd pf = {p[0], POLLIN, 0};
	if (poll(&pf, 1, 5000) != 1) {
		printf("%ld hang\n", nr);	/* (the child is left behind) */
		close(p[0]);
		return;
	}
	ssize_t n = read(p[0], &e, sizeof(e));
	close(p[0]);
	waitpid(pid, &st, 0);
	if (n == sizeof(e))
		printf("%ld %ld\n", nr, e);
	else if (WIFSIGNALED(st))
		printf("%ld signal%d\n", nr, WTERMSIG(st));
	else
		printf("%ld none\n", nr);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc > 1)
		for (int i = 1; i < argc; i++)
			one(atol(argv[i]));
	else
		for (long nr = 0; nr < 470; nr++)
			if (nr < 335 || nr >= 424)
				one(nr);
	printf("SYSAUDIT_DONE\n");
	return 0;
}
