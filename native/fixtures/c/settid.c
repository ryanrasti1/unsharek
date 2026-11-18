// CLONE_CHILD_SETTID is written once (fork mode). Linux writes a fork child's tid at that address
// at the child's first schedule; LKL's host tasks go through schedule_tail() again at every switch
// back to them, so the tid used to be written there for the task's whole life: after an exec, into
// the new program's memory (capnix tier A: a forked bash's thread pointer area became the exec'd
// program's ld.so heap, and the tid landed in a version table: "undefined symbol:
// __isoc23_strtoul, version GLIBC_2.38" on a pipeline's C++ program). Ported from capnix.
//
// The parent forks with CLONE_CHILD_SETTID at an address A of its own memory; the child execs this
// program, which maps A again (zeros), then ping-pongs with the parent over pipes, so that every
// one of its syscalls enters the kernel with another task current. A must still be 0 after.
//
//   settid            SETTID_OK
//   settid child A    (the exec'd child)
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 50

static int child(char **argv)
{
	unsigned long a = strtoul(argv[2], 0, 16);
	int rd = atoi(argv[3]), wr = atoi(argv[4]);
	volatile int *w = mmap((void *)(a & ~4095UL), 4096, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (w == MAP_FAILED) {
		perror("settid: mmap");
		return 2;
	}
	w = (volatile int *)a;
	*w = 0;
	char c = 0;
	for (int i = 0; i < ROUNDS; i++)
		if (write(wr, &c, 1) != 1 || read(rd, &c, 1) != 1)
			return 2;
	if (*w) {
		printf("SETTID_FAIL: %d written at the old CLONE_CHILD_SETTID address after the exec\n", *w);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 5 && !strcmp(argv[1], "child"))
		return child(argv);
	/* Far into a large mapping: in the sandbox the exec'd child's arena starts over, and its own
	 * stack and ld.so's heap are at the start. */
	size_t len = 64 << 20;
	char *a = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	int up[2], down[2];
	if (a == MAP_FAILED || pipe(up) || pipe(down))
		return 2;
	int *tid = (int *)(a + len - 4096 + 400);
	/* A plain fork with the tid at our own address (glibc's fork puts it in its thread pointer). */
	long pid = syscall(SYS_clone, CLONE_CHILD_SETTID | SIGCHLD, 0, 0, tid, 0);
	if (pid == 0) {
		char sa[32], sr[16], sw[16];
		snprintf(sa, sizeof(sa), "%lx", (unsigned long)tid);
		snprintf(sr, sizeof(sr), "%d", down[0]);
		snprintf(sw, sizeof(sw), "%d", up[1]);
		char *args[] = {argv[0], "child", sa, sr, sw, NULL};
		execv(argv[0], args);
		_exit(3);
	}
	if (pid < 0)
		return 2;
	close(up[1]);	/* (a child that could not exec ends the rounds: EOF) */
	close(down[0]);
	char c;
	for (int i = 0; i < ROUNDS; i++)
		if (read(up[0], &c, 1) != 1 || write(down[1], &c, 1) != 1)
			break;
	int st;
	if (waitpid(pid, &st, 0) != pid)
		return 2;
	if (!WIFEXITED(st) || WEXITSTATUS(st)) {
		printf("settid: child status %#x\n", st);
		return 1;
	}
	printf("SETTID_OK\n");
	return 0;
}
