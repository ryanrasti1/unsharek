// An "interpreter" a hostile binary names in its PT_INTERP (interp_victim is linked to this one).
// No libc: it starts at _start with the program's initial stack, as the kernel or a loader would
// start ld.so. It must run only after lockdown (or not at all). argv[2] says what it tries:
//   read   read the host file argv[1]: prints LEAKED:<contents> if it reached the host, BLOCKED
//   write  create the host file argv[1]: the suite checks the host afterwards
//   gate   a disallowed syscall (openat) through the runtime's own gate, found in the auxiliary
//          vector: under the default deny the sandbox dies by SIGSYS before it prints
//          GATE_SURVIVED. If the filter were installed after the loader ran, the call would reach
//          the host. Natively there is no gate: it prints NO_GATE.
// Built -nostdlib -shared -fPIC: position-independent, no relocations.

#define EXOBOX_AT_GATE 0x4558 /* exobox_test.h */

static long sys(long nr, long a, long b, long c)
{
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return r;
}

static long len(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	return n;
}

static void out(const char *s) { sys(1, 1, (long)s, len(s)); }

static int eq(const char *a, const char *b)
{
	while (*a && *a == *b)
		a++, b++;
	return *a == *b;
}

__attribute__((used, visibility("hidden"))) void evil_main(long *sp)
{
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	if (argc < 3) {
		out("usage: <victim> <path> read|write|gate\n");
		sys(231 /* exit_group */, 2, 0, 0);
	}
	const char *path = argv[1], *mode = argv[2];
	if (eq(mode, "read")) {
		long fd = sys(257 /* openat */, -100 /* AT_FDCWD */, (long)path, 0);
		char buf[256];
		long n = fd >= 0 ? sys(0 /* read */, fd, (long)buf, sizeof(buf) - 1) : -1;
		if (n > 0) {
			buf[n] = 0;
			out("LEAKED:");
			out(buf);
			out("\n");
		} else {
			out("BLOCKED\n");
		}
	} else if (eq(mode, "write")) {
		long fd = sys(257, -100, (long)path, 0101 /* O_WRONLY|O_CREAT */ | 01000000 /* O_CLOEXEC */);
		out(fd >= 0 ? "CREATED\n" : "NOT_CREATED\n");
	} else if (eq(mode, "gate")) {
		/* argv, then envp, then the auxiliary vector: (type, value) pairs ending in AT_NULL. */
		long *p = sp + 1 + argc + 1;
		while (*p)
			p++;
		long gate = 0;
		for (p++; p[0]; p += 2)
			if (p[0] == EXOBOX_AT_GATE)
				gate = p[1];
		if (!gate) {
			out("NO_GATE\n");
		} else {
			long (*g)(long, long, long, long, long, long, long) = (void *)gate;
			g(257, -100, (long)path, 0, 0, 0, 0);
			out("GATE_SURVIVED\n");
		}
	} else {
		out("unknown mode\n");
	}
	sys(231, 0, 0, 0);
}

__asm__(".globl _start\n"
	"_start:\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call evil_main\n"
	"	hlt\n");
