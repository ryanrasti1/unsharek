// An "interpreter" a hostile binary names in its PT_INTERP (interp_victim is linked to this one).
// No libc: it starts at _start with the program's initial stack, as the kernel or a loader would
// start ld.so, and tries to read the host file named in the program's argv[1]. It must run only
// after lockdown (or not at all), so the read can't reach the host: it prints LEAKED:<contents> if
// it did, BLOCKED otherwise. Built -nostdlib -shared -fPIC: position-independent, no relocations.

static long sys(long nr, long a, long b, long c)
{
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return r;
}

static void out(const char *s, long n) { sys(1, 1, (long)s, n); }

static long len(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	return n;
}

__attribute__((used, visibility("hidden"))) void evil_main(long *sp)
{
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	if (argc >= 2) {
		long fd = sys(257 /* openat */, -100 /* AT_FDCWD */, (long)argv[1], 0);
		char buf[256];
		long n = fd >= 0 ? sys(0 /* read */, fd, (long)buf, sizeof(buf)) : -1;
		if (n > 0) {
			out("LEAKED:", 7);
			out(buf, n);
			out("\n", 1);
		} else {
			out("BLOCKED\n", 8);
		}
	} else {
		out("BLOCKED: no argv[1]\n", len("BLOCKED: no argv[1]\n"));
	}
	sys(231 /* exit_group */, 0, 0, 0);
}

__asm__(".globl _start\n"
	"_start:\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call evil_main\n"
	"	hlt\n");
