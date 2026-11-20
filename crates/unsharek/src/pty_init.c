// The guest's init on a terminal (src/pty.rs): `pty_init ROWS COLS PROGRAM ARGS...`. A pty from the
// guest's devpts at ROWS x COLS, the program on its slave (a child process: a session of its own,
// the pty its controlling terminal and its stdio), and the copy both ways between the master and
// fds 0 and 1 (the host's stdio) until the program's side closes; then the program's status, a
// signal's death as 128 + n (init can't die of its own signal).
//
// A program of its own, exec'd as init, rather than Rust in a `Locked::run` closure: a fork from
// such a closure resumes on a stack fork mode shares among the processes (init's thread's), where
// init's own trap frames still are. No libc (it runs in a guest that may have none, and any
// glibc's version would be the program's choice): raw syscalls, nothing that needs relocating
// (built -static-pie with no self-relocation: no data holds a pointer).

#define NR_read 0
#define NR_write 1
#define NR_open 2
#define NR_close 3
#define NR_poll 7
#define NR_ioctl 16
#define NR_dup2 33
#define NR_clone 56
#define NR_execve 59
#define NR_exit 60
#define NR_wait4 61
#define NR_setsid 112

#define O_RDWR 02
#define O_NOCTTY 0400
#define O_CLOEXEC 02000000
#define SIGCHLD 17
#define POLLIN 1
#define TIOCSWINSZ 0x5414
#define TIOCSCTTY 0x540E
#define TIOCGPTN 0x80045430
#define TIOCSPTLCK 0x40045431
#define EINTR 4

// What the compiler may call for a struct or array copy, with no libc to provide it.
void *memcpy(void *d, const void *s, unsigned long n)
{
	char *a = d;
	const char *b = s;
	while (n--)
		*a++ = *b++;
	return d;
}

void *memset(void *d, int c, unsigned long n)
{
	char *a = d;
	while (n--)
		*a++ = (char)c;
	return d;
}

static long sys(long nr, long a, long b, long c, long d)
{
	long r;
	register long r10 __asm__("r10") = d;
	__asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
	return r;
}

static void say(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	sys(NR_write, 2, (long)s, n, 0);
}

static __attribute__((noreturn)) void quit(int code)
{
	for (;;)
		sys(NR_exit, code, 0, 0, 0);
}

static unsigned num(const char *s)
{
	unsigned v = 0;
	while (*s >= '0' && *s <= '9')
		v = v * 10 + (unsigned)(*s++ - '0');
	return v;
}

static void write_all(int fd, const char *b, long n)
{
	while (n > 0) {
		long w = sys(NR_write, fd, (long)b, n, 0);
		if (w == -EINTR)
			continue;
		if (w <= 0)
			return;
		b += w;
		n -= w;
	}
}

struct winsize { unsigned short row, col, x, y; };
struct pollfd { int fd; short events, revents; };

static __attribute__((noreturn, used)) void start(long *sp)
{
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	if (argc < 4) {
		say("unsharek: pty_init ROWS COLS PROGRAM [ARGS...]\n");
		quit(125);
	}
	int m = sys(NR_open, (long)"/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0, 0);
	int unlock = 0, n = -1;
	struct winsize ws = { (unsigned short)num(argv[1]), (unsigned short)num(argv[2]), 0, 0 };
	if (m < 0 || sys(NR_ioctl, m, TIOCSPTLCK, (long)&unlock, 0) < 0 || sys(NR_ioctl, m, TIOCGPTN, (long)&n, 0) < 0) {
		say("unsharek: no pty in the guest (/dev/ptmx)\n");
		quit(125);
	}
	if (ws.row && ws.col)
		sys(NR_ioctl, m, TIOCSWINSZ, (long)&ws, 0);
	char slave[24] = "/dev/pts/";
	int i = 9;
	char digits[12];
	int d = 0;
	do {
		digits[d++] = (char)('0' + n % 10);
		n /= 10;
	} while (n);
	while (d)
		slave[i++] = digits[--d];
	slave[i] = 0;

	long pid = sys(NR_clone, SIGCHLD, 0, 0, 0);
	if (pid < 0) {
		say("unsharek: the program's fork\n");
		quit(125);
	}
	if (pid == 0) {
		sys(NR_setsid, 0, 0, 0, 0);
		int s = sys(NR_open, (long)slave, O_RDWR, 0, 0);
		if (s < 0 || sys(NR_ioctl, s, TIOCSCTTY, 0, 0) < 0)
			quit(125);
		for (int fd = 0; fd < 3; fd++)
			sys(NR_dup2, s, fd, 0, 0);
		if (s > 2)
			sys(NR_close, s, 0, 0, 0);
		sys(NR_execve, (long)argv[3], (long)(argv + 3), (long)envp, 0);
		say("unsharek: ");
		say(argv[3]);
		say(": can't exec\n");
		quit(127);
	}

	char buf[4096];
	int stdin_open = 1;
	for (;;) {
		struct pollfd fds[2] = { { m, POLLIN, 0 }, { 0, stdin_open ? POLLIN : 0, 0 } };
		long r = sys(NR_poll, (long)fds, 2, -1, 0);
		if (r == -EINTR)
			continue;
		if (r < 0)
			break;
		if (fds[0].revents) {
			long k = sys(NR_read, m, (long)buf, sizeof(buf), 0);
			if (k == -EINTR)
				continue;
			if (k <= 0)
				break;
			write_all(1, buf, k);
		}
		if (fds[1].revents) {
			long k = sys(NR_read, 0, (long)buf, sizeof(buf), 0);
			if (k <= 0)
				stdin_open = 0;
			else
				write_all(m, buf, k);
		}
	}
	int st = 0;
	while (sys(NR_wait4, pid, (long)&st, 0, 0) == -EINTR)
		;
	if ((st & 0x7f) == 0)
		quit((st >> 8) & 0xff);
	quit(128 + (st & 0x7f));
}

__asm__(".globl _start\n_start:\n\tmov %rsp, %rdi\n\tand $-16, %rsp\n\tcall start\n\thlt\n");
