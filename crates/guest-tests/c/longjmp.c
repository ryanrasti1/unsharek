// signals::longjmp_out's half in C, which Rust can't write: sigsetjmp, and a handler that
// siglongjmps out (the kernel's signal frame abandoned, no rt_sigreturn). Returns how many of `n`
// jumps came back to the sigsetjmp, or -1 if a handler returned.
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

static sigjmp_buf jb;

static void on_jump(int s) { siglongjmp(jb, s); }

int guest_tests_longjmp_out(int n_)
{
	struct sigaction sa = {0}, old;
	sa.sa_handler = on_jump;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, &old))
		return -2;
	/* volatile: live across the siglongjmps */
	volatile int n = n_, jumped = 0;
	for (volatile int i = 0; i < n; i++) {
		if (sigsetjmp(jb, 1) == 0) {
			raise(SIGUSR1);
			return -1; /* returned from a handler that jumps */
		}
		jumped++;
	}
	sigaction(SIGUSR1, &old, NULL);
	return jumped;
}
