// A signal sent to a thread just before it waits in a futex must cut that wait short, as Linux's
// futex_wait checks signal_pending before sleeping. glibc's setresuid in a threaded program is
// this: the caller signals every other thread (SIGSETXID) and waits for each to acknowledge.
// The runtime's emulated futex woke only waiters already blocked when the signal was sent
// (Sched::interrupt_waits); a thread still on its way into the wait (in threaded mode, waiting
// for the CPU token, which the sender held) blocked for good: guest-tests' files::devnodes hung
// about 1 run in 50 in threaded mode once the token was offered rather than assigned (rt/par.rs).
// Here a helper signals main 2000 times and waits for main's handler each time, while main sits
// in an untimed futex wait between handlers. Prints SIGNAL_FUTEX_RACE_OK.
#include "unsharek_test.h"
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ROUNDS 2000

static atomic_int ack, done;
static atomic_int never; // main's futex word: no one wakes it
static pid_t main_tid;

static long futex(atomic_int *w, int op, int val)
{
	return syscall(SYS_futex, w, op, val, NULL, NULL, 0);
}

static void on_usr1(int sig)
{
	(void)sig;
	atomic_store(&ack, 1);
	futex(&ack, FUTEX_WAKE_PRIVATE, 1);
}

static void *helper(void *a)
{
	(void)a;
	for (int i = 0; i < ROUNDS; i++) {
		atomic_store(&ack, 0);
		syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1);
		while (!atomic_load(&ack))
			futex(&ack, FUTEX_WAIT_PRIVATE, 0);
	}
	atomic_store(&done, 1);
	syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1);
	return NULL;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	main_tid = syscall(SYS_gettid);
	struct sigaction sa = {0};
	sa.sa_handler = on_usr1; // no SA_RESTART: each signal ends the wait with EINTR
	CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
	pthread_t t;
	CHECK(pthread_create(&t, NULL, helper, NULL) == 0, "pthread_create");
	while (!atomic_load(&done))
		futex(&never, FUTEX_WAIT_PRIVATE, 0);
	pthread_join(t, NULL);
	printf("SIGNAL_FUTEX_RACE_OK\n");
	return 0;
}
