// A process ends while its other threads wait where the runtime, not the guest kernel, has them:
// in an emulated futex (a scheduler wait queue) or reading a host fd (stdin, a passed fd). The
// kernel ends a thread at its next call into it, which these never made: exit_group (or a fatal
// signal) hung for good (the threaded agent's futex, capnix's reader on fd 1000).
//   argv[1]: the waiting threads, comma-separated: futex, stdin, fd1000 (a passed host fd)
//   argv[2]: how the process ends:
//     exit    exit(3): status 3
//     signal  raise(SIGTERM), its default action: killed by SIGTERM
//     alarm   main waits in a futex too, and an itimer's SIGALRM (default action) ends it: every
//             thread is in a runtime wait when the kernel's timer sends it
// Prints GROUP_EXIT_READY once the threads wait; never GROUP_EXIT_SURVIVED.
#include "exobox_test.h"
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static unsigned int word;

static void futex_forever(void)
{
	for (;;)
		syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
}

static void *futex_waiter(void *a)
{
	(void)a;
	futex_forever();
	return NULL;
}

static void *reader(void *a)
{
	char b[16];
	ssize_t n = read((int)(long)a, b, sizeof b);
	printf("reader of fd %ld: read returned %zd\n", (long)a, n);
	return NULL;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc == 3, "usage: group_exit futex,stdin,fd1000 exit|signal|alarm");
	char *list = strdup(argv[1]);
	for (char *w = strtok(list, ","); w; w = strtok(NULL, ",")) {
		pthread_t t;
		void *(*f)(void *) = futex_waiter;
		long fd = 0;
		if (!strcmp(w, "stdin"))
			f = reader;
		else if (!strcmp(w, "fd1000"))
			f = reader, fd = 1000;
		else
			CHECK(!strcmp(w, "futex"), "unknown waiter %s", w);
		CHECK(pthread_create(&t, NULL, f, (void *)fd) == 0, "pthread_create");
	}
	struct timespec ts = {0, 20 * 1000 * 1000};
	nanosleep(&ts, NULL); /* let them block */
	printf("GROUP_EXIT_READY\n");
	const char *how = argv[2];
	if (!strcmp(how, "exit"))
		exit(3);
	if (!strcmp(how, "signal"))
		raise(SIGTERM);
	if (!strcmp(how, "alarm")) {
		struct itimerval it = {{0, 0}, {0, 20 * 1000}};
		CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0, "setitimer");
		futex_forever();
	}
	printf("GROUP_EXIT_SURVIVED\n");
	return 1;
}
