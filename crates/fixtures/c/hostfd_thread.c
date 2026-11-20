// A thread blocked in read(2) on a host fd (stdin: a pipe nobody writes to, held open) while the
// main thread carries on and exits. The process must exit: the blocked reader is ended by the
// group exit (capnix: an app's reader thread on its channel, fd 1000, hung the app's exit; ported
// from capnix's repro). argv[1]: what main does first:
//   exit   exit at once (exit_group with the reader still in read)
//   sleep  nanosleep 100 ms, then exit
//   write  3 lines 10 ms apart (write(1) is a host fd too), then exit
// Prints HOSTFD_THREAD_OK, exits 0.
#include "exobox_test.h"
#include <pthread.h>
#include <time.h>
#include <unistd.h>

static void *reader(void *arg)
{
	(void)arg;
	char buf[16];
	ssize_t n = read(0, buf, sizeof buf);
	dprintf(2, "reader: read returned %zd\n", n);
	return NULL;
}

static void ms(long n)
{
	struct timespec t = {n / 1000, (n % 1000) * 1000000};
	nanosleep(&t, NULL);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2, "usage: hostfd_thread exit|sleep|write");
	pthread_t t;
	CHECK(pthread_create(&t, NULL, reader, NULL) == 0, "pthread_create");
	ms(10); /* let the reader block */
	if (!strcmp(argv[1], "sleep")) {
		ms(100);
	} else if (!strcmp(argv[1], "write")) {
		for (int i = 0; i < 3; i++) {
			dprintf(1, "main: line %d\n", i);
			ms(10);
		}
	}
	printf("HOSTFD_THREAD_OK\n");
	fflush(stdout);
	return 0;
}
