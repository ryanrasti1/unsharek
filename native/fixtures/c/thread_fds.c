// Threads share their process's fd table: a thread waits on the main thread's epoll fd, and the
// main thread reads a pipe the thread made. (capnix tier A: every thread's guest task was a clone
// of a kernel thread with its own table, so tokio's worker got EBADF on its runtime's epoll fd.)
// Prints THREAD_FDS_OK.
#include "exobox_test.h"
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>

static int ep, wake[2], made[2];

static void *worker(void *a)
{
	(void)a;
	struct epoll_event ev;
	int n = epoll_wait(ep, &ev, 1, 2000);
	if (n != 1 || ev.data.fd != wake[0])
		return (void *)1;
	if (pipe(made) || write(made[1], "t", 1) != 1)
		return (void *)2;
	return NULL;
}

int main(void)
{
	CHECK((ep = epoll_create1(0)) >= 0, "epoll_create1");
	CHECK(pipe(wake) == 0, "pipe");
	struct epoll_event ev = {.events = EPOLLIN, .data.fd = wake[0]};
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, wake[0], &ev) == 0, "epoll_ctl");
	pthread_t t;
	CHECK(pthread_create(&t, NULL, worker, NULL) == 0, "pthread_create");
	usleep(10000);
	CHECK(write(wake[1], "m", 1) == 1, "write");
	void *ret;
	pthread_join(t, &ret);
	CHECK(ret == NULL, "worker failed at step %ld", (long)ret);
	char b;
	CHECK(read(made[0], &b, 1) == 1 && b == 't', "the thread's pipe from the main thread");
	printf("a thread used the main thread's epoll fd; the main thread read the thread's pipe\n");
	printf("THREAD_FDS_OK\n");
	return 0;
}
