// An idle sandbox uses no CPU: 300 ms of sleeping in each way programs sleep, which the suite runs
// under a CPU-time budget (the host's rusage of the run). (capnix tier A: the guest kernel's
// tickless idle arms "no timer" as ULONG_MAX, and now + ULONG_MAX overflowed the scheduler's
// deadline into the past: ~700k timer fires a second.) Prints IDLE_OK.
#include "unsharek_test.h"
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
	struct timespec ts = {0, 60 * 1000 * 1000};
	CHECK(nanosleep(&ts, NULL) == 0, "nanosleep");
	CHECK(poll(NULL, 0, 60) == 0, "poll");
	int ep = epoll_create1(0);
	struct epoll_event ev;
	CHECK(epoll_wait(ep, &ev, 1, 60) == 0, "epoll_wait");
	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t c = PTHREAD_COND_INITIALIZER;
	struct timespec dl;
	clock_gettime(CLOCK_REALTIME, &dl);
	dl.tv_nsec += 60 * 1000 * 1000;
	if (dl.tv_nsec >= 1000000000) {
		dl.tv_sec++;
		dl.tv_nsec -= 1000000000;
	}
	pthread_mutex_lock(&m);
	CHECK(pthread_cond_timedwait(&c, &m, &dl) != 0, "timedwait returned early");
	pthread_mutex_unlock(&m);
	usleep(60 * 1000);
	printf("slept 300 ms: nanosleep, poll, epoll_wait, cond_timedwait, usleep\n");
	printf("IDLE_OK\n");
	return 0;
}
