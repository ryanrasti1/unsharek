// The main thread sleeps (usleep, then pthread_cond_timedwait) while a thread works. In coroutine
// mode the thread must run meanwhile (a sleep used to be a host wait, which stopped every coroutine,
// a hosted program's too), and the main thread's timed waits must time out (its coroutine wasn't on
// the list the scheduler times waits out from). Prints SLEEP_OK.
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static volatile int ticks;

static void *work(void *a)
{
	(void)a;
	for (int i = 0; i < 20; i++) {
		ticks++;
		usleep(2000);
	}
	return NULL;
}

int main(void)
{
	pthread_t t;
	pthread_create(&t, NULL, work, NULL);
	usleep(20000);
	int seen = ticks;
	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t c = PTHREAD_COND_INITIALIZER;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += 30000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	pthread_mutex_lock(&m);
	int r = pthread_cond_timedwait(&c, &m, &ts);
	pthread_mutex_unlock(&m);
	pthread_join(t, NULL);
	printf("ticks during the main thread's 20 ms sleep: %d; timedwait: %d\n", seen, r);
	printf(seen > 0 && r != 0 ? "SLEEP_OK\n" : "FAIL\n");
	return !(seen > 0 && r != 0);
}
