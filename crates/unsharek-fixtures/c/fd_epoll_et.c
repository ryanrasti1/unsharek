// capnix's repro: a passed host fd (at 1000) made O_NONBLOCK and driven as tokio drives it
// (edge-triggered epoll; each round, read to EAGAIN, then wait for the next edge). The host writes
// once per round, after it reads "ready". Prints FD_EPOLL_ET_OK after three rounds.
// Fails at 13763ba: the first drain's read on the empty fd blocks instead of failing with EAGAIN
// (F_GETFL shows O_NONBLOCK set), so the program never writes "ready" and the case times out.
#include "unsharek_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
	CHECK(fcntl(1000, F_SETFL, fcntl(1000, F_GETFL) | O_NONBLOCK) == 0, "O_NONBLOCK");
	int ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.fd = 1000 };
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, 1000, &ev) == 0, "epoll_ctl");
	for (int round = 0; round < 3; round++) {
		char buf[16];
		// Drain: read to EAGAIN, as tokio does before it waits for the next edge.
		while (read(1000, buf, sizeof(buf)) > 0) {
		}
		CHECK(errno == EAGAIN, "round %d: read: errno %d", round, errno);
		CHECK(write(1000, "ready", 5) == 5, "write(1000)");
		int got = 0;
		while (!got) {
			int n = epoll_wait(ep, &ev, 1, 4000);
			CHECK(n == 1, "round %d: epoll_wait: %d (no edge for the host's write)", round, n);
			if (!(ev.events & EPOLLIN))
				continue;
			ssize_t r = read(1000, buf, sizeof(buf));
			if (r == 4 && !memcmp(buf, "ping", 4))
				got = 1;
		}
	}
	printf("FD_EPOLL_ET_OK\n");
	return 0;
}
