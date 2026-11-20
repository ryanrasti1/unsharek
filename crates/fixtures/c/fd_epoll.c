// A passed host fd (Guest::pass_fd, at 1000) the guest epolls, as tokio would: not readable
// until the host writes (the host fd file's poll asks the host: the kernel's hostfd_poll), then
// epoll_wait wakes (lkl_hostfd_ready from the runtime's idle wait). Prints FD_EPOLL_OK.
#include "exobox_test.h"
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
	struct pollfd p = { .fd = 1000, .events = POLLIN };
	int n = poll(&p, 1, 0);
	CHECK(n == 0, "poll before the host writes: %d (0x%x)", n, p.revents);
	int ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = 1000 };
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, 1000, &ev) == 0, "epoll_ctl");
	// The host writes once it reads this.
	CHECK(write(1000, "ready", 5) == 5, "write(1000)");
	n = epoll_wait(ep, &ev, 1, 4000);
	CHECK(n == 1 && (ev.events & EPOLLIN), "epoll_wait: %d", n);
	char buf[16] = { 0 };
	CHECK(read(1000, buf, sizeof(buf)) == 4 && !memcmp(buf, "ping", 4), "read %s", buf);
	printf("FD_EPOLL_OK\n");
	return 0;
}
