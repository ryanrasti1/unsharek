// A program's end with its network still busy (native/exobox/tests/net.rs). `net_exit CASE ARGS...`:
//   connect IP PORT CODE   one connect (a hook call), then exit(CODE) at once, the socket left
//                          open. The sandbox must end with CODE. Hung at ae806b4 when the hook
//                          made a syscall of its own (capnweb's stacker reads /proc/self/maps):
//                          the hooks' executor got a guest task, a thread of init's process,
//                          which kept the process from ending.
//   write IP PORT N        connect, write N bytes (byte i is i % 251), shut writing down, exit 0
//                          at once. Every byte and then the EOF must reach the hook's stream, as
//                          a closed socket's data is still sent on Linux. Lost at ae806b4: the
//                          sandbox ended at init's exit, before the hooks' copy ran.
#include "exobox_test.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_to(const char *ip, const char *port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(port)) };
	CHECK(inet_pton(AF_INET, ip, &a.sin_addr) == 1, "bad address %s", ip);
	int s = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s >= 0, "socket: %s", strerror(errno));
	CHECK(connect(s, (struct sockaddr *)&a, sizeof(a)) == 0, "connect: %s", strerror(errno));
	return s;
}

int main(int argc, char **argv)
{
	CHECK(argc >= 5, "usage: net_exit connect|write IP PORT CODE|N");
	int s = connect_to(argv[2], argv[3]);
	if (!strcmp(argv[1], "connect")) {
		printf("NET_EXIT_CONNECTED\n");
		fflush(stdout);
		_exit(atoi(argv[4]));
	}
	CHECK(!strcmp(argv[1], "write"), "no case %s", argv[1]);
	size_t n = strtoul(argv[4], NULL, 10);
	static char buf[64 << 10];
	for (size_t done = 0; done < n;) {
		size_t k = n - done < sizeof(buf) ? n - done : sizeof(buf);
		for (size_t i = 0; i < k; i++)
			buf[i] = (char)((done + i) % 251);
		ssize_t w = write(s, buf, k);
		CHECK(w > 0, "write: %s after %zu of %zu", strerror(errno), done, n);
		done += w;
	}
	CHECK(shutdown(s, SHUT_WR) == 0, "shutdown: %s", strerror(errno));
	printf("NET_EXIT_WRITTEN\n");
	fflush(stdout);
	_exit(0);
}
