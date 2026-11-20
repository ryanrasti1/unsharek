// The program's network beyond loopback, through a sandbox's hooks (crates/unsharek/tests/net.rs:
// a provider over one held fd, proxying to echo servers the test started). `net CASE ARGS...`,
// each case printing NET_<CASE>_OK:
//   echo IP PORT          connect, bytes both ways, then a half-close: the echo server's EOF
//                         after what it echoed
//   many IP PORT          eight connections at once, interleaved
//   nonblock IP PORT      a nonblocking connect: EINPROGRESS, then poll's POLLOUT, SO_ERROR 0;
//                         the echo awaited with epoll
//   names IP PORT         getpeername is the address connected to, getsockname AF_INET, a port
//   refused IP PORT       ECONNREFUSED (the provider's Refused)
//   denied IP PORT        EACCES (Denied)
//   reset IP PORT         the provider's stream fails: the next read is ECONNRESET
//   loopback              a server of the guest's own on 127.0.0.1: still the guest's
//   resolve NAME IP NX DENIED   getaddrinfo: NAME is IP (no IPv6 address); NX has none
//                         (EAI_NONAME); DENIED fails, not as a temporary failure
//   listen PORT PEER      a listen on 0.0.0.0:PORT gets the host's connection from PEER, which
//                         says "hello from the host"
//   serve PORT            a listen on 0.0.0.0:PORT: one connection, "ping" read, "pong" written
//                         (the network plugin's --publish: crates/unsharek/tests/netplugin.rs)
#include "unsharek_test.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in addr(const char *ip, const char *port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(port)) };
	CHECK(inet_pton(AF_INET, ip, &a.sin_addr) == 1, "bad address %s", ip);
	return a;
}

static int connect_to(struct sockaddr_in a)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s >= 0, "socket: %s", strerror(errno));
	CHECK(connect(s, (struct sockaddr *)&a, sizeof(a)) == 0, "connect: %s", strerror(errno));
	return s;
}

static void read_all(int s, char *buf, size_t n)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(s, buf + got, n - got);
		CHECK(r > 0, "read: %zd (%s) after %zu of %zu", r, strerror(errno), got, n);
		got += r;
	}
}

static void echo(char **a)
{
	int s = connect_to(addr(a[0], a[1]));
	int one = 1;
	CHECK(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0, "TCP_NODELAY");
	char buf[64] = { 0 }, big[100000];
	CHECK(write(s, "ping", 4) == 4, "write");
	read_all(s, buf, 4);
	CHECK(!memcmp(buf, "ping", 4), "echoed %.4s", buf);
	printf("echo: ping\n");
	// More than a buffer's worth, then the half-close: all of it comes back, then EOF.
	for (size_t i = 0; i < sizeof(big); i++)
		big[i] = i * 7;
	size_t sent = 0;
	static char back[sizeof(big)];
	size_t got = 0;
	while (sent < sizeof(big)) {
		ssize_t w = write(s, big + sent, sizeof(big) - sent > 8192 ? 8192 : sizeof(big) - sent);
		CHECK(w > 0, "write: %s", strerror(errno));
		sent += w;
		ssize_t r = read(s, back + got, sizeof(back) - got);
		CHECK(r > 0, "read back: %zd", r);
		got += r;
	}
	CHECK(shutdown(s, SHUT_WR) == 0, "shutdown: %s", strerror(errno));
	while (got < sizeof(back)) {
		ssize_t r = read(s, back + got, sizeof(back) - got);
		CHECK(r > 0, "read: %zd %s", r, strerror(errno));
		got += r;
	}
	char extra;
	CHECK(read(s, &extra, 1) == 0, "no EOF after the half-close");
	CHECK(got == sizeof(big) && !memcmp(back, big, sizeof(big)), "echoed %zu of %zu", got, sizeof(big));
	printf("echo: %zu bytes, then EOF after the half-close\n", got);
	close(s);
}

static void many(char **a)
{
	enum { N = 8 };
	int s[N];
	for (int i = 0; i < N; i++)
		s[i] = connect_to(addr(a[0], a[1]));
	for (int round = 0; round < 3; round++) {
		for (int i = 0; i < N; i++) {
			char msg[16];
			int n = snprintf(msg, sizeof(msg), "c%d-r%d", i, round);
			CHECK(write(s[i], msg, n) == n, "write %d", i);
		}
		for (int i = N - 1; i >= 0; i--) {
			char msg[16], buf[16] = { 0 };
			int n = snprintf(msg, sizeof(msg), "c%d-r%d", i, round);
			read_all(s[i], buf, n);
			CHECK(!memcmp(buf, msg, n), "connection %d got %s for %s", i, buf, msg);
		}
	}
	for (int i = 0; i < N; i++)
		close(s[i]);
	printf("many: %d connections, 3 rounds each\n", N);
}

static void nonblock(char **a)
{
	struct sockaddr_in to = addr(a[0], a[1]);
	int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	int r = connect(s, (struct sockaddr *)&to, sizeof(to));
	CHECK(r == -1 && errno == EINPROGRESS, "connect: %d %s", r, strerror(errno));
	struct pollfd p = { .fd = s, .events = POLLOUT };
	CHECK(poll(&p, 1, 3000) == 1 && (p.revents & POLLOUT), "poll: 0x%x", p.revents);
	int err = -1;
	socklen_t len = sizeof(err);
	CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0, "SO_ERROR %d", err);
	int ep = epoll_create1(0);
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = s };
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) == 0, "epoll_ctl");
	char buf[8] = { 0 };
	CHECK(read(s, buf, sizeof(buf)) == -1 && errno == EAGAIN, "read before: %s", strerror(errno));
	CHECK(write(s, "nb", 2) == 2, "write");
	CHECK(epoll_wait(ep, &ev, 1, 3000) == 1 && (ev.events & EPOLLIN), "epoll_wait");
	CHECK(read(s, buf, sizeof(buf)) == 2 && !memcmp(buf, "nb", 2), "read %s", buf);
	// A second nonblocking connect, its socket in epoll before the connect: EPOLLOUT once done.
	int s2 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	struct epoll_event ev2 = { .events = EPOLLOUT, .data.fd = s2 };
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s2, &ev2) == 0, "epoll_ctl 2");
	r = connect(s2, (struct sockaddr *)&to, sizeof(to));
	CHECK(r == -1 && errno == EINPROGRESS, "connect 2: %s", strerror(errno));
	struct epoll_event got;
	int n;
	do
		n = epoll_wait(ep, &got, 1, 3000);
	while (n == 1 && got.data.fd != s2);
	CHECK(n == 1 && (got.events & EPOLLOUT), "epoll_wait 2: %d", n);
	printf("nonblock: EINPROGRESS, POLLOUT, SO_ERROR 0, epoll (before and after the connect)\n");
}

static void names(char **a)
{
	struct sockaddr_in to = addr(a[0], a[1]), peer, me;
	int s = connect_to(to);
	socklen_t len = sizeof(peer);
	CHECK(getpeername(s, (struct sockaddr *)&peer, &len) == 0, "getpeername: %s", strerror(errno));
	CHECK(peer.sin_family == AF_INET && peer.sin_port == to.sin_port &&
		      peer.sin_addr.s_addr == to.sin_addr.s_addr, "peer %s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
	len = sizeof(me);
	CHECK(getsockname(s, (struct sockaddr *)&me, &len) == 0, "getsockname: %s", strerror(errno));
	CHECK(me.sin_family == AF_INET && me.sin_port != 0, "local port %d", ntohs(me.sin_port));
	int domain = 0;
	len = sizeof(domain);
	CHECK(getsockopt(s, SOL_SOCKET, SO_DOMAIN, &domain, &len) == 0 && domain == AF_INET, "SO_DOMAIN %d", domain);
	printf("names: peer %s:%d, local port %d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port), ntohs(me.sin_port));
	close(s);
}

static void fails(char **a, int want)
{
	struct sockaddr_in to = addr(a[0], a[1]);
	int s = socket(AF_INET, SOCK_STREAM, 0);
	int r = connect(s, (struct sockaddr *)&to, sizeof(to));
	CHECK(r == -1 && errno == want, "connect: %d %s, wanted %s", r, strerror(errno), strerror(want));
	printf("connect to %s: %s\n", a[0], strerror(errno));
	close(s);
}

static void reset(char **a)
{
	int s = connect_to(addr(a[0], a[1]));
	char buf[8];
	ssize_t r = read(s, buf, sizeof(buf));
	CHECK(r == -1 && errno == ECONNRESET, "read: %zd %s, wanted ECONNRESET", r, strerror(errno));
	printf("reset: %s\n", strerror(errno));
	close(s);
}

static void loopback(void)
{
	int l = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in at = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int one = 1;
	setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	CHECK(bind(l, (struct sockaddr *)&at, sizeof(at)) == 0, "bind: %s", strerror(errno));
	CHECK(listen(l, 4) == 0, "listen");
	socklen_t len = sizeof(at);
	getsockname(l, (struct sockaddr *)&at, &len);
	int c = connect_to(at);
	int a = accept(l, NULL, NULL);
	CHECK(a >= 0, "accept: %s", strerror(errno));
	CHECK(write(c, "lo", 2) == 2, "write");
	char buf[4] = { 0 };
	read_all(a, buf, 2);
	CHECK(!memcmp(buf, "lo", 2), "got %s", buf);
	struct sockaddr_in peer;
	len = sizeof(peer);
	CHECK(getpeername(c, (struct sockaddr *)&peer, &len) == 0 && peer.sin_port == at.sin_port, "peer");
	printf("loopback: the guest's own server on 127.0.0.1:%d\n", ntohs(at.sin_port));
}

static void resolve(char **a)
{
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
	int r = getaddrinfo(a[0], "80", &hints, &res);
	CHECK(r == 0, "getaddrinfo(%s): %s", a[0], gai_strerror(r));
	char ip[32];
	inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof(ip));
	CHECK(!strcmp(ip, a[1]), "%s is %s, wanted %s", a[0], ip, a[1]);
	freeaddrinfo(res);
	printf("resolve: %s is %s\n", a[0], ip);
	// AF_UNSPEC too: the A and AAAA queries (AAAA has no data).
	struct addrinfo six = { .ai_family = AF_INET6, .ai_socktype = SOCK_STREAM };
	r = getaddrinfo(a[0], "80", &six, &res);
	CHECK(r == EAI_NODATA || r == EAI_NONAME, "getaddrinfo(%s, AF_INET6): %s, wanted no address", a[0], gai_strerror(r));
	struct addrinfo any = { .ai_socktype = SOCK_STREAM };
	r = getaddrinfo(a[0], "80", &any, &res);
	CHECK(r == 0 && res->ai_family == AF_INET, "getaddrinfo(%s, AF_UNSPEC): %s", a[0], gai_strerror(r));
	freeaddrinfo(res);
	r = getaddrinfo(a[2], "80", &hints, &res);
	CHECK(r == EAI_NONAME, "getaddrinfo(%s): %d %s, wanted EAI_NONAME", a[2], r, gai_strerror(r));
	printf("resolve: %s: %s\n", a[2], gai_strerror(r));
	r = getaddrinfo(a[3], "80", &hints, &res);
	// A refusal that isn't to be retried: musl says EAI_FAIL, glibc (which folds a
	// non-recoverable answer into "not found") EAI_NONAME; never EAI_AGAIN.
	CHECK(r == EAI_FAIL || r == EAI_NONAME, "getaddrinfo(%s): %d %s, wanted EAI_FAIL", a[3], r, gai_strerror(r));
	printf("resolve: %s: %s\n", a[3], gai_strerror(r));
}

static void do_listen(char **a)
{
	int l = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in at = { .sin_family = AF_INET, .sin_port = htons(atoi(a[0])) }, peer;
	CHECK(bind(l, (struct sockaddr *)&at, sizeof(at)) == 0, "bind: %s", strerror(errno));
	CHECK(listen(l, 4) == 0, "listen");
	socklen_t len = sizeof(peer);
	int c = accept(l, (struct sockaddr *)&peer, &len);
	CHECK(c >= 0, "accept: %s", strerror(errno));
	char buf[64] = { 0 };
	read_all(c, buf, strlen("hello from the host"));
	CHECK(!strcmp(buf, "hello from the host"), "read %s", buf);
	char p[32];
	snprintf(p, sizeof(p), "%s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
	CHECK(!strcmp(p, a[1]), "peer %s, wanted %s", p, a[1]);
	printf("listen: accepted the host's connection from %s\n", p);
}

static void serve(char **a)
{
	int l = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in at = { .sin_family = AF_INET, .sin_port = htons(atoi(a[0])) };
	CHECK(bind(l, (struct sockaddr *)&at, sizeof(at)) == 0, "bind: %s", strerror(errno));
	CHECK(listen(l, 4) == 0, "listen: %s", strerror(errno));
	int c = accept(l, NULL, NULL);
	CHECK(c >= 0, "accept: %s", strerror(errno));
	char buf[8] = { 0 };
	read_all(c, buf, 4);
	CHECK(!memcmp(buf, "ping", 4), "read %.4s", buf);
	CHECK(write(c, "pong", 4) == 4, "write: %s", strerror(errno));
	close(c);
	printf("serve: ping, pong\n");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(argc >= 2, "usage: net CASE ARGS...");
	const char *c = argv[1];
	char **a = argv + 2;
	if (!strcmp(c, "echo"))
		echo(a);
	else if (!strcmp(c, "many"))
		many(a);
	else if (!strcmp(c, "nonblock"))
		nonblock(a);
	else if (!strcmp(c, "names"))
		names(a);
	else if (!strcmp(c, "refused"))
		fails(a, ECONNREFUSED);
	else if (!strcmp(c, "serve"))
		serve(a);
	else if (!strcmp(c, "denied"))
		fails(a, EACCES);
	else if (!strcmp(c, "reset"))
		reset(a);
	else if (!strcmp(c, "loopback"))
		loopback();
	else if (!strcmp(c, "resolve"))
		resolve(a);
	else if (!strcmp(c, "listen"))
		do_listen(a);
	else
		CHECK(0, "no case %s", c);
	char up[32];
	for (int i = 0; c[i] && i < 31; i++)
		up[i] = c[i] >= 'a' && c[i] <= 'z' ? c[i] - 32 : c[i], up[i + 1] = 0;
	printf("NET_%s_OK\n", up);
	return 0;
}
