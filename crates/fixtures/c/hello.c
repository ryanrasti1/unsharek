// Smoke test: stdio, files, loopback TCP, threads, big allocations, all after lockdown.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static void *worker(void *p) { return (void *)(long)(getpid() > 0); }

int main(void)
{
	struct utsname u;
	uname(&u);
	printf("hello from %s %s\n", u.sysname, u.release);
	int fd = open("/tmp/x", O_CREAT | O_RDWR | O_TRUNC, 0644);
	write(fd, "abc", 3);
	lseek(fd, 0, SEEK_SET);
	char b[8] = {0};
	read(fd, b, 3);
	struct stat st;
	fstat(fd, &st);
	printf("file: %s size=%ld\n", b, (long)st.st_size);
	close(fd);

	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	bind(ls, (void *)&a, sizeof(a));
	socklen_t al = sizeof(a);
	getsockname(ls, (void *)&a, &al);
	listen(ls, 1);
	int c = socket(AF_INET, SOCK_STREAM, 0);
	int r = connect(c, (void *)&a, sizeof(a));
	int s = accept(ls, NULL, NULL);
	write(c, "ping", 4);
	char rb[8] = {0};
	read(s, rb, 4);
	printf("tcp: connect=%d got=%s port=%d\n", r, rb, ntohs(a.sin_port));

	pthread_t t;
	void *ret;
	int pe = pthread_create(&t, NULL, worker, NULL);
	if (pe) { printf("pthread_create=%d\n", pe); return 1; }
	pthread_join(t, &ret);
	char *big = malloc(64 << 20);
	memset(big, 1, 64 << 20);
	free(big);
	printf("thread=%ld big-malloc ok\n", (long)ret);
	printf("HELLO_OK\n");
	return 0;
}
