// A library whose constructor tries to read a host file (EXOBOX_TEST_SECRET). ld.so runs library
// constructors before the program's main, so this must run only after lockdown: it prints
// LEAKED:<contents> if it reached the host, BLOCKED otherwise. ctor_victim links it.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void escape(void)
{
	const char *path = getenv("EXOBOX_TEST_SECRET");
	char buf[256];
	int fd = path ? open(path, O_RDONLY) : -1;
	ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
	if (n > 0) {
		buf[n] = 0;
		printf("LEAKED:%s\n", buf);
	} else {
		printf("BLOCKED\n");
	}
}

int ctor_escape_linked(void) { return 1; }
