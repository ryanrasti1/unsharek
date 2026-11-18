// A host fd given to the guest at a fixed fd (Sandbox::pass_fd; capnix's channel at 1000): read what
// the host sent on fd 1000, answer "got:<it>" on the same fd. Prints FD_ECHO_OK.
#include "exobox_test.h"
#include <unistd.h>

int main(void)
{
	char buf[64];
	ssize_t n = read(1000, buf, sizeof(buf));
	CHECK(n > 0, "read(1000) -> %zd", n);
	char out[80];
	int m = snprintf(out, sizeof(out), "got:%.*s", (int)n, buf);
	CHECK(write(1000, out, m) == m, "write(1000)");
	printf("FD_ECHO_OK\n");
	return 0;
}
