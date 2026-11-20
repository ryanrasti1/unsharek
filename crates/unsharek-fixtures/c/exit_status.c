// How a run ends, by argv[1]:
//   exit42  exit(42)
//   abort   abort(): SIGABRT (or, where signals are emulated, exit 134)
//   term    raise(SIGTERM) with the default action
//   cat     stdin to stdout, then exit 0
//   stderr  a line on stderr, then exit 3
#include "unsharek_test.h"
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	CHECK(argc == 2, "usage: exit_status exit42|abort|term|cat|stderr");
	const char *m = argv[1];
	if (!strcmp(m, "exit42"))
		return 42;
	if (!strcmp(m, "abort"))
		abort();
	if (!strcmp(m, "term")) {
		raise(SIGTERM);
		return 1;
	}
	if (!strcmp(m, "cat")) {
		char b[4096];
		ssize_t n;
		while ((n = read(0, b, sizeof(b))) > 0)
			CHECK(write(1, b, n) == n, "write");
		CHECK(n == 0, "read(0)");
		return 0;
	}
	if (!strcmp(m, "stderr")) {
		fprintf(stderr, "to stderr\n");
		return 3;
	}
	CHECK(0, "unknown mode %s", m);
}
