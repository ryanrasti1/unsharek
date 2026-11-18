// A program may read and set SIGSYS's disposition, and its syscalls are still served afterwards:
// the host's SIGSYS handler is the runtime's, and the program's is only recorded. (capnix tier A:
// Go installs a handler for every signal and throws "sigaction failed" on an error; Node reads every
// disposition at startup and asserts.) Prints SIGSYS_OK.
#include "exobox_test.h"
#include <signal.h>
#include <unistd.h>

static void on_sigsys(int s) { (void)s; }

int main(void)
{
	struct sigaction old, sa = {.sa_handler = on_sigsys, .sa_flags = SA_ONSTACK | SA_SIGINFO};
	CHECK(sigaction(SIGSYS, NULL, &old) == 0, "reading SIGSYS's disposition");
	CHECK(sigaction(SIGSYS, &sa, NULL) == 0, "setting a SIGSYS handler");
	CHECK(sigaction(SIGSYS, NULL, &old) == 0 && old.sa_handler == on_sigsys,
	      "SIGSYS's disposition reads back as set");
	CHECK(getppid() >= 0 && write(1, "", 0) == 0, "syscalls after the program's SIGSYS handler");
	printf("SIGSYS: read, set, read back; syscalls still served\n");
	printf("SIGSYS_OK\n");
	return 0;
}
