// Shared libraries' code mapped in place from the store's images, in every mode and after every
// fork, and never writable. The image zone was writable on the host, so a library's data pages,
// written by one program, kept it from being mapped in place again where nothing gives pages back
// (threaded and fork mode): fork mode copied nearly every exec's libraries whole (make -j4: 2.3 GB
// for 142 execs, bench/PERF.md). Now the zone is read-only but for each ELF's writable segments.
// argv[1]:
//   inplace N   libc's code is in the image zone (above the program's memory: the arena's first
//               4 GiB + 2 MiB, unsharek's default), then exec itself N more times, alternately
//               directly and from a forked child (where there are processes: argv[2] "fork")
//   write       write to libc's code: dies of SIGSEGV, as natively
//   mprotect    make libc's code writable: EACCES in the sandbox (no host mprotect after lockdown;
//               the image is read-only), allowed natively
// Prints LIBCODE_OK (inplace, mprotect) or dies (write).
#include "unsharek_test.h"
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

// Where the zone starts: the arena at 2 MiB, then the program's 4 GiB (unsharek's defaults).
#define ZONE 0x100200000UL

int main(int argc, char **argv)
{
	CHECK(argc >= 2, "usage: libcode inplace N [fork] | write | mprotect");
	uintptr_t code = (uintptr_t)&getpid;
	if (!strcmp(argv[1], "inplace")) {
		CHECK(code >= ZONE, "libc's code at %#lx, below the image zone (%#lx): copied, not in place",
		      (unsigned long)code, ZONE);
		long n = argc > 2 ? atol(argv[2]) : 0;
		int fork_too = argc > 3 && !strcmp(argv[3], "fork");
		if (n > 0) {
			char next[16];
			snprintf(next, sizeof next, "%ld", n - 1);
			char *args[] = {argv[0], "inplace", next, fork_too ? "fork" : NULL, NULL};
			if (fork_too && n % 2) {
				pid_t p = fork();
				CHECK(p >= 0, "fork: %s", strerror(errno));
				if (p == 0) {
					execv(argv[0], args);
					_exit(127);
				}
				int st;
				CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0, "child: %#x", st);
				printf("LIBCODE_OK\n");
				return 0;
			}
			fflush(stdout);
			execv(argv[0], args);
			CHECK(0, "execv: %s", strerror(errno));
		}
		printf("LIBCODE_OK\n");
		return 0;
	}
	if (!strcmp(argv[1], "write")) {
		*(volatile unsigned char *)code = 0xc3;
		printf("LIBCODE_WROTE\n");
		return 0;
	}
	if (!strcmp(argv[1], "mprotect")) {
		void *page = (void *)(code & ~4095UL);
		int r = mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
		printf("%s\n", r == 0 ? "MPROTECT_OK" : errno == EACCES ? "MPROTECT_EACCES" : strerror(errno));
		printf("LIBCODE_OK\n");
		return 0;
	}
	CHECK(0, "unknown %s", argv[1]);
}
