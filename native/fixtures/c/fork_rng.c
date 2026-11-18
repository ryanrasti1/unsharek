// A forked child's randomness is its own: parent and child each read getrandom after the fork and
// must differ. (A fork copies the guest kernel's RNG state; without a reseed per child, every child
// of one template sees the same stream.) Prints FORK_RNG_OK.
#include "exobox_test.h"
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	int p[2];
	CHECK(pipe(p) == 0, "pipe");
	pid_t c = fork();
	CHECK(c >= 0, "fork");
	unsigned char mine[16], theirs[16];
	CHECK(getrandom(mine, sizeof(mine), 0) == sizeof(mine), "getrandom");
	if (c == 0) {
		_exit(write(p[1], mine, sizeof(mine)) != sizeof(mine));
	}
	CHECK(read(p[0], theirs, sizeof(theirs)) == sizeof(theirs), "the child's bytes");
	int st;
	CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && !WEXITSTATUS(st), "child status %#x", st);
	CHECK(memcmp(mine, theirs, sizeof(mine)), "parent and child read the same random bytes");
	printf("parent and child: different random bytes\n");
	printf("FORK_RNG_OK\n");
	return 0;
}
