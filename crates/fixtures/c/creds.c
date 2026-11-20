// The program's credentials and its random bytes, for the library's tests (tests/guest.rs): a
// setresuid/setresgid in a setup closure must reach the exec'd program (its ids and the
// auxiliary vector's AT_UID/AT_EUID/AT_GID/AT_EGID come from init's credentials at exec, not
// fixed 0s: they were, before). And getrandom's bytes, which two template children must not
// share (a fork copies the guest's RNG). Prints `CREDS uid euid gid egid auid aeuid agid aegid`,
// `RANDOM <hex>`, the hostname, then CREDS_OK.
#include "exobox_test.h"
#include <sys/random.h>
#include <unistd.h>

int main(void)
{
	printf("CREDS %d %d %d %d %lu %lu %lu %lu\n", getuid(), geteuid(), getgid(), getegid(), getauxval(AT_UID),
	       getauxval(AT_EUID), getauxval(AT_GID), getauxval(AT_EGID));
	unsigned char r[16];
	CHECK(getrandom(r, sizeof(r), 0) == sizeof(r), "getrandom");
	printf("RANDOM ");
	for (size_t i = 0; i < sizeof(r); i++)
		printf("%02x", r[i]);
	char host[65] = "";
	gethostname(host, sizeof(host) - 1);
	printf("\nHOST %s\n", host);
	printf("CREDS_OK\n");
	return 0;
}
