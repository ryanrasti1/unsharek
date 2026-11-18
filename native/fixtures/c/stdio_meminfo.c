// What runtimes read about their environment at startup:
// - stdio has a file type (capnix tier A fork mode: its stdio were anon inodes with none, which
//   libuv calls UNKNOWN, so Node's process.stdout threw and output vanished);
// - the memory size is the program's, not the guest kernel's pool (it was 16 MB: V8 picked its
//   smallest heap and allocation-heavy JS ran 2.5x slower). sysinfo and /proc/meminfo must both
//   say at least EXOBOX_TEST_MIN_MEM_MB (default 256).
// Prints STDIO_MEMINFO_OK.
#include "exobox_test.h"
#include <sys/stat.h>
#include <sys/sysinfo.h>

int main(void)
{
	for (int fd = 0; fd <= 2; fd++) {
		struct stat st;
		CHECK(fstat(fd, &st) == 0, "fstat(%d)", fd);
		CHECK((st.st_mode & S_IFMT) != 0, "fd %d has no file type (mode %o)", fd, st.st_mode);
	}
	printf("stdio: each has a file type\n");

	const char *m = getenv("EXOBOX_TEST_MIN_MEM_MB");
	unsigned long min_kb = (m ? atol(m) : 256) * 1024;
	struct sysinfo si;
	CHECK(sysinfo(&si) == 0, "sysinfo");
	unsigned long total_kb = si.totalram * si.mem_unit / 1024;
	CHECK(total_kb >= min_kb, "sysinfo totalram %lu KB < %lu KB", total_kb, min_kb);
	FILE *f = fopen("/proc/meminfo", "r");
	CHECK(f, "/proc/meminfo");
	unsigned long mt = 0;
	CHECK(fscanf(f, "MemTotal: %lu kB", &mt) == 1, "MemTotal line");
	fclose(f);
	CHECK(mt >= min_kb, "MemTotal %lu KB < %lu KB", mt, min_kb);
	printf("memory: sysinfo %lu KB, MemTotal %lu KB\n", total_kb, mt);
	printf("STDIO_MEMINFO_OK\n");
	return 0;
}
