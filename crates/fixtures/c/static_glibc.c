// A glibc program linked -static-pie (fixtures' build.rs, with the devshell's glibc.static): an
// ET_DYN with no PT_INTERP that relocates itself (_dl_relocate_static_pie), resolves its own
// IFUNCs (memcpy, strlen: IRELATIVE relocations, chosen by cpuid), and sets up its TLS and its
// threads' without ld.so (__libc_setup_tls). The suite runs it in every mode and natively: what a
// static glibc program does at startup and in its threads is the loader's and the runtime's to get
// right, with no interpreter to paper over a wrong auxiliary vector.
//
// Prints STATIC_GLIBC_OK if all was right; with "fork", a child process (fork mode) too.

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static __thread int tls = 7;
static int sum;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg)
{
	long n = (long)arg;
	tls += (int)n; // this thread's own copy, from the TLS image
	char *buf = malloc(1 << 16); // each thread's own arena
	memset(buf, (int)n, 1 << 16);
	int s = tls + buf[100];
	free(buf);
	pthread_mutex_lock(&mu);
	sum += s;
	pthread_mutex_unlock(&mu);
	return NULL;
}

static int cmp(const void *a, const void *b)
{
	return *(const int *)a - *(const int *)b;
}

int main(int argc, char **argv)
{
	if (tls != 7) {
		printf("FAIL tls %d\n", tls);
		return 1;
	}
	// IFUNC'd string functions, through IRELATIVE relocations the program applied itself.
	char a[64], b[64];
	strcpy(a, "static-pie");
	memcpy(b, a, strlen(a) + 1);
	if (strcmp(a, b) != 0) {
		printf("FAIL strings\n");
		return 1;
	}
	// Threads: their TLS blocks and stacks, set up by libc with no ld.so.
	pthread_t t[8];
	for (long i = 0; i < 8; i++)
		pthread_create(&t[i], NULL, worker, (void *)i);
	for (int i = 0; i < 8; i++)
		pthread_join(t[i], NULL);
	// each worker: tls (7 + i) + i
	if (sum != 8 * 7 + 2 * 28 || tls != 7) {
		printf("FAIL threads sum %d tls %d\n", sum, tls);
		return 1;
	}
	int v[] = { 5, 3, 9, 1 };
	qsort(v, 4, sizeof v[0], cmp);
	struct timespec ts;
	if (v[0] != 1 || v[3] != 9 || clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		printf("FAIL qsort/clock\n");
		return 1;
	}
	if (argc > 1 && strcmp(argv[1], "fork") == 0) {
		pid_t p = fork();
		if (p == 0)
			_exit(tls == 7 ? 3 : 4);
		int st;
		if (p < 0 || waitpid(p, &st, 0) != p || !WIFEXITED(st) || WEXITSTATUS(st) != 3) {
			printf("FAIL fork\n");
			return 1;
		}
	}
	printf("STATIC_GLIBC_OK\n");
	return 0;
}
