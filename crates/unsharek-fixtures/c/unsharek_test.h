// Shared by the test programs. Each prints one line per check and a final <NAME>_OK; it exits
// nonzero on the first failure. The suite (crates/unsharek/tests/suite.rs) passes what a program needs
// to know about the run in its environment: UNSHAREK_TEST_MODE (native, coroutine, threaded, fork).
#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#define CHECK(c, ...)                                                                              \
	do {                                                                                       \
		if (!(c)) {                                                                        \
			printf("FAIL %s:%d: ", __FILE__, __LINE__);                                \
			printf(__VA_ARGS__);                                                       \
			printf("\n");                                                              \
			fflush(stdout);                                                            \
			exit(1);                                                                   \
		}                                                                                  \
	} while (0)

static inline const char *test_mode(void)
{
	const char *m = getenv("UNSHAREK_TEST_MODE");
	return m ? m : "native";
}

static inline int mode_is(const char *m) { return !strcmp(test_mode(), m); }

// The runtime's own syscall instruction, the one its host syscalls are allowed from: in the
// auxiliary vector under this type, so the escape tests can call through it as a compromised app
// would after finding it. (The instruction pointer check routes syscalls; it is not a boundary:
// what the filter permits from there is.) 0 when not sandboxed.
#define UNSHAREK_AT_GATE 0x4558
typedef long (*gate_fn)(long, long, long, long, long, long, long);
static inline gate_fn unsharek_gate(void) { return (gate_fn)getauxval(UNSHAREK_AT_GATE); }
