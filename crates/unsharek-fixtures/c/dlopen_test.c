// dlopen maps only what the run allows: argv[1] is a library inside the allowed paths, which must
// load and run; argv[2] the same library outside them, which must not load. Natively both load,
// and the second prints DENIED_LOADED. Prints DLOPEN_OK.
#include "unsharek_test.h"
#include <dlfcn.h>

int main(int argc, char **argv)
{
	CHECK(argc == 3, "usage: dlopen_test <allowed lib> <denied lib>");
	void *h = dlopen(argv[1], RTLD_NOW);
	CHECK(h, "dlopen(allowed): %s", dlerror());
	int (*answer)(void) = (int (*)(void))dlsym(h, "plug_answer");
	CHECK(answer && answer() == 7, "plug_answer from the allowed library");
	printf("allowed library loaded and ran\n");
	if (dlopen(argv[2], RTLD_NOW)) {
		printf("DENIED_LOADED\n");
		return 0;
	}
	printf("library outside the allowed paths: %s\n", dlerror());
	printf("DLOPEN_OK\n");
	return 0;
}
