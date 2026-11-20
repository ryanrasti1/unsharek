// Linked with --dynamic-linker=<evil_interp>: the program itself never runs natively; the
// interpreter does (see evil_interp.c).
#include <stdio.h>

int main(void)
{
	printf("INTERP_VICTIM_RAN\n");
	return 0;
}
