// An idle program for memory and startup measurements: prints READY once running, then waits
// for stdin's end (the suite closes it to stop the program).
#include <stdio.h>
#include <unistd.h>

int main(void)
{
	printf("READY\n");
	fflush(stdout);
	char b[64];
	while (read(0, b, sizeof(b)) > 0)
		;
	return 0;
}
