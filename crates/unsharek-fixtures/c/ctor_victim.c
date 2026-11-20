// Links libctor_escape.so (its constructor runs before main: see ctor_escape.c).
#include <stdio.h>

int ctor_escape_linked(void);

int main(void)
{
	printf("CTOR_VICTIM_RAN %d\n", ctor_escape_linked());
	return 0;
}
