// The program's environment, a line a variable: the CLI gives it only what was set (--setenv)
// or kept (--keep-env), never the rest of the host's (suite.rs's `env_dump`).
#include <stdio.h>

extern char **environ;

int main(void)
{
	for (char **e = environ; *e; e++)
		printf("%s\n", *e);
	printf("ENV_DUMP_OK\n");
	return 0;
}
