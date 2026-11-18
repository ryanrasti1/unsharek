// A writable MAP_SHARED file mapping: its writes reach the file at msync and at munmap.
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void)
{
	int fd = open("/tmp/shm", O_CREAT | O_RDWR | O_TRUNC, 0644);
	ftruncate(fd, 4096);
	char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	strcpy(p, "after-msync");
	msync(p, 4096, MS_SYNC);
	char b[16] = {0};
	pread(fd, b, 11, 0);
	printf("msync:  %s\n", b);
	strcpy(p, "after-munmap");
	munmap(p, 4096);
	pread(fd, b, 12, 0);
	printf("munmap: %s\n", b);
	if (strcmp(b, "after-munmap")) return 1;
	printf("SHMAP_OK\n");
	return 0;
}
