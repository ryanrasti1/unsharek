// A static program with no libc, for exobox-rt's loader tests (crates/rt/src/exec): the loader
// maps it into an arena and jumps to its entry with a stack it built, outside any sandbox. With no
// libc and no interpreter, nothing here repairs a wrong stack or auxiliary vector: it checks them
// itself, prints what it got, and exits with 42 if all was right.
//
// Built twice (fixtures' build.rs): `static_start` as a static PIE (-static-pie: ET_DYN, no
// PT_INTERP) and `static_start_nopie` at the linker's fixed address (-static -no-pie: ET_EXEC at
// 0x400000). There is no self-relocation, so the code must need none: every address is taken
// RIP-relative (strings, _start, __ehdr_start), and no data holds a pointer.
//
// Exit codes: 42 all right; 10 rsp not 16-aligned at _start (ld.so's `movaps` faults on that);
// 11 AT_ENTRY isn't _start; 12 AT_PHDR isn't this ELF's program headers; 13 AT_PHNUM/AT_PHENT
// wrong; 14 AT_PAGESZ isn't 4096; 15 AT_RANDOM missing; 16 AT_BASE isn't 0 (no interpreter);
// 17 argv or envp not NULL-terminated where argc says; 18 .bss not zero (p_memsz > p_filesz: the
// loader zeroes the rest); 19 .data not the file's bytes.

#include <elf.h>

static long sys(long nr, long a, long b, long c)
{
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return r;
}

static long len(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	return n;
}

static void out(const char *s) { sys(1, 1, (long)s, len(s)); }

static void num(unsigned long v)
{
	char b[24];
	int i = sizeof(b);
	b[--i] = 0;
	do
		b[--i] = '0' + v % 10;
	while (v /= 10);
	out(b + i);
}

static __attribute__((noreturn)) void quit(long status)
{
	sys(231 /* exit_group */, status, 0, 0);
	__builtin_unreachable();
}

// A .bss bigger than a page, after initialized data: the data segment's file part ends mid-page,
// so the loader must zero that page's tail as well as map zero pages after it.
static volatile unsigned char bss[3 * 4096 + 100];
static volatile long data_word = 0x1234;

extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));
// Hidden: taken RIP-relative, not through a GOT entry nothing would relocate.
void _start(void) __attribute__((visibility("hidden")));

__attribute__((used, visibility("hidden"), noreturn)) void start_main(long *sp, long misaligned)
{
	if (misaligned)
		quit(10);
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	if (argv[argc])
		quit(17);
	char **envp = argv + argc + 1;
	long envc = 0;
	while (envp[envc])
		envc++;
	Elf64_auxv_t *aux = (Elf64_auxv_t *)(envp + envc + 1);
	unsigned long entry = 0, phdr = 0, phnum = 0, phent = 0, pagesz = 0, random = 0, base = 1;
	for (; aux->a_type != AT_NULL; aux++) {
		unsigned long v = aux->a_un.a_val;
		switch (aux->a_type) {
		case AT_ENTRY: entry = v; break;
		case AT_PHDR: phdr = v; break;
		case AT_PHNUM: phnum = v; break;
		case AT_PHENT: phent = v; break;
		case AT_PAGESZ: pagesz = v; break;
		case AT_RANDOM: random = v; break;
		case AT_BASE: base = v; break;
		}
	}
	if (entry != (unsigned long)&_start)
		quit(11);
	if (phdr != (unsigned long)&__ehdr_start + __ehdr_start.e_phoff)
		quit(12);
	if (phnum != __ehdr_start.e_phnum || phent != sizeof(Elf64_Phdr))
		quit(13);
	if (pagesz != 4096)
		quit(14);
	if (!random)
		quit(15);
	if (base != 0)
		quit(16);
	for (unsigned long i = 0; i < sizeof(bss); i++)
		if (bss[i])
			quit(18);
	if (data_word != 0x1234)
		quit(19);
	bss[sizeof(bss) - 1] = 1;
	out("static_start argc=");
	num(argc);
	for (long i = 0; i < argc; i++) {
		out(" [");
		out(argv[i]);
		out("]");
	}
	out(" envc=");
	num(envc);
	out("\n");
	quit(42);
}

// The entry: rsp points at argc and must be 16-aligned (the loader's job); say so before
// realigning for the C call.
__asm__(".globl _start\n"
	"_start:\n"
	"	mov %rsp, %rdi\n"
	"	mov %rsp, %rsi\n"
	"	and $15, %rsi\n"
	"	and $-16, %rsp\n"
	"	call start_main\n"
	"	hlt\n");
