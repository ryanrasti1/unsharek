/* The two functions the kernel object needs from its host besides the host-operations table:
 * lkl_printf and lkl_bug (declared in lkl/asm/host_ops.h; stock LKL defines them in
 * tools/lkl/lib/utils.c, with the posix host unsharek doesn't link). They are variadic, which stable
 * Rust can't define, so they are here: each formats into a stack buffer and hands the bytes to
 * unsharek, which defines the two unsharek_lkl_* functions below.
 *
 * Weak, so a binary that also links the stock posix host (lkl-sys's smoke test) gets the stock
 * ones whatever order the linker meets the archives in, with no duplicate definitions. */
#include <stdarg.h>
#include <stdio.h>

/* Defined by unsharek (Rust): write the kernel's message somewhere, and end the sandbox. */
extern void unsharek_lkl_print(const char *s, unsigned long len);
extern void unsharek_lkl_panic(void) __attribute__((noreturn));

/* The kernel's messages through lkl_printf are a line or two (its console goes through the
 * print host op instead); longer ones are cut. */
#define BUF 512

static int format(char *buf, const char *fmt, va_list ap)
{
	int n = vsnprintf(buf, BUF, fmt, ap);
	if (n < 0)
		return n;
	unsharek_lkl_print(buf, n < BUF ? (unsigned long)n : BUF - 1);
	return n;
}

__attribute__((weak)) int lkl_printf(const char *fmt, ...)
{
	char buf[BUF];
	va_list ap;
	va_start(ap, fmt);
	int n = format(buf, fmt, ap);
	va_end(ap);
	return n;
}

__attribute__((weak)) void lkl_bug(const char *fmt, ...)
{
	char buf[BUF];
	va_list ap;
	va_start(ap, fmt);
	format(buf, fmt, ap);
	va_end(ap);
	unsharek_lkl_panic();
}
