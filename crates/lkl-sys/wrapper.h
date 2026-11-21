/* What bindgen reads (build.rs narrows it with allowlists). lkl.h is the kernel's API: the generated
 * lkl/asm/syscalls.h (lkl_syscall, lkl_sys_halt, the __lkl__NR_* numbers). lkl/asm/host_ops.h has
 * struct lkl_host_operations and lkl_init, lkl_start_kernel, lkl_cleanup. lkl_host.h, which
 * includes it in tools/lkl, is left out: the rest of it declares tools/lkl/lib's posix host
 * (lkl_host_ops, the virtio and disk helpers), which unsharek doesn't link. */
#include <lkl.h>
#include <lkl/asm/host_ops.h>
/* lkl_get_free_irq, lkl_trigger_irq: a host-backed device's interrupt (unsharek-fs). */
#include <lkl/asm/irq.h>
