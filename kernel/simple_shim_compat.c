#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(MODULE))
#include "pkg_observer.c"
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0) ||                           \
     !defined(CONFIG_KSU_KPROBES) || !defined(MODULE))
#include "lsm_hooks.c"
#endif
