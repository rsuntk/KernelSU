#include <linux/version.h>
#include <linux/kconfig.h>

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(MODULE)) ||    \
     (defined(CONFIG_KSU_KPROBES) &&                                           \
      LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)))
#include "pkg_observer.c"
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0) && !defined(MODULE) &&      \
      !defined(CONFIG_KSU_KPROBES)) ||                                         \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && !defined(MODULE) &&    \
      defined(CONFIG_KSU_KPROBES)))
#include "lsm_hooks.c"
#endif
