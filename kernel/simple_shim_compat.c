#include <linux/version.h>
#include <linux/kconfig.h>

/*
 * pkg_observer must be used, if:
 * - Compiled as a Loadable Kernel Module
 * - Your kernel is 6.8+ (manual hooks or KPROBES)
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)) &&                       \
         (defined(MODULE) && defined(CONFIG_KSU_KPROBES)) ||                   \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)))
#include "pkg_observer.c"
#endif

/*
 * LSM hooks must be used, if:
 * - Not compiled as a Loadable Kernel Module
 * - Your kernel is 5.4+, (and doesn't exceed 5.10 if KPROBES enabled)
 * - Your kernel is below 6.8 and using manual hooks
 */
#ifndef MODULE
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0) &&                          \
      !defined(CONFIG_KSU_KPROBES)) ||                                         \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) &&                         \
      LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) &&                         \
      defined(CONFIG_KSU_KPROBES)))
#include "lsm_hooks.c"
#endif
#endif
