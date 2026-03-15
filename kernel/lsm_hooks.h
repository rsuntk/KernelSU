#ifndef __KSU_H_LSM_HOOKS
#define __KSU_H_LSM_HOOKS

#include <linux/version.h>

#ifndef MODULE

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0) &&                          \
      !defined(CONFIG_KSU_KPROBES)) ||                                         \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) &&                         \
      LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) &&                         \
      defined(CONFIG_KSU_KPROBES)))

void __init ksu_lsm_hook_init(void);

#define USE_LSM_HOOKS

#endif

#endif

#endif
