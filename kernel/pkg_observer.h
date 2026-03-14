#ifndef __KSU_H_PKG_OBSERVER_H
#define __KSU_H_PKG_OBSERVER_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(MODULE))

int ksu_observer_init(void);

void ksu_observer_exit(void);

#define USE_PKG_OBSERVER

#endif

#endif
