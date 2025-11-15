#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include "linux/types.h"
#include "linux/version.h"
#include "linux/cred.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)) ||                        \
	defined(KSU_COMPAT_HAS_SELINUX_STATE)
#define KSU_COMPAT_USE_SELINUX_STATE
#endif

void setup_selinux(const char *);

void setenforce(bool);

bool getenforce(void);

bool is_task_ksu_domain(const struct cred *cred);

bool is_ksu_domain(void);

bool is_zygote(const struct cred *cred);

bool is_init(const struct cred *cred);

void apply_kernelsu_rules(void);

u32 ksu_get_ksu_file_sid(void);

int handle_sepolicy(unsigned long arg3, void __user *arg4);

#endif
