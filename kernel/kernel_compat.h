#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/cred.h>
#include "ss/policydb.h"
#include "linux/key.h"
#include <linux/list.h>

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#define kcompat_barrier() do { barrier(); isb(); } while (0)
#else
#define kcompat_barrier() barrier()
#endif

/*
 * Linux 6.8+ does not have LKM support, due to numerous changes on LSM.
 * Let's fails if MODULE were defined.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) && defined(MODULE) 
#error "LKM mode is not supported on Linux 6.8+, aborting build."
#endif

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                           \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||               \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                      \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

// Checks for UH, KDP and RKP
#ifdef SAMSUNG_UH_DRIVER_EXIST
#if defined(CONFIG_UH) || defined(CONFIG_KDP) || defined(CONFIG_RKP)
#error "CONFIG_UH, CONFIG_KDP and CONFIG_RKP is enabled! Please disable or remove it before compile a kernel with KernelSU!"
#endif
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
					  const void __user *unsafe_addr,
					  long count);
extern long ksu_strncpy_from_user_retry(char *dst,
					  const void __user *unsafe_addr,
					  long count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||	\
	defined(CONFIG_IS_HW_HISI) ||	\
	defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

extern void ksu_android_ns_fs_check(void);
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size)	access_ok(addr, size)
#else
#define ksu_access_ok(addr, size)	access_ok(VERIFY_READ, addr, size)
#endif

#endif
