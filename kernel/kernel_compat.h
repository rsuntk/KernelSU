#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/cred.h>
#include "ss/policydb.h"
#include "linux/key.h"
#include <linux/types.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/err.h>

// ---- KernelSU original code ----

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||	\
	defined(CONFIG_IS_HW_HISI) ||	\
	defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

extern void ksu_android_ns_fs_check();
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

// ---- Kernel 3.4 COMPAT STUBS ----

// d_is_reg for old kernels
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
#ifndef d_is_reg
#define d_is_reg(dentry) S_ISREG((dentry)->d_inode->i_mode)
#endif
#endif

// groups_sort for old kernels
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
struct group_info;
static inline void groups_sort(struct group_info *group_info) { }
#endif

// ext4_unregister_sysfs for old kernels
#if !defined(CONFIG_EXT4_FS) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static inline void ext4_unregister_sysfs(void) { }
#endif

// kernel_write compat: use vfs_write for old kernels
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#include <linux/uio.h>
static inline ssize_t kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos)
{
	return vfs_write(file, buf, count, pos);
}
#endif

// compat_ptr for old kernels
#ifndef compat_ptr
#define compat_ptr(x) ((void __user *)(uintptr_t)(x))
#endif

// current_user_stack_pointer for old kernels (ARM/ARM64 - arch specific)
#ifndef current_user_stack_pointer
#if defined(__arm__) || defined(__aarch64__)
static inline unsigned long current_user_stack_pointer(void)
{
	register unsigned long sp asm("sp");
	return sp;
}
#else
static inline unsigned long current_user_stack_pointer(void) { return 0; }
#endif
#endif

#endif // __KSU_H_KERNEL_COMPAT