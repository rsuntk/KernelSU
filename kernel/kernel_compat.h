#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include "ss/policydb.h"
#include "linux/key.h"
#include <linux/list.h>

/**
 * list_count_nodes - count the number of nodes in a list
 * the head of the list
 * 
 * Returns the number of nodes in the list
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static inline size_t list_count_nodes(const struct list_head *head)
{
	const struct list_head *pos;
	size_t count = 0;

	if (!head)
		return 0;

	list_for_each(pos, head) {
		count++;
	}
	
	return count;
}
#endif

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                         \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||             \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                    \
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && defined(KSU_KPROBE_HOOK)
#define KSU_SHOULD_USE_NEW_TP
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
					  const void __user *unsafe_addr,
					  long count);
extern long ksu_strncpy_from_user_retry(char *dst,
					const void __user *unsafe_addr,
					long count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. 
// false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling conventions).
// Rationale: callers never looked at specific -E... values anyway.
// -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

#endif
