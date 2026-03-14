#ifndef __KSU_H_KERNEL_COMPAT_H
#define __KSU_H_KERNEL_COMPAT_H

#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/key.h>

#include "objsec.h"

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                         \
        (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||                     \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                        \
        (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
                                          const void __user *unsafe_addr,
                                          long count);
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
                                         umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
                                      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
                                       size_t count, loff_t *pos);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
extern void __weak *kvmalloc(size_t size, gfp_t flags);
#endif

#ifndef VERIFY_READ
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) &&                           \
    LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
int __weak close_fd(unsigned int fd)
{
    return __close_fd(current->files, fd);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
void __weak ext4_unregister_sysfs(struct super_block *sb)
{
    pr_info("%s: feature not implemented!\n", __func__);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&                            \
    !defined(KSU_HAS_SELINUX_CRED)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
    return cred->security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&                            \
    !defined(KSU_HAS_SELINUX_INODE)
static inline struct inode_security_struct *
selinux_inode(const struct inode *inode)
{
    if (unlikely(!inode->i_security))
        return NULL;
    return inode->i_security;
}
#endif

#endif
