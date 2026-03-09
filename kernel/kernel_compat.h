#ifndef __KSU_H_KERNEL_COMPAT_H
#define __KSU_H_KERNEL_COMPAT_H

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/key.h>

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

long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                                   long count);
struct file *ksu_filp_open_compat(const char *filename, int flags,
                                  umode_t mode);
ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
                               loff_t *pos);
ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
                                loff_t *pos);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize,
                           gfp_t flags);
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

#endif
