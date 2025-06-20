#ifndef KSUCOMPAT_H
#define KSUCOMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#include <linux/fs.h>
#define ksu_nameptr(filename) ((filename)->name)
#define ksu_current_uid() (current_uid().val)
#else
#include <linux/dcache.h>
#define ksu_nameptr(dentry) ((dentry)->d_name.name)
#define ksu_current_uid() (current_uid())
#endif

// For manager.h: always include cred.h and sched.h for current->cred
#include <linux/cred.h>
#include <linux/sched.h>

#endif /* KSUCOMPAT_H */
