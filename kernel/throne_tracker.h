#ifndef __KSU_H_THRONE_TRACKER
#define __KSU_H_THRONE_TRACKER

#include <linux/version.h>
#include <linux/fs.h>

// Inode access compatibility for 3.4 - 6.16
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
#define ksu_file_inode(file) file_inode(file)
#else
#define ksu_file_inode(file) ((file)->f_inode)
#endif

// Directory iteration compatibility
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#define KSU_USE_OLD_READDIR 1
#else
#define KSU_USE_OLD_READDIR 0
#endif

void ksu_throne_tracker_init(void);
void ksu_throne_tracker_exit(void);
void track_throne(void);

#endif