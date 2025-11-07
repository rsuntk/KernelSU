#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <linux/sched.h>
#include <linux/version.h>

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

void ksu_sucompat_enable(void);
void ksu_sucompat_disable(void);

extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
					void *argv, void *envp, int *flags);

extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
				    void *argv, void *envp, int *flags);
#endif
