#ifndef __KSU_H_SECCOMP
#define __KSU_H_SECCOMP

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);

static inline void disable_seccomp(struct task_struct *tsk)
{
	if (!tsk)
		return;

	assert_spin_locked(&tsk->sighand->siglock);

	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
	tsk->seccomp.mode = 0;
	// 5.9+ have filter_count, but optional.
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                          \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_CNT))
	atomic_set(&tsk->seccomp.filter_count, 0);
#endif
	// some old kernel backport seccomp_filter_release..
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) &&                           \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
	seccomp_filter_release(tsk);
#endif
	// never, ever call seccomp_filter_release on 6.10+ (no effect)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) &&                          \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0))
	seccomp_filter_release(tsk);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	put_seccomp_filter(tsk);
#endif
    // finally, we freed it to avoid use-after-free
	if (tsk->seccomp.filter != NULL)
	    tsk->seccomp.filter = NULL;
#endif
}

#endif
