#include <linux/version.h>
#include <linux/fs.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "klog.h" // IWYU pragma: keep
#include "seccomp_cache.h"

// Kcompat
#ifndef SECCOMP_ARCH_NATIVE_NR
#define SECCOMP_ARCH_NATIVE_NR  NR_syscalls
#endif
#ifndef SECCOMP_ARCH_COMPAT_NR
#define SECCOMP_ARCH_COMPAT_NR  __NR_compat_syscalls
#endif

struct action_cache {
	DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
	DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

extern struct seccomp_filter;

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
	if (!filter) {
		return;
	}

	if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
		clear_bit(nr, filter->cache.allow_native);
	}

#ifdef SECCOMP_ARCH_COMPAT
	if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
		clear_bit(nr, filter->cache.allow_compat);
	}
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
	if (!filter) {
		return;
	}

	if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
		set_bit(nr, filter->cache.allow_native);
	}

#ifdef SECCOMP_ARCH_COMPAT
	if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
		set_bit(nr, filter->cache.allow_compat);
	}
#endif
}
