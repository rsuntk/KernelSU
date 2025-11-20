#ifndef __KSU_H_SECCOMP_CACHE
#define __KSU_H_SECCOMP_CACHE

#include <linux/fs.h>
#include <linux/version.h>

#ifndef CONFIG_KSU_MANUAL_HOOK
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);
#else
static inline void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
	return;
}
static inline void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
	return;
}
#endif
