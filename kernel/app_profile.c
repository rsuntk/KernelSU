#include <linux/version.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h> // signal_struct
#include <linux/sched/task.h>
#endif
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/refcount.h>

#include "allowlist.h"
#include "app_profile.h"
#include "arch.h"
#include "kernel_compat.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "syscall_handler.h"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static struct group_info root_groups = {
	.usage = REFCOUNT_INIT(2),
};
#else
static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };
#endif

void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

// RKSU: Use it wisely, not static.
void disable_seccomp(struct task_struct *tsk)
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
	// Skip releasing filter ref when its already NULL.
	if (tsk->seccomp.filter == NULL)
		return;

	tsk->seccomp.mode = 0;
	// 5.9+ have filter_count, but optional.
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0) || defined(KSU_OPTIONAL_SECCOMP_FILTER_CNT))
	atomic_set(&tsk->seccomp.filter_count, 0);
#endif
	// some old kernel backport seccomp_filter_release..
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) &&                           \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
	seccomp_filter_release(tsk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	put_seccomp_filter(tsk);
#endif
	// never, ever call seccomp_filter_release on 6.10+ (no effect)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) &&                          \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0))
	seccomp_filter_release(tsk);
#endif
	// finally, we freed the filter to avoid UAF.
	tsk->seccomp.filter = NULL;
#endif
}

void escape_with_root_profile(void)
{
	struct cred *cred;
#ifdef CONFIG_KSU_SYSCALL_HOOK
	struct task_struct *p, *t;
	p = current;
#endif

	if (current_euid().val == 0) {
		pr_warn("Already root, don't escape!\n");
		return;
	}

	cred = prepare_creds();
	if (!cred) {
		pr_warn("prepare_creds failed!\n");
		return;
	}

	struct root_profile *profile = ksu_get_root_profile(cred->uid.val);

	cred->uid.val = profile->uid;
	cred->suid.val = profile->uid;
	cred->euid.val = profile->uid;
	cred->fsuid.val = profile->uid;

	cred->gid.val = profile->gid;
	cred->fsgid.val = profile->gid;
	cred->sgid.val = profile->gid;
	cred->egid.val = profile->gid;
	cred->securebits = 0;

	BUILD_BUG_ON(sizeof(profile->capabilities.effective) !=
		     sizeof(kernel_cap_t));

	// setup capabilities
	// we need CAP_DAC_READ_SEARCH becuase `/data/adb/ksud` is not accessible for non root process
	// we add it here but don't add it to cap_inhertiable, it would be dropped automaticly after exec!
	u64 cap_for_ksud =
		profile->capabilities.effective | CAP_DAC_READ_SEARCH;
	memcpy(&cred->cap_effective, &cap_for_ksud,
	       sizeof(cred->cap_effective));
	memcpy(&cred->cap_permitted, &profile->capabilities.effective,
	       sizeof(cred->cap_permitted));
	memcpy(&cred->cap_bset, &profile->capabilities.effective,
	       sizeof(cred->cap_bset));

	setup_groups(profile, cred);

	commit_creds(cred);

	// Refer to kernel/seccomp.c: seccomp_set_mode_strict
	// When disabling Seccomp, ensure that current->sighand->siglock is held during the operation.
	spin_lock_irq(&current->sighand->siglock);
	disable_seccomp(current);
	spin_unlock_irq(&current->sighand->siglock);

	setup_selinux(profile->selinux_domain);

#ifdef CONFIG_KSU_SYSCALL_HOOK
	for_each_thread (p, t) {
		ksu_set_task_tracepoint_flag(t);
	}
#endif
}
