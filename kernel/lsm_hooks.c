#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "setuid_hook.h"

#ifndef KSU_SHOULD_USE_NEW_TP

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif

extern int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid, uid_t new_euid, uid_t old_euid);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;
	uid_t new_euid = new->euid.val;
	uid_t old_euid = old->euid.val;

	return ksu_handle_setuid_common(new_uid, old_uid, new_euid, old_euid);
}

static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid)
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

void ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
	pr_info("LSM hooks initialized.\n");
}
#else
void ksu_lsm_hook_init(void)
{
	return;
}
#endif
