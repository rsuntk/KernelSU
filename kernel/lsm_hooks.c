#include <linux/version.h>
#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/string.h>

#include "klog.h" // IWYU pragma: keep
#include "lsm_hooks.h"
#include "kernel_compat.h"
#include "setuid_hook.h"
#include "throne_tracker.h"

static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
                              unsigned perm)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    if (init_session_keyring != NULL) {
        return 0;
    }
    if (strcmp(current->comm, "init")) {
        // we are only interested in `init` process
        return 0;
    }
    init_session_keyring = cred->session_keyring;
    pr_info("kernel_compat: got init_session_keyring\n");
#endif
    return 0;
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
                               int flags)
{
    if (!new || !old)
        return 0;

    return ksu_handle_setresuid(__kuid_val(new->uid), __kuid_val(new->euid),
                                __kuid_val(new->suid));
}

static struct security_hook_list ksu_hooks[] = {
    LSM_HOOK_INIT(key_permission, ksu_key_permission),
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid)
};

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    // https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
    pr_info("LSM hooks initialized.\n");
}
