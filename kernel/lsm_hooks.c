#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/uidgid.h>
#include <linux/string.h>

#include "klog.h" // IWYU pragma: keep
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

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                            struct inode *new_inode, struct dentry *new_dentry)
{
    // skip kernel threads
    if (!current->mm) {
        return 0;
    }

    // skip non system uid
    if (current_uid().val != 1000) {
        return 0;
    }

    if (!old_dentry || !new_dentry) {
        return 0;
    }

    // /data/system/packages.list.tmp -> /data/system/packages.list
    if (strcmp(new_dentry->d_iname, "packages.list")) {
        return 0;
    }

    char path[128];
    char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
    if (IS_ERR(buf)) {
        pr_err("dentry_path_raw failed.\n");
        return 0;
    }

    if (!strstr(buf, "/system/packages.list")) {
        return 0;
    }

    pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
            new_dentry->d_iname, buf);

    track_throne(false);

    return 0;
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
                               int flags)
{
    kuid_t euid, uid;

    if (!new)
        return 0;

    euid = new->euid;
    uid = new->uid;

    return ksu_handle_setresuid((uid_t)euid.val, (uid_t)uid.val,
                                (uid_t)uid.val);
}

static struct security_hook_list ksu_hooks[] = {
    LSM_HOOK_INIT(key_permission, ksu_key_permission),
    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
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
