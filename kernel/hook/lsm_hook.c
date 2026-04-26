#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) ||                                     \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred, unsigned perm)
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

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    uid_t new_uid, old_uid = 0;

    if (unlikely(!new || !old))
        return 0;

    new_uid = new->uid.val;
    old_uid = old->uid.val;

    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}

#ifdef CONFIG_KSU_LSM_HOOKS
static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) ||                                     \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
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
#else
void __init ksu_lsm_hook_init(void)
{
} /* no opt */
#endif

void ksu_lsm_hook_exit(void)
{
}
