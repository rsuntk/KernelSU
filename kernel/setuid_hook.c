#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/uidgid.h>
#include <linux/susfs.h>

#include "allowlist.h"
#include "setuid_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "supercalls.h"
#include "kernel_umount.h"
#include "kernel_compat.h"

static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 99000 && uid < 100000);
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 10000 && uid < 19999);
}

extern u32 susfs_zygote_sid;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern void susfs_reorder_mnt_id(void);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_try_umount(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT

static bool ksu_enhanced_security_enabled = false;

static int enhanced_security_feature_get(u64 *value)
{
	*value = ksu_enhanced_security_enabled ? 1 : 0;
	return 0;
}

static int enhanced_security_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_enhanced_security_enabled = enable;
	pr_info("enhanced_security: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler enhanced_security_handler = {
	.feature_id = KSU_FEATURE_ENHANCED_SECURITY,
	.name = "enhanced_security",
	.get_handler = enhanced_security_feature_get,
	.set_handler = enhanced_security_feature_set,
};

static void ksu_install_manager_fd_tw_func(struct callback_head *cb)
{
	ksu_install_fd();
	kfree(cb);
}

static void do_install_manager_fd(void)
{
	struct callback_head *cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
	if (!cb)
		return;

	cb->func = ksu_install_manager_fd_tw_func;
	if (task_work_add(current, cb, TWA_RESUME)) {
		kfree(cb);
		pr_warn("install manager fd add task_work failed\n");
	}
}

// force_sig kcompat, TODO: move it out of core_hook.c
// https://elixir.bootlin.com/linux/v5.3-rc1/source/kernel/signal.c#L1613
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define send_sigkill() force_sig(SIGKILL)
#else
#define send_sigkill() force_sig(SIGKILL, current)
#endif

extern void disable_seccomp(void);
int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid, uid_t new_euid)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("handle_setuid from %d to %d\n", old_uid, new_uid);
#endif

	// if old process is root, ignore it.
	if (old_uid != 0 && ksu_enhanced_security_enabled) {
		// disallow any non-ksu domain escalation from non-root to root!
		// euid is what we care about here as it controls permission
		if (unlikely(new_euid == 0) && !is_ksu_domain()) {
			pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
				current->pid, current->comm, old_uid, new_uid);
			send_sigkill();
			return 0;
		}
		// disallow appuid decrease to any other uid if it is not allowed to su
		if (is_appuid(old_uid) && new_euid < current_euid().val &&
		    !ksu_is_allow_uid_for_current(old_uid)) {
			pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
				current->pid, current->comm, old_uid, new_euid);
			send_sigkill();
			return 0;
		}
		return 0;
	}

	if (current_cred() &&
	    !susfs_is_sid_equal(current_cred()->security, susfs_zygote_sid)) {
		return 0;
	}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// Check if spawned process is isolated service first, and force to do umount if so
	if (is_zygote_isolated_service_uid(new_uid)) {
		goto do_umount;
	}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

	if (ksu_get_manager_appid() == new_uid % PER_USER_RANGE) {
		disable_seccomp();
		pr_info("install fd for manager (uid=%d)\n", new_uid);
		do_install_manager_fd();
		return 0;
	}

	// Check if spawned process is normal user app and needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) &&
		   ksu_uid_should_umount(new_uid))) {
		goto do_umount;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		disable_seccomp();
	}

	return 0;

do_umount:
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	susfs_try_umount(new_uid);
#else
	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// We can reorder the mnt_id now after all sus mounts are umounted
	susfs_reorder_mnt_id();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop(new_uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

	susfs_set_current_proc_umounted();

	return 0;
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return 0;
}

void ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
	if (ksu_register_feature_handler(&enhanced_security_handler)) {
		pr_err("Failed to register enhanced security feature handler\n");
	}
}

void ksu_setuid_hook_exit(void)
{
	pr_info("ksu setuid exit\n");
	ksu_kernel_umount_exit();
	ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
