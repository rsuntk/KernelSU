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
#include <linux/uidgid.h>

#include "allowlist.h"
#include "setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "supercalls.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "syscall_handler.h"
#endif
#include "kernel_umount.h"
#include "kernel_compat.h"

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
#define send_sig(sig) force_sig(sig)
#else
#define send_sig(sig) force_sig(sig, current)
#endif

extern void disable_seccomp(void);
int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid, uid_t new_euid)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("handle_setuid from %d to %d\n", old_uid, new_uid);
#endif

	if (likely(ksu_is_manager_appid_valid()) &&
	    unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		disable_seccomp();
#ifdef CONFIG_KSU_SYSCALL_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
		pr_info("install fd for manager (uid=%d)\n", new_uid);
		do_install_manager_fd();
		return 0;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		disable_seccomp();
#ifdef CONFIG_KSU_SYSCALL_HOOK
		ksu_set_task_tracepoint_flag(current);
	} else {
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
	}

	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                          \
     defined(CONFIG_KSU_MANUAL_HOOK))
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!is_sid_equal(current_cred(), ksu_zygote_sid)) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("setresuid: disallow non zygote sid!\n");
#endif
		return 0;
	}
	return ksu_handle_setuid_common(ruid, current_uid().val, euid);
}
#endif

void ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void ksu_setuid_hook_exit(void)
{
	pr_info("ksu setuid exit\n");
	ksu_kernel_umount_exit();
}
