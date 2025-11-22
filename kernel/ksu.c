#include <linux/export.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kconfig.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */

#include "allowlist.h"
#include "arch.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "syscall_handler.h"
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK
#include "setuid_hook.h"
#include "sucompat.h"
#endif
#include "ksud.h"
#include "supercalls.h"

#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_execveat_ksud(int *__never_use_fd,
			     struct filename **filename_ptr, void *__argv,
			     void *__envp, int *__never_use_flags);
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}
extern void ksu_lsm_hook_init(void);
#endif

int __init kernelsu_init(void)
{
#ifndef DDK_ENV
	pr_info("Initialized on: %s (%s) with driver version: %u\n",
		UTS_RELEASE, UTS_MACHINE, KSU_VERSION);
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_feature_init();

	ksu_supercalls_init();

#ifdef CONFIG_KSU_SYSCALL_HOOK
	ksu_syscall_hook_manager_init();
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_lsm_hook_init();
	ksu_setuid_hook_init();
	ksu_sucompat_init();
#endif

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	ksu_ksud_init();

#if IS_MODULE(CONFIG_KSU)
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_observer_exit();

	ksu_ksud_exit();

#ifdef CONFIG_KSU_SYSCALL_HOOK
	ksu_syscall_hook_manager_exit();
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_sucompat_exit();
	ksu_setuid_hook_exit();
#endif

	ksu_supercalls_exit();

	ksu_feature_exit();
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif
