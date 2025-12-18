#include <linux/export.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/susfs.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */

#include "allowlist.h"
#include "arch.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"
#include "setuid_hook.h"
#include "sucompat.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"

struct cred *ksu_cred;

extern void __init ksu_lsm_hook_init(void);

int __init kernelsu_init(void)
{
	pr_info("KernelSU driver informations:\n");
	pr_info("- UTS_RELEASE = %s\n", UTS_RELEASE);
	pr_info("- UTS_MACHINE = %s\n", UTS_MACHINE);
	pr_info("- KSU_VERSION = %u\n", KSU_VERSION);
	pr_info("- KSU_BRANCH  = %s\n", KSU_BRANCH);

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_cred = prepare_creds();
	if (!ksu_cred) {
		pr_err("prepare cred failed!\n");
	}

	ksu_feature_init();

	ksu_supercalls_init();

	ksu_lsm_hook_init();
	ksu_setuid_hook_init();
	ksu_sucompat_init();

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	susfs_init();

	ksu_ksud_init();

	ksu_file_wrapper_init();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_ksud_exit();

	ksu_sucompat_exit();
	ksu_setuid_hook_exit();

	ksu_supercalls_exit();

	ksu_feature_exit();

	if (ksu_cred) {
		put_cred(ksu_cred);
	}
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
