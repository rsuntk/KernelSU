#include "kernel_includes.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"
#include "include/uapi/sulog.h"

// includes
#include "include/arch.h"
#include "include/klog.h"
#include "include/ksu.h"

// kernel compat
#include "kernel_compat.h"
#include "include/util.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"
#include "infra/event_queue.h"
#include "feature/adb_root.h"
#include "feature/kernel_umount.h"
#include "feature/selinux_hide.h"
#include "feature/shell_su_adb_only.h"
#include "feature/sucompat.h"
#include "feature/sulog.h"
#include "preinit/preinit.h"
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "sulog/fd.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

// unity build
#include "policy/allowlist.c"
#include "policy/app_profile.c"
#include "policy/feature.c"
#include "manager/apk_sign.c"
#include "manager/throne_tracker.c"

#include "supercall/perm.c"
#include "supercall/dispatch.c"
#include "supercall/supercall.c"

#include "infra/su_mount_ns.c"
#include "infra/file_wrapper.c"
#include "infra/event_queue.c"

#include "feature/adb_root.c"
#include "feature/kernel_umount.c"
#include "feature/selinux_hide.c"
#include "feature/shell_su_adb_only.c"
#include "feature/sucompat.c"
#include "feature/sulog.c"
#include "runtime/boot_event.c"
#include "runtime/ksud_integration.c"

#include "sulog/event.c"
#include "sulog/fd.c"

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

static int __init kernelsu_init(void)
{

	pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");

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
		return -ENOSYS;
	}

	// register features
	ksu_feature_init();
	ksu_sucompat_init();
	ksu_kernel_umount_init();
	ksu_sulog_init();
	ksu_selinux_hide_init();
	ksu_shell_su_adb_only_init();

	ksu_supercalls_init();

	ksu_allowlist_init();
	ksu_throne_tracker_init();
	ksu_ksud_init();
	ksu_file_wrapper_init();

	return 0;
}

device_initcall(kernelsu_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
