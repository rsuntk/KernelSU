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
