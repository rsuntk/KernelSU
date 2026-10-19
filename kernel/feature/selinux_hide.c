static bool ksu_selinux_hide_enabled __read_mostly = true;

static int selinux_hide_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_feature_set(u64 value)
{
	bool enable = value != 0;
	int ret = 0;

	if (enable == ksu_selinux_hide_enabled)
		return 0;

	pr_info("selinux_hide: set to %d\n", enable);

	if (enable)
		ksu_selinux_hide_enabled = true;
	else
		ksu_selinux_hide_enabled = false;

	return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_feature_get,
	.set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init()
{
	if (ksu_register_feature_handler(&selinux_hide_handler)) {
		pr_err("Failed to register selinux_hide feature handler\n");
	}
}

void __exit ksu_selinux_hide_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
}

