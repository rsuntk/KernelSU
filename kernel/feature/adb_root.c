static bool ksu_adb_root __read_mostly = false;

static long is_libadbroot_ok()
{
	static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
	struct path path;
	long ret = kern_path(kLibAdbRoot, 0, &path);
	if (ret < 0) {
		if (ret == -ENOENT) {
			pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
			ret = 0;
		} else {
			pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
		}
		return ret;
	} else {
		ret = 1;
	}
	path_put(&path);
	return ret;
}

// TODO: implement downstream

static int kernel_adb_root_feature_get(u64 *value)
{
	*value = ksu_adb_root ? 1 : 0;
	return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
	bool enable = value != 0;
	if (enable) {
		ksu_adb_root = true;
	} else {
		ksu_adb_root = false;
	}
	pr_info("adb_root: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
	.feature_id = KSU_FEATURE_ADB_ROOT,
	.name = "adb_root",
	.get_handler = kernel_adb_root_feature_get,
	.set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
	if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
		pr_err("Failed to register adb_root feature handler\n");
	}
}

void __exit ksu_adb_root_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}

