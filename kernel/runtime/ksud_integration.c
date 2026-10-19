static const char KERNEL_SU_RC[] =
	"\n"

	"on post-fs-data\n"
	"    start logd\n"
	// We should wait for the post-fs-data finish
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " post-fs-data\n"
	"\n"

	"on nonencrypted\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " boot-completed\n"
	"\n"

	"\n";

static void stop_init_rc_hook();

static bool ksu_vfs_read_hook __read_mostly = true;
static bool ksu_input_hook __read_mostly = true;

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// Prefer /metadata/vold, else /metadata/watchdog, else /metadata.
#define MODULE_RC_PATH_VOLD "/metadata/vold/ksu/modules.rc"
#define MODULE_RC_PATH_WATCHDOG "/metadata/watchdog/ksu/modules.rc"
#define MODULE_RC_PATH_DEFAULT "/metadata/ksu/modules.rc"
#define MODULE_RC_MAX (1u << 20) /* 1 MiB cap */
static char *module_rc_buf;
static size_t module_rc_len;
static ssize_t module_rc_pos;

static struct file *open_module_rc(const char **chosen_path)
{
	struct file *f = filp_open(MODULE_RC_PATH_VOLD, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_VOLD;
		return f;
	}
	f = filp_open(MODULE_RC_PATH_WATCHDOG, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_WATCHDOG;
		return f;
	}
	f = filp_open(MODULE_RC_PATH_DEFAULT, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_DEFAULT;
		return f;
	}
	*chosen_path = MODULE_RC_PATH_DEFAULT;
	return f;
}

static void load_module_rc_once(void)
{
	static bool loaded = false;
	struct file *f;
	const char *path = NULL;
	loff_t pos = 0;
	ssize_t r;
	size_t fsize;
	const struct cred *old_cred;

	if (loaded)
		return;
	loaded = true;
 
	old_cred = override_creds(ksu_cred);

	f = open_module_rc(&path);
	if (IS_ERR(f)) {
		pr_info("module rc: open %s failed: %ld\n", path, PTR_ERR(f));
		goto out_revert_creds;
	}

	if (!S_ISREG(file_inode(f)->i_mode)) {
		pr_warn("module rc: %s is not a regular file\n", path);
		goto out_close_file;
	}

	fsize = i_size_read(file_inode(f));
	if (fsize == 0) {
		pr_warn("module rc: skip empty module rc\n");
		goto out_close_file;
	}

	module_rc_buf = kvmalloc(fsize, GFP_KERNEL);
	if (!module_rc_buf) {
		pr_err("module rc: alloc %zu failed\n", fsize);
		goto out_close_file;
	}

	r = kernel_read(f, module_rc_buf, fsize, &pos);
 
	if (r <= 0) {
		pr_err("module rc: read failed: %zd\n", r);
		kvfree(module_rc_buf);
		module_rc_buf = NULL;
		goto out_close_file;
	}

	module_rc_len = r;
	pr_info("module rc: loaded %zu bytes from %s\n", module_rc_len, path);

out_close_file:
	filp_close(f, NULL);

out_revert_creds:
	revert_creds(old_cred);
}

static void free_module_rc(void)
{
	kvfree(module_rc_buf);
	module_rc_buf = NULL;
	module_rc_len = 0;
}

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
		goto append_module_rc;

	ret = orig_read(file, buf, count, pos);
	if (ret != 0) {
		return ret;
	}
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
		return ret;
	}
	pr_info("read_proxy: orig read finished, start append rc\n");

append_ksu_rc:
	if (ksu_rc_pos < ksu_rc_len) {
		append_count = ksu_rc_len - ksu_rc_pos;
		if (append_count > count - ret)
			append_count = count - ret;
		// copy_to_user returns the number of bytes that could not be copied
		if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
			pr_info("read_proxy: append error, totally appended %ld\n", ksu_rc_pos);
			return ret;
		}
		pr_info("read_proxy: append static %zu\n", append_count);
		ksu_rc_pos += append_count;
		ret += append_count;
		if (ksu_rc_pos == ksu_rc_len)
			pr_info("read_proxy: static append done\n");
	}

append_module_rc:
	if (module_rc_pos < module_rc_len && (size_t)ret < count) {
		append_count = module_rc_len - module_rc_pos;
		if (append_count > count - ret)
			append_count = count - ret;
		if (copy_to_user(buf + ret, module_rc_buf + module_rc_pos, append_count)) {
			pr_info("read_proxy: module append error, totally appended %zd\n", module_rc_pos);
			return ret;
		}
		pr_info("read_proxy: append module %zu\n", append_count);
		module_rc_pos += append_count;
		ret += append_count;
		if (module_rc_pos == (ssize_t)module_rc_len) {
			pr_info("read_proxy: module append done\n");
			free_module_rc();
		}
	}

	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
		goto append_module_rc;

	ret = orig_read_iter(iocb, to);
	if (ret != 0) {
		return ret;
	}
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
		return ret;
	}
	pr_info("read_iter_proxy: orig read finished, start append rc\n");

append_ksu_rc:
	if (ksu_rc_pos < ksu_rc_len) {
		// copy_to_iter returns the number of bytes successfully copied
		append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos, ksu_rc_len - ksu_rc_pos, to);
		if (!append_count) {
			pr_info("read_iter_proxy: append error, totally appended %ld\n", ksu_rc_pos);
			return ret;
		}
		pr_info("read_iter_proxy: append static %zu\n", append_count);
		ksu_rc_pos += append_count;
		ret += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_iter_proxy: static append done\n");
		}
	}

append_module_rc:
	if (module_rc_pos < module_rc_len) {
		append_count = copy_to_iter(module_rc_buf + module_rc_pos, module_rc_len - module_rc_pos, to);
		if (!append_count) {
			pr_info("read_iter_proxy: module append error, appended %zd\n", module_rc_pos);
			return ret;
		}
		pr_info("read_iter_proxy: append module %zu\n", append_count);
		module_rc_pos += append_count;
		ret += append_count;
		if (module_rc_pos == (ssize_t)module_rc_len) {
			pr_info("read_iter_proxy: module append done\n");
			free_module_rc();
		}
	}
	return ret;
}

// TODO: add init.rc handling here!

static void stop_init_rc_hook()
{
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
}

static void ksu_stop_input_hook_runtime()
{
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
}

void __init ksu_ksud_init() { }

