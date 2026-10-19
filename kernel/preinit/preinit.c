#define INIT_PATH "/system/bin/init"

static bool ksu_preinit_enabled = true;
module_param_named(preinit, ksu_preinit_enabled, bool, 0);

static bool is_selinux_setup(const char __user *const __user *argv_user)
{
	static const char expected[] = "selinux_setup";
	const char __user *arg;
	char buf[sizeof(expected) + 1];

	if (!argv_user || get_user(arg, argv_user + 1) || !arg)
		return false;

	memset(buf, 0, sizeof(buf));
	if (strncpy_from_user(buf, arg, sizeof(buf) - 1) < 0)
		return false;

	return !strcmp(buf, expected);
}

void ksu_preinit_release(void) { }

void ksu_preinit_init(void) { }

void ksu_preinit_exit(void) { }
