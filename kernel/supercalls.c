#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "kp_hook.h"
#include "syscall_handler.h"
#endif
#include "kernel_compat.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "objsec.h"
#include "file_wrapper.h"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
	bool is_allowed =
		is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
	return is_allowed;
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()

	pr_info("allow root for: %d\n", current_uid().val);
	escape_with_root_profile();

	return 0;
}

static int do_get_info(void __user *arg)
{
	struct ksu_get_info_cmd cmd = { .version = KERNEL_SU_VERSION,
					.flags = 0 };

#ifdef MODULE
	cmd.flags |= 0x1;
#endif

	if (is_manager()) {
		cmd.flags |= 0x2;
	}
	cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static bool post_fs_data_lock = false;
		if (!post_fs_data_lock) {
			post_fs_data_lock = true;
			pr_info("post-fs-data triggered\n");
			on_post_fs_data();
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			pr_info("boot_complete triggered\n");
			on_boot_completed();
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, (void __user *)cmd.arg);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_allow_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success =
		ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, true);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_allow_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_deny_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success =
		ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, false);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_deny_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_uid(void __user *arg)
{
	struct ksu_get_manager_uid_cmd cmd;

	cmd.uid = ksu_get_manager_uid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_uid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_set_app_profile(&cmd.profile, true)) {
		return -EFAULT;
	}

	return 0;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}

	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n",
		       cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}

	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n",
		       cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

// kcompat for older kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define getfd_secure anon_inode_create_getfd
#elif defined(KSU_HAS_GETFD_SECURE)
#define getfd_secure anon_inode_getfd_secure
#else
// technically not a secure inode, but, this is the only way so.
#define getfd_secure(name, ops, data, flags, __unused)                         \
	anon_inode_getfd(name, ops, data, flags)
#endif

static int do_get_wrapper_fd(void __user *arg)
{
	if (!ksu_file_sid) {
		return -EINVAL;
	}

	struct ksu_get_wrapper_fd_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_wrapper_fd: copy_from_user failed\n");
		return -EFAULT;
	}

	struct file *f = fget(cmd.fd);
	if (!f) {
		return -EBADF;
	}

	struct ksu_file_wrapper *data = ksu_create_file_wrapper(f);
	if (data == NULL) {
		ret = -ENOMEM;
		goto put_orig_file;
	}

	ret = getfd_secure("[ksu_fdwrapper]", &data->ops, data, f->f_flags,
			   NULL);
	if (ret < 0) {
		pr_err("ksu_fdwrapper: getfd failed: %d\n", ret);
		goto put_wrapper_data;
	}
	struct file *pf = fget(ret);

	struct inode *wrapper_inode = file_inode(pf);
	// copy original inode mode
	wrapper_inode->i_mode = file_inode(f)->i_mode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||                           \
	defined(KSU_OPTIONAL_SELINUX_INODE)
	struct inode_security_struct *sec = selinux_inode(wrapper_inode);
#else
	struct inode_security_struct *sec =
		(struct inode_security_struct *)wrapper_inode->i_security;
#endif

	if (sec) {
		sec->sid = ksu_file_sid;
	}

	fput(pf);
	goto put_orig_file;
put_wrapper_data:
	ksu_delete_file_wrapper(data);
put_orig_file:
	fput(f);

	return ret;
}

static int do_manage_mark(void __user *arg)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	struct ksu_manage_mark_cmd cmd;
	int ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n",
			       cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
	}
	case KSU_MARK_MARK: {
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n",
				       cmd.pid, ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_UNMARK: {
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
				       cmd.pid, ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_REFRESH: {
		ksu_mark_running_process();
		pr_info("manage_mark: refreshed running processes\n");
		break;
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}
	return 0;
#else
	// We don't care, just return -ENOTSUPP
	pr_warn("manage_mark: this supercalls is not implemented for manual hook.\n");
	return -ENOTSUPP;
#endif
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
	struct mount_entry *new_entry, *entry, *tmp;
	struct ksu_add_try_umount_cmd cmd;
	char buf[256] = { 0 };

	if (copy_from_user(&cmd, arg, sizeof cmd))
		return -EFAULT;

	switch (cmd.mode) {
	case KSU_UMOUNT_WIPE: {
		struct mount_entry *entry, *tmp;
		down_write(&mount_list_lock);
		list_for_each_entry_safe (entry, tmp, &mount_list, list) {
			pr_info("wipe_umount_list: removing entry: %s\n",
				entry->umountable);
			list_del(&entry->list);
			kfree(entry->umountable);
			kfree(entry);
		}
		up_write(&mount_list_lock);

		return 0;
	}

	case KSU_UMOUNT_ADD: {
		long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
					     256);
		if (len <= 0)
			return -EFAULT;

		buf[sizeof(buf) - 1] = '\0';

		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry)
			return -ENOMEM;

		new_entry->umountable = kstrdup(buf, GFP_KERNEL);
		if (!new_entry->umountable) {
			kfree(new_entry);
			return -1;
		}

		down_write(&mount_list_lock);

		// disallow dupes
		// if this gets too many, we can consider moving this whole task to a kthread
		list_for_each_entry (entry, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				pr_info("cmd_add_try_umount: %s is already here!\n",
					buf);
				up_write(&mount_list_lock);
				kfree(new_entry->umountable);
				kfree(new_entry);
				return -1;
			}
		}

		// now check flags and add
		// this also serves as a null check
		if (cmd.flags)
			new_entry->flags = cmd.flags;
		else
			new_entry->flags = 0;

		// debug
		list_add(&new_entry->list, &mount_list);
		up_write(&mount_list_lock);
		pr_info("cmd_add_try_umount: %s added!\n", buf);

		return 0;
	}

	// this is just strcmp'd wipe anyway
	case KSU_UMOUNT_DEL: {
		long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
					     sizeof(buf) - 1);
		if (len <= 0)
			return -EFAULT;

		buf[sizeof(buf) - 1] = '\0';

		down_write(&mount_list_lock);
		list_for_each_entry_safe (entry, tmp, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				pr_info("cmd_add_try_umount: entry removed: %s\n",
					entry->umountable);
				list_del(&entry->list);
				kfree(entry->umountable);
				kfree(entry);
			}
		}
		up_write(&mount_list_lock);

		return 0;
	}

	default: {
		pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
		return -EINVAL;
	}

	} // switch(cmd.mode)

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
	struct ksu_nuke_ext4_sysfs_cmd cmd;
	char mnt[256];
	long ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (!cmd.arg)
		return -EINVAL;

	memset(mnt, 0, sizeof(mnt));

	ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
	if (ret < 0) {
		pr_err("nuke ext4 copy mnt failed: %ld\\n", ret);
		return -EFAULT; // 或者 return ret;
	}

	if (ret == sizeof(mnt)) {
		pr_err("nuke ext4 mnt path too long\\n");
		return -ENAMETOOLONG;
	}

	pr_info("do_nuke_ext4_sysfs: %s\n", mnt);

	return nuke_ext4_sysfs(mnt);
}

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
	KSU_IOCTL(GRANT_ROOT, "GRANT_ROOT", do_grant_root, allowed_for_su),
	KSU_IOCTL(GET_INFO, "GET_INFO", do_get_info, always_allow),
	KSU_IOCTL(REPORT_EVENT, "REPORT_EVENT", do_report_event, only_root),
	KSU_IOCTL(SET_SEPOLICY, "SET_SEPOLICY", do_set_sepolicy, only_root),
	KSU_IOCTL(CHECK_SAFEMODE, "CHECK_SAFEMODE", do_check_safemode,
		  always_allow),
	KSU_IOCTL(GET_ALLOW_LIST, "GET_ALLOW_LIST", do_get_allow_list,
		  manager_or_root),
	KSU_IOCTL(GET_DENY_LIST, "GET_DENY_LIST", do_get_deny_list,
		  manager_or_root),
	KSU_IOCTL(UID_GRANTED_ROOT, "UID_GRANTED_ROOT", do_uid_granted_root,
		  manager_or_root),
	KSU_IOCTL(UID_SHOULD_UMOUNT, "UID_SHOULD_UMOUNT", do_uid_should_umount,
		  manager_or_root),
	KSU_IOCTL(GET_MANAGER_UID, "GET_MANAGER_UID", do_get_manager_uid,
		  manager_or_root),
	KSU_IOCTL(GET_APP_PROFILE, "GET_APP_PROFILE", do_get_app_profile,
		  only_manager),
	KSU_IOCTL(SET_APP_PROFILE, "SET_APP_PROFILE", do_set_app_profile,
		  only_manager),
	KSU_IOCTL(GET_FEATURE, "GET_FEATURE", do_get_feature, manager_or_root),
	KSU_IOCTL(SET_FEATURE, "SET_FEATURE", do_set_feature, manager_or_root),
	KSU_IOCTL(GET_WRAPPER_FD, "GET_WRAPPER_FD", do_get_wrapper_fd,
		  manager_or_root),
	KSU_IOCTL(MANAGE_MARK, "MANAGE_MARK", do_manage_mark, manager_or_root),
	KSU_IOCTL(NUKE_EXT4_SYSFS, "NUKE_EXT4_SYSFS", do_nuke_ext4_sysfs,
		  manager_or_root),
	KSU_IOCTL(ADD_TRY_UMOUNT, "ADD_TRY_UMOUNT", add_try_umount,
		  manager_or_root),

	// Sentinel
	{ .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }
};

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		// downstream: dereference all arg usage!
		if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
			pr_err("install ksu fd reply err\n");
			do_close_fd(fd);
		}
		return 0;
	}

	return 0;
}

void ksu_supercalls_init(void)
{
	int i;

	pr_info("KernelSU IOCTL Commands:\n");
	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name,
			ksu_ioctl_handlers[i].cmd);
	}
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_supercalls_init();
#endif
}

void ksu_supercalls_exit(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_supercalls_exit();
#endif
}

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		if (cmd == ksu_ioctl_handlers[i].cmd) {
			// Check permission first
			if (ksu_ioctl_handlers[i].perm_check &&
			    !ksu_ioctl_handlers[i].perm_check()) {
				pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
					cmd, current_uid().val);
				return -EPERM;
			}
			// Execute handler
			return ksu_ioctl_handlers[i].handler(argp);
		}
	}

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu fd released\n");
#endif
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu fd[%d] installed for %s/%d\n", fd, current->comm,
		current->pid);
#endif

	return fd;
}
