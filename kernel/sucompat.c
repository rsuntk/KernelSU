#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <linux/susfs_def.h>
#include <linux/namei.h>
#include <asm/current.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "sucompat.h"
#include "app_profile.h"
#include "selinux/selinux.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static const char su_path[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;
static const char sh_path[] = SH_PATH;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static inline bool is_su_allowed(void)
{
	if (!ksu_su_compat_enabled)
		return false;

#ifdef CONFIG_SECCOMP
	if (likely(!!current->seccomp.mode))
		return false;
#endif

	return true;
}

static int ksu_sucompat_user_common(const char __user **filename_user,
				    const char *syscall_name,
				    const bool escalate)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (unlikely(!filename_user))
		return 0;
	if (!is_su_allowed())
		return 0;

	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));
	if (memcmp(path, su_path, sizeof(su_path)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_with_root_profile(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)
{
	struct filename *filename_p;

	if (unlikely(!filename))
		return 0;

	if (!is_su_allowed())
		return 0;

	filename_p = *filename;
	if (IS_ERR(filename_p))
		return 0;

	if (filename_p->name == NULL)
		return 0;

	if (likely(memcmp(filename_p->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("vfs_statx: su->sh!\n");
	memcpy((void *)filename_p->name, sh_path, sizeof(sh_path));
	return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}
#endif

int ksu_handle_execveat_init(struct filename *filename)
{
	if (current->pid != 1 && is_init(get_current_cred())) {
		if (likely(strstr(filename->name, "/app_process") == NULL &&
			   strstr(filename->name, "/adbd") == NULL)) {
			pr_info("hook_manager: unmark %d exec %s\n",
				current->pid, filename->name);
			susfs_set_current_proc_umounted();
		}
		return 0;
	}
	return 1;
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (unlikely(!filename_ptr))
		return 0;

	if (!is_su_allowed())
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;

	if (filename->name == NULL)
		return 0;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	if (ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags)) {
		return 0;
	}
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

// dead code: devpts handling
int __maybe_unused ksu_handle_devpts(struct inode *inode)
{
	return 0;
}

// sucompat: permitted process can execute 'su' to gain root access.
void ksu_sucompat_init(void)
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void ksu_sucompat_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
