// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

// security.c hijack for 6.8+

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int vfs_rename(struct renamedata *rd);
static int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);
	return ret;
}
#endif

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

#define __AARCH64_setresuid 147
static void *aarch64_setresuid __read_mostly = nullptr;
asmlinkage long hook_aarch64_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}

#ifdef CONFIG_COMPAT
#define __ARMEABI_setresuid 208
static void *armeabi_setresuid __read_mostly = nullptr;
asmlinkage long hook_armeabi_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#ifdef CONFIG_COMPAT
#define __ARMEABI_read		3
extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];	

	ksu_handle_sys_read_fd(fd);
	return __arm64_sys_read(regs);
}
#endif // CONFIG_COMPAT
#define __AARCH64_read		63
extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);
	return __arm64_sys_read(regs);
}
static int ksu_syscall_table_restore(void *data)
{
	set_user_nice(current, 19); // low prio
loop_start:
	msleep(1000);
	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, compat_sct);
#endif
	restore_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, native_sct);
	return 0;
}
#endif // !CONFIG_KSU_TAMPER_SYSCALL_TABLE && !CONFIG_KSU_HACK_ARM64_BRANCH_LINK

#define SETPROCATTR_TYPE_lsmid	int lsmid, const char *name, void *value, size_t size
__overloaded static int ksu_setprocattr_lsmid(SETPROCATTR_TYPE_lsmid)
{
	ksu_hide_setprocattr_inline(name, value, size);

	assume(!!&security_setprocattr);
	return ((typeof(ksu_setprocattr_lsmid) *)(void *)security_setprocattr)(lsmid, name, value, size);
}

#define SETPROCATTR_TYPE_lsm	const char *lsm, const char *name, void *value, size_t size
__overloaded static int ksu_setprocattr_lsm(SETPROCATTR_TYPE_lsm)
{
	ksu_hide_setprocattr_inline(name, value, size);

	assume(!!&security_setprocattr);
	return ((typeof(ksu_setprocattr_lsm) *)(void *)security_setprocattr)(lsm, name, value, size);
}

#define SETPROCATTR_TYPE_name	const char *name, void *value, size_t size
__overloaded static int ksu_setprocattr_name(SETPROCATTR_TYPE_name)
{
	ksu_hide_setprocattr_inline(name, value, size);

	assume(!!&security_setprocattr);
	return ((typeof(ksu_setprocattr_name) *)(void *)security_setprocattr)(name, value, size);
}

#define ksu_setprocattr_overloaded _Generic(			\
(security_setprocattr),						\
	int (*)(SETPROCATTR_TYPE_lsmid)	:ksu_setprocattr_lsmid,	\
	int (*)(SETPROCATTR_TYPE_lsm)	:ksu_setprocattr_lsm,	\
	int (*)(SETPROCATTR_TYPE_name)	:ksu_setprocattr_name	\
)

struct mnt_idmap;
#define INODE_SETXATTR_TYPE_idmap	struct mnt_idmap *idmap, struct dentry *dentry, const char *name, const void *value, size_t size, int flags
__overloaded static int ksu_inode_setxattr_idmap(INODE_SETXATTR_TYPE_idmap)
{
	ksu_hide_setxattr_inline(name, value, size);

	assume(!!&security_inode_setxattr);
	return ((typeof(ksu_inode_setxattr_idmap) *)(void *)security_inode_setxattr)(idmap, dentry, name, value, size, flags);
}

struct user_namespace;
#define INODE_SETXATTR_TYPE_userns	struct user_namespace *mnt_userns, struct dentry *dentry, const char *name, const void *value, size_t size, int flags
__overloaded static int ksu_inode_setxattr_userns(INODE_SETXATTR_TYPE_userns)
{
	ksu_hide_setxattr_inline(name, value, size);

	assume(!!&security_inode_setxattr);
	return ((typeof(ksu_inode_setxattr_userns) *)(void *)security_inode_setxattr)(mnt_userns, dentry, name, value, size, flags);
}

#define INODE_SETXATTR_TYPE_legacy	struct dentry *dentry, const char *name, const void *value, size_t size, int flags
__overloaded static int ksu_inode_setxattr_legacy(INODE_SETXATTR_TYPE_legacy)
{
	ksu_hide_setxattr_inline(name, value, size);

	assume(!!&security_inode_setxattr);
	return ((typeof(ksu_inode_setxattr_legacy) *)(void *)security_inode_setxattr)(dentry, name, value, size, flags);
}

#define ksu_inode_setxattr_overloaded _Generic(				\
(security_inode_setxattr),						\
	int (*)(INODE_SETXATTR_TYPE_idmap)  :ksu_inode_setxattr_idmap,	\
	int (*)(INODE_SETXATTR_TYPE_userns) :ksu_inode_setxattr_userns,	\
	int (*)(INODE_SETXATTR_TYPE_legacy) :ksu_inode_setxattr_legacy	\
)

#define __ksym_size(callsite)	ksu_get_ksym_size(callsite, (256 * sizeof(uint32_t)))
static void print_branch_targets(uintptr_t callsite, uintptr_t symbol_addr, char *hook_name)
{
	char buf1[KSYM_SYMBOL_LEN];
	sprint_symbol_no_offset(buf1, symbol_addr);
	pr_info("LSM: Initializing hook for %s -> %s \n", buf1, hook_name);
}
#define patch_arm64_branches_trampolined(callsite, symbol_addr, hook) ({					\
	print_branch_targets(callsite, symbol_addr, #hook);							\
	arm64_branch_patch_trampolined(callsite, __ksym_size(callsite), symbol_addr, (uintptr_t)hook, true);	\
})

static void __init ksu_lsm_hook_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) 
	target_callsite = kallsyms_lookup_retry("filename_renameat2", lookup_noscan); // k7.0
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("do_renameat2");
	symbol_addr = kallsyms_lookup_retry("vfs_rename");
	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, ksu_vfs_rename);
	pr_info("LSM: vfs_rename: ret %d \n", ret);
	if (!ret)
		goto rename_hook_done;
#endif // > 5.12
	target_callsite = kallsyms_lookup_retry("vfs_rename2", lookup_noscan); // vfs2
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("vfs_rename");
	symbol_addr = kallsyms_lookup_retry("security_inode_rename");
	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, ksu_inode_rename);
	pr_info("LSM: security_inode_rename: ret %d \n", ret);
rename_hook_done:

	target_callsite = kallsyms_lookup_retry("__sys_setresuid");
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("__arm64_sys_setresuid");
	symbol_addr = kallsyms_lookup_retry("security_task_fix_setuid");
	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, ksu_task_fix_setuid);
	if (ret) {
		pr_info("LSM: security_task_fix_setuid: err: %d ! fallback to sys_setresuid!\n", ret);
		replace_syscall((void *)&aarch64_setresuid, __AARCH64_setresuid, (void *)hook_aarch64_setresuid, native_sct);
	#ifdef CONFIG_COMPAT
		replace_syscall((void *)&armeabi_setresuid, __ARMEABI_setresuid, (void *)hook_armeabi_setresuid, compat_sct);
	#endif
	} else
		pr_info("LSM: security_task_fix_setuid: ret %d \n", ret);

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#ifdef CONFIG_COMPAT
	replace_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, compat_sct);
#endif
	replace_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, native_sct);
	kthread_run(ksu_syscall_table_restore, NULL, "kthread");
#endif // !CONFIG_KSU_TAMPER_SYSCALL_TABLE && !CONFIG_KSU_HACK_ARM64_BRANCH_LINK

}

// see selinux_hide.c
static void ksu_decide_inode_setxattr(bool sh_hooked)
{
	if (sh_hooked)
		return;
	uintptr_t target_callsite = kallsyms_lookup_retry("__vfs_setxattr_locked"); // exported symbol
	uintptr_t symbol_addr = kallsyms_lookup_retry("security_inode_setxattr");
	int ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, ksu_inode_setxattr_overloaded);
	pr_info("LSM: security_inode_setxattr: ret %d \n", ret);
}

static void ksu_decide_setprocattr(bool sh_hooked)
{
	if (sh_hooked)
		return;
	uintptr_t target_callsite = kallsyms_lookup_retry("proc_pid_attr_write"); // fn ptr on dispatch table
	uintptr_t symbol_addr = kallsyms_lookup_retry("security_setprocattr");
	int ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, ksu_setprocattr_overloaded);
	pr_info("LSM: security_setprocattr: ret %d \n", ret);
}

#undef patch_arm64_branches_trampolined
#undef __ksym_size

#undef INODE_SETXATTR_TYPE_idmap
#undef INODE_SETXATTR_TYPE_userns
#undef INODE_SETXATTR_TYPE_idmap
#undef ksu_inode_setxattr_overloaded

#undef SETPROCATTR_TYPE_lsmid
#undef SETPROCATTR_TYPE_lsm
#undef SETPROCATTR_TYPE_name
#undef ksu_setprocattr_overloaded

