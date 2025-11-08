#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "arch.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "sucompat.h"
#include "core_hook.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static const char su[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;
bool ksu_su_compat_enabled __read_mostly = true;

#ifdef KSU_SHOULD_USE_NEW_TP

#include "linux/compiler.h"
#include "linux/printk.h"
#include "selinux/selinux.h"

#include <linux/tracepoint.h>
#include <linux/spinlock.h>
#include <asm/syscall.h>
#include <trace/events/syscalls.h>

void ksu_mark_running_process(void)
{
	struct task_struct *p, *t;
	read_lock(&tasklist_lock);
	for_each_process_thread (p, t) {
		if (!t->mm) { // only user processes
			continue;
		}
		int uid = task_uid(t).val;
		bool ksu_root_process =
			uid == 0 && is_task_ksu_domain(get_task_cred(t));
		if (ksu_root_process || ksu_is_allow_uid(uid)) {
			ksu_set_task_tracepoint_flag(t);
			pr_info("sucompat: mark process: pid:%d, uid: %d, comm:%s\n",
				t->pid, uid, t->comm);
		}
	}
	read_unlock(&tasklist_lock);
}

static void handle_process_mark(bool mark)
{
	struct task_struct *p, *t;
	read_lock(&tasklist_lock);
	for_each_process_thread (p, t) {
		if (mark)
			ksu_set_task_tracepoint_flag(t);
		else
			ksu_clear_task_tracepoint_flag(t);
	}
	read_unlock(&tasklist_lock);
}

static void mark_all_process(void)
{
	handle_process_mark(true);
	pr_info("sucompat: mark all user process done!\n");
}

static void unmark_all_process(void)
{
	handle_process_mark(false);
	pr_info("sucompat: unmark all user process done!\n");
}
#else
void ksu_mark_running_process(void)
{
}

static void handle_process_mark(bool mark)
{
}

static void mark_all_process(void)
{
}

static void unmark_all_process(void)
{
}
#endif

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_su_compat_enabled) {
		pr_info("su_compat: no need to change\n");
		return 0;
	}

	if (enable) {
		ksu_sucompat_enable();
	} else {
		ksu_sucompat_disable();
	}

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

static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static inline char __user *sh_user_path(void)
{
	const char sh_path[] = SH_PATH;
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static inline char __user *ksud_user_path(void)
{
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static inline bool __is_su_allowed(const void *ptr_to_check)
{
#ifndef KSU_KPROBE_HOOK
	if (!ksu_su_compat_enabled)
		return false;
#endif
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}
#define is_su_allowed(ptr) __is_su_allowed((const void *)ptr)

static int ksu_sucompat_user_common(const char __user **filename_user,
				    const char *syscall_name,
				    const bool escalate)
{
	char path[sizeof(su)]; // sizeof includes nullterm already!
	memset(path, 0, sizeof(path));

	ksu_strncpy_from_user_retry(path, *filename_user, sizeof(path));

	if (memcmp(path, su, sizeof(su)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_to_root(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (!is_su_allowed(filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_to_root();

	return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
	return 0;
}

#ifdef KSU_SHOULD_USE_NEW_TP
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS

// Tracepoint probe for sys_enter
static void sucompat_sys_enter_handler(void *data, struct pt_regs *regs,
				       long id)
{
	// Handle newfstatat
	if (unlikely(id == __NR_newfstatat)) {
		int *dfd = (int *)&PT_REGS_PARM1(regs);
		const char __user **filename_user =
			(const char __user **)&PT_REGS_PARM2(regs);
		int *flags = (int *)&PT_REGS_SYSCALL_PARM4(regs);
		ksu_handle_stat(dfd, filename_user, flags);
		return;
	}

	// Handle faccessat
	if (unlikely(id == __NR_faccessat)) {
		int *dfd = (int *)&PT_REGS_PARM1(regs);
		const char __user **filename_user =
			(const char __user **)&PT_REGS_PARM2(regs);
		int *mode = (int *)&PT_REGS_PARM3(regs);
		ksu_handle_faccessat(dfd, filename_user, mode, NULL);
		return;
	}

	// Handle execve
	if (unlikely(id == __NR_execve)) {
		const char __user **filename_user =
			(const char __user **)&PT_REGS_PARM1(regs);
		ksu_handle_execve_sucompat(AT_FDCWD, filename_user, NULL, NULL,
					   NULL);
		return;
	}
}

#endif // CONFIG_HAVE_SYSCALL_TRACEPOINTS

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name,
					kretprobe_handler_t handler)
{
	struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
	if (!rp)
		return NULL;
	rp->kp.symbol_name = name;
	rp->handler = handler;
	rp->data_size = 0;
	rp->maxactive = 0;

	int ret = register_kretprobe(rp);
	pr_info("sucompat: register_%s kretprobe: %d\n", name, ret);
	if (ret) {
		kfree(rp);
		return NULL;
	}

	return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
	struct kretprobe *rp = *rp_ptr;
	if (!rp)
		return;
	unregister_kretprobe(rp);
	synchronize_rcu();
	kfree(rp);
	*rp_ptr = NULL;
}

static int tracepoint_reg_count = 0;
static DEFINE_SPINLOCK(tracepoint_reg_lock);

static int syscall_regfunc_handler(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	unsigned long flags;
	spin_lock_irqsave(&tracepoint_reg_lock, flags);
	if (tracepoint_reg_count < 1) {
		// while install our tracepoint, mark our processes
		unmark_all_process();
		ksu_mark_running_process();
	} else {
		// while installing other tracepoint, mark all processes
		mark_all_process();
	}
	tracepoint_reg_count++;
	spin_unlock_irqrestore(&tracepoint_reg_lock, flags);
	return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	unsigned long flags;
	spin_lock_irqsave(&tracepoint_reg_lock, flags);
	if (tracepoint_reg_count <= 1) {
		// while uninstall our tracepoint, unmark all processes
		unmark_all_process();
	} else {
		// while uninstalling other tracepoint, mark our processes
		unmark_all_process();
		ksu_mark_running_process();
	}
	tracepoint_reg_count--;
	spin_unlock_irqrestore(&tracepoint_reg_lock, flags);
	return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif
#endif

void ksu_sucompat_enable(void)
{
#ifdef KSU_SHOULD_USE_NEW_TP
	int ret;
	pr_info("sucompat: ksu_sucompat_enable called\n");

#ifdef CONFIG_KRETPROBES
	// Register kretprobe for syscall_regfunc
	syscall_regfunc_rp =
		init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
	// Register kretprobe for syscall_unregfunc
	syscall_unregfunc_rp =
		init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
	ret = register_trace_sys_enter(sucompat_sys_enter_handler, NULL);
#ifndef CONFIG_KRETPROBES
	unmark_all_process();
	ksu_mark_running_process();
#endif
	if (ret) {
		pr_err("sucompat: failed to register sys_enter tracepoint: %d\n",
		       ret);
	} else {
		pr_info("sucompat: sys_enter tracepoint registered\n");
	}
#endif
#else
	ksu_su_compat_enabled = true;
	pr_info("init sucompat\n");
#endif
}

void ksu_sucompat_disable(void)
{
#ifdef KSU_SHOULD_USE_NEW_TP
	pr_info("sucompat: ksu_sucompat_disable called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
	unregister_trace_sys_enter(sucompat_sys_enter_handler, NULL);
	tracepoint_synchronize_unregister();
	pr_info("sucompat: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
	destroy_kretprobe(&syscall_regfunc_rp);
	destroy_kretprobe(&syscall_unregfunc_rp);
#endif
#else
	ksu_su_compat_enabled = false;
	pr_info("deinit sucompat\n");
#endif
}

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init(void)
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
	if (ksu_su_compat_enabled) {
		ksu_sucompat_enable();
	}
}

void ksu_sucompat_exit(void)
{
	if (ksu_su_compat_enabled) {
		ksu_sucompat_disable();
	}
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
