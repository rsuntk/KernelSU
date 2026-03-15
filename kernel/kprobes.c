#include <linux/task_work.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"
#include "syscall_hook_manager.h" // #define USE_SYSCALL_MANAGER
#include "kprobes.h"
#include "util.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)                                                          \
    (sizeof(x) / sizeof(x)[0]) // no __must_be_array, be careful!
#endif

#define KSU_KPROBE(name, sym, pre_func)                                        \
    struct kprobe name = {                                                     \
        .symbol_name = sym,                                                    \
        .pre_handler = pre_func,                                               \
    }

#define KSU_KRETPROBE(name, sym, entry, ret, sz)                               \
    struct kretprobe name = {                                                  \
        .kp.symbol_name = sym,                                                 \
        .entry_handler = entry,                                                \
        .handler = ret,                                                        \
        .data_size = sz,                                                       \
    }

//
// ksud - for executing userspace daemon (ksud)
//

static struct work_struct stop_init_rc_hook_work;
static struct work_struct stop_execve_hook_work;
static struct work_struct stop_input_hook_work;

extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
                                    struct user_arg_ptr *argv,
                                    struct user_arg_ptr *envp, int *flags);
static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user **filename_user =
        (const char **)&PT_REGS_PARM1(real_regs);
    const char __user *const __user *__argv =
        (const char __user *const __user *)PT_REGS_PARM2(real_regs);
    struct user_arg_ptr argv = { .ptr.native = __argv };
    struct filename filename_in, *filename_p;
    char path[32];

    if (!filename_user)
        return 0;

    if (!ksu_retry_filename_access(filename_user, path, 32, false))
        return 0;

    filename_in.name = path;
    filename_p = &filename_in;
    return ksu_handle_execveat_ksud((int *)AT_FDCWD, &filename_p, &argv, NULL,
                                    NULL);
}

extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
                               size_t *count_ptr);
static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    unsigned int fd = PT_REGS_PARM1(real_regs);

    ksu_handle_sys_read(fd, NULL, NULL);
    return 0;
}

extern const size_t ksu_rc_len;
extern bool is_init_rc(struct file *fp);
static int sys_fstat_handler_pre(struct kretprobe_instance *p,
                                 struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    unsigned int fd = PT_REGS_PARM1(real_regs);
    void *statbuf = PT_REGS_PARM2(real_regs);
    *(void **)&p->data = NULL;

    struct file *file = fget(fd);
    if (!file)
        return 1;
    if (is_init_rc(file)) {
        pr_info("stat init.rc");
        fput(file);
        *(void **)&p->data = statbuf;
        return 0;
    }
    fput(file);
    return 1;
}

static int sys_fstat_handler_post(struct kretprobe_instance *p,
                                  struct pt_regs *regs)
{
    void __user *statbuf = *(void **)&p->data;
    if (statbuf) {
        void __user *st_size_ptr = statbuf + offsetof(struct stat, st_size);
        long size, new_size;
        if (!copy_from_user_nofault(&size, st_size_ptr, sizeof(long))) {
            new_size = size + ksu_rc_len;
            pr_info("adding ksu_rc_len: %ld -> %ld", size, new_size);
            if (!copy_to_user_nofault(st_size_ptr, &new_size, sizeof(long))) {
                pr_info("added ksu_rc_len");
            } else {
                pr_err("add ksu_rc_len failed: statbuf 0x%lx",
                       (unsigned long)st_size_ptr);
            }
        } else {
            pr_err("read statbuf 0x%lx failed", (unsigned long)st_size_ptr);
        }
    }

    return 0;
}

extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
                                         int *value);
static int input_handle_event_handler_pre(struct kprobe *p,
                                          struct pt_regs *regs)
{
    unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
    unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
    int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
    return ksu_handle_input_handle_event(type, code, value);
}

static KSU_KPROBE(execve_kp, SYS_EXECVE_SYMBOL, sys_execve_handler_pre);
static KSU_KPROBE(sys_read_kp, SYS_READ_SYMBOL, sys_read_handler_pre);
static KSU_KRETPROBE(sys_fstat_kp, SYS_FSTAT_SYMBOL, sys_fstat_handler_pre,
                     sys_fstat_handler_post, sizeof(void *));
static KSU_KPROBE(input_event_kp, "input_event",
                  input_handle_event_handler_pre);

static void do_stop_init_rc_hook(struct work_struct *work)
{
    unregister_kprobe(&sys_read_kp);
    unregister_kretprobe(&sys_fstat_kp);
}

static void do_stop_execve_hook(struct work_struct *work)
{
    unregister_kprobe(&execve_kp);
}

static void do_stop_input_hook(struct work_struct *work)
{
    unregister_kprobe(&input_event_kp);
}

void kp_handle_ksud_stop(enum ksud_stop_code stop_code)
{
    bool ret;
    switch (stop_code) {
    case KSU_INIT_RC_KP_HANDLER: {
        ret = schedule_work(&stop_init_rc_hook_work);
        pr_info("unregister init_rc hook: %d!\n", ret);
        break;
    }
    case KSU_EXECVE_KP_HANDLER: {
        ret = schedule_work(&stop_execve_hook_work);
        pr_info("unregister execve kprobe: %d!\n", ret);
        break;
    }
    case KSU_INPUT_EVENT_KP_HANDLER: {
        static bool input_hook_stopped = false;
        if (input_hook_stopped) {
            return;
        }
        input_hook_stopped = true;
        ret = schedule_work(&stop_input_hook_work);
        pr_info("unregister input kprobe: %d!\n", ret);
        break;
    }
    case KSU_KP_HANDLER_MAX:
    default: {
        pr_err("ksud: invalid enum / max!\n");
        return;
    }
    }
}

void kp_handle_ksud_init(void)
{
    int ret;

    ret = register_kprobe(&execve_kp);
    pr_info("ksud: execve_kp: %d\n", ret);

    ret = register_kprobe(&sys_read_kp);
    pr_info("ksud: sys_read_kp: %d\n", ret);

    ret = register_kretprobe(&sys_fstat_kp);
    pr_info("ksud: sys_fstat_kp: %d\n", ret);

    ret = register_kprobe(&input_event_kp);
    pr_info("ksud: input_event_kp: %d\n", ret);

    INIT_WORK(&stop_init_rc_hook_work, do_stop_init_rc_hook);
    INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
    INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
}

void kp_handle_ksud_exit(void)
{
    unregister_kprobe(&execve_kp);
    // this should be done before unregister sys_read_kp
    // unregister_kprobe(&sys_read_kp);
    unregister_kprobe(&input_event_kp);
}

//
// supercalls - Providing a way to call KSU IOCTL interface
//
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
                                 void __user **arg);
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);
    void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);
    int cmd = (int)PT_REGS_PARM3(real_regs);

    ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
    return 0;
}
static KSU_KPROBE(reboot_kp, REBOOT_SYMBOL, reboot_handler_pre);

void kp_handle_supercalls_init(void)
{
    int ret = register_kprobe(&reboot_kp);
    pr_info("supercalls: sys_reboot kp init: %d\n", ret);
}

void kp_handle_supercalls_exit(void)
{
    unregister_kprobe(&reboot_kp);
    pr_info("supercalls: sys_reboot kp unregistered.\n");
}

//
// sucompat - Invoke 'su' commands via terminal
//
#ifndef USE_SYSCALL_MANAGER
#ifdef CONFIG_COMPAT
static struct kprobe *su_kps[5];
#else
static struct kprobe *su_kps[3];
#endif

static struct kprobe *init_kprobe(const char *name,
                                  kprobe_pre_handler_t handler)
{
    int ret;
    struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
    if (!kp)
        return NULL;
    kp->symbol_name = name;
    kp->pre_handler = handler;

    ret = register_kprobe(kp);
    pr_info("sucompat: register %s kprobe: %d\n", name, ret);
    if (ret) {
        kfree(kp);
        return NULL;
    }

    return kp;
}

static void destroy_kprobe(struct kprobe **kp_ptr)
{
    struct kprobe *kp = *kp_ptr;
    if (!kp)
        return;
    unregister_kprobe(kp);
    synchronize_rcu();
    kfree(kp);
    *kp_ptr = NULL;
}

extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
                                int *mode, int *__unused_flags);
static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int *dfd = (int *)&PT_REGS_PARM1(real_regs);
    const char __user **filename_user =
        (const char **)&PT_REGS_PARM2(real_regs);
    int *mode = (int *)&PT_REGS_PARM3(real_regs);

    return ksu_handle_faccessat(dfd, filename_user, mode, NULL);
}

extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
                           int *flags);
static int newfstatat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int *dfd = (int *)&PT_REGS_PARM1(real_regs);
    const char __user **filename_user =
        (const char **)&PT_REGS_PARM2(real_regs);
    int *flags = (int *)&PT_REGS_SYSCALL_PARM4(real_regs);

    return ksu_handle_stat(dfd, filename_user, flags);
}

extern int ksu_handle_execve_sucompat(int *fd,
                                      const char __user **filename_user,
                                      void *__never_use_argv,
                                      void *__never_use_envp,
                                      int *__never_use_flags);
static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user **filename_user =
        (const char **)&PT_REGS_PARM1(real_regs);

    return ksu_handle_execve_sucompat(NULL, filename_user, NULL, NULL, NULL);
}

void kp_handle_sucompat_init(void)
{
    su_kps[0] = init_kprobe(SYS_EXECVE_SYMBOL, execve_handler_pre);
    su_kps[1] = init_kprobe(SYS_FACCESSAT_SYMBOL, faccessat_handler_pre);
    su_kps[2] = init_kprobe(SYS_NEWFSTATAT_SYMBOL, newfstatat_handler_pre);
#ifdef CONFIG_COMPAT
    su_kps[3] = init_kprobe(SYS_EXECVE_COMPAT_SYMBOL, execve_handler_pre);
    su_kps[4] = init_kprobe(SYS_FSTATAT64_SYMBOL, newfstatat_handler_pre);
#endif
}

void kp_handle_sucompat_exit(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(su_kps); i++) {
        destroy_kprobe(&su_kps[i]);
    }
}
#endif
