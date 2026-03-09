#include <linux/task_work.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>

#include "kprobes.h"
#include "arch.h"

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
    long ret;
    unsigned long addr;
    const char __user *fn;

    if (!filename_user)
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, fn, 32);
    if (ret < 0 && try_set_access_flag(addr)) {
        ret = strncpy_from_user_nofault(path, fn, 32);
    }
    if (ret < 0) {
        pr_err("Access filename failed for execve_handler_pre\n");
        return 0;
    }
    filename_in.name = path;

    filename_p = &filename_in;
    return ksu_handle_execveat_ksud((int *)AT_FDCWD, &filename_p, &argv, NULL,
                                    NULL);
}
static KSU_KPROBE(execve_kp, SYS_EXECVE_SYMBOL, sys_execve_handler_pre);

extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
                               size_t *count_ptr);
static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    unsigned int fd = PT_REGS_PARM1(real_regs);

    ksu_handle_sys_read(fd, NULL, NULL);
    return 0;
}
static KSU_KPROBE(sys_read_kp, SYS_READ_SYMBOL, sys_read_handler_pre);

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
static KSU_KRETPROBE(sys_fstat_kp, SYS_FSTAT_SYMBOL, sys_fstat_handler_pre,
                     sys_fstat_handler_post, sizeof(void *));

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
static KSU_KPROBE(input_event_kp, "input_event",
                  input_handle_event_handler_pre);

static struct ksu_kp_desc ksu_probes[] = {
    [KSU_KP_ENUM_MEMBER(INIT_RC)] = { .kp = &sys_read_kp,
                                      .rp = &sys_fstat_kp,
                                      .name = "init_rc" },
    [KSU_KP_ENUM_MEMBER(EXECVE)] = { .kp = &execve_kp, .name = "execve" },
    [KSU_KP_ENUM_MEMBER(INPUT_EVENT)] = { .kp = &input_event_kp,
                                          .name = "input_event" },
};

static void do_stop_probe_work(struct work_struct *work)
{
    struct ksu_kp_desc *desc =
        container_of(work, struct ksu_kp_desc, stop_work);

    if (unlikely(!desc))
        return;

    if (desc->rp) {
        unregister_kretprobe(desc->rp);
        pr_info("ksud: %s kretprobe unregistered.\n", desc->name);
    }

    if (desc->kp) {
        unregister_kprobe(desc->kp);
        pr_info("ksud: %s kprobe unregistered.\n", desc->name);
    }
}

void kp_handle_ksud_stop(enum ksud_stop_code stop_code)
{
    int ret;
    if (stop_code > ARRAY_SIZE(ksu_probes))
        return;
    if (!ksu_probes[stop_code].name)
        return;

    ret = schedule_work(&ksu_probes[stop_code].stop_work);
    if (ret) {
        pr_info("ksud: unregister %s kprobe, ret: %d\n",
                ksu_probes[stop_code].name, ret);
    }
}

void kp_handle_ksud_init(void)
{
    int i, ret;
    struct ksu_kp_desc *desc;

    for (i = 0; i < ARRAY_SIZE(ksu_probes); i++) {
        desc = &ksu_probes[i];
        if (!desc->name)
            continue;

        // Init workqueue
        INIT_WORK(&desc->stop_work, do_stop_probe_work);

        ret = (desc->rp) ? register_kretprobe(desc->rp) :
                           register_kprobe(desc->kp);
        pr_info("ksud: %s_kp registration: %d\n", desc->name, ret);
    }
}

void kp_handle_ksud_exit(void)
{
    int i;
    struct ksu_kp_desc *desc;

    for (i = 0; i < ARRAY_SIZE(ksu_probes); i++) {
        desc = &ksu_probes[i];
        if (!desc->name)
            continue;

        if (desc->rp)
            unregister_kretprobe(desc->rp);
        if (desc->kp)
            unregister_kprobe(desc->kp);
    }
}
