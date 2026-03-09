#ifndef __KSU_H_KPROBES_H
#define __KSU_H_KPROBES_H

#ifdef CONFIG_KSU_KPROBES

#include <linux/kprobes.h>
#include <linux/workqueue.h>

#define KSU_KP_ENUM_MEMBER(name) KSU_##name##_KP_HANDLER

enum ksud_kp_stop {
    KSU_KP_ENUM_MEMBER(INIT_RC),
    KSU_KP_ENUM_MEMBER(EXECVE),
    KSU_KP_ENUM_MEMBER(INPUT_EVENT),
    KSU_KP_HANDLER_MAX,
};

struct ksu_kp_desc {
    struct kprobe *kp;
    struct kretprobe *rp;
    const char *name;
    struct work_struct stop_work;
};

#endif /* CONFIG_KSU_KPROBES */

#endif
