#ifndef __KSU_H_KPROBES_H
#define __KSU_H_KPROBES_H

#ifdef CONFIG_KSU_KPROBES

#define KSU_KP_ENUM_MEMBER(name) KSU_##name##_KP_HANDLER

enum ksud_kp_stop {
    KSU_KP_ENUM_MEMBER(INIT_RC),
    KSU_KP_ENUM_MEMBER(EXECVE),
    KSU_KP_ENUM_MEMBER(INPUT_EVENT),
    KSU_KP_HANDLER_MAX,
};

void kp_handle_ksud_stop(enum ksud_kp_stop stop_code);

void kp_handle_ksud_init(void);
void kp_handle_supercalls_init(void);
void kp_handle_sucompat_init(void);

void kp_handle_ksud_exit(void);
void kp_handle_supercalls_exit(void);
void kp_handle_sucompat_exit(void);

#endif /* CONFIG_KSU_KPROBES */

#endif
