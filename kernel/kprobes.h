#ifndef __KSU_H_KPROBES_H
#define __KSU_H_KPROBES_H

enum ksud_stop_code {
    KSU_INIT_RC_KP_HANDLER,
    KSU_EXECVE_KP_HANDLER,
    KSU_INPUT_EVENT_KP_HANDLER,
    KSU_KP_HANDLER_MAX,
};

#ifdef CONFIG_KSU_KPROBES

void kp_handle_ksud_stop(enum ksud_stop_code stop_code);

void kp_handle_ksud_init(void);
void kp_handle_supercalls_init(void);
void kp_handle_sucompat_init(void);

void kp_handle_ksud_exit(void);
void kp_handle_supercalls_exit(void);
void kp_handle_sucompat_exit(void);

#endif /* CONFIG_KSU_KPROBES */

#endif
