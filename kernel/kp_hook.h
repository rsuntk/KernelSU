#ifndef __KSU_H_KP_HOOK
#define __KSU_H_KP_HOOK

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

// ksud.c
enum ksud_stop_code {
	VFS_READ_HOOK_KP = 0,
	EXECVE_HOOK_KP,
	INPUT_EVENT_HOOK_KP,
};

int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
			     struct user_arg_ptr *argv,
			     struct user_arg_ptr *envp, int *flags);

int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			size_t *count_ptr);

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value);

void kp_handle_ksud_stop(enum ksud_stop_code);
void kp_handle_ksud_init(void);
void kp_handle_ksud_exit(void);

// supercalls.c
void kp_handle_supercalls_init(void);
void kp_handler_supercalls_exit(void);

#endif
