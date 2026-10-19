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
// adapted from: https://github.com/tiann/KernelSU/pull/3907
#define INIT_PATH "/system/bin/init"

static bool ksu_preinit_enabled = true;
module_param_named(preinit, ksu_preinit_enabled, bool, 0);

static bool is_selinux_setup(const char __user *const __user *argv_user)
{
	static const char expected[] = "selinux_setup";
	const char __user *arg;
	char buf[sizeof(expected) + 1];

	if (!argv_user)
		return false;

	if (is_compat_task()) {
		uint32_t __user *compat_argv_user = (uint32_t __user *)argv_user;
		uint32_t arg32_p;
		if (get_user(arg32_p, compat_argv_user + 1))
			return false;
		arg = (void *)(uintptr_t)arg32_p;
	} else {
		if (get_user(arg, argv_user + 1))
			return false;
	}

	if (!arg)
		return false;

	memset(buf, 0, sizeof(buf));
	if (strncpy_from_user(buf, arg, sizeof(buf) - 1) < 0)
		return false;

	return !strcmp(buf, expected);
}

static void ksu_stage_preinit_binary(void ***u_argv, void ***u_envp)
{
	struct file *file;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, EMPTY_VMA_FLAGS);
#else
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, 0);
#endif
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return;
	}

	loff_t pos = 0;
	int ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return;
	}

	pr_info("preinit: runner staged (%zu bytes)\n", runner_binary_len);

	int fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return;
	}

	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);

	char fd_path[32];
	int len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return;
	}
	path_put(&p);

	uintptr_t mmap_page = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(mmap_page)) {
		pr_info("preinit: mmap fail!\n");
		ksu_close_fd(fd);
		return;
	}

	pr_info("preinit: mmap_page: 0x%lx \n", mmap_page);

	if (!!copy_to_user((void *)mmap_page, fd_path, sizeof(fd_path)))
		goto unmap_and_close;

	void __user *argv = (void __user *)(const char __user **)*(void ***)u_argv;
	void __user *envp = (void __user *)(const char __user **)*(void ***)u_envp;
	void __user *filename = (void __user *)(const char __user *)mmap_page;

	if (likely(!is_compat_task())) 
		goto ksyscall_exec;

	pr_info("preinit: compat init detected! \n");

	// now extend the pointers
	uintptr_t *m_argv = (uintptr_t *)(mmap_page + 1024);
	uintptr_t *m_envp = (uintptr_t *)(mmap_page + 2048);

	uint32_t buf4;
	uint32_t __user *c_ptr = (uint32_t __user *)argv;
	int i = 0;

	while (i < 127 && !get_user(buf4, &c_ptr[i]) && !!buf4) {
		uintptr_t buf8 = (uintptr_t)buf4;
		if (!!put_user(buf8, &m_argv[i]))
			break;
		i++;
	}

	// reset
	buf4 = 0;
	i = 0;
	c_ptr = (uint32_t __user *)envp;

	while (i < 127 && !get_user(buf4, &c_ptr[i]) && !!buf4) {
		uintptr_t buf8 = (uintptr_t)buf4;
		if (!!put_user(buf8, &m_envp[i]))
			break;
		i++;
	}

	argv = (char __user **)m_argv;
	envp = (char __user **)m_envp;

ksyscall_exec:;
	ret = (int)ksyscall(execve, filename, argv, envp);
	pr_info("preinit: ksyscall(execve, 0x%lx, 0x%lx, 0x%lx); ret: %d\n", (uintptr_t)filename, (uintptr_t)argv, (uintptr_t)envp, ret);
	if (!ret)
		return;

unmap_and_close: // not rly needed, but its ok.
	ksyscall(munmap, mmap_page, PAGE_SIZE);
	ksu_close_fd(fd);
	return;
}

// filename_kernel is char **, filename_user is void * char __user *
static noinline void do_ksu_preinit_execve(void **filename_kernel, const char __user **filename_user, void *u_argv, void *u_envp)
{
	if (!current->mm || current->pid != 1)
		return;

	if (!filename_kernel && !filename_user)
		return;

	constexpr char expected[] = INIT_PATH;
	
	if (filename_kernel) {
		assume_dereferenceable(*filename_kernel, 32);
		if (!!memcmp_inline(*(char **)filename_kernel, expected, sizeof(expected)))
			return;

		pr_info("preinit: kernel_execve: %s \n", INIT_PATH);	
		if (!is_selinux_setup((const char __user **)*(void ***)u_argv))
			return;

		pr_info("preinit: kernel_execve: /system/bin/init with selinux_setup! \n");

		kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");
	} else {
		char buf[sizeof(expected) + 1];
		buf[sizeof(buf) - 1] = 0;
		if (!!copy_from_user(buf, *filename_user, sizeof(buf) - 1 ))
			return;

		if (!!strcmp(buf, expected))
			return;

		pr_info("preinit: sys_execve: %s \n", INIT_PATH);
		if (!is_selinux_setup((const char __user **)*(void ***)u_argv))
			return;

		pr_info("preinit: sys_execve: %s with selinux_setup! \n", INIT_PATH);
	}

	kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");

	ksu_stage_preinit_binary((void ***)u_argv, (void ***)u_envp);
}

static inline void ksu_preinit_execve(void **filename_kernel, const char __user **filename_user, void *u_argv, void *u_envp)
{
	if (static_branch_unlikely(&ksu_preinit_key))
		do_ksu_preinit_execve(filename_kernel, filename_user, u_argv, u_envp);
}

void ksu_preinit_release(void) { }

void ksu_preinit_init(void)
{
	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled!\n");
		return;
	}
	
	static_branch_enable(&ksu_preinit_key);
	kick_all_cpus_sync();
	pr_info("preinit: enabled!\n");
	return;
}

void ksu_preinit_exit(void) { }
