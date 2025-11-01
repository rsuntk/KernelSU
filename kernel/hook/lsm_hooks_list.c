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
// k4.2 ~ 6.7, LSM Hijacking, pure function pointer edition.
extern struct security_hook_heads security_hook_heads;

static int (*task_fix_setuid_fn)(struct cred *new, const struct cred *old, int flags) __read_mostly = nullptr;
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return task_fix_setuid_fn(new, old, flags);
}

static int (*inode_rename_fn)(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry) __read_mostly = nullptr;
static __nocfi int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return inode_rename_fn(old_inode, old_dentry, new_inode, new_dentry);
}

/**
 *
 * Instead of using list/hlist abstractions and shit, since we know these things exist
 * we can just pointerwalk and walk away like its nothing.
 *
 * this should work as the first member of both list_head and hlist_head are just *
 *
 * struct list_head { struct list_head *next, *prev; };
 * struct hlist_head { struct hlist_node *first; }; / struct hlist_node { struct hlist_node *next, **pprev; };
 *
 * variant 1: 4.3 ~ 4.10
 * struct security_hook_list {
 *	struct list_head		list;	// 2 uintptr
 *	struct list_head		*head;
 *	union security_list_options	hook;	// 1 uintptr
 * };
 *
 * variant 2: 4.11 - 4.17
 * struct security_hook_list {
 *	struct list_head		list;
 * 	struct list_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 * variant 3: 4.17+, normally backported to 4.14
 * struct security_hook_list {
 * 	struct hlist_node		list;
 * 	struct hlist_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 */
static int ksu_hack_lsm_slot(void *hook_head, uintptr_t *old_ptr, uintptr_t new_ptr, const char *hook_name)
{
	if (!hook_head || !*(void **)hook_head)
		return 1;

	static_assert(sizeof(struct security_hook_list) >= 4 * sizeof(uintptr_t));
	static_assert(offsetof(struct security_hook_list, hook) == 3 * sizeof(uintptr_t));

	// technincally next/first
	uintptr_t node = *(uintptr_t *)hook_head;
	uintptr_t hook_slot_addr = node + 3 * sizeof(uintptr_t);

	uintptr_t current_hook = *(uintptr_t *)hook_slot_addr;
	if (!current_hook) {
		pr_info("LSM: No LSM hook on slot\n");
		return 1;
	}

#if defined(CONFIG_KALLSYMS) // kallsyms strstr check
	char symbuf[KSYM_NAME_LEN];
	sprint_symbol_no_offset(symbuf, current_hook);
	if (!strstr(symbuf, hook_name)) {
		pr_info("LSM: expected: %s on 0x%lx mismatches ksym: %s\n", hook_name, current_hook, symbuf);
		return 2;
	}
	pr_info("LSM: expected: %s on 0x%lx matches ksym: %s\n", hook_name, current_hook, symbuf);
#endif

	// *old_ptr = current_hook;
	patch_ptr_slot_kick_cpu((void **)old_ptr, (void *)current_hook);

	if (sizeof(struct security_hook_list) == 5 * sizeof(uintptr_t))
		pr_info("LSM: 0x%lx found at 0x%lx slot, name: %s \n", current_hook, hook_slot_addr, *(char **)(node + 4 * sizeof(uintptr_t)));
	else
		pr_info("LSM: 0x%lx found at slot 0x%lx\n", current_hook, hook_slot_addr);

	int err = patch_ro_slot(hook_slot_addr, new_ptr);
	if (err)
		return 1;

	pr_info("LSM: 0x%lx written to slot\n", new_ptr);
	return 0;
}

#if defined(CONFIG_KALLSYMS)
static void ksu_bruteforce_lsm_slot(uintptr_t *old_ptr, uintptr_t new_ptr, const char *hook_name)
{
	// context: https://github.com/PhoenixKernel/linux-staging/commit/63074fbdb6971ec43f39934b96f4b475eedcaf7e
	extern struct security_hook_heads security_hook_heads;

	uintptr_t *heads_arr = (uintptr_t *)&security_hook_heads;
	constexpr size_t compiled_size = sizeof(security_hook_heads);

	unsigned int total_slots = ksu_get_ksym_size((uintptr_t *)&security_hook_heads, compiled_size) / sizeof(uintptr_t);
	pr_info("LSM: slots: const: %u / live: %u addr: 0x%lx\n", compiled_size/sizeof(uintptr_t),  total_slots, heads_arr);

	uintptr_t first_node = 0;
	uintptr_t current_hook_fn = 0;
	unsigned int i = 0;

start_scan:
	if (!!copy_from_kernel_nofault(&first_node, &heads_arr[i], sizeof(first_node)))
		goto increment;

	if (!first_node)
		goto increment;

	uintptr_t hook_slot_addr = first_node + (3 * sizeof(uintptr_t));
	if (!!copy_from_kernel_nofault(&current_hook_fn, (void *)hook_slot_addr, sizeof(current_hook_fn)))
		goto increment;

	if (!current_hook_fn)
		goto increment;

	char symbuf[KSYM_NAME_LEN];
	sprint_symbol_no_offset(symbuf, current_hook_fn);
	if (!strstr(symbuf, hook_name))
		goto increment;
	
	pr_info("LSM: tries: %u expected: %s found on 0x%lx matches ksym: %s\n", i, hook_name, current_hook_fn, symbuf);
	ksu_hack_lsm_slot(&heads_arr[i], old_ptr, new_ptr, hook_name);
	return;

increment:
	i++;
	if (total_slots > i)
		goto start_scan;
}
#else
#define ksu_bruteforce_lsm_slot(...) do { } while (0)
#endif

#define LSM_HACK_INIT(hook_name, hook_fn)							\
do {												\
	pr_info("LSM: Initializing hook for %s -> %s\n", #hook_name, #hook_fn);			\
	void *hook_head = (void *)&security_hook_heads.hook_name;				\
	uintptr_t *old_ptr = (uintptr_t *)&hook_name##_fn; /* storage, fnp */			\
	int ret = ksu_hack_lsm_slot(hook_head, old_ptr, (uintptr_t)(hook_fn), #hook_name);	\
	if (ret == 2)										\
		ksu_bruteforce_lsm_slot(old_ptr, (uintptr_t)(hook_fn), #hook_name);		\
} while (0)

#define LSM_HACK_RESTORE(hook_name)								\
do {												\
	if (!hook_name##_fn)									\
		break;										\
	uintptr_t __dummy; /* dummy storage */							\
	pr_info("LSM: Restoring original hook for %s\n", #hook_name);				\
	void *hook_head = (void *)&security_hook_heads.hook_name;				\
	int r = ksu_hack_lsm_slot(hook_head, &__dummy, (uintptr_t)hook_name##_fn, #hook_name);	\
	if (r == 2)										\
		ksu_bruteforce_lsm_slot(&__dummy, (uintptr_t)hook_name##_fn, #hook_name);	\
} while (0)


static __init void ksu_lsm_hook_init(void)
{
	LSM_HACK_INIT(task_fix_setuid, ksu_task_fix_setuid);
	LSM_HACK_INIT(inode_rename, ksu_inode_rename);
}
