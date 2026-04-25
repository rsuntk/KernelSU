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

// selinux_ops (LSM), security_operations struct tampering for ultra legacy

static uintptr_t selinux_ops_addr = 0x0;

static int (*orig_inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry) __read_mostly = nullptr;
static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return orig_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static int (*orig_task_fix_setuid) (struct cred *new, const struct cred *old, int flags) __read_mostly = nullptr;
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	return orig_task_fix_setuid(new, old, flags);
}

static __nocfi bool verify_selinux_cred_free(void *fn_ptr)
{
	if (!fn_ptr)
		return false;

	// ref: https://elixir.bootlin.com/linux/v3.18.140/source/security/selinux/hooks.c#L3474
	void (*selinux_cred_free_fn)(struct cred *) = fn_ptr;

	struct cred dummy_cred;

	// explicitly set it to NULL
	// make sure this happens!
	// #1. it wont trigger BUG_ON
	// #2. this way it will kfree(NULL), which does nothing
	*(void **)&dummy_cred.security = nullptr;
	barrier();

	selinux_cred_free_fn(&dummy_cred);

	// check if selinux_cred_free is successful
	if ((unsigned long)*(void **)&dummy_cred.security != 0x7UL)
		return false;

	pr_info("LSM: found: selinux_cred_free @ 0x%lx cred->security: 0x%lx\n", (uintptr_t)fn_ptr, (unsigned long)dummy_cred.security);
	return true;
}

// we should see a lot of pointers that is inside stext && etext
// basically we check for "pointer density"
static bool is_selinux_ops_valid(uintptr_t addr)
{
	extern char _stext[], _etext[];
	int total_slots = sizeof(struct security_operations) / sizeof(void *); 
	int valid_ptr = 0;
	int i = 0;

	uintptr_t member_ptr = 0;
	uintptr_t current_slot_addr;

	// we will be off by two or three due to sizeof(security_operations.name)
	// thats 11 bytes, on 32 bit, this is three pointers worth, not a big deal

density_verify_start:
	current_slot_addr = addr + (i * sizeof(void *));

	member_ptr = 0;
	if (copy_from_kernel_nofault(&member_ptr, (void *)current_slot_addr, sizeof(uintptr_t) ))
		goto next_iter; // if it fails, just try next slot

	// give up early
	if (!valid_ptr && i >= 20)
		return false;

	if (member_ptr >= (uintptr_t)_stext && member_ptr <= (uintptr_t)_etext)
		valid_ptr++;

next_iter:
	i++;	
	if (i < total_slots)
		goto density_verify_start;

	pr_info("LSM: density: valid: %lu slots: %lu \n", valid_ptr, total_slots);

	// maybe increase to 75% or something?
	return (valid_ptr > (total_slots / 2));
}

static bool check_candidate(uintptr_t addr)
{
	struct security_operations *candidate = (struct security_operations *)addr;

	char char_buf[sizeof("selinux")];
	if (copy_from_kernel_nofault(char_buf, (void *)addr, sizeof("selinux") ))
		return false;

	if (!!memcmp_inline(char_buf, "selinux", sizeof("selinux")))
		return false;

	// candidate found!
	pr_info("LSM: candidate: selinux_ops at 0x%lx\n", (uintptr_t)addr);

	// check ptr density	
	if (!is_selinux_ops_valid(addr))
		return false;

	if (!candidate->cred_free)
		return false;

#if 0 // def CONFIG_KALLSYMS // not always available, but it wont hurt to try.
	uintptr_t ksym_ptr = (uintptr_t)kallsyms_lookup_name("selinux_cred_free");
	if (unlikely(ksym_ptr != (uintptr_t)candidate->cred_free))
		goto test_fn;

	pr_info("LSM: found: selinux_cred_free: 0x%lx probe: 0x%lx \n", (uintptr_t)ksym_ptr, (uintptr_t)candidate->cred_free);
	return true;
test_fn:
#endif
	// oh yeah I am so confident that this is it, we might as well show off.
	pr_info("LSM: candidate: selinux_cred_free @ 0x%lx\n", (uintptr_t)candidate->cred_free);
	return verify_selinux_cred_free((void *)candidate->cred_free);
}

/** 
 * we do this in blocks of sequential 10k pointers.
 * 10k pointers up, 10k pointers down
 * this is predictable, more cache friendly, no trashing.
 *
 * one up, one down oscillating scan isn't as friendly to teh cahce.
 * once ptrdiff of up vs down is larger than L1, it will be trashy.
 *
 */
static void *do_hunt_for_selinux_ops(void *heuristic_ptr, const char *anchor_name)
{
	uintptr_t anchor = (uintptr_t)heuristic_ptr;
	uintptr_t curr;
	unsigned long iter_count = 0;
	unsigned long max_index = 10000; // max number of pointers to test, one way
	unsigned long i = 0;

	uintptr_t start = anchor - max_index * sizeof(void *);
	uintptr_t end = anchor + max_index * sizeof(void *);

	pr_info("LSM: scan: anchor: %s @ 0x%lx\n", anchor_name, anchor);
	pr_info("LSM: scan: range: 0x%lx - 0x%lx\n", start, end);

scan_up:
	if (i >= max_index) {
		i = 1;
		goto scan_down;
	}

	curr = anchor + (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_up;

scan_down:
	if (i >= max_index)
		goto not_found;

	curr = anchor - (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_down;

found:
	pr_info("LSM: found: selinux_ops at 0x%lx! iterations: %lu \n", curr, iter_count);
	return (void *)curr;

not_found:
	pr_info("LSM: selinux_ops not found in range! iterations: %lu \n", iter_count);
	return nullptr;
}
#define hunt_for_selinux_ops(ptr) ({ do_hunt_for_selinux_ops((void *)ptr, #ptr); })

static void set_selinux_ops()
{
	extern int selinux_enabled;
	extern struct security_class_mapping secclass_map[];
	extern struct list_head crypto_alg_list;
	extern unsigned int avc_cache_threshold;
	
	struct security_operations *ops = nullptr;

	// if user exports selinux_ops, we just go for it!
	extern struct security_operations selinux_ops __weak;
	if (!!&selinux_ops) {
		pr_info("LSM: exported selinux_ops: 0x%lx \n", (uintptr_t)&selinux_ops);
		ops = (struct security_operations *)&selinux_ops;
	}

#ifdef CONFIG_KEYS
	extern struct key_user root_key_user;
	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops(&root_key_user);
#endif

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops(&avc_cache_threshold);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops(&crypto_alg_list);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops(&selinux_enabled);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops(&secclass_map);

	if (!ops)
		return;

	selinux_ops_addr = (uintptr_t)ops;	
}

#ifdef CONFIG_KALLSYMS
static void print_lsm_symbol(uintptr_t sym1, uintptr_t sym2)
{
	char buf1[KSYM_NAME_LEN] = "(undefined)";
	char buf2[KSYM_NAME_LEN] = "(undefined)";
	sprint_symbol_no_offset(buf1, sym1);
	sprint_symbol_no_offset(buf2, sym2);
	pr_info("LSM: exchange: %s with hook: %s \n", buf1, buf2);
}
#else
#define print_lsm_symbol(...)	do { } while (0)
#endif

#define LSM_HACK_INIT(lsm_name, hook_fn)							\
do {												\
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;	\
	if (!ops) break;									\
	pr_info("LSM: Initializing hook for %s -> %s\n", #lsm_name, #hook_fn);			\
	patch_ptr_slot_kick_cpu((void **)&orig_##lsm_name, (void *)ops->lsm_name);		\
	pr_info("LSM: %s: slot: 0x%lx hook: 0x%lx\n", 						\
		#lsm_name, (uintptr_t)&ops->lsm_name, (uintptr_t)ops->lsm_name);		\
	print_lsm_symbol((uintptr_t)ops->lsm_name, (uintptr_t)hook_fn);				\
	int ret = patch_ro_slot((uintptr_t)&ops->lsm_name, (uintptr_t)hook_fn);			\
	pr_info("LSM: %s: slot: 0x%lx hook: 0x%lx ret: %d\n", 					\
		#lsm_name, (uintptr_t)&ops->lsm_name, (uintptr_t)ops->lsm_name, ret);		\
} while (0)

#define LSM_HACK_RESTORE(lsm_name)								\
do {												\
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;	\
	if (!ops || !orig_##lsm_name) break;							\
	pr_info("LSM: Restoring hook for %s\n", #lsm_name);					\
	pr_info("LSM: %s: slot: 0x%lx hook: 0x%lx\n", 						\
		#lsm_name, (uintptr_t)&ops->lsm_name, (uintptr_t)ops->lsm_name);		\
	print_lsm_symbol((uintptr_t)ops->lsm_name, (uintptr_t)orig_##lsm_name);			\
	int ret = patch_ro_slot((uintptr_t)&ops->lsm_name, (uintptr_t)orig_##lsm_name);		\
	pr_info("LSM: %s: slot: 0x%lx hook: 0x%lx ret: %d\n", 					\
		#lsm_name, (uintptr_t)&ops->lsm_name, (uintptr_t)ops->lsm_name, ret);		\
} while (0)

static inline void ksu_register_lsm_hook(void)
{
	LSM_HACK_INIT(task_fix_setuid, ksu_task_fix_setuid);
	LSM_HACK_INIT(inode_rename, ksu_inode_rename);
}

static void __init ksu_lsm_hook_init(void)
{
	set_selinux_ops();

	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!ops)
		return;

	if (!!memcmp_inline(ops, "selinux", sizeof("selinux")))
		return;

	pr_info("LSM: selinux_ops: 0x%lx .name = %s\n", (long)ops, (const char *)ops );
	ksu_register_lsm_hook();

	return;
}
