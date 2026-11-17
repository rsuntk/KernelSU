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

// selinux hide, arm64 only, mostly handlers. thas has random callbacks around

// callbacks
static void ksu_init_hook_transaction_ops_write(void);
static void ksu_init_hook_sel_handle_status_ops_open(void);

static void ksu_decide_inode_setxattr(bool sh_hooked);
static void ksu_decide_setprocattr(bool sh_hooked);
static bool ksu_selinux_hide_enabled __read_mostly;
static struct page *ksu_fake_status_page __read_mostly;

#if defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS)

// flag to check
#define KSU_HAS_ARM64_SELINUX_HIDE

#define __ksym_size(callsite)	ksu_get_ksym_size(callsite, (256 * sizeof(uint32_t)))
#define patch_arm64_branches_trampolined(callsite, symbol_addr, hook)	\
	arm64_branch_patch_trampolined(callsite, __ksym_size(callsite), symbol_addr, (uintptr_t)hook, true)

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
__attribute__((used)) struct page *sh_selinux_kernel_status_page(struct selinux_state *state)
#else
__attribute__((used)) struct page *sh_selinux_kernel_status_page(void)
#endif
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto orig_page;

	if (!ksu_is_seccomp_enabled())
		goto orig_page;

	if (current_uid().val < 10000)
		goto orig_page;

	assume(!!ksu_fake_status_page);
	if (unlikely(!ksu_fake_status_page))
		goto orig_page;

	pr_info_ratelimited("selinux_hide: selinux_kernel_status_page: served fake_page\n");
	return ksu_fake_status_page;

orig_page:
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
	return selinux_kernel_status_page(&selinux_state);
#else
	return selinux_kernel_status_page();
#endif
}

static void patch_branch_sel_open_handle_status(void)
{
	uintptr_t target_callsite = kallsyms_lookup_retry("sel_open_handle_status");
	uintptr_t symbol_addr = kallsyms_lookup_retry("selinux_kernel_status_page");
	if (!symbol_addr || !target_callsite)
		goto hook_classic;

	int ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_selinux_kernel_status_page);
	pr_info("selinux_hide: hook_site: sel_open_handle_status->selinux_kernel_status_page ret: %d \n", ret);
	if (!ret)
		return;
hook_classic:
	pr_info("selinux_hide: fallback to function pointer hook!\n");
	ksu_init_hook_sel_handle_status_ops_open();
}

static char *sh_simple_transaction_get(struct file *file, const char __user *buf, size_t size)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto skip_destroy;

	if (!ksu_is_seccomp_enabled())
		goto skip_destroy;

	if (current_uid().val < 10000)
		goto skip_destroy;

#define SEL_CONTEXT 5
#define SEL_ACCESS 6
	ino_t ino = file_inode(file)->i_ino;

	char *data = simple_transaction_get(file, buf, size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	if (ino == SEL_CONTEXT && ksu_should_destroy_context(data, size, true)) {
		pr_info_ratelimited("selinux_hide: simple_transaction_get: context: destroy: %s \n", data);
		do_useless_alloc(size);
		do_useless_alloc(size);
		do_useless_alloc(size);
		return ERR_PTR(-EINVAL);

//		replace_after_second_colon(data, size);
//		do_useless_alloc(size);
	}

	if (ino == SEL_ACCESS && ksu_should_destroy_context(data, size, false)) {
		pr_info("selinux_hide: simple_transaction_get: access: destroy: %s \n", data);
		do_useless_alloc(size);
		do_useless_alloc(size);
		do_useless_alloc(size);
		return ERR_PTR(-EINVAL);

//		replace_after_second_colon(data, size);
//		do_useless_alloc(size);
	}
	return data;

skip_destroy:;
	return simple_transaction_get(file, buf, size);
}

#if 0
static void sh_simple_transaction_set(struct file *file, size_t n)
{
	simple_transaction_set(file, n);

	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	if (!ksu_is_seccomp_enabled())
		return;

	if (current_uid().val < 10000)
		return;

	ino_t ino = file_inode(file)->i_ino;
	if (ino != SEL_ACCESS)
		return;

	// simple_transaction_get()
	struct simple_transaction_argresp *ar = file->private_data;
	if (!ar)
		return;

	uint32_t avd_allowed, ff, avd_auditallow, avd_auditdeny, avd_seqno, avd_flags;
	if (sscanf(ar->data, "%x %x %x %x %u %x", &avd_allowed, &ff, &avd_auditallow, &avd_auditdeny, &avd_seqno, &avd_flags) != 6)
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("ar->data: before: %s \n", ar->data);

	avd_seqno = 1; // simple_transaction_set()
	ar->size = scnprintf(ar->data, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd_allowed, ff, avd_auditallow, avd_auditdeny, avd_seqno, avd_flags);

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("ar->data: after: %s \n", ar->data);
}
#endif // 0

static inline void sh_swap_seqno(struct av_decision *avd)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;
	if (!ksu_is_seccomp_enabled())
		return;
	if (current_uid().val < 10000)
		return;
	if (!avd)
		return;
	avd->seqno = 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
static void sh_security_compute_av_user(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
	security_compute_av_user(state, ssid, tsid, tclass, avd);
	sh_swap_seqno(avd);
}
#else
static void sh_security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
	security_compute_av_user(ssid, tsid, tclass, avd);
	sh_swap_seqno(avd);
}
#endif

static void patch_branches_selinux_transaction_write(void)
{
	uintptr_t target_callsite = kallsyms_lookup_retry("selinux_transaction_write");
	uintptr_t symbol_addr = kallsyms_lookup_retry("simple_transaction_get");
	if (!symbol_addr || !target_callsite)
		goto hook_classic;

	uintptr_t trampoline = 0x0;
	int ret = arm64_branch_patch_trampolined_reusable(&trampoline, target_callsite, symbol_addr, (uintptr_t)&sh_simple_transaction_get);
	pr_info("selinux_hide: hook_site: selinux_transaction_write->simple_transaction_get ret: %d \n", ret);
	if (ret)
		goto hook_classic;

#if 0
	symbol_addr = kallsyms_lookup_retry("simple_transaction_set");
	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_simple_transaction_set);
	pr_info("selinux_hide: hook_site: selinux_transaction_write->simple_transaction_set ret: %d \n", ret);
	if (!ret)
		return;

	/**
	 * on LTO + CONFIG_MODULES=n this can fail. (EXPORT_SYMBOL becomes useless, compiler inlines simple_transaction_set)
	 * 
	 * inline, melted.
	 * ffffff80104ea128: f100041f     	cmp	x0, #0x1
	 * ffffff80104ea12c: 54fffdab     	b.lt	0xffffff80104ea0e0 <selinux_transaction_write+0x30>
	 * ffffff80104ea130: f13fe41f     	cmp	x0, #0xff9
	 * ffffff80104ea134: 540000c2     	b.hs	0xffffff80104ea14c <selinux_transaction_write+0x9c>
	 * ffffff80104ea138: f9406688     	ldr	x8, [x20, #0xc8]	// ar = file->private_data; 
	 * ffffff80104ea13c: d5033bbf     	dmb	ish			// smp_mb()
	 * ffffff80104ea140: f9000100     	str	x0, [x8]		// ar->size = n;
	 * ffffff80104ea144: aa1303e0     	mov	x0, x19
	 * ffffff80104ea148: 17ffffe6     	b	0xffffff80104ea0e0 <selinux_transaction_write+0x30>
	 * ffffff80104ea14c: d4210000     	brk	#0x800 			// BUG_ON()
	 * ffffff80104ea150: 14000000     	b	0xffffff80104ea150 <selinux_transaction_write+0xa0>
	 *
	 * non-inlined here, as normal.
	 * ffffff8010470194: f100041f     	cmp	x0, #0x1
	 * ffffff8010470198: 540000ab     	b.lt	0xffffff80104701ac <selinux_transaction_write+0x8c>
	 * ffffff801047019c: aa1403e0     	mov	x0, x20
	 * ffffff80104701a0: 97f8d990     	bl	0xffffff80102a67e0 <simple_transaction_set>
	 *
	 * however lets be opportunistic here, we keep the code, maybe we can get lucky
	 * so if second hook fails, we just gc the first one and fallback to fnptr
	 */
#else
	target_callsite = kallsyms_lookup_retry("sel_write_access");
	symbol_addr = kallsyms_lookup_retry("security_compute_av_user");
	if (!symbol_addr || !target_callsite)
		goto hook_classic;

	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_security_compute_av_user);
	pr_info("selinux_hide: hook_site: sel_write_access->security_compute_av_user ret: %d \n", ret);
	if (!ret)
		return;
#endif
	symbol_addr = kallsyms_lookup_retry("simple_transaction_get");
	assume(!!symbol_addr);
	if (!!trampoline)
		ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 32 * 4), trampoline, symbol_addr);
	else
		ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 32 * 4), (uintptr_t)&sh_simple_transaction_get, symbol_addr);
	pr_info("selinux_hide: unhook_site: selinux_transaction_write->transaction_get ret: %d \n", ret);
	if (ret) // uh oh, indeterminate state, just warn and limp on
		pr_info("selinux_hide: unhook_site: selinux_transaction_write->transaction_get unhook failed! indeterminate state!\n");

hook_classic:
	pr_info("selinux_hide: fallback to function pointer hook!\n");
	ksu_init_hook_transaction_ops_write();
}

static void *security_context_to_sid_core_fn __read_mostly = nullptr;
static __always_inline int should_ret_einval(const char *scontext, u32 scontext_len)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return 0;

	if (!ksu_is_seccomp_enabled())
		return 0;

	if (current_uid().val < 10000)
		return 0;

	if (!ksu_should_destroy_context(scontext, scontext_len, true))
		return 0;

	pr_info_ratelimited("selinux_hide: security_context_to_sid: destroy: %.*s\n", scontext_len, scontext);
//	replace_after_second_colon(data, size);
	do_useless_alloc(scontext_len);
	do_useless_alloc(scontext_len);
	do_useless_alloc(scontext_len);
	return -EINVAL;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
static __nocfi int sh_security_context_to_sid_core(struct selinux_state *state, const char *scontext, u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags, int force)
{
	int fret = should_ret_einval(scontext, scontext_len);
	if (fret)
		return fret;

	int ret = ((typeof (sh_security_context_to_sid_core) *)security_context_to_sid_core_fn)(state, scontext, scontext_len, sid, def_sid, gfp_flags, force);
	return ret;
}
#else
static __nocfi int sh_security_context_to_sid_core(const char *scontext, u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags, int force)
{
	int fret = should_ret_einval(scontext, scontext_len);
	if (fret)
		return fret;

	int ret = ((typeof (sh_security_context_to_sid_core) *)security_context_to_sid_core_fn)(scontext, scontext_len, sid, def_sid, gfp_flags, force);
	return ret;
}
#endif

#define SECURITY_CONTEXT_TO_SID_sstate	struct selinux_state *state, const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp
__overloaded static int sh_security_context_to_sstate(SECURITY_CONTEXT_TO_SID_sstate)
{
	int fret = should_ret_einval(scontext, scontext_len);
	if (fret)
		return fret;

	assume(!!&security_context_to_sid);
	int ret = ((typeof(sh_security_context_to_sstate) *)(void *)security_context_to_sid)(state, scontext, scontext_len, sid, gfp);
	return ret;
}

#define SECURITY_CONTEXT_TO_SID_gfp	const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp
__overloaded static int sh_security_context_to_sid_gfp(SECURITY_CONTEXT_TO_SID_gfp)
{
	int fret = should_ret_einval(scontext, scontext_len);
	if (fret)
		return fret;

	assume(!!&security_context_to_sid);
	int ret = ((typeof(sh_security_context_to_sid_gfp) *)(void *)security_context_to_sid)(scontext, scontext_len, sid, gfp);
	return ret;
}

#define SECURITY_CONTEXT_TO_SID_legacy	const char *scontext, u32 scontext_len, u32 *sid
__overloaded static int sh_security_context_to_sid_legacy(SECURITY_CONTEXT_TO_SID_legacy)
{
	int fret = should_ret_einval(scontext, scontext_len);
	if (fret)
		return fret;

	assume(!!&security_context_to_sid);
	int ret = ((typeof(sh_security_context_to_sid_legacy) *)(void *)security_context_to_sid)(scontext, scontext_len, sid);
	return ret;
}

#define sh_security_context_to_sid_overloaded _Generic(					\
(security_context_to_sid),								\
	int(*)(SECURITY_CONTEXT_TO_SID_sstate): sh_security_context_to_sstate,		\
	int(*)(SECURITY_CONTEXT_TO_SID_gfp): 	sh_security_context_to_sid_gfp,		\
	int(*)(SECURITY_CONTEXT_TO_SID_legacy): sh_security_context_to_sid_legacy	\
)

static inline int patch_branch_context_to_sid_inode_setxattr(void)
{
	uintptr_t target_callsite = kallsyms_lookup_retry("selinux_inode_setxattr");
	uintptr_t symbol_addr = kallsyms_lookup_retry("security_context_to_sid_core");
	if (!symbol_addr || !target_callsite)
		goto noncore_xattr;

	if (!security_context_to_sid_core_fn)
		security_context_to_sid_core_fn = (void *)symbol_addr;

	int ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_security_context_to_sid_core);
	pr_info("selinux_hide: hook_site: selinux_inode_setxattr->security_context_to_sid_core ret: %d \n", ret);
	if (!ret)
		goto success_xattr;
noncore_xattr:;
	target_callsite = kallsyms_lookup_retry("selinux_inode_setxattr");
	symbol_addr = kallsyms_lookup_retry("security_context_to_sid");
	if (!symbol_addr || !target_callsite)
		goto failure_xattr;

	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_security_context_to_sid_overloaded);
	pr_info("selinux_hide: hook_site: selinux_inode_setxattr->security_context_to_sid ret: %d \n", ret);
	if (ret)
		goto failure_xattr;
success_xattr:
	ksu_decide_inode_setxattr(true);
	return ret;

failure_xattr:
	ksu_decide_inode_setxattr(false);
	return ret;
}

static inline int patch_branch_context_to_sid_procattr(void)
{
	uintptr_t target_callsite = 0x0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	if (!target_callsite) 
		target_callsite = kallsyms_lookup_retry("selinux_lsm_setattr", lookup_noscan);
#endif
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("selinux_setprocattr");
	uintptr_t symbol_addr = kallsyms_lookup_retry("security_context_to_sid_core");
	if (!symbol_addr || !target_callsite)
		goto noncore_procattr;

	if (!security_context_to_sid_core_fn)
		security_context_to_sid_core_fn = (void *)symbol_addr;

	int ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_security_context_to_sid_core);
	pr_info("selinux_hide: hook_site: selinux_setprocattr->security_context_to_sid_core ret: %d \n", ret);
	if (!ret)
		goto success_procattr;
noncore_procattr:;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("selinux_lsm_setattr", lookup_noscan);
#endif
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("selinux_setprocattr");
	symbol_addr = kallsyms_lookup_retry("security_context_to_sid");
	if (!symbol_addr || !target_callsite)
		goto failure_procattr;

	ret = patch_arm64_branches_trampolined(target_callsite, symbol_addr, (uintptr_t)&sh_security_context_to_sid_overloaded);
	pr_info("selinux_hide: hook_site: selinux_setprocattr->security_context_to_sid ret: %d \n", ret);
	if (ret)
		goto failure_procattr;
success_procattr:
	ksu_decide_setprocattr(true);
	return ret;
failure_procattr:
	ksu_decide_setprocattr(false);
	return ret;
}

static inline int patch_branch_context_to_sid(void)
{
	patch_branch_context_to_sid_inode_setxattr();
	patch_branch_context_to_sid_procattr();
	return 0;
}

static inline void init_arm64_selinux_hide(void)
{
	pr_info("selinux_hide: init aarch64 dedicated implementation! \n");
	patch_branch_sel_open_handle_status();
	patch_branches_selinux_transaction_write();
	patch_branch_context_to_sid();
}

#undef patch_arm64_branches_trampolined
#undef __ksym_size

#endif // ARM64 && KALLSYMS
