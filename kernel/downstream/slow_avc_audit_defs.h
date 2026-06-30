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

#ifndef __KSU_H_SLOW_AVC_AUDIT_HOOK
#define __KSU_H_SLOW_AVC_AUDIT_HOOK

static bool ksu_selinux_hide_enabled;
static u32 cached_su_sid;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	int err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", priv_app_sid);

	if (!priv_app_sid)
		return -1;

	return 0;
}

static __always_inline void ksu_slow_avc_audit_inline(u32 *tsid)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	// won't happen. this is unreachable if so
	//if (unlikely(!priv_app_sid))
	//	return;

	if (*tsid != cached_su_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;
}

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS)

struct selinux_state;
__maybe_unused void ksu_slow_avc_audit(u32 *tsid) { return; } // dummy

extern typeof(slow_avc_audit) slow_avc_audit;

#define SLOW_AVC_AUDIT_TYPE_1	u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a
__overloaded static int ksu_slow_avc_audit_handler_1(SLOW_AVC_AUDIT_TYPE_1)
{
	ksu_slow_avc_audit_inline(&tsid);

	assume(!!&slow_avc_audit);
	return ((typeof(ksu_slow_avc_audit_handler_1) *)(void *)slow_avc_audit)(ssid, tsid, tclass, requested, audited, denied, result, a);
}

#define SLOW_AVC_AUDIT_TYPE_2	struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a
__overloaded static int ksu_slow_avc_audit_handler_2(SLOW_AVC_AUDIT_TYPE_2)
{
	ksu_slow_avc_audit_inline(&tsid);

	assume(!!&slow_avc_audit);
	return ((typeof(ksu_slow_avc_audit_handler_2) *)(void *)slow_avc_audit)(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

#define SLOW_AVC_AUDIT_TYPE_3	struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags
__overloaded static int ksu_slow_avc_audit_handler_3(SLOW_AVC_AUDIT_TYPE_3)
{
	ksu_slow_avc_audit_inline(&tsid);

	assume(!!&slow_avc_audit);
	return ((typeof(ksu_slow_avc_audit_handler_3) *)(void *)slow_avc_audit)(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

#define SLOW_AVC_AUDIT_TYPE_4	u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags
__overloaded static int ksu_slow_avc_audit_handler_4(SLOW_AVC_AUDIT_TYPE_4)
{
	ksu_slow_avc_audit_inline(&tsid);

	assume(!!&slow_avc_audit);
	return ((typeof(ksu_slow_avc_audit_handler_4) *)(void *)slow_avc_audit)(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

#define ksu_slow_avc_audit_overloaded _Generic(				\
(slow_avc_audit),							\
	int (*)(SLOW_AVC_AUDIT_TYPE_1): ksu_slow_avc_audit_handler_1, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_2): ksu_slow_avc_audit_handler_2, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_3): ksu_slow_avc_audit_handler_3, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_4): ksu_slow_avc_audit_handler_4	\
)

static void ksu_init_slow_avc_audit_hook(void)
{
	int ret = ksu_selinux_get_sids();
	if (ret) {
		pr_info("selinux_hide: sid grab fail?\n");
		goto bail;
	}

	uintptr_t target = kallsyms_lookup_retry("slow_avc_audit");
	if (!target)
		goto bail;

	uintptr_t landing_pad = 0x0;
	uintptr_t callsite = kallsyms_lookup_retry("avc_has_extended_perms");
	if (!callsite)
		goto skip1;
	ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, (uintptr_t)&ksu_slow_avc_audit_overloaded);
	if (ret == -ERANGE) {
		landing_pad = create_landing_pad_kernel((uintptr_t)&ksu_slow_avc_audit_overloaded);
		if (!!landing_pad)
			ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, landing_pad);
	}
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_extended_perms ret: %d\n", ret);
skip1:
	callsite = kallsyms_lookup_retry("avc_has_perm_flags");
	if (!callsite)
		goto skip2;
	ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, (uintptr_t)&ksu_slow_avc_audit_overloaded);
	if (ret == -ERANGE) {
		if (!landing_pad)
			landing_pad = create_landing_pad_kernel((uintptr_t)&ksu_slow_avc_audit_overloaded);	
		if (!!landing_pad)
			ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, landing_pad);
	}
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm_flags ret: %d\n", ret);
skip2:
	callsite = kallsyms_lookup_retry("avc_has_perm");
	if (!callsite)
		goto bail;
	ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, (uintptr_t)&ksu_slow_avc_audit_overloaded);
	if (ret == -ERANGE) {
		if (!landing_pad)
			landing_pad = create_landing_pad_kernel((uintptr_t)&ksu_slow_avc_audit_overloaded);	
		if (!!landing_pad)
			ret = arm64_bl_patch(callsite, ksu_get_ksym_size(callsite, 384 * sizeof(uint32_t)), target, landing_pad);
	}
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm ret: %d\n", ret);

bail:;
	extern typeof(dotted_kallsyms_destroy_hash_array) dotted_kallsyms_destroy_hash_array;
	dotted_kallsyms_destroy_hash_array();
}

#undef SLOW_AVC_AUDIT_TYPE_4
#undef SLOW_AVC_AUDIT_TYPE_3
#undef SLOW_AVC_AUDIT_TYPE_2
#undef SLOW_AVC_AUDIT_TYPE_1

#elif defined(CONFIG_KPROBES)
static struct kprobe *slow_avc_audit_kp;
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(KSU_COMPAT_HAS_SELINUX_STATE))
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif
	ksu_slow_avc_audit_inline(tsid);

	return 0;
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	int ret = ksu_selinux_get_sids();
	if (ret)
		pr_info("selinux_hide: sid grab fail?\n");

	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
}

#else /* ! CONFIG_KPROBES */

void ksu_slow_avc_audit(u32 *tsid)
{
	ksu_slow_avc_audit_inline(tsid);
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	int ret = ksu_selinux_get_sids();
	if (!ret)
		return;

	// doesnt really matter if this fails
	// replacing 0 with soemthing is not a problem
	// this is for the manual hook part so yeah
	pr_info("selinux_hide: sid grab fail?\n");
}
#endif

#endif // __KSU_H_SLOW_AVC_AUDIT_HOOK
