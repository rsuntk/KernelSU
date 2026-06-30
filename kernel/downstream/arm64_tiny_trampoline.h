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
#ifndef __H_ARM64_TINY_TRAMPOLINE
#define __H_ARM64_TINY_TRAMPOLINE

#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/insn.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#include <asm/text-patching.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <asm/patching.h>
#endif

#if !defined(__aarch64__)
static_assert(1 == 0, "ARM64 only!");
#endif

/**
 * small 4-word aarch64 trampoline
 *
 * in reality, its more of a landing pad. no register-stack-register spill
 * all this does is extend the branching range to full 64 bit address space.
 *
 *  Changelog:
 *	- init, 261115
 *	- small build fixups, 261116
 *	- add local nop bank, 261118
 *
 * printf '%s\n' '.text' '.global tp' 'tp:' 'ldr x16, #8' 'br x16' '.quad 0x12345678FFFFFFFF' | aarch64-linux-gnu-as -o test.o
 *
 * 0:	58000050 	ldr	x16, #8 
 * 4:	d61f0200 	br	x16
 * 8:	ffffffff 	.word	0xffffffff
 * c:	12345678 	.word	0x12345678
 *
 * alternative:
 * printf '%s\n' '.text' '.global tp' 'tp:' 'adrp x16, 0x0' 'br x16'| aarch64-linux-gnu-as -o test.o
 * 	- needs pc-relative encoding/decoding + __attribute__((aligned(4096))) functions to jump to
 *
 * - nbd for now. will explore once code caves are small.
 *
 */
static inline void generate_trampoline(uint32_t buf[], uint64_t target)
{
	buf[0] = 0x58000050u;
	buf[1] = 0xd61f0200u;

	// now cut it up
	buf[2] = (uint32_t)(target & 0xFFFFFFFFULL);
	buf[3] = (uint32_t)(target >> 32);

	return;
}

// looks for code cave inside __entry_text_start[], __entry_text_end[];
nodiscard static void *hunt_entry_text_code_cave(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	extern char __entry_text_start[], __entry_text_end[];
	uintptr_t entry_text_start_p = (uintptr_t)__entry_text_start;
	uintptr_t entry_text_end_p = (uintptr_t)__entry_text_end;
#else
	uintptr_t entry_text_start_p = (uintptr_t)kallsyms_lookup_name("__entry_text_start");
	uintptr_t entry_text_end_p = (uintptr_t)kallsyms_lookup_name("__entry_text_end");
	if (!entry_text_start_p || !entry_text_end_p)
		return nullptr;
#endif

	// d503201f
	uintptr_t start = entry_text_start_p;
	uintptr_t end = entry_text_end_p;
	uintptr_t curr = start;

	uint32_t raw_insn;
	uint32_t cnt = 0; 

	uintptr_t best_addr_end = 0;
	uintptr_t addr_end = 0;
	uint32_t highest = 0;

start_scan:
	if (curr >= end)
		goto bail;


	if (!!copy_from_kernel_nofault(&raw_insn, (void *)curr, sizeof(uint32_t)))
		goto reset_cnt;

	if (raw_insn != 0xd503201fU) // aarch64 nop
		goto reset_cnt;

	cnt++;
	addr_end = curr;
	goto increment;

reset_cnt:
	if (cnt > highest) {
		highest = cnt;
		best_addr_end = addr_end;
	}

	cnt = 0;
increment:
	curr = curr + 4;
	goto start_scan;
bail:;
	char cbuf[KSYM_SYMBOL_LEN];
	sprint_symbol(cbuf, best_addr_end);
	pr_info("%s: highest: %u end_addr: 0x%lx owned by: %s\n", __func__, highest, best_addr_end, cbuf);
	if (highest > 16)
		return (void *)best_addr_end;

	return nullptr;
}

static DEFINE_MUTEX(trampoline_routine_mutex);

nodiscard static noinline uintptr_t create_landing_pad_kernel(uintptr_t target)
{
	if (!target)
		return 0x0;

	guarded_mutex_lock(&trampoline_routine_mutex);
	might_sleep();

	uint32_t ibuf; // test that target is reachable
	if (!!copy_from_kernel_nofault(&ibuf, (void *)target, sizeof(uint32_t))) {
		pr_info("%s: target unreachable!\n", __func__);
		return 0x0;
	}

	void *cave_end = hunt_entry_text_code_cave();
	if (!cave_end) {
		pr_info("%s: no sizeable code cave found!\n", __func__);
		return 0x0;
	}

	// we get the address of last nop
	uintptr_t last_nop_addr  = (uintptr_t)cave_end;
	uintptr_t trampoline_start = last_nop_addr - 3 * sizeof(uint32_t);

	uint32_t arr_insn[4];
	void *arr_addr[] = { 
		(void*)(trampoline_start + 0 * sizeof(uint32_t)),
		(void*)(trampoline_start + 1 * sizeof(uint32_t)),
		(void*)(trampoline_start + 2 * sizeof(uint32_t)),
		(void*)(trampoline_start + 3 * sizeof(uint32_t))
	};

	generate_trampoline(arr_insn, target);

#ifdef CONFIG_KSU_DEBUG
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[0], (uintptr_t)arr_addr[0]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[1], (uintptr_t)arr_addr[1]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[2], (uintptr_t)arr_addr[2]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[3], (uintptr_t)arr_addr[3]);
#endif
	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 4);
	if (res) {
		pr_info("%s: err: %d\n", __func__, res);
		return 0x0;
	}

	ptrdiff_t delta = (ptrdiff_t)trampoline_start - (ptrdiff_t)target;
	pr_info("%s: trampoline: 0x%lx target: 0x%lx delta: %ld bytes\n", __func__, trampoline_start, target, __builtin_labs(delta));
	pr_info("%s: trampoline written to: 0x%lx ret: %d\n", __func__, trampoline_start, res);
	return trampoline_start;
}

#define NOP_COUNT 64
#define __tt_stringify2(x) #x
#define __tt_stringify(x) __tt_stringify2(x)
asm(
	".text					\n"
	".p2align 4				\n" // aligned to 2^4, trampoline is 16 bytes
	".global arm64_nop_bank			\n"
"arm64_nop_bank:				\n"
	".rept "__tt_stringify(NOP_COUNT)"	\n"
	"nop					\n"
	".endr					\n"
);
extern uint128_t arm64_nop_bank[];
constexpr unsigned int arm64_nop_bank_max = NOP_COUNT / 4; // 4 nops per trampoline
static unsigned int arm64_nop_bank_curr = 0;

// tiny bump allocator, locally owned nops
nodiscard static noinline uintptr_t create_landing_pad_local(uintptr_t target)
{
	if (!target)
		return 0x0;

	guarded_mutex_lock(&trampoline_routine_mutex);
	might_sleep();

	if (arm64_nop_bank_curr >= arm64_nop_bank_max) {
		pr_info("%s: nop bank full! \n", __func__);	
		return 0x0;
	}

	uint32_t ibuf; // test that target is reachable
	if (!!copy_from_kernel_nofault(&ibuf, (void *)target, sizeof(uint32_t))) {
		pr_info("%s: target unreachable!\n", __func__);
		return 0x0;
	}

	uintptr_t trampoline_start = (uintptr_t)(void *)&arm64_nop_bank[arm64_nop_bank_curr];

	uint32_t arr_insn[4];
	void *arr_addr[] = { 
		(void*)(trampoline_start + 0 * sizeof(uint32_t)),
		(void*)(trampoline_start + 1 * sizeof(uint32_t)),
		(void*)(trampoline_start + 2 * sizeof(uint32_t)),
		(void*)(trampoline_start + 3 * sizeof(uint32_t))
	};

	generate_trampoline(arr_insn, target);

#ifdef CONFIG_KSU_DEBUG
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[0], (uintptr_t)arr_addr[0]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[1], (uintptr_t)arr_addr[1]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[2], (uintptr_t)arr_addr[2]);
	pr_info("%s: .inst 0x%08x to 0x%lx\n", __func__, arr_insn[3], (uintptr_t)arr_addr[3]);
#endif
	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 4);
	if (res) {
		pr_info("%s: err: %d\n", __func__, res);
		return 0x0;
	}

	// bump
	arm64_nop_bank_curr++;


	ptrdiff_t delta = (ptrdiff_t)trampoline_start - (ptrdiff_t)target;
	pr_info("%s: trampoline: 0x%lx target: 0x%lx delta: %ld bytes\n", __func__, trampoline_start, target, __builtin_labs(delta));
	pr_info("%s: trampolines: %u of %u used\n", __func__, arm64_nop_bank_curr, arm64_nop_bank_max);

	return trampoline_start;
}

#ifdef __H_ARM64_BRANCH_PATCH
nodiscard static int arm64_branch_patch_trampolined(uintptr_t callsite, ptrdiff_t size, uintptr_t symbol_addr, uintptr_t target, bool is_kernel)
{
	int ret = arm64_b_or_bl_patch(callsite, size, symbol_addr, target);
	if (ret != -ERANGE)
		return ret;

	uintptr_t trampoline = 0x0;

	if (is_kernel)
		trampoline = create_landing_pad_kernel(target);
	else
		trampoline = create_landing_pad_local(target);

	if (!trampoline)
		return ret;

	return arm64_b_or_bl_patch(callsite, size, symbol_addr, trampoline);
}

// caller is resposnible for zero initing trampoline
nodiscard static int arm64_branch_patch_trampolined_reusable(uintptr_t *trampoline, uintptr_t callsite, uintptr_t symbol_addr, uintptr_t target_hook)
{
	ptrdiff_t depth = ksu_get_ksym_size(callsite, 256 * sizeof(uint32_t));
	int ret = arm64_b_or_bl_patch(callsite, depth, symbol_addr, target_hook);
	if (ret != -ERANGE)
		return ret;
	if (!*trampoline)
		*trampoline = create_landing_pad_kernel(target_hook);
	if (!!*trampoline)
		ret = arm64_b_or_bl_patch(callsite, depth, symbol_addr, *trampoline);
	return ret;
}
#endif

#endif // __H_ARM64_TINY_TRAMPOLINE
