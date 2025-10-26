#include <linux/version.h>
#include "selinux_defs.h"
#include "../klog.h" // IWYU pragma: keep

#define KERNEL_SU_DOMAIN "u:r:su:s0"

static int transive_to_domain(const char *domain)
{
	struct cred *cred;
	struct task_security_struct *tsec;
	u32 sid;
	int error;

	cred = (struct cred *)__task_cred(current);

	tsec = cred->security;
	if (!tsec) {
		pr_err("tsec == NULL!\n");
		return -1;
	}

	error = security_secctx_to_secid(domain, strlen(domain), &sid);
	if (error) {
		pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n",
			domain, sid, error);
	}

	if (!error) {
		tsec->sid = sid;
		tsec->create_sid = 0;
		tsec->keycreate_sid = 0;
		tsec->sockcreate_sid = 0;
	}

	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 0)
bool __maybe_unused is_ksu_transition(const struct task_security_struct *old_tsec,
			const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid(KERNEL_SU_DOMAIN, strlen(KERNEL_SU_DOMAIN), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif

void setup_selinux(const char *domain)
{
	if (transive_to_domain(domain)) {
		pr_err("transive domain failed.\n");
		return;
	}
}

void setenforce(bool enforce)
{
	__setenforce(enforce);
}

bool getenforce(void)
{
	if (is_selinux_disabled()) {
		return false;
	}

	return __is_selinux_enforcing();
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&                         \
	!defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
	const struct task_security_struct *tsec = current_security();

	return tsec->sid;
}
#endif

bool is_ksu_domain(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	struct lsm_context ctx;
#else
	char *domain;
	u32 seclen;
#endif
	bool result;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	int err = security_secid_to_secctx(current_sid(), &ctx);
#else
	int err = security_secid_to_secctx(current_sid(), &domain, &seclen);
#endif

	if (err) {
		return false;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	result = strncmp(KERNEL_SU_DOMAIN, ctx.context, ctx.len) == 0;
	security_release_secctx(&ctx);
#else
	result = strncmp(KERNEL_SU_DOMAIN, domain, seclen) == 0;
	security_release_secctx(domain, seclen);
#endif
	return result;
}

bool is_zygote(void *sec)
{
	struct task_security_struct *tsec = (struct task_security_struct *)sec;
	if (!tsec) {
		return false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	struct lsm_context ctx;
#else
	char *domain;
	u32 seclen;
#endif
	bool result;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	int err = security_secid_to_secctx(tsec->sid, &ctx);
#else
	int err = security_secid_to_secctx(tsec->sid, &domain, &seclen);
#endif
	if (err) {
		return false;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	result = strncmp("u:r:zygote:s0", ctx.context, ctx.len) == 0;
	security_release_secctx(&ctx);
#else
	result = strncmp("u:r:zygote:s0", domain, seclen) == 0;
	security_release_secctx(domain, seclen);
#endif
	return result;
}
