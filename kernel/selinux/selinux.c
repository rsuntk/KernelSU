#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "linux/version.h"
#include "selinux_defs.h"
#include "../klog.h" // IWYU pragma: keep
#include "../ksu.h"

static int transive_to_domain(const char *domain, struct cred *cred)
{
	taskcred_sec_t *sec;
	u32 sid;
	int error;

	sec = selinux_cred(cred);
	if (!sec) {
		pr_err("cred->security == NULL!\n");
		return -1;
	}

	error = security_secctx_to_secid(domain, strlen(domain), &sid);
	if (error) {
		pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n",
			domain, sid, error);
	}
	if (!error) {
		sec->sid = sid;
		sec->create_sid = 0;
		sec->keycreate_sid = 0;
		sec->sockcreate_sid = 0;
	}
	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 0)
bool __maybe_unused
is_ksu_transition(const struct task_security_struct *old_tsec,
		  const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	int err;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid) {
		err = security_secctx_to_secid(
			KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid);
		pr_err("failed to get ksu_sid: %d\n", err);
	}

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif

void setup_selinux(const char *domain)
{
	if (transive_to_domain(domain, (struct cred *)__task_cred(current))) {
		pr_err("transive domain failed.\n");
		return;
	}
}

void setup_ksu_cred(void)
{
	if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred)) {
		pr_err("setup ksu cred failed.\n");
	}
}

void setenforce(bool enforce)
{
	do_setenforce(enforce);
}

bool getenforce(void)
{
	if (is_selinux_disabled()) {
		return false;
	}

	return is_selinux_enforcing();
}

bool is_context(const struct cred *cred, const char *context)
{
	const taskcred_sec_t *sec;
	struct lsm_context ctx = { 0 };
	bool result = false;
	int err;

	if (!cred) {
		return result;
	}

	sec = selinux_cred(cred);
	if (!sec) {
		pr_err("cred->security == NULL\n");
		return result;
	}

	err = __security_secid_to_secctx(sec->sid, &ctx);
	if (err) {
		pr_err("secid_to_secctx failed: %d\n", err);
		return result;
	}

	result = strncmp(context, ctx.context, ctx.len) == 0;
	__security_release_secctx(&ctx);
	return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
	return is_context(cred, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
	current_sid();
	return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
	return is_context(cred, "u:r:zygote:s0");
}

bool is_init(const struct cred *cred)
{
	return is_context(cred, "u:r:init:s0");
}

bool is_sid_equal(const struct cred *cred, u32 val)
{
	taskcred_sec_t *tsec = selinux_cred(cred);
	if (!tsec) {
		return false;
	}
	return tsec->sid == val;
}

static inline void ksu_get_sid(const char *secctx_name, u32 *out_sid)
{
	int err;

	if (!secctx_name || !out_sid) {
		return;
	}

	err = security_secctx_to_secid(secctx_name, strlen(secctx_name),
				       out_sid);
	if (err) {
		pr_err("ksu_get_sid: cannot get sid for %s, err: %d\n",
		       secctx_name, err);
		return;
	}
	pr_info("ksu_get_sid: %u (secctx=%s)\n", *out_sid, secctx_name);
}

u32 ksu_zygote_sid = 0;
void ksu_set_zygote_sid(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                          \
     defined(CONFIG_KSU_MANUAL_HOOK))
	ksu_get_sid("u:r:zygote:s0", &ksu_zygote_sid);
#endif
}

u32 ksu_get_ksu_file_sid(void)
{
	u32 ksu_file_sid = 0;
	ksu_get_sid(KSU_FILE_CONTEXT, &ksu_file_sid);
	return ksu_file_sid;
}
