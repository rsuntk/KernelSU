#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#define KERNEL_SU_VERSION KSU_VERSION

struct cred* ksu_cred;
static bool ksu_late_loaded = false;

static inline int startswith(char *s, char *prefix)
{
	return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
	size_t slen = strlen(s);
	size_t tlen = strlen(t);
	if (tlen > slen)
		return 1;
	return strcmp(s + slen - tlen, t);
}

extern struct cred* ksu_cred;

#endif
