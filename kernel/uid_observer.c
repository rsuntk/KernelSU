#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/version.h>

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "throne_tracker.h"
#include "kernel_compat.h"

#define USERDATA_PATH "/data/user_de/0"
#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"

#define USERDATA_PATH_LEN 288

struct userdata_context {
	struct dir_context ctx;
	struct list_head *uid_list;
};

FILLDIR_RETURN_TYPE userdata_actor(struct dir_context *ctx, const char *name,
				   int namelen, loff_t off, u64 ino,
				   unsigned int d_type)
{
	struct userdata_context *my_ctx =
		container_of(ctx, struct userdata_context, ctx);

	if (!my_ctx)
		return FILLDIR_ACTOR_STOP;

	struct path kpath;
	struct kstat stat;
	char package_path[USERDATA_PATH_LEN];
	int err;

	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_ACTOR_CONTINUE;

	if (d_type != DT_DIR)
		return FILLDIR_ACTOR_CONTINUE;

	if (namelen >= KSU_MAX_PACKAGE_NAME) {
		pr_warn("Package name too long: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	if (snprintf(package_path, sizeof(package_path), "%s/%.*s",
		     USERDATA_PATH, namelen, name) >= sizeof(package_path)) {
		pr_err("Path too long for package: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	err = kern_path(package_path, LOOKUP_FOLLOW, &kpath);
	if (err) {
		pr_debug("Package path lookup failed: %s (err: %d)\n",
			 package_path, err);
		return FILLDIR_ACTOR_CONTINUE;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) ||                          \
	defined(KSU_HAS_NEW_VFS_GETATTR)
	err = vfs_getattr(&kpath, &stat, STATX_UID, AT_STATX_SYNC_AS_STAT);
#else
	err = vfs_getattr(&kpath, &stat);
#endif
	path_put(&kpath);

	if (err) {
		pr_debug("Failed to get attributes for: %s (err: %d)\n",
			 package_path, err);
		return FILLDIR_ACTOR_CONTINUE;
	}

	uid_t uid = from_kuid(&init_user_ns, stat.uid);
	if (uid == (uid_t)-1) {
		pr_warn("Invalid UID for package: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	struct uid_data *data = kzalloc(sizeof(struct uid_data), GFP_ATOMIC);
	if (!data) {
		pr_err("Failed to allocate memory for package: %.*s\n", namelen,
		       name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	data->uid = uid;
	size_t copy_len = min(namelen, KSU_MAX_PACKAGE_NAME - 1);
	strncpy(data->package, name, copy_len);
	data->package[copy_len] = '\0';

	list_add_tail(&data->list, my_ctx->uid_list);

	return FILLDIR_ACTOR_CONTINUE;
}

static void read_package_list(struct list_head *uid_list)
{
	struct file *package_list;
	struct uid_data *np, *n;

	if (!uid_list) {
		return;
	}

	package_list =
		ksu_filp_open_compat(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
	if (IS_ERR(package_list)) {
		pr_err("Failed to open %s, err: %ld\n",
		       SYSTEM_PACKAGES_LIST_PATH, PTR_ERR(package_list));
		return;
	}

	char chr = 0;
	loff_t pos = 0;
	loff_t line_start = 0;
	char buf[KSU_MAX_PACKAGE_NAME];
	for (;;) {
		ssize_t count =
			ksu_kernel_read_compat(package_list, &chr, sizeof(chr), &pos);
		if (count != sizeof(chr))
			break;
		if (chr != '\n')
			continue;

		count = ksu_kernel_read_compat(package_list, buf, sizeof(buf),
					       &line_start);

		struct uid_data *data =
			kzalloc(sizeof(struct uid_data), GFP_ATOMIC);
		if (!data) {
			filp_close(package_list, 0);
			goto out;
		}

		char *tmp = buf;
		const char *delim = " ";
		char *package = strsep(&tmp, delim);
		char *uid = strsep(&tmp, delim);
		if (!uid || !package) {
			pr_err("update_uid: package or uid is NULL!\n");
			break;
		}

		u32 res;
		if (kstrtou32(uid, 10, &res)) {
			pr_err("update_uid: uid parse err\n");
			break;
		}
		data->uid = res;
		strncpy(data->package, package, KSU_MAX_PACKAGE_NAME);
		list_add_tail(&data->list, uid_list);
		// reset line start
		line_start = pos;
	}
	filp_close(package_list, 0);
	return;
out:
	/* Let's mimic how throne_tracker freed unused memories. */
	list_for_each_entry_safe (np, n, uid_list, list) {
		list_del(&np->list);
		kfree(np);
	}
}

void scan_uids(struct list_head *uid_list)
{
	struct file *dir_file;
	static bool once_lock = false;
	long ptr_err = 0;

	if (!uid_list) {
		goto skip_iterate;
	}

	if (!once_lock) {
		dir_file = ksu_filp_open_compat(USERDATA_PATH, O_RDONLY, 0);
		if (IS_ERR(dir_file)) {
			ptr_err = PTR_ERR(dir_file);
			pr_err("Failed to open %s, err: %ld\n", USERDATA_PATH,
			       ptr_err);
		}
	}
	
	// if dir_file error, it should return negative value, thus
	// we fallback to packages.list reading!
	if (ptr_err != 0) {
		once_lock = true;
		pr_warn("Read userdata_de failed! Falling back..\n");
		read_package_list(uid_list);
		goto skip_iterate;
	}

	struct userdata_context ctx = {
		.ctx.actor = userdata_actor,
		.uid_list = uid_list,
	};

	iterate_dir(dir_file, &ctx.ctx);
	filp_close(dir_file, NULL);

skip_iterate:
	return;
}
