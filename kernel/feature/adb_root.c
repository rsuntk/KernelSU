static bool ksu_adb_root __read_mostly = false;

static long is_exec_adbd(const char __user **filename_user)
{
    // should be bigger than `/apex/com.android.adbd/bin/adbd`
    char buf[40] = { 0 };
    size_t copysize = sizeof("/apex/com.android.adbd/bin/adbd");

    if (!!copy_from_user(buf, *filename_user, copysize))
        return 0;

    if (!!endswith(buf, "/adbd"))
        return 0;

    pr_info("%s: adbd: %s \n", __func__, buf);

    return 1;
}

static long is_libadbroot_ok(void)
{
    static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
    struct path path;
    long ret = kern_path(kLibAdbRoot, 0, &path);
    if (ret < 0) {
        if (ret == -ENOENT) {
            pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
            ret = 0;
        } else {
            pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
        }
        return ret;
    } else {
        ret = 1;
    }
    path_put(&path);
    return ret;
}

// NOTE: envp is (void ***), void * const char __user * const char __user *
static long setup_ld_preload(void ***envp_arg)
{
    static const char kLdPreload[] = "LD_PRELOAD=/data/adb/ksu/lib/libadbroot.so";
    static const char kLdLibraryPath[] = "LD_LIBRARY_PATH=/data/adb/ksu/lib";
    static const size_t kReadEnvBatch = 16;
    static const size_t kPtrSize = sizeof(unsigned long);
    unsigned long stackp = current_user_stack_pointer();
    unsigned long envp, ld_preload_p, ld_library_path_p;
    unsigned long *envp_p = (uintptr_t)envp_arg;
    unsigned long *tmp_env_p = NULL, *tmp_env_p2 = NULL;
    size_t env_count = 0, total_size;
    long ret;

    envp = (char __user **)untagged_addr((unsigned long)*envp_p);

    ld_preload_p = stackp =
        ALIGN_DOWN(stackp - sizeof(kLdPreload), 8); // 2 words on 32-bit, 32-on-64 its gonna be fine dw.
    ret = copy_to_user(ld_preload_p, kLdPreload, sizeof(kLdPreload));
    if (ret != 0) {
        pr_warn("write ld_preload when adb_root_handle_execve failed: %ld\n", ret);
        return -EFAULT;
    }

    ld_library_path_p = stackp = ALIGN_DOWN(stackp - sizeof(kLdLibraryPath), 8);
    ret = copy_to_user(ld_library_path_p, kLdLibraryPath, sizeof(kLdLibraryPath));
    if (ret != 0) {
        pr_warn("write ld_library_path when adb_root_handle_execve failed: %ld\n", ret);
        return -EFAULT;
    }

    for (;;) {
        tmp_env_p2 = krealloc(tmp_env_p, (env_count + kReadEnvBatch + 2) * kPtrSize, GFP_KERNEL);
        if (tmp_env_p2 == NULL) {
            pr_err("alloc tmp env failed\n");
            ret = -ENOMEM;
            goto out_release_env_p;
        }
        tmp_env_p = tmp_env_p2;
        ret = copy_from_user(&tmp_env_p[env_count], envp + env_count * kPtrSize, kReadEnvBatch * kPtrSize);
        if (ret < 0) {
            pr_warn("Access envp when adb_root_handle_execve failed: %ld\n", ret);
            ret = -EFAULT;
            goto out_release_env_p;
        }
        size_t read_count = kReadEnvBatch * kPtrSize - ret;
        size_t max_new_env_count = read_count / kPtrSize, new_env_count = 0;
        bool meet_zero = false;
        for (; new_env_count < max_new_env_count; new_env_count++) {
            if (!tmp_env_p[new_env_count + env_count]) {
                meet_zero = true;
                break;
            }
        }
        if (!meet_zero) {
            if (read_count % kPtrSize != 0) {
                pr_err("unaligned envp array!\n");
                ret = -EFAULT;
                goto out_release_env_p;
            } else if (ret != 0) {
                pr_err("truncated envp array!\n");
                ret = -EFAULT;
                goto out_release_env_p;
            }
        }
        env_count += new_env_count;
        if (meet_zero)
            break;
    }

    // We should have allocated enough memory
    // TODO: handle existing LD_PRELOAD
    tmp_env_p[env_count++] = ld_preload_p;
    tmp_env_p[env_count++] = ld_library_path_p;
    tmp_env_p[env_count++] = 0;
    total_size = env_count * kPtrSize;

    stackp -= total_size;
    ret = copy_to_user(stackp, tmp_env_p, total_size);
    if (ret != 0) {
        pr_err("copy new env failed: %ld\n", ret);
        ret = -EFAULT;
        goto out_release_env_p;
    }

    *envp_p = stackp;
    ret = 0;

out_release_env_p:
    if (tmp_env_p) {
        kfree(tmp_env_p);
    }

    return ret;
}

__attribute__((cold)) static noinline long do_ksu_adb_root_handle_execve(const char __user **filename_user,
                                                                         void ***envp)
{
    if (likely(!is_exec_adbd(filename_user)))
        return 0;

    if (unlikely(!is_libadbroot_ok()))
        return 0;

    long ret = setup_ld_preload(envp);
    if (ret)
        return ret;

    pr_info("escape to root for adb\n");
    escape_to_root_for_adb_root();
    escape_with_root_profile(); // why is this needed for 3.x?
    return 0;
}

// sys_execve, syscall hooks
static __always_inline long ksu_adb_root_handle_execve(const char __user **filename_user, void ***envp)
{
    if (likely(!ksu_adb_root))
        return 0;

    if (likely(!!current->seccomp.mode))
        return 0;

    do_ksu_adb_root_handle_execve(filename_user, envp);

    return 0;
}

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

__attribute__((cold)) static noinline long do_ksu_adb_root_handle_execveat(char *filename, void *envp_in)
{
    if (!!endswith(filename, "/adbd"))
        return 0;

    if (unlikely(!is_libadbroot_ok()))
        return 0;

    struct user_arg_ptr *envp = (struct user_arg_ptr *)envp_in;

    void ***envp_addr = (void ***)&envp->ptr.native;
#ifdef CONFIG_COMPAT
    if (unlikely(envp->is_compat))
        envp_addr = (void ***)&envp->ptr.compat;
#endif

    pr_info("%s: envp 0x%lx \n", __func__, (uintptr_t)*envp_addr);

    long ret = setup_ld_preload(envp_addr);
    if (ret)
        return ret;

    pr_info("escape to root for adb\n");
    escape_to_root_for_adb_root();
    escape_with_root_profile(); // why is this needed?
    return 0;
}

// do_execve, do_execve_common, do_execveat_common
static __always_inline long ksu_adb_root_handle_execveat(char *filename, void *envp_in)
{
    if (likely(!ksu_adb_root))
        return 0;

    if (likely(!!current->seccomp.mode))
        return 0;

    if (!filename)
        return 0;

    if (!envp_in)
        return 0;

    do_ksu_adb_root_handle_execveat(filename, envp_in);

    return 0;
}

static int kernel_adb_root_feature_get(u64 *value)
{
    *value = ksu_adb_root ? 1 : 0;
    return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
    bool enable = value != 0;
    if (enable) {
        ksu_adb_root = true;
    } else {
        ksu_adb_root = false;
    }
    pr_info("adb_root: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
    .feature_id = KSU_FEATURE_ADB_ROOT,
    .name = "adb_root",
    .get_handler = kernel_adb_root_feature_get,
    .set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
    if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
        pr_err("Failed to register adb_root feature handler\n");
    }
}

void __exit ksu_adb_root_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}
