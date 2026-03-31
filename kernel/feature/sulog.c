static bool ksu_sulog_enabled __read_mostly = false;

static int sulog_feature_get(u64 *value)
{
    *value = ksu_sulog_enabled ? 1 : 0;
    return 0;
}

static int sulog_feature_set(u64 value)
{
    bool enable = value != 0;

    ksu_sulog_enabled = enable;
    pr_info("sulog: set to %d (dummy)\n", enable);
    return 0;
}

static const struct ksu_feature_handler sulog_handler = {
    .feature_id = KSU_FEATURE_SULOG,
    .name = "sulog",
    .get_handler = sulog_feature_get,
    .set_handler = sulog_feature_set,
};

void ksu_sulog_init(void)
{
    int ret;

    ret = ksu_register_feature_handler(&sulog_handler);
    if (ret) {
        pr_err("Failed to register sulog feature handler\n");
        return;
    }
}

void ksu_sulog_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SULOG);
}
