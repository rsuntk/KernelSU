//
// Created by weishu on 2022/12/9.
//

#include <sys/prctl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "ksu.h"

#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_GRANT_ROOT 0

#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_ALLOW_SU 3
#define CMD_DENY_SU 4
#define CMD_GET_SU_LIST 5
#define CMD_GET_DENY_LIST 6
#define CMD_CHECK_SAFEMODE 9

#define CMD_GET_APP_PROFILE 10
#define CMD_SET_APP_PROFILE 11

#define CMD_IS_UID_GRANTED_ROOT 12
#define CMD_IS_UID_SHOULD_UMOUNT 13
#define CMD_IS_SU_ENABLED 14
#define CMD_ENABLE_SU 15

#define KSU_FLAG_MODE_LKM	(1 << 0)
#define KSU_FLAG_HOOK_KP	(1 << 1)
#define KSU_FLAG_HOOK_MANUAL	(1 << 2)
#define KSU_FLAG_GKI		(1 << 3)

static bool ksuctl(int cmd, void* arg1, void* arg2) {
    int32_t result = 0;
    prctl(KERNEL_SU_OPTION, cmd, arg1, arg2, &result);
    return result == KERNEL_SU_OPTION;
}

bool become_manager(const char* pkg) {
    char param[128];
    uid_t uid = getuid();
    uint32_t userId = uid / 100000;
    if (userId == 0) {
        sprintf(param, "/data/data/%s", pkg);
    } else {
        snprintf(param, sizeof(param), "/data/user/%d/%s", userId, pkg);
    }

    return ksuctl(CMD_BECOME_MANAGER, param, nullptr);
}

// cache the result to avoid unnecessary syscall
static bool is_lkm = false;
static bool is_kp_hook = false;
static bool is_manual_hook = false;
static bool __is_gki_kernel = false;

int get_version(void) {
    int32_t version = -1;
    // grep from kernel
    ksuctl(CMD_GET_VERSION, &version, nullptr);
    if (version != -1) {
        if (version >= 12276) {
            int32_t flags = 0;
            ksuctl(CMD_GET_VERSION, nullptr, &flags);
            if (!is_lkm && (flags & KSU_FLAG_MODE_LKM))
                is_lkm = true;
            if (!is_kp_hook && (flags & KSU_FLAG_HOOK_KP))
    	        is_kp_hook = true;
            if (!is_manual_hook && (flags & KSU_FLAG_HOOK_MANUAL))
    	        is_manual_hook = true;
            if (!__is_gki_kernel && (flags & KSU_FLAG_GKI))
    	        __is_gki_kernel = true;
        } else {
    	    // old detection method
    	    int32_t lkm = 0;
    	    ksuctl(CMD_GET_VERSION, nullptr, &lkm);
    	    if (!is_lkm && lkm != 0)
    	       is_lkm = true;
        }
    }
    return version;
}

bool get_allow_list(int *uids, int *size) {
    return ksuctl(CMD_GET_SU_LIST, uids, size);
}

bool is_safe_mode() {
    return ksuctl(CMD_CHECK_SAFEMODE, nullptr, nullptr);
}

// start: you should call get_version first!
bool is_lkm_mode() {
    return is_lkm;
}
bool is_kp_mode() {
    return is_kp_hook && !is_manual_hook;
}
bool is_gki_kernel() {
    return __is_gki_kernel;
}
// end: you should call get_version first!

bool uid_should_umount(int uid) {
    bool should;
    return ksuctl(CMD_IS_UID_SHOULD_UMOUNT, reinterpret_cast<void*>(uid), &should) && should;
}

bool set_app_profile(const app_profile *profile) {
    return ksuctl(CMD_SET_APP_PROFILE, (void*) profile, nullptr);
}

bool get_app_profile(p_key_t key, app_profile *profile) {
    return ksuctl(CMD_GET_APP_PROFILE, (void*) profile, nullptr);
}

bool set_su_enabled(bool enabled) {
    return ksuctl(CMD_ENABLE_SU, (void*) enabled, nullptr);
}

bool is_su_enabled() {
    bool enabled = true;
    // if ksuctl failed, we assume su is enabled, and it cannot be disabled.
    ksuctl(CMD_IS_SU_ENABLED, &enabled, nullptr);
    return enabled;
}
