ksu_obj-y := ksu_init.o
ksu_obj-y += allowlist.o
ksu_obj-y += app_profile.o
ksu_obj-y += apk_sign.o
ksu_obj-y += sucompat.o
ksu_obj-y += throne_tracker.o
ksu_obj-y += setuid_hook.o
ksu_obj-$(CONFIG_KSU_MANUAL_HOOK) += lsm_hook.o
ksu_obj-$(CONFIG_KSU_SYSCALL_HOOK) += kp_hook.o kp_util.o syscall_handler.o pkg_observer.o
ksu_obj-y += kernel_compat.o
ksu_obj-y += kernel_umount.o
ksu_obj-y += supercalls.o
ksu_obj-y += feature.o
ksu_obj-y += ksud.o
ksu_obj-y += seccomp_cache.o
ksu_obj-y += file_wrapper.o
ksu_obj-y += selinux/selinux.o
ksu_obj-y += selinux/sepolicy.o
ksu_obj-y += selinux/rules.o

kernelsu-objs := $(ksu_obj-y)

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_KSU) += kernelsu.o

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Stop printing unless ddk environment
ifneq ($(KDIR),)
$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

# DDK environment workaround.
ccflags-y += -DDDK_ENV
endif

# Check if this is a git repository
# For in - tree build : check $(srctree) / $(src) /../.git
# For out - of - tree build : check $(MDIR) /../.git
ifeq ($(shell test -e $(srctree)/$(src)/../.git && echo "in-tree"),in-tree)
# In - tree build(git submodule)
$(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin [ -f ../.git/shallow ] && git fetch --unshallow)
KSU_GIT_VERSION := $(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git rev-list --count HEAD)
KSU_GIT_VERSION_VALID := 1
else ifeq ($(shell test -e $(MDIR)/../.git && echo "out-of-tree"),out-of-tree)
# Out - of - tree build(standalone repository)
$(shell cd $(MDIR); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin [ -f ../.git/shallow ] && git fetch --unshallow)
KSU_GIT_VERSION := $(shell cd $(MDIR); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git rev-list --count HEAD)
KSU_GIT_VERSION_VALID := 1
endif

# Calculate version if git version is available
ifdef KSU_GIT_VERSION_VALID
$(eval KSU_VERSION=$(shell expr 20000 + $(KSU_GIT_VERSION)))
$(info -- KernelSU version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
else
# If there is no.git directory, use default version
$(warning "KSU_GIT_VERSION not defined! It is better to make KernelSU a git submodule!")
ccflags-y += -DKSU_VERSION=16
endif

# Checks hooks state
ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
$(info -- KernelSU: CONFIG_KSU_MANUAL_HOOK)
ccflags-y += -DCONFIG_KSU_MANUAL_HOOK
endif

ifeq ($(CONFIG_KSU_SYSCALL_HOOK), y)
$(info -- KernelSU: CONFIG_KSU_SYSCALL_HOOK)
ccflags-y += -DCONFIG_KSU_SYSCALL_HOOK
endif

# SELinux drivers check
ifeq ($(shell grep -q "current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# Handle optional backports
ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_STRNCPY
endif

ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_READ
endif

ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_WRITE
endif

ifeq ($(shell grep -q "int\s\+path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
ccflags-y += -DKSU_HAS_PATH_UMOUNT
endif

ifeq ($(shell grep -q "inode_security_struct\s\+\*selinux_inode" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SELINUX_INODE
endif

ifeq ($(shell grep -q "task_security_struct\s\+\*selinux_cred" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SELINUX_CRED
endif

ifeq ($(shell grep -q "atomic_t\s\+filter_count" $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_CNT
endif

# some old kernel backport this, let's check if put_seccomp_filter still exist
ifneq ($(shell grep -wq "put_seccomp_filter" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_RELEASE
endif

ifeq ($(shell grep -q "anon_inode_getfd_secure" $(srctree)/fs/anon_inodes.c; echo $$?),0)
ccflags-y += -DKSU_HAS_GETFD_SECURE
endif

# Checks Samsung
ifeq ($(shell grep -q "CONFIG_KDP_CRED" $(srctree)/kernel/cred.c; echo $$?),0)
ccflags-y += -DSAMSUNG_UH_DRIVER_EXIST
endif
ifeq ($(shell grep -q "SEC_SELINUX_PORTING_COMMON" $(srctree)/security/selinux/avc.c; echo $$?),0)
ccflags-y += -DSAMSUNG_SELINUX_PORTING
endif

# Custom Signs
ifdef KSU_EXPECTED_SIZE
ccflags-y += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
$(info -- Custom KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
endif

ifdef KSU_EXPECTED_HASH
ccflags-y += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"
$(info -- Custom KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- Supported KernelSU Manager(s): tiann, rsuntk, 5ec1cff)

ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-missing-prototypes

all:
	make -C $(KDIR) M=$(MDIR) modules
compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)
clean:
	make -C $(KDIR) M=$(MDIR) clean

# Keep a new line here !!Because someone may append config
