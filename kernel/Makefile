kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += app_profile.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += syscall_hook_manager.o
kernelsu-objs += throne_tracker.o
kernelsu-objs += pkg_observer.o
kernelsu-objs += setuid_hook.o
kernelsu-objs += lsm_hooks.o
kernelsu-objs += kernel_compat.o
kernelsu-objs += kernel_umount.o
kernelsu-objs += supercalls.o
kernelsu-objs += feature.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += seccomp_cache.o
kernelsu-objs += file_wrapper.o

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o

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
IS_GKI2 := "true"
CONFIG_KSU_SHOULD_USE_NEW_TP := y
else
IS_GKI2 := $(shell test $(VERSION) -ge 5 -a $(SUBLEVEL) -ge 10 && echo "true")
IS_MODULE := $(shell test $(CONFIG_KSU) = "m" && echo "true")
endif

# Check if this is a git repository
# For in-tree build: check $(srctree)/$(src)/../.git
# For out-of-tree build: check $(MDIR)/../.git
ifeq ($(shell test -e $(srctree)/$(src)/../.git && echo "in-tree"),in-tree)
# In-tree build (git submodule)
$(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin [ -f ../.git/shallow ] && git fetch --unshallow)
KSU_GIT_VERSION := $(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git rev-list --count HEAD)
KSU_GIT_VERSION_VALID := 1
else ifeq ($(shell test -e $(MDIR)/../.git && echo "out-of-tree"),out-of-tree)
# Out-of-tree build (standalone repository)
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
# If there is no .git directory, use default version
$(warning "KSU_GIT_VERSION not defined! It is better to make KernelSU a git repository!")
ccflags-y += -DKSU_VERSION=16
endif

# RKSU: checks for available hook
## Logic flipped for HAVE_KSU_HOOK: 0 is success, 1 is failure, but not with KSU_DRY_RUN
HAVE_KSU_HOOK ?= 1
KSU_DRY_RUN ?= 0

# Checks hooks state
ifeq ($(CONFIG_KSU_SHOULD_USE_NEW_TP), y)
ifneq ($(strip $(IS_GKI2) $(IS_MODULE)),)
$(info -- KernelSU: SHOULD_USE_NEW_TP)
ccflags-y += -DKSU_SHOULD_USE_NEW_TP
# Let's make it 0, so it would pass.
HAVE_KSU_HOOK := 0
endif
endif

ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
HAVE_KSU_HOOK := $(shell grep -q "ksu_handle_faccessat" $(srctree)/fs/open.c; echo $$?)
ifeq ($(HAVE_KSU_HOOK),0)
$(info -- KernelSU: CONFIG_KSU_MANUAL_HOOK)
endif
endif

ifeq ($(KSU_DRY_RUN),0)
ifneq ($(HAVE_KSU_HOOKS),0)
$(error -- KernelSU: No hooks were defined, bail!)
endif
else
$(info -- KernelSU in dry run mode, skip hook checks)
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
ifeq ($(shell grep -q "anon_inode_getfd_secure" $(srctree)/fs/anon_inodes.c; echo $$?),0)
ccflags-y += -DKSU_HAS_GETFD_SECURE
endif
ifeq ($(shell grep -A1 "^int vfs_getattr" $(srctree)/fs/stat.c | grep -q "query_flags"; echo $$?),0)
ccflags-y += -DKSU_HAS_NEW_VFS_GETATTR
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

# Keep a new line here!! Because someone may append config
