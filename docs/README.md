<img src="https://kernelsu.org/logo.png" style="width: 96px;" alt="logo">

# KernelSU (Rissu's fork)

### A Kernel-based root solution for Android devices.

> [!NOTE]
> Official KernelSU support for Non-GKI kernels has been ended.
> 
> This is unofficial KernelSU fork, all changes are not guaranteed stable!
>
> All rights reserved to [@tiann](https://github.com/tiann), the author of KernelSU.
>

[![Latest release](https://img.shields.io/github/v/release/rsuntk/KernelSU?label=Release&logo=github)](https://github.com/rsuntk/KernelSU/releases/latest)
[![Latest LKM release](https://img.shields.io/github/v/release/rsuntk/ksu-lkm?label=Release&logo=github)](https://github.com/rsuntk/ksu-lkm/releases/latest)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/rsukrnlsu)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## How to add RKSU kernel driver into your kernel source

- **main branch**
```
curl -LSs "https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh" | bash -s main
```

- **tag**
```
curl -LSs "https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh" | bash -s v3.0.0-30-legacy
```

- **susfs branch**

> [!WARNING]
> This branch is not always updated.
>

```
curl -LSs "https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh" | bash -s susfs-rksu-master
```

## Hook method

1. **Syscall hook:**
    - Used for Loadable Kernel Module (LKM) or GKI with this hook.
    - Default hook method on GKI kernels.
    - Does not support armv7l.
    - Need `CONFIG_KSU_SYSCALL_HOOK=y` & `CONFIG_KPROBES=y`, `CONFIG_KRETPROBES=y`, `CONFIG_HAVE_SYSCALL_TRACEPOINTS=y`
2. **Manual hook:**
    - [See this repository for more information](https://github.com/rksuorg/kernel_patches)
    - Default hook method on Non-GKI kernels, with condition that `CONFIG_KPROBES` off by default.
    - Need `CONFIG_KSU_MANUAL_HOOK=y`

## Features

1. Kernel-based `su` and root access management.
2. Module system based on [Metamodule](https://kernelsu.org/guide/metamodule.html)
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock up the root power in a cage.

## Compatibility State

- **Kernel compatibility:**
    - Android GKI 2.0 (5.10+): aarch64, armv8l, x86_64
    - Android GKI 1.0 (5.4): aarch64, armv8l, armv7l
    - Non-GKI (4.4-4.19): aarch64, armv8l, armv7l
- **Application compaibility (ksud/manager):**
    - arm64-v8a, armeabi-v7a, x86_64

## Usage

- [Installation Instruction](https://kernelsu.org/guide/installation.html)
- [How to build?](https://kernelsu.org/guide/how-to-build.html)
- [Official Website](https://kernelsu.org/)

## Discussion

- RKSU Telegram Group: [@rsukrnlsu_grp](https://t.me/rsukrnlsu_grp)

## Security

For information on reporting security vulnerabilities in KernelSU, see [SECURITY.md](/SECURITY.md).

## License

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `kernel` directory are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits

- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): the KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): the powerful root tool.
- [genuine](https://github.com/brevent/genuine/): apk v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): some rootkit skills.
- [simonpunk](https://gitlab.com/simonpunk): susfs add-on.
