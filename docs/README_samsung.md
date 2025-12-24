# Some important notes for Samsung device

## Before you integrate KernelSU

* Make sure to disable `CONFIG_UH`, `CONFIG_KDP`, and `CONFIG_RKP`
* Also disable all configurations that related to this (e.g `CONFIG_KDP_CRED`)
* If you unsure, you could nuke entire UH driver (usually placed in drivers/uh, including Kconfig)
* Optional, but it is recommended to disable all Samsung's security drivers like `DEFEX`, `PROCA`, and `FIVE` for example.

## "Why would i need to disable this?"

* This is Samsung anti-root escalation kernel driver
* Building KernelSU while keeping this configuration active would cause your system to crash when it request for root (e.g opening ksu manager would cause entire system to reboot ([smiliar issue](https://github.com/rsuntk/KernelSU/issues/250)))
