mod apk_sign;
mod assets;

// Rissu comments: by default, boot patching is not supported
// on non-GKI device, and since GKI kernel is impossible
// To have 32bit version of it, we must disable it.
#[cfg(not(target_arch = "arm"))]
mod boot_patch;

mod cli;
mod debug;
mod defs;
mod init_event;
mod ksucalls;
mod module;
mod mount;
mod profile;
mod restorecon;
mod sepolicy;
mod su;
mod utils;

fn main() -> anyhow::Result<()> {
    cli::run()
}
