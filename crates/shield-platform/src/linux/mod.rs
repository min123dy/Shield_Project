//! Linux implementation.

pub mod display;
mod entropy;
pub mod fs;
mod install;
pub mod mem;
mod shell;
mod storage;
#[path = "sys.rs"]
mod sys_impl;
#[cfg(test)]
mod tests;

/// System helpers (memory, processes, UI language, time, pkexec).
pub mod sys {
    pub use super::storage::{volume_label, wipe_free_space};
    pub use super::install::{install_package, package_kind, Installed};
    pub use super::sys_impl::*;

    /// Linux has no hidden elevated helper (TRIM needs `sudo fstrim`, shown as a hint).
    pub fn elevated_helper(_args: &[String]) -> Option<i32> {
        None
    }
}

use crate::*;
use std::path::{Path, PathBuf};

pub struct LinuxOs;
pub static OS: LinuxOs = LinuxOs;

/// $XDG_RUNTIME_DIR when it is a real 0700 folder of this user (tmpfs, never written to disk).
fn runtime_dir() -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let d = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    let m = std::fs::symlink_metadata(&d).ok()?;
    (d.is_absolute() && m.is_dir() && m.uid() == unsafe { libc::getuid() } && m.permissions().mode() & 0o077 == 0).then_some(d)
}

impl Platform for LinuxOs {
    fn os(&self) -> Os {
        Os::Linux
    }
    fn entropy_extra(&self, poll: Poll, ctx: &EntropyCtx<'_>, sink: &mut dyn FnMut(Source, Sample<'_>)) {
        entropy::collect(poll, ctx, sink)
    }
    fn detect_storage_kind(&self, path: &Path) -> StorageKind {
        storage::detect(path)
    }
    fn run_trim(&self, path: &Path) -> PResult<TrimReport> {
        storage::trim(path)
    }
    fn snapshot_warning(&self, path: &Path) -> SnapshotInfo {
        storage::snapshots(path)
    }
    fn secure_memory_init(&self) -> HardenReport {
        mem::harden_process()
    }
    fn set_capture_protection(&self, _window: Option<isize>, _on: bool) -> PResult<CaptureState> {
        Err(PlatformError::Unsupported("X11 and Wayland offer no capture protection for a window"))
    }
    fn restrict_file_permissions(&self, path: &Path) -> PResult<()> {
        fs::restrict_permissions(path)
    }
    fn mark_of_the_web_propagate(&self, src: &Path, dst: &[PathBuf]) -> PResult<MotwReport> {
        Ok(fs::motw_propagate(src, dst))
    }
    fn strip_extra_streams(&self, path: &Path, passes: usize, fill: &mut dyn FnMut(&mut [u8], usize)) -> PResult<u64> {
        fs::strip_streams(path, passes, fill)
    }
    fn open_url(&self, url: &str) -> PResult<()> {
        shell::open_url(url)
    }
    fn config_dir(&self) -> PathBuf {
        // $XDG_CONFIG_HOME/shield (usually ~/.config/shield)
        dirs::config_dir().or_else(|| dirs::home_dir().map(|h| h.join(".config"))).unwrap_or_else(|| PathBuf::from("/tmp")).join("shield")
    }
    fn temp_dir(&self) -> PathBuf {
        // small temporary files (update downloads): RAM-backed runtime folder when available
        runtime_dir().map(|d| d.join("shield")).or_else(|| dirs::cache_dir().map(|c| c.join("shield").join("tmp"))).unwrap_or_else(std::env::temp_dir)
    }
    fn integration_register(&self, exe: &Path) -> PResult<Vec<PathBuf>> {
        shell::register(exe)
    }
    fn integration_unregister(&self) -> PResult<Vec<PathBuf>> {
        shell::unregister()
    }
}
