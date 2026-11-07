//! Windows implementation.

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

/// System helpers (memory, processes, UI language, time, sealing, the elevated TRIM helper).
pub mod sys {
    pub use super::storage::{volume_label, wipe_free_space};
    pub use super::install::{install_package, package_kind, Installed};
    pub use super::sys_impl::*;

    /// Runs the hidden elevated helper when `args` asks for it (exit code), otherwise None.
    /// Must be called before any window is created.
    pub fn elevated_helper(args: &[String]) -> Option<i32> {
        (args.first().map(String::as_str) == Some(super::storage::RETRIM_ARG))
            .then(|| super::storage::retrim_main(args.get(1).filter(|_| args.len() == 2).map(String::as_str)))
    }
}

use crate::*;
use std::path::{Path, PathBuf};

pub struct WindowsOs;
pub static OS: WindowsOs = WindowsOs;

impl Platform for WindowsOs {
    fn os(&self) -> Os {
        Os::Windows
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
    fn set_capture_protection(&self, window: Option<isize>, on: bool) -> PResult<CaptureState> {
        shell::capture(window, on)
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
        // %LOCALAPPDATA%\Shield (FOLDERID_LocalAppData), the same place as Shield 2.x
        dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("Shield")
    }
    fn temp_dir(&self) -> PathBuf {
        // %TEMP% is below the user's profile, which is owner-only by default
        std::env::temp_dir()
    }
    fn integration_register(&self, exe: &Path) -> PResult<Vec<PathBuf>> {
        shell::register(exe)
    }
    fn integration_unregister(&self) -> PResult<Vec<PathBuf>> {
        shell::unregister()
    }
}
