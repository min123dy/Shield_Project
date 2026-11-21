//! Windows implementation.

pub mod display;
mod entropy;
mod erase;
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
    pub use super::install::{
        create_update_file, install_from_private, install_package, package_kind, remove_private_dir, run_update_helper, update_helper_allowed, update_input_owner_ok, update_private_dir, update_state_path, Installed,
        HELPER_ARG as UPDATE_HELPER_ARG,
    };
    pub use super::sys_impl::*;

    /// Runs a hidden elevated helper when `args` asks for it (exit code), otherwise None: the
    /// TRIM helper and the second stage of an update installation. (The first stage of an
    /// update, `UPDATE_HELPER_ARG`, needs shield-core and is handled by the program.) Must be
    /// called before any window is created.
    pub fn elevated_helper(args: &[String]) -> Option<i32> {
        match args.first().map(String::as_str) {
            Some(super::storage::RETRIM_ARG) => Some(super::storage::retrim_main(args.get(1).filter(|_| args.len() == 2).map(String::as_str))),
            Some(super::install::RUN_ARG) => Some(super::install::run_stage2(&args[1..])),
            _ => None,
        }
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
    fn config_dir(&self) -> PResult<PathBuf> {
        // %LOCALAPPDATA%\Shield (FOLDERID_LocalAppData), the same place as Shield 2.x; no fallback
        dirs::data_local_dir().map(|d| d.join("Shield")).ok_or_else(|| PlatformError::Failed("no local application data folder".into()))
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
