//! Shield platform layer. Everything that depends on the operating system lives here, so that
//! `shield-core` contains no OS-specific code at all.
//!
//! * [`Platform`] (via [`platform()`]) holds the OS services named in the 3.0 design: extra entropy
//!   sources, storage kind, TRIM, snapshot warnings, process hardening, capture protection, owner-only
//!   permissions, download-mark propagation, extra streams, URLs, folders and file manager integration.
//! * [`fs`], [`mem`] and [`sys`] are the low-level primitives the core builds on (handle-based file
//!   identity, no-follow opens, renames that never overwrite, memory locking, ...).
//!
//! Each OS has its own module (`windows/`, `linux/`), selected with `cfg(target_os)`. A service an
//! OS cannot provide returns [`PlatformError::Unsupported`]; nothing is silently skipped.

mod types;
pub use types::*;

pub mod cpu;

#[cfg(windows)]
#[path = "windows/mod.rs"]
mod imp;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod imp;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("Shield 3.0 supports Windows and Linux only (macOS and other systems are not supported).");

pub use imp::{display, fs, mem, sys};

use std::path::{Path, PathBuf};

/// OS services (see the module docs). Implemented once per OS.
pub trait Platform: Send + Sync {
    fn os(&self) -> Os;
    /// Collects the additional (never sole) entropy inputs of this OS into `sink`.
    fn entropy_extra(&self, poll: Poll, ctx: &EntropyCtx<'_>, sink: &mut dyn FnMut(Source, Sample<'_>));
    /// SSD / HDD / unknown for the device that holds `path`.
    fn detect_storage_kind(&self, path: &Path) -> StorageKind;
    /// TRIM of the free space of the volume that holds `path` (last step of every shred).
    fn run_trim(&self, path: &Path) -> PResult<TrimReport>;
    /// Snapshots (VSS, btrfs, ZFS, LVM, Timeshift, Snapper) that may keep old copies of `path`.
    fn snapshot_warning(&self, path: &Path) -> SnapshotInfo;
    /// Core dumps off, memory locking set up, debugger attach restricted (best effort).
    fn secure_memory_init(&self) -> HardenReport;
    /// Screen capture protection for `window` (raw handle) or, with None, every window of this process.
    fn set_capture_protection(&self, window: Option<isize>, on: bool) -> PResult<CaptureState>;
    /// Owner-only access (Windows protected DACL; Unix 0600 for files, 0700 for folders).
    fn restrict_file_permissions(&self, path: &Path) -> PResult<()>;
    /// Copies the download mark of `src` (Zone.Identifier / user.xdg.origin.*) to `dst` and every file below.
    fn mark_of_the_web_propagate(&self, src: &Path, dst: &[PathBuf]) -> PResult<MotwReport>;
    /// Overwrites (`passes` times, data from `fill(buf, pass)`) and removes the extra streams of
    /// `path` (Windows ADS, Linux user xattrs). Returns how many were removed.
    fn strip_extra_streams(&self, path: &Path, passes: usize, fill: &mut dyn FnMut(&mut [u8], usize)) -> PResult<u64>;
    /// Opens an already validated https URL in the default browser.
    fn open_url(&self, url: &str) -> PResult<()>;
    /// Per-user folder for settings, journal and locks.
    fn config_dir(&self) -> PathBuf;
    /// Per-user temporary folder (private where the OS offers one).
    fn temp_dir(&self) -> PathBuf;
    /// Adds the file manager entries for `exe` (GUI binary) for the current user. Returns what was written.
    fn integration_register(&self, exe: &Path) -> PResult<Vec<PathBuf>>;
    fn integration_unregister(&self) -> PResult<Vec<PathBuf>>;
}

/// The implementation for the OS this binary was built for.
pub fn platform() -> &'static dyn Platform {
    &imp::OS
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_codes_round_trip_and_gui_only_set() {
        for s in Source::ALL {
            assert_eq!(Source::from_code(s.code()), Some(s));
        }
        let gui: Vec<_> = Source::ALL.into_iter().filter(|s| s.gui_only()).collect();
        assert_eq!(gui, vec![Source::WindowState, Source::InputTiming, Source::Mouse]);
    }
    #[test]
    fn console_context_never_wants_gui_sources() {
        let all = |_: Source| true;
        let c = EntropyCtx { gui: false, enabled: &all };
        assert!(!c.wants(Source::Mouse) && !c.wants(Source::WindowState) && c.wants(Source::Timers));
    }
    #[test]
    fn folders_exist_or_can_be_named() {
        let p = platform();
        assert!(p.config_dir().is_absolute());
        assert!(p.temp_dir().is_absolute());
    }
}
