//! Data types shared by every OS implementation. Nothing here is localized: the core and the
//! front ends turn these values into user-facing text.

use std::{fmt, fs::File, io, path::PathBuf};

/// Why an OS service did not do what was asked.
#[derive(Debug)]
pub enum PlatformError {
    /// This OS (or this build / desktop environment) cannot do it at all.
    Unsupported(&'static str),
    /// It needs more rights; `hint` is a command the user can run (e.g. `sudo fstrim -v /home`).
    NeedsPrivilege { hint: String },
    /// The user declined an elevation prompt.
    Declined,
    Io(io::Error),
    /// Any other failure, with a technical (not localized) detail.
    Failed(String),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::Unsupported(w) => write!(f, "unsupported: {w}"),
            PlatformError::NeedsPrivilege { hint } => write!(f, "needs privileges: {hint}"),
            PlatformError::Declined => write!(f, "declined"),
            PlatformError::Io(x) => write!(f, "{x}"),
            PlatformError::Failed(x) => write!(f, "{x}"),
        }
    }
}

impl From<io::Error> for PlatformError {
    fn from(x: io::Error) -> Self {
        PlatformError::Io(x)
    }
}

pub type PResult<T> = Result<T, PlatformError>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Os {
    Windows,
    Linux,
}

/// Identity of an opened file, read from the handle (not the path) to narrow TOCTOU windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub vol: u64,
    pub idx: u64,
    pub nlink: u32,
    /// The handle refers to a reparse point / symlink or a non-regular object.
    pub special: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageKind {
    /// Flash storage (no seek penalty / not rotational): TRIM is useful, overwriting is not reliable.
    Ssd,
    Hdd,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrimReport {
    /// Volume as the user knows it ("C:" or a mount point).
    pub volume: String,
    /// The TRIM ran through an elevation prompt (Windows UAC).
    pub elevated: bool,
    /// Something the user should know although TRIM ran (e.g. LUKS without discard).
    pub note: Option<TrimNote>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrimNote {
    /// Encrypted (dm-crypt/LUKS) or device-mapper volume that drops discards.
    DiscardDisabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    /// Windows Volume Shadow Copies (Previous Versions, System Restore).
    Vss,
    Btrfs,
    Zfs,
    Lvm,
    Timeshift,
    Snapper,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotState {
    /// Snapshots exist (count when known).
    Found(Option<u64>),
    /// Checked, none found.
    NoneFound,
    /// Could not check (no rights, tool missing).
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub volume: String,
    /// Mechanisms that apply to this volume and what was found for each.
    pub found: Vec<(SnapshotKind, SnapshotState)>,
}

impl SnapshotInfo {
    pub fn any_found(&self) -> bool {
        self.found.iter().any(|(_, s)| matches!(s, SnapshotState::Found(_)))
    }
}

/// One protection item of `secure_memory_init`, and whether it was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardenItem {
    /// Windows: process DACL that denies same-user memory access.
    ProcessDacl,
    /// Windows: DLL search limited to System32.
    DllSearch,
    /// Windows: no DLLs from remote / low-integrity locations.
    ImageLoadPolicy,
    /// Windows: no crash dialogs. Linux: core dumps off (RLIMIT_CORE = 0).
    NoCoreDumps,
    /// Linux: PR_SET_DUMPABLE = 0 (no ptrace attach by same-user processes, no /proc/self/mem).
    NotDumpable,
}

#[derive(Clone, Debug, Default)]
pub struct HardenReport {
    pub items: Vec<(HardenItem, bool)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureState {
    /// Windows WDA_EXCLUDEFROMCAPTURE.
    Excluded,
    /// Windows WDA_MONITOR (captured as a black rectangle).
    Monitor,
    Off,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MotwReport {
    /// The source carried a download mark at all.
    pub had_mark: bool,
    pub marked: usize,
    pub failed: Vec<String>,
}

/// A named alternate stream (Windows ADS) or extended attribute (Linux xattr).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub name: String,
    pub size: u64,
    /// The stream is only a download mark (Zone.Identifier / user.xdg.origin.*).
    pub is_mark: bool,
}

/// What `fs::replace_keep_old` left behind for the caller to shred.
pub enum Retained {
    /// The old contents now live under this path (Windows ReplaceFileW backup).
    Path(PathBuf),
    /// The old contents are only reachable through this open, already unlinked file (Linux).
    Open(File),
}

/// Local civil time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub y: i64,
    pub mo: u32,
    pub d: u32,
    pub h: u32,
    pub mi: u32,
    pub s: u32,
}

/// Secret sealed for the current user (Windows DPAPI). `os_protected` is false where the OS has no
/// such service and the bytes are returned as they are (they then rely on file permissions only).
pub struct Sealed {
    pub bytes: Vec<u8>,
    pub os_protected: bool,
}

// ------------------------------------------------------------------ entropy sources

/// How much to collect: Fast = cheap values read at every draw (rate limited by the core),
/// Slow = expensive system statistics read at start-up and periodically.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Poll {
    Fast,
    Slow,
}

/// Additional entropy sources. None of them is ever used alone: they are hashed into a pool
/// that is mixed with fresh OS CSPRNG output at every draw.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Source {
    /// getrandom / BCryptGenRandom (the base; can't be switched off; read by the core).
    OsCsprng,
    /// A second OS generator path (Windows BCryptGenRandom, Linux AT_RANDOM). Mixing only.
    OsAux,
    /// RDRAND / RDSEED. Not trusted: mixing only.
    HwRng,
    /// QPC / RDTSC / CNTVCT / clock_gettime jitter (low bits of differences).
    Timers,
    /// Memory access / scheduling jitter loops.
    CpuJitter,
    /// Memory and paging statistics.
    Memory,
    /// Process and thread CPU times, rusage.
    Process,
    /// PIDs, TIDs, heap / stack / mmap addresses (ASLR).
    Ids,
    /// System idle/kernel/user times, /proc/stat.
    SystemTimes,
    /// Free space and disk I/O counters.
    Disk,
    /// Network packet / byte counters.
    Network,
    /// Process / thread / module / heap list counts and sizes (ToolHelp), numbers only.
    Processes,
    /// HKEY_PERFORMANCE_DATA (Windows).
    PerfData,
    /// /proc statistics files (Linux).
    ProcFs,
    /// Temperature / hardware monitor sensors (Linux).
    Sensors,
    /// Window, focus, caret, capture and clipboard-owner handles (GUI only; no clipboard contents).
    WindowState,
    /// Timing of key and pointer events inside Shield's window (time differences only; GUI only).
    InputTiming,
    /// Pointer positions inside Shield's window (GUI only).
    Mouse,
}

impl Source {
    pub const ALL: [Source; 18] = [
        Source::OsCsprng,
        Source::OsAux,
        Source::HwRng,
        Source::Timers,
        Source::CpuJitter,
        Source::Memory,
        Source::Process,
        Source::Ids,
        Source::SystemTimes,
        Source::Disk,
        Source::Network,
        Source::Processes,
        Source::PerfData,
        Source::ProcFs,
        Source::Sensors,
        Source::WindowState,
        Source::InputTiming,
        Source::Mouse,
    ];

    /// Stable code: settings file, `shield entropy`, and the domain separator in the pool.
    pub fn code(self) -> &'static str {
        match self {
            Source::OsCsprng => "os",
            Source::OsAux => "os_aux",
            Source::HwRng => "hwrng",
            Source::Timers => "timers",
            Source::CpuJitter => "cpu_jitter",
            Source::Memory => "memory",
            Source::Process => "process",
            Source::Ids => "ids",
            Source::SystemTimes => "system_times",
            Source::Disk => "disk",
            Source::Network => "network",
            Source::Processes => "processes",
            Source::PerfData => "perfdata",
            Source::ProcFs => "procfs",
            Source::Sensors => "sensors",
            Source::WindowState => "window_state",
            Source::InputTiming => "input_timing",
            Source::Mouse => "mouse",
        }
    }

    pub fn from_code(s: &str) -> Option<Source> {
        Source::ALL.into_iter().find(|x| x.code() == s)
    }

    /// Never collected by console commands (input devices, window state, clipboard handles).
    pub fn gui_only(self) -> bool {
        matches!(self, Source::WindowState | Source::InputTiming | Source::Mouse)
    }

    /// Whether this OS has the source at all.
    pub fn exists_on(self, os: Os) -> bool {
        match self {
            Source::PerfData => os == Os::Windows,
            Source::ProcFs | Source::Sensors => os == Os::Linux,
            Source::WindowState => os == Os::Windows,
            _ => true,
        }
    }
}

/// One collected value set. Numbers allow the core's simple health tests (stuck / constant step);
/// byte strings are only hashed.
pub enum Sample<'a> {
    Nums(&'a [u64]),
    Bytes(&'a [u8]),
}

/// What a poll may collect.
pub struct EntropyCtx<'a> {
    /// GUI process: window state may be read. Console commands pass false.
    pub gui: bool,
    pub enabled: &'a dyn Fn(Source) -> bool,
}

impl EntropyCtx<'_> {
    pub fn wants(&self, s: Source) -> bool {
        (self.gui || !s.gui_only()) && (self.enabled)(s)
    }
}

// ---------------------------------------------------------------- display (3.0.0 §2)

/// A monitor's work area in physical pixels (virtual desktop coordinates) and its scale.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Monitor {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// Display scale (1.0 = 96 dpi).
    pub scale: f32,
    pub primary: bool,
}

/// A value winit accepts for `WINIT_X11_SCALE_FACTOR` without panicking.
pub fn x11_scale_valid(v: &str) -> bool {
    v.eq_ignore_ascii_case("randr") || v.parse::<f64>().is_ok_and(|s| s.is_finite() && s > 0.0 && s <= 20.0)
}

/// The `WINIT_X11_SCALE_FACTOR` to run with (None = unset) so X11 uses the configured scale like
/// Windows does and never winit's guess from the monitor size:
/// * a valid value the user set is kept (an explicit choice, `randr` included);
/// * an invalid one is dropped (winit would panic) and the rules below apply;
/// * `Xft.dpi` is set: unset, winit reads it itself;
/// * otherwise GDK_SCALE (1..=8) x GDK_DPI_SCALE (0.25..=4), each 1 when missing or invalid.
pub fn x11_scale_choice(current: Option<&str>, xft_dpi: Option<f64>, gdk_scale: Option<&str>, gdk_dpi_scale: Option<&str>) -> Option<String> {
    if let Some(c) = current.filter(|c| x11_scale_valid(c)) {
        return Some(c.to_string());
    }
    if xft_dpi.is_some_and(|d| d.is_finite() && d > 0.0 && d <= 20.0 * 96.0) {
        return None;
    }
    let g = gdk_scale.and_then(|v| v.trim().parse::<u32>().ok()).filter(|v| (1..=8).contains(v)).unwrap_or(1) as f64;
    let d = gdk_dpi_scale.and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| v.is_finite() && (0.25..=4.0).contains(v)).unwrap_or(1.0);
    let s = (g * d * 100.0).round() / 100.0;
    Some(if s.fract() == 0.0 { format!("{s:.0}") } else { format!("{s}") })
}

#[cfg(test)]
mod display_tests {
    use super::*;
    #[test]
    fn x11_follows_the_configured_scale_and_never_guesses() {
        // explicit valid choices are kept
        assert_eq!(x11_scale_choice(Some("1.5"), None, None, None).as_deref(), Some("1.5"));
        assert_eq!(x11_scale_choice(Some("randr"), Some(144.0), None, None).as_deref(), Some("randr"));
        // Xft.dpi set by the desktop: winit reads it (variable unset)
        assert_eq!(x11_scale_choice(None, Some(120.0), None, None), None);
        assert_eq!(x11_scale_choice(Some("nonsense"), Some(120.0), None, None), None, "an invalid value would make winit panic");
        // no Xft.dpi: GDK settings, else 1 (never the monitor-size guess)
        assert_eq!(x11_scale_choice(None, None, None, None).as_deref(), Some("1"));
        assert_eq!(x11_scale_choice(None, None, Some("2"), None).as_deref(), Some("2"));
        assert_eq!(x11_scale_choice(None, None, Some("2"), Some("0.75")).as_deref(), Some("1.5"));
        assert_eq!(x11_scale_choice(None, None, Some("99"), Some("x")).as_deref(), Some("1"));
        assert_eq!(x11_scale_choice(Some("-3"), Some(f64::NAN), None, None).as_deref(), Some("1"));
        for v in ["0", "-1", "inf", "NaN", "", "21"] {
            assert!(!x11_scale_valid(v), "{v}");
        }
        assert!(x11_scale_valid("RandR") && x11_scale_valid("1.25"));
    }
}
