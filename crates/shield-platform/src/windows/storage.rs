//! Windows storage: SSD/HDD detection (seek penalty), TRIM (MSFT_Volume.Optimize -ReTrim through an
//! elevated helper when needed), free-space overwrite (cipher /w) and Volume Shadow Copy detection.

use crate::{PResult, PlatformError, SnapshotInfo, SnapshotKind, SnapshotState, StorageKind, TrimReport};
use std::{fs, path::Path};

fn plain_path(p: &Path) -> String {
    let s = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().into_owned();
    s.strip_prefix(r"\\?\").map(String::from).unwrap_or(s)
}

pub fn drive_letter(p: &Path) -> Option<char> {
    let s = plain_path(p);
    let mut it = s.chars();
    let a = it.next()?;
    (it.next() == Some(':') && a.is_ascii_alphabetic()).then(|| a.to_ascii_uppercase())
}

pub fn volume_label(p: &Path) -> String {
    drive_letter(p).map(|l| format!("{l}:")).unwrap_or_else(|| p.display().to_string())
}

/// StorageDeviceSeekPenaltyProperty of volume `l:` (IOCTL_STORAGE_QUERY_PROPERTY, the same source as
/// Get-PhysicalDisk MediaType). None when the device does not report it.
pub(crate) fn seek_penalty(l: char) -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    use windows_sys::Win32::System::Ioctl::{PropertyStandardQuery, StorageDeviceSeekPenaltyProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    if !l.is_ascii_alphabetic() {
        return None;
    }
    let dev = super::fs::wstr(&format!(r"\\.\{l}:"));
    unsafe {
        // access 0: a property query needs no read/write access, hence no administrator rights
        let h = CreateFileW(dev.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, core::ptr::null(), OPEN_EXISTING, 0, 0);
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let q = STORAGE_PROPERTY_QUERY { PropertyId: StorageDeviceSeekPenaltyProperty, QueryType: PropertyStandardQuery, AdditionalParameters: [0] };
        let mut d: DEVICE_SEEK_PENALTY_DESCRIPTOR = core::mem::zeroed();
        let mut n = 0u32;
        let ok = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &q as *const _ as _,
            core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            &mut d as *mut _ as _,
            core::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut n,
            core::ptr::null_mut(),
        );
        CloseHandle(h);
        let need = core::mem::offset_of!(DEVICE_SEEK_PENALTY_DESCRIPTOR, IncursSeekPenalty) + 1;
        (ok != 0 && n as usize >= need).then_some(d.IncursSeekPenalty != 0)
    }
}

pub fn detect(p: &Path) -> StorageKind {
    match drive_letter(p).and_then(seek_penalty) {
        Some(true) => StorageKind::Hdd,
        Some(false) => StorageKind::Ssd,
        None => StorageKind::Unknown,
    }
}

/// Hidden command line of the elevated TRIM helper: `<exe> --retrim <letter>`.
pub const RETRIM_ARG: &str = "--retrim";
/// Exit code of a helper that really trimmed. Not 0: a program that ignored `--retrim` and
/// opened its normal window also exits with 0, and that must never count as a finished TRIM.
const RETRIM_OK: i32 = 0x5452;

/// `__Path` of the MSFT_Volume mounted at `l:` (ROOT\Microsoft\Windows\Storage).
pub(crate) fn volume_path(con: &wmi::WMIConnection, l: char) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct Vol {
        __Path: String,
    }
    if !l.is_ascii_alphabetic() {
        return Err("bad drive".into()); // also keeps the WQL literal injection-free
    }
    let v: Vec<Vol> = con.raw_query(format!("SELECT __Path FROM MSFT_Volume WHERE DriveLetter = '{l}'")).map_err(|x| x.to_string())?;
    v.into_iter().next().map(|v| v.__Path).ok_or_else(|| "no such volume".to_string())
}

fn retrim_wmi(l: char) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    #[allow(non_camel_case_types)]
    struct MSFT_Volume;
    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct OptimizeIn {
        ReTrim: bool,
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct OptimizeOut {
        ReturnValue: u32,
    }
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Storage").map_err(|x| x.to_string())?;
    let path = volume_path(&con, l)?;
    let out: OptimizeOut = con.exec_instance_method::<MSFT_Volume, _>(&path, "Optimize", OptimizeIn { ReTrim: true }).map_err(|x| x.to_string())?;
    match out.ReturnValue {
        0 => Ok(()),
        n => Err(format!("MSFT_Volume.Optimize: {n}")),
    }
}

/// Entry point of the elevated helper: exactly one drive letter; RETRIM_OK on success, 2 on a bad
/// argument, 3 when the TRIM request failed.
pub fn retrim_main(arg: Option<&str>) -> i32 {
    let mut c = arg.unwrap_or("").chars();
    match (c.next(), c.next()) {
        (Some(l), None) if l.is_ascii_alphabetic() => match retrim_wmi(l.to_ascii_uppercase()) {
            Ok(()) => RETRIM_OK,
            Err(_) => 3,
        },
        _ => 2,
    }
}

/// What runs elevated for TRIM: Windows' own `defrag.exe <l>: /L` (ReTrim) from System32. Never
/// this program: a portable copy lies in a folder its user can write, and an administrator
/// prompt for it would run whatever was put next to it (security review 2026-11-08).
pub(crate) fn elevated_trim_command(l: char) -> Option<(std::path::PathBuf, String)> {
    l.is_ascii_alphabetic().then_some(())?;
    Some((super::fs::system_dir()?.join("defrag.exe"), format!("{}: /L", l.to_ascii_uppercase())))
}

/// TRIM of the volume holding `p`: directly first, then once through a UAC prompt.
pub fn trim(p: &Path) -> PResult<TrimReport> {
    let l = drive_letter(p).ok_or(PlatformError::Unsupported("TRIM needs a volume with a drive letter"))?;
    let volume = format!("{l}:");
    if retrim_wmi(l).is_ok() {
        return Ok(TrimReport { volume, elevated: false, note: None });
    }
    const ERROR_CANCELLED: i32 = 1223;
    let (exe, params) = elevated_trim_command(l).ok_or(PlatformError::Failed("System32".into()))?;
    match super::sys::run_elevated(&exe, &params) {
        Ok(0) => Ok(TrimReport { volume, elevated: true, note: None }),
        Err(x) if x.raw_os_error() == Some(ERROR_CANCELLED) => Err(PlatformError::Declined),
        Ok(c) => Err(PlatformError::Failed(format!("defrag /L exit code {c}"))),
        Err(x) => Err(x.into()),
    }
}

/// Overwrites the free space of the volume holding `dir` (cipher /w: 0x00, 0xFF, random).
/// `cancelled` is polled; a cancel kills cipher.exe.
pub fn wipe_free_space(dir: &Path, cancelled: &dyn Fn() -> bool) -> PResult<Option<String>> {
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    let l = drive_letter(dir).ok_or(PlatformError::Unsupported("free-space overwrite needs a drive letter"))?;
    let exe = super::fs::system_dir().ok_or(PlatformError::Failed("System32".into()))?.join("cipher.exe");
    let mut child = std::process::Command::new(exe)
        .arg(format!("/w:{}", plain_path(dir)))
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    loop {
        match child.try_wait()? {
            Some(st) if st.success() => return Ok(Some(format!("{l}:"))),
            Some(st) => return Err(PlatformError::Failed(format!("cipher.exe exit {st}"))),
            None if cancelled() => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
            None => std::thread::sleep(std::time::Duration::from_millis(300)),
        }
    }
}

fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, &mut e as *mut _ as _, core::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len);
        CloseHandle(tok);
        ok != 0 && e.TokenIsElevated != 0
    }
}

/// `\\?\Volume{GUID}\` of the drive holding `p`.
fn volume_guid(p: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
    let l = drive_letter(p)?;
    let root = super::fs::wstr(&format!("{l}:\\"));
    let mut buf = [0u16; 64];
    (unsafe { GetVolumeNameForVolumeMountPointW(root.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } != 0).then(|| {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..n])
    })
}

/// Volume Shadow Copies of the volume holding `p` (Win32_ShadowCopy). Listing them needs
/// administrator rights; without them an empty answer is reported as "unknown", never as "none".
/// Nothing is ever deleted here.
pub fn snapshots(p: &Path) -> SnapshotInfo {
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct Shadow {
        VolumeName: Option<String>,
    }
    let volume = volume_label(p);
    let state = (|| {
        let guid = volume_guid(p)?;
        let con = wmi::WMIConnection::new().ok()?;
        let v: Vec<Shadow> = con.raw_query("SELECT VolumeName FROM Win32_ShadowCopy").ok()?;
        let n = v.iter().filter(|s| s.VolumeName.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(&guid))).count() as u64;
        Some(match (n, is_elevated()) {
            (0, true) => SnapshotState::NoneFound,
            (0, false) => SnapshotState::Unknown,
            (n, _) => SnapshotState::Found(Some(n)),
        })
    })()
    .unwrap_or(SnapshotState::Unknown);
    SnapshotInfo { volume, found: vec![(SnapshotKind::Vss, state)] }
}
