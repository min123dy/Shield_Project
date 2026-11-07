//! Windows desktop integration: this process's windows, capture protection, opening URLs and the
//! per-user Explorer context menu (used by the portable build; the MSI writes the same entries
//! machine-wide).

use crate::{CaptureState, PResult, PlatformError};
use std::path::{Path, PathBuf};

/// Top-level windows of this process (eframe has one), minus NVIDIA's OpenGL helper window.
pub fn own_windows() -> Vec<isize> {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetClassNameW, GetWindowThreadProcessId};
    unsafe fn is_nvidia_dummy(h: HWND) -> bool {
        let mut c = [0u16; 256];
        let n = GetClassNameW(h, c.as_mut_ptr(), c.len() as i32);
        n > 0 && String::from_utf16_lossy(&c[..n as usize]).eq_ignore_ascii_case("__wglDummyWindowFodder")
    }
    unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
        let v = &mut *(l as *mut Vec<isize>);
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, &mut pid);
        if pid == std::process::id() && !is_nvidia_dummy(h) {
            v.push(h);
        }
        1
    }
    let mut v: Vec<isize> = Vec::new();
    unsafe { EnumWindows(Some(cb), &mut v as *mut _ as LPARAM) };
    v
}

pub const WDA_NONE: u32 = 0x00;
pub const WDA_MONITOR: u32 = 0x01;
pub const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

/// SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) (Windows 10 2004+), falling back to WDA_MONITOR;
/// the DWM peek / iconic attributes keep the content out of Alt+Tab and taskbar thumbnails.
/// Only software capture through the normal Windows APIs is blocked.
pub fn capture(window: Option<isize>, on: bool) -> PResult<CaptureState> {
    use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_DISALLOW_PEEK, DWMWA_EXCLUDED_FROM_PEEK, DWMWA_FORCE_ICONIC_REPRESENTATION};
    use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity;
    let wins = window.map(|w| vec![w]).unwrap_or_else(own_windows);
    if wins.is_empty() {
        return Err(PlatformError::Failed("no window".into()));
    }
    let plan: &[u32] = if on { &[WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR] } else { &[WDA_NONE] };
    let mut worst = CaptureState::Excluded;
    for h in wins {
        let done = plan.iter().copied().find(|&a| unsafe { SetWindowDisplayAffinity(h, a) } != 0);
        let flag: i32 = on as i32;
        for attr in [DWMWA_EXCLUDED_FROM_PEEK, DWMWA_DISALLOW_PEEK, DWMWA_FORCE_ICONIC_REPRESENTATION] {
            unsafe { DwmSetWindowAttribute(h, attr as u32, &flag as *const i32 as _, 4) };
        }
        match done {
            None => return Err(PlatformError::Io(std::io::Error::last_os_error())),
            Some(WDA_NONE) => worst = CaptureState::Off,
            Some(WDA_MONITOR) if worst == CaptureState::Excluded => worst = CaptureState::Monitor,
            _ => {}
        }
    }
    Ok(worst)
}

/// Opens a URL (already validated by the caller) with the default browser.
pub fn open_url(url: &str) -> PResult<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let (verb, u) = (super::fs::wstr("open"), super::fs::wstr(url));
    let r = unsafe { ShellExecuteW(0, verb.as_ptr(), u.as_ptr(), core::ptr::null(), core::ptr::null(), SW_SHOWNORMAL) };
    if r > 32 {
        Ok(())
    } else {
        Err(PlatformError::Failed(format!("ShellExecute {r}")))
    }
}

fn reg_set(key: &str, name: Option<&str>, val: &str) -> PResult<()> {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ};
    let k = super::fs::wstr(key);
    let mut h: HKEY = 0;
    let rc = unsafe { RegCreateKeyExW(HKEY_CURRENT_USER, k.as_ptr(), 0, core::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, core::ptr::null(), &mut h, core::ptr::null_mut()) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32).into());
    }
    let n = name.map(super::fs::wstr);
    let v = super::fs::wstr(val);
    let rc = unsafe { RegSetValueExW(h, n.as_ref().map_or(core::ptr::null(), |n| n.as_ptr()), 0, REG_SZ, v.as_ptr() as *const u8, (v.len() * 2) as u32) };
    unsafe { RegCloseKey(h) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32).into());
    }
    Ok(())
}

const KEYS: [&str; 4] = [
    r"Software\Classes\*\shell\Shield.Encrypt",
    r"Software\Classes\Directory\shell\Shield.Encrypt",
    r"Software\Classes\SystemFileAssociations\.shd\shell\Shield.Decrypt",
    r"Software\Classes\SystemFileAssociations\.shd\shell\Shield.Open",
];

/// Per-user (HKCU) classic context menu entries pointing at `exe`.
pub fn register(exe: &Path) -> PResult<Vec<PathBuf>> {
    let ko = super::sys::system_lang_is_korean();
    let labels = if ko { ["Shield로 암호화", "Shield로 암호화", "Shield로 복호화", "SHIELD에서 열기"] } else { ["Encrypt with Shield", "Encrypt with Shield", "Decrypt with Shield", "Open in SHIELD"] };
    let args = ["--encrypt-multi", "--encrypt-multi", "--decrypt", "--open"];
    let e = exe.display().to_string();
    if e.contains('"') {
        return Err(PlatformError::Failed("quote in path".into()));
    }
    for ((k, l), a) in KEYS.iter().zip(labels).zip(args) {
        reg_set(k, None, l)?;
        reg_set(k, Some("Icon"), &e)?;
        // one Explorer call per selected item; the GUI collects them (see the core `collect` module)
        reg_set(k, Some("MultiSelectModel"), "Player")?;
        reg_set(&format!(r"{k}\command"), None, &format!("\"{e}\" {a} \"%1\""))?;
    }
    Ok(KEYS.iter().map(|k| PathBuf::from(format!(r"HKEY_CURRENT_USER\{k}"))).collect())
}

pub fn unregister() -> PResult<Vec<PathBuf>> {
    use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};
    let mut gone = Vec::new();
    for k in KEYS {
        let w = super::fs::wstr(k);
        let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, w.as_ptr()) };
        match rc {
            0 => gone.push(PathBuf::from(format!(r"HKEY_CURRENT_USER\{k}"))),
            2 => {} // ERROR_FILE_NOT_FOUND: not registered
            n => return Err(std::io::Error::from_raw_os_error(n as i32).into()),
        }
    }
    Ok(gone)
}
