//! E-1 Screen capture protection and E-4 dark title bar (Windows window attributes).
//!
//! `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` (Windows 10 2004+) removes the window from
//! screenshots, screen recording, Snipping Tool and most screen sharing; older systems fall back to
//! `WDA_MONITOR` (the window is captured as a black rectangle). The DWM peek/iconic attributes keep
//! the content out of the Alt+Tab / taskbar thumbnails and Aero Peek.
//!
//! Limits (shown in Settings): this blocks *software* capture through the normal Windows APIs only.
//! It does not stop a camera or phone, a capture card, a remote desktop/VM host that captures
//! below Windows, a kernel driver, or malware running as the same user.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Applied {
    /// WDA_EXCLUDEFROMCAPTURE
    Excluded,
    /// WDA_MONITOR (black rectangle)
    Monitor,
    /// Protection switched off by the user.
    Off,
}

pub const WDA_NONE: u32 = 0x00;
pub const WDA_MONITOR: u32 = 0x01;
pub const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

/// Which affinity to try, in order, for a requested state.
pub fn plan(on: bool) -> &'static [u32] {
    if on {
        &[WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR]
    } else {
        &[WDA_NONE]
    }
}

/// Window of this process (eframe has exactly one). Found by enumerating top-level windows.
#[cfg(windows)]
pub fn own_windows() -> Vec<isize> {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId};
    unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
        let v = &mut *(l as *mut Vec<isize>);
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, &mut pid);
        if pid == std::process::id() {
            v.push(h);
        }
        1
    }
    let mut v: Vec<isize> = Vec::new();
    unsafe { EnumWindows(Some(cb), &mut v as *mut _ as LPARAM) };
    v
}

/// Applies capture protection to every window of this process. Err = text for the status bar.
#[cfg(windows)]
pub fn apply(on: bool) -> Result<Applied, String> {
    use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_DISALLOW_PEEK, DWMWA_EXCLUDED_FROM_PEEK, DWMWA_FORCE_ICONIC_REPRESENTATION};
    use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity;
    let wins = own_windows();
    if wins.is_empty() {
        return Err(crate::i18n::t("cap.no_window").into());
    }
    let mut worst = Applied::Excluded;
    for h in wins {
        let mut done = None;
        for &a in plan(on) {
            if unsafe { SetWindowDisplayAffinity(h, a) } != 0 {
                done = Some(a);
                break;
            }
        }
        let flag: i32 = on as i32;
        for attr in [DWMWA_EXCLUDED_FROM_PEEK, DWMWA_DISALLOW_PEEK, DWMWA_FORCE_ICONIC_REPRESENTATION] {
            unsafe { DwmSetWindowAttribute(h, attr as u32, &flag as *const i32 as _, 4) };
        }
        match done {
            None => return Err(crate::i18n::tf("cap.failed", &[&std::io::Error::last_os_error()])),
            Some(WDA_NONE) => worst = Applied::Off,
            Some(WDA_MONITOR) if worst == Applied::Excluded => worst = Applied::Monitor,
            _ => {}
        }
    }
    Ok(worst)
}

#[cfg(not(windows))]
pub fn apply(on: bool) -> Result<Applied, String> {
    if on {
        Err(crate::i18n::t("cap.unsupported").into())
    } else {
        Ok(Applied::Off)
    }
}

/// Dark or light title bar (DWMWA_USE_IMMERSIVE_DARK_MODE, attribute 20; 19 on early Windows 10).
#[cfg(windows)]
pub fn dark_title_bar(dark: bool) {
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    let v: i32 = dark as i32;
    for h in own_windows() {
        unsafe {
            if DwmSetWindowAttribute(h, 20, &v as *const i32 as _, 4) != 0 {
                DwmSetWindowAttribute(h, 19, &v as *const i32 as _, 4);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn dark_title_bar(_dark: bool) {}

/// Windows "apps use dark mode" (AppsUseLightTheme = 0).
#[cfg(windows)]
pub fn system_dark() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0".encode_utf16().collect();
    let val: Vec<u16> = "AppsUseLightTheme\0".encode_utf16().collect();
    let mut data = 1u32;
    let mut len = 4u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), val.as_ptr(), RRF_RT_REG_DWORD, core::ptr::null_mut(), &mut data as *mut u32 as _, &mut len)
    };
    r == 0 && data == 0
}

#[cfg(not(windows))]
pub fn system_dark() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_prefers_exclusion_then_monitor() {
        assert_eq!(plan(true), &[0x11, 0x01]);
        assert_eq!(plan(false), &[0x00]);
    }
    #[test]
    fn default_and_damaged_settings_turn_protection_on() {
        assert!(crate::settings::Settings::default().capture_protect);
        assert!(crate::settings::Settings::from_toml("capture_protect = ???").capture_protect);
        assert!(crate::settings::Settings::from_toml("\u{0}\u{1}garbage").capture_protect);
    }
    #[cfg(windows)]
    #[test]
    fn without_a_window_the_failure_is_reported() {
        // the test process has no top-level window: apply must say so instead of claiming success
        if own_windows().is_empty() {
            assert!(apply(true).is_err());
        }
    }
}
