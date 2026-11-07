//! Windows system helpers: memory, process start times, clipboard, UI language, dark mode, local
//! time, fonts, DPAPI sealing, URLs and the elevated helper used for TRIM.

use crate::{Civil, PResult, PlatformError, Sealed};
use std::{
    io,
    path::{Path, PathBuf},
};

pub fn avail_mem() -> u64 {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    unsafe {
        let mut m: MEMORYSTATUSEX = core::mem::zeroed();
        m.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut m) != 0 {
            return m.ullAvailPhys;
        }
    }
    2 << 30
}

/// Start time (FILETIME) of a running process, None when it does not exist (any more).
pub fn process_start(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return None;
        }
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut x, mut k, mut u) = (z, z, z, z);
        let mut code = 0u32;
        let ok = GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) != 0 && GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        (ok && code == 259).then_some((c.dwHighDateTime as u64) << 32 | c.dwLowDateTime as u64)
    }
}

/// Empties the clipboard (after a password was pasted).
pub fn clear_clipboard() -> bool {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
    unsafe {
        if OpenClipboard(0) == 0 {
            return false;
        }
        let ok = EmptyClipboard() != 0;
        CloseClipboard();
        ok
    }
}

pub fn system_lang_is_korean() -> bool {
    let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
    id & 0x3FF == 0x12
}

/// Windows "apps use dark mode" (AppsUseLightTheme = 0).
pub fn system_dark() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let key = super::fs::wstr("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
    let val = super::fs::wstr("AppsUseLightTheme");
    let mut data = 1u32;
    let mut len = 4u32;
    let r = unsafe { RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), val.as_ptr(), RRF_RT_REG_DWORD, core::ptr::null_mut(), &mut data as *mut u32 as _, &mut len) };
    r == 0 && data == 0
}

/// Dark or light title bar for every window of this process.
pub fn dark_title_bar(dark: bool) {
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    let v: i32 = dark as i32;
    for h in super::shell::own_windows() {
        unsafe {
            if DwmSetWindowAttribute(h, 20, &v as *const i32 as _, 4) != 0 {
                DwmSetWindowAttribute(h, 19, &v as *const i32 as _, 4);
            }
        }
    }
}

/// Local civil time with the time zone rules valid at that date (DST included).
pub fn local_time(secs: i64) -> Option<Civil> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    if secs <= -11_644_473_600 {
        return None;
    }
    let ft100 = (secs + 11_644_473_600) as u64 * 10_000_000;
    let ft = FILETIME { dwLowDateTime: ft100 as u32, dwHighDateTime: (ft100 >> 32) as u32 };
    unsafe {
        let mut utc: SYSTEMTIME = core::mem::zeroed();
        let mut loc: SYSTEMTIME = core::mem::zeroed();
        if FileTimeToSystemTime(&ft, &mut utc) != 0 && SystemTimeToTzSpecificLocalTime(core::ptr::null(), &utc, &mut loc) != 0 {
            return Some(Civil { y: loc.wYear as i64, mo: loc.wMonth as u32, d: loc.wDay as u32, h: loc.wHour as u32, mi: loc.wMinute as u32, s: loc.wSecond as u32 });
        }
    }
    None
}

/// Fonts with Hangul, best first: (path, face index).
pub fn font_candidates() -> Vec<(PathBuf, u32)> {
    let mut v = Vec::new();
    if let Some(win) = super::fs::system_dir().and_then(|s| s.parent().map(|p| p.to_path_buf())) {
        v.push((win.join("Fonts").join("malgun.ttf"), 0));
    }
    v
}

fn blob(d: &[u8]) -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB { cbData: d.len() as u32, pbData: d.as_ptr() as *mut u8 }
}

fn take_blob(b: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = unsafe { std::slice::from_raw_parts(b.pbData, b.cbData as usize) }.to_vec();
    unsafe {
        // the plaintext copy made by DPAPI is wiped before it is freed
        std::ptr::write_bytes(b.pbData, 0, b.cbData as usize);
        windows_sys::Win32::Foundation::LocalFree(b.pbData as _);
    }
    v
}

const DPAPI_UI_FORBIDDEN: u32 = 1;

/// DPAPI's optional entropy: tools that unseal every DPAPI blob of a user without knowing the
/// program that made it (credential dumpers) get nothing from these. It is not a secret: a
/// program running as this user that knows Shield can still pass it (security review
/// 2026-11-08, documented). Blobs sealed by 3.0.0 without it still open.
const DPAPI_ENTROPY: &[u8] = b"SHIELD-SEAL-v2 settings MAC key";

/// DPAPI (current user): another user or an offline copy of the disk can't unseal it; a program
/// running as the same user can.
pub fn seal(data: &[u8]) -> PResult<Sealed> {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: core::ptr::null_mut() };
    let ent = blob(DPAPI_ENTROPY);
    let ok = unsafe { CryptProtectData(&blob(data), core::ptr::null(), &ent, core::ptr::null(), core::ptr::null(), DPAPI_UI_FORBIDDEN, &mut out) };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(Sealed { bytes: take_blob(out), os_protected: true })
}

pub fn unseal(data: &[u8]) -> PResult<Vec<u8>> {
    unseal_with(data, Some(DPAPI_ENTROPY)).or_else(|_| unseal_with(data, None))
}

fn unseal_with(data: &[u8], entropy: Option<&[u8]>) -> PResult<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: core::ptr::null_mut() };
    let ent = entropy.map(blob);
    let ent_ptr = ent.as_ref().map_or(core::ptr::null(), |e| e as *const CRYPT_INTEGER_BLOB);
    let ok = unsafe { CryptUnprotectData(&blob(data), core::ptr::null_mut(), ent_ptr, core::ptr::null(), core::ptr::null(), DPAPI_UI_FORBIDDEN, &mut out) };
    if ok == 0 {
        return Err(PlatformError::Failed("DPAPI unseal failed".into()));
    }
    Ok(take_blob(out))
}

/// Test only: unseals the way a tool that does not know Shield would (no entropy).
#[cfg(test)]
pub(crate) fn unseal_without_entropy(data: &[u8]) -> PResult<Vec<u8>> {
    unseal_with(data, None)
}

/// Test only: seals the way 3.0.0 did (no entropy).
#[cfg(test)]
pub(crate) fn seal_3_0_0(data: &[u8]) -> PResult<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: core::ptr::null_mut() };
    let ok = unsafe { CryptProtectData(&blob(data), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), DPAPI_UI_FORBIDDEN, &mut out) };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(take_blob(out))
}

/// Runs `program` (a System32 tool) elevated (UAC "runas", hidden window) with `params` and
/// waits for it. Shield never elevates itself.
pub fn run_elevated(program: &Path, params: &str) -> io::Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
    if super::fs::system_dir().is_none_or(|s| program.parent() != Some(s.as_path())) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "only System32 programs are elevated"));
    }
    let exe = super::fs::wide(program);
    let (verb, params) = (super::fs::wstr("runas"), super::fs::wstr(params));
    unsafe {
        let mut i: SHELLEXECUTEINFOW = core::mem::zeroed();
        i.cbSize = core::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        i.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        i.lpVerb = verb.as_ptr();
        i.lpFile = exe.as_ptr();
        i.lpParameters = params.as_ptr();
        i.nShow = SW_HIDE;
        if ShellExecuteExW(&mut i) == 0 {
            return Err(io::Error::last_os_error());
        }
        if i.hProcess == 0 {
            return Err(io::Error::other("no process handle"));
        }
        WaitForSingleObject(i.hProcess, INFINITE);
        let mut code = 1u32;
        let r = if GetExitCodeProcess(i.hProcess, &mut code) == 0 { Err(io::Error::last_os_error()) } else { Ok(code) };
        CloseHandle(i.hProcess);
        r
    }
}

/// Console handle for "is this an interactive console" checks (CLI).
pub fn stdin_is_console() -> bool {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};
    let mut m = 0u32;
    unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut m) != 0 }
}
