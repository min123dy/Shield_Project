//! Small OS helpers: memory/CPU/free space, file identity by handle, no-follow opens, private
//! (owner-only) folders and files, renames that never overwrite, system directory and clipboard.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

/// Identity of an opened file, read from the handle (not the path) to narrow TOCTOU windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub vol: u64,
    pub idx: u64,
    pub nlink: u32,
    /// The handle refers to a reparse point (symlink/junction) or a non-regular object.
    pub special: bool,
}

pub fn cores() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1)
}

#[cfg(windows)]
fn wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Available physical memory in bytes (fallback: 2 GiB when the OS can't tell).
pub fn avail_mem() -> u64 {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut m: MEMORYSTATUSEX = core::mem::zeroed();
        m.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut m) != 0 {
            return m.ullAvailPhys;
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let pages = libc::sysconf(libc::_SC_AVPHYS_PAGES);
        let size = libc::sysconf(libc::_SC_PAGESIZE);
        if pages > 0 && size > 0 {
            return pages as u64 * size as u64;
        }
    }
    2 << 30
}

/// Free bytes available to this user on the volume holding `dir`.
pub fn free_space(dir: &Path) -> Option<u64> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let w = wide(dir);
        let mut free = 0u64;
        if GetDiskFreeSpaceExW(w.as_ptr(), &mut free, core::ptr::null_mut(), core::ptr::null_mut()) != 0 {
            return Some(free);
        }
        None
    }
    #[cfg(unix)]
    unsafe {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut s: libc::statvfs = core::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut s) == 0 {
            return Some(s.f_bavail as u64 * s.f_frsize as u64);
        }
        None
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = dir;
        None
    }
}

/// Fails early with a clear message when `dir` has less than `need` bytes free.
pub fn require_space(dir: &Path, need: u64, what: &str) -> Result<(), String> {
    match free_space(dir) {
        Some(f) if f < need => Err(format!(
            "디스크 공간이 부족합니다 ({what}): 필요 약 {} / 남은 공간 {}. 작업을 시작하지 않았습니다.",
            crate::ui_fmt::human(need),
            crate::ui_fmt::human(f)
        )),
        _ => Ok(()),
    }
}

/// System32 from the API (not from the SystemRoot environment variable, which a caller controls).
#[cfg(windows)]
pub fn system_dir() -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    let mut buf = [0u16; 520];
    let n = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize]))
}

/// Opens without following a final symlink/junction. Windows: FILE_FLAG_OPEN_REPARSE_POINT.
pub fn open_no_follow(p: &Path, write: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    if write {
        o.write(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        if write {
            o.access_mode(0x8000_0000 | 0x4000_0000 | 0x0001_0000); // GENERIC_READ|WRITE|DELETE
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(p)
}

pub fn file_id(f: &File) -> io::Result<FileId> {
    #[cfg(windows)]
    unsafe {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
        let mut i: BY_HANDLE_FILE_INFORMATION = core::mem::zeroed();
        if GetFileInformationByHandle(f.as_raw_handle() as _, &mut i) == 0 {
            return Err(io::Error::last_os_error());
        }
        const REPARSE: u32 = 0x400;
        const DIR: u32 = 0x10;
        Ok(FileId {
            vol: i.dwVolumeSerialNumber as u64,
            idx: (i.nFileIndexHigh as u64) << 32 | i.nFileIndexLow as u64,
            nlink: i.nNumberOfLinks,
            special: i.dwFileAttributes & (REPARSE | DIR) != 0,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = f.metadata()?;
        Ok(FileId { vol: m.dev(), idx: m.ino(), nlink: m.nlink() as u32, special: !m.file_type().is_file() })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = f;
        Err(io::Error::other("unsupported"))
    }
}

#[cfg(windows)]
fn current_user_sid() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 256];
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr() as _, buf.len() as u32, &mut len);
        CloseHandle(tok);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: *mut u16 = core::ptr::null_mut();
        if ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as _);
        Ok(out)
    }
}

/// Runs `f` with a self-relative security descriptor built from `sddl`.
#[cfg(windows)]
fn with_sd<T>(sddl: &str, f: impl FnOnce(*mut core::ffi::c_void) -> T) -> io::Result<T> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    let w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), 1, &mut sd, core::ptr::null_mut()) == 0 {
            return Err(io::Error::last_os_error());
        }
        let r = f(sd);
        LocalFree(sd as _);
        Ok(r)
    }
}

/// Creates a new folder that only the current user (and SYSTEM) can access. Fails if anything
/// already exists at `p`, then checks that the result is a real folder (not a link).
pub fn create_private_dir(p: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
        let sid = current_user_sid()?;
        let sddl = format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)");
        let w = wide(p);
        let ok = with_sd(&sddl, |sd| unsafe {
            let sa = SECURITY_ATTRIBUTES {
                nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            CreateDirectoryW(w.as_ptr(), &sa) != 0
        })?;
        if !ok {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(p)?;
    }
    #[cfg(not(any(windows, unix)))]
    fs::create_dir(p)?;
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(io::Error::other("임시 폴더 검증 실패 (폴더가 아니거나 링크)"));
    }
    Ok(())
}

/// Restricts an existing file to the current user (key files).
pub fn restrict_file(p: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION};
        const PROTECTED: u32 = 0x8000_0000;
        let sid = current_user_sid()?;
        let w = wide(p);
        let r = with_sd(&format!("D:P(A;;FA;;;{sid})"), |sd| unsafe {
            let (mut present, mut def) = (0, 0);
            let mut dacl: *mut ACL = core::ptr::null_mut();
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut def) == 0 || present == 0 {
                return 1;
            }
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                dacl,
                core::ptr::null(),
            )
        })?;
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = p;
        Ok(())
    }
}

/// Rename that fails instead of replacing an existing destination.
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
        if MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), MOVEFILE_WRITE_THROUGH) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "대상이 이미 있습니다"));
        }
        if fs::metadata(from)?.is_dir() {
            return fs::rename(from, to); // small race accepted on non-Windows test hosts
        }
        fs::hard_link(from, to)?;
        fs::remove_file(from)
    }
}

/// Atomic replace of `to` by `from` (same folder), written through to disk.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
        if MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    fs::rename(from, to)
}

/// Marks an open handle for deletion (Windows) so the object deleted is the one that was checked.
#[cfg(windows)]
pub fn delete_by_handle(f: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO};
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    let ok = unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle() as _,
            FileDispositionInfo,
            &info as *const _ as _,
            core::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Empties the clipboard (after a password was pasted). Returns false when it could not.
pub fn clear_clipboard() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
        if OpenClipboard(0) == 0 {
            return false;
        }
        let ok = EmptyClipboard() != 0;
        CloseClipboard();
        ok
    }
    #[cfg(not(windows))]
    false
}

/// Resolves `p` for overlap checks (symlinks resolved; a missing file resolves through its parent).
pub fn resolve(p: &Path) -> Option<PathBuf> {
    if let Ok(c) = fs::canonicalize(p) {
        return Some(c);
    }
    let parent = p.parent().filter(|x| !x.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    Some(fs::canonicalize(parent).ok()?.join(p.file_name()?))
}

/// Case-insensitive on Windows (NTFS default), exact elsewhere.
pub fn path_key(p: &Path) -> String {
    let s = p.to_string_lossy().into_owned();
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

/// True when `inner` is `outer` or lies below it (after resolving links).
pub fn is_within(inner: &Path, outer: &Path) -> bool {
    match (resolve(inner), resolve(outer)) {
        (Some(i), Some(o)) => {
            let (i, o) = (path_key(&i), path_key(&o));
            let sep = std::path::MAIN_SEPARATOR;
            i == o || i.starts_with(&format!("{}{sep}", o.trim_end_matches(sep)))
        }
        _ => false,
    }
}

/// Drive roots (Windows: existing A:\ .. Z:\, elsewhere "/").
pub fn roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        ('A'..='Z').map(|c| PathBuf::from(format!("{c}:\\"))).filter(|p| p.exists()).collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

pub fn is_shd(p: &Path) -> bool {
    p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("shd"))
}
