//! Windows file primitives: identity by handle, no-follow opens, owner-only objects, renames that
//! never overwrite, replace-with-backup, delete by handle, lock files, NTFS alternate data streams
//! and the Mark of the Web (Zone.Identifier).

use crate::{FileId, MotwReport, PResult, PlatformError, Retained, Stream};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use windows_sys::Win32::Foundation::LocalFree;

pub const ZONE: &str = "Zone.Identifier";

pub(crate) fn wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Opens without following a final symlink/junction (FILE_FLAG_OPEN_REPARSE_POINT).
pub fn open_no_follow(p: &Path, write: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut o = OpenOptions::new();
    o.read(true);
    if write {
        o.write(true);
        o.access_mode(0x8000_0000 | 0x4000_0000 | 0x0001_0000); // GENERIC_READ|WRITE|DELETE
    }
    o.custom_flags(0x0020_0000);
    o.open(p)
}

/// Opens a folder itself (never what a junction or link points to) and holds it: without
/// FILE_SHARE_DELETE nobody can rename, move or delete it while the handle is open. A reparse
/// point is refused.
pub fn open_dir_held(p: &Path) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let f = OpenOptions::new().read(true).share_mode(0x1 | 0x2).custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT).open(p)?;
    let a = f.metadata()?.file_attributes();
    if a & 0x10 == 0 || a & 0x400 != 0 {
        return Err(io::Error::other("not a real folder"));
    }
    Ok(f)
}

/// Where the object behind `f` really is (junctions and links resolved by the file system).
pub fn final_path(f: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let mut buf = vec![0u16; 1024];
    loop {
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle() as _, buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])));
        }
        buf.resize(n + 1, 0);
    }
}

pub fn file_id(f: &File) -> io::Result<FileId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut i) } == 0 {
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

pub(crate) fn current_user_sid() -> io::Result<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
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
pub(crate) fn with_sd<T>(sddl: &str, f: impl FnOnce(*mut core::ffi::c_void) -> T) -> io::Result<T> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    let w = wstr(sddl);
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

fn sa(sd: *mut core::ffi::c_void) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
    windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    }
}

/// New folder only the current user (and SYSTEM) can access; fails if anything exists at `p`.
pub fn create_private_dir(p: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let sid = current_user_sid()?;
    let w = wide(p);
    let ok = with_sd(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"), |sd| unsafe {
        let a = sa(sd);
        CreateDirectoryW(w.as_ptr(), &a) != 0
    })?;
    if !ok {
        return Err(io::Error::last_os_error());
    }
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || is_reparse(&m) {
        return Err(io::Error::other("private folder check failed"));
    }
    Ok(())
}

/// Owner of a file or folder as a string SID.
fn owner_sid(p: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Foundation::PSID;
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let w = wide(p);
    unsafe {
        let mut owner: PSID = core::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut sd);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let r = if owner.is_null() {
            Err(io::Error::other("no owner (file system without security)"))
        } else {
            let mut s: *mut u16 = core::ptr::null_mut();
            if ConvertSidToStringSidW(owner, &mut s) == 0 {
                Err(io::Error::last_os_error())
            } else {
                let mut n = 0;
                while *s.add(n) != 0 {
                    n += 1;
                }
                let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
                LocalFree(s as _);
                Ok(out)
            }
        };
        LocalFree(sd as _);
        r
    }
}

/// An existing folder only this user controls: a real folder (not a junction or link) owned by
/// this user. FAT/exFAT folders (no owner) do not count (security review 2026-11-08).
pub fn is_private_dir(p: &Path) -> bool {
    let Ok(m) = fs::symlink_metadata(p) else { return false };
    if !m.is_dir() || is_reparse(&m) {
        return false;
    }
    matches!((owner_sid(p), current_user_sid()), (Ok(a), Ok(b)) if a.eq_ignore_ascii_case(&b))
}

/// New file only the current user can access: the protected DACL is part of the create call.
pub fn create_private_file(p: &Path) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
    let sid = current_user_sid()?;
    let w = wide(p);
    let h = with_sd(&format!("D:P(A;;FA;;;{sid})"), |sd| unsafe {
        let a = sa(sd);
        CreateFileW(w.as_ptr(), 0x8000_0000 | 0x4000_0000, 0, &a, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0)
    })?;
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(h as _) })
}

/// Replaces the DACL of an existing object by a protected owner-only one (+ SYSTEM).
pub fn restrict_permissions(p: &Path) -> PResult<()> {
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    let sid = current_user_sid()?;
    let dir = fs::symlink_metadata(p)?.is_dir();
    let inherit = if dir { "OICI" } else { "" };
    let w = wide(p);
    let rc = with_sd(&format!("D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY)"), |sd| unsafe {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = core::ptr::null_mut();
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 || present == 0 {
            return u32::MAX;
        }
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            dacl,
            core::ptr::null(),
        )
    })?;
    match rc {
        0 => Ok(()),
        u32::MAX => Err(PlatformError::Failed("security descriptor".into())),
        n => Err(PlatformError::Io(io::Error::from_raw_os_error(n as i32))),
    }
}

pub fn is_reparse(m: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0
}

/// Dot names and the hidden attribute.
pub fn is_hidden(name: &str, md: Option<&fs::Metadata>) -> bool {
    use std::os::windows::fs::MetadataExt;
    name.starts_with('.') || md.is_some_and(|m| m.file_attributes() & 0x2 != 0)
}

/// Rename that fails instead of replacing an existing destination (write-through).
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    if unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Atomic replace of `to` by `from` (same folder), written through to disk.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    if unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Puts `new` in place of `target` in one step and keeps the old contents under `backup`
/// (ReplaceFileW), so the caller can shred them after the swap succeeded.
pub fn replace_keep_old(new: &Path, target: &Path, backup: &Path) -> io::Result<Retained> {
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    if fs::symlink_metadata(backup).is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "backup name taken"));
    }
    let (t, n, b) = (wide(target), wide(new), wide(backup));
    const REPLACEFILE_WRITE_THROUGH: u32 = 1;
    let ok = unsafe { ReplaceFileW(t.as_ptr(), n.as_ptr(), b.as_ptr(), REPLACEFILE_WRITE_THROUGH, core::ptr::null(), core::ptr::null()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Retained::Path(backup.to_path_buf()))
}

/// Deletes the object behind `f` (opened with DELETE access) by handle, so the object deleted is
/// the one that was checked, whatever happened to the name meanwhile.
pub fn delete_checked(f: File, _p: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO};
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    let ok = unsafe {
        SetFileInformationByHandle(f.as_raw_handle() as _, FileDispositionInfo, &info as *const _ as _, core::mem::size_of::<FILE_DISPOSITION_INFO>() as u32)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(f);
    Ok(())
}

/// Lock side file: shared READ|WRITE, no DELETE, so it can't be removed while somebody holds it.
pub fn open_lock_file(p: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    OpenOptions::new().read(true).write(true).create(true).truncate(false).share_mode(0x1 | 0x2).open(p)
}

/// Case-insensitive key (NTFS default).
pub fn path_key(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// Existing drive roots A:\ .. Z:\.
pub fn roots() -> Vec<PathBuf> {
    ('A'..='Z').map(|c| PathBuf::from(format!("{c}:\\"))).filter(|p| p.exists()).collect()
}

/// System32 from the API (not from %SystemRoot%, which a caller controls).
pub fn system_dir() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buf = [0u16; 520];
    let n = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return Some(PathBuf::from(r"C:\Windows\System32"));
    }
    Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize])))
}

/// Folders a Shield temp folder may never be removed from: drive roots and the Windows folder.
pub fn forbidden_parent(p: &Path) -> bool {
    let key = path_key(p);
    let win = system_dir().and_then(|s| s.parent().map(path_key)).unwrap_or_default();
    p.parent().is_none() || key.trim_end_matches(['\\', '/']).len() <= 3 || (!win.is_empty() && key.starts_with(&win))
}

/// Free bytes available to this user on the volume holding `dir`.
pub fn free_space(dir: &Path) -> Option<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let w = wide(dir);
    let mut free = 0u64;
    (unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, core::ptr::null_mut(), core::ptr::null_mut()) } != 0).then_some(free)
}

fn stream_path(p: &Path, name: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(":");
    s.push(name);
    PathBuf::from(s)
}

/// Named streams of `p` (the unnamed main stream is not included).
pub fn list_streams(p: &Path) -> io::Result<Vec<Stream>> {
    use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA};
    let w = wide(p);
    let mut d: WIN32_FIND_STREAM_DATA = unsafe { core::mem::zeroed() };
    let h = unsafe { FindFirstStreamW(w.as_ptr(), FindStreamInfoStandard, &mut d as *mut _ as _, 0) };
    if h == INVALID_HANDLE_VALUE {
        let x = io::Error::last_os_error();
        // ERROR_HANDLE_EOF: no streams (e.g. a folder); 87 / 1: file system without streams
        return match x.raw_os_error() {
            Some(c) if c == ERROR_HANDLE_EOF as i32 || c == 87 || c == 1 => Ok(Vec::new()),
            _ => Err(x),
        };
    }
    let mut out = Vec::new();
    loop {
        let n = d.cStreamName.iter().position(|&c| c == 0).unwrap_or(d.cStreamName.len());
        let full = String::from_utf16_lossy(&d.cStreamName[..n]);
        let name = full.strip_suffix(":$DATA").unwrap_or(&full);
        let name = name.strip_prefix(':').unwrap_or(name).to_string();
        if !name.is_empty() {
            let is_mark = name.eq_ignore_ascii_case(ZONE);
            out.push(Stream { name, size: d.StreamSize.max(0) as u64, is_mark });
        }
        if unsafe { FindNextStreamW(h, &mut d as *mut _ as _) } == 0 {
            let x = io::Error::last_os_error();
            unsafe { FindClose(h) };
            return if x.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) { Ok(out) } else { Err(x) };
        }
    }
}

/// Overwrites every named stream of `p` `passes` times (data from `fill`), then empties it.
pub fn strip_streams(p: &Path, passes: usize, fill: &mut dyn FnMut(&mut [u8], usize)) -> PResult<u64> {
    let streams = list_streams(p)?;
    let mut buf = vec![0u8; 1 << 16];
    for st in &streams {
        let mut f = OpenOptions::new().write(true).open(stream_path(p, &st.name))?;
        for pass in 0..passes.max(1) {
            f.seek(SeekFrom::Start(0))?;
            let mut left = st.size;
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                fill(&mut buf[..n], pass);
                f.write_all(&buf[..n])?;
                left -= n as u64;
            }
            f.sync_all()?;
        }
        f.set_len(0)?;
        f.sync_all()?;
    }
    Ok(streams.len() as u64)
}

/// Mark used when the original can't be copied: Internet zone.
const INTERNET_ZONE: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// Reads the Mark of the Web of `p` (None when it has none). A mark that is there but too large
/// (over 64 KiB) or unreadable becomes a plain Internet-zone mark instead of "no mark" (security
/// review 2026-11-08: an oversized mark used to drop the protection).
pub fn read_zone(p: &Path) -> Option<Vec<u8>> {
    let sp = stream_path(p, ZONE);
    match fs::metadata(&sp) {
        Err(x) if x.kind() == io::ErrorKind::NotFound => None,
        Ok(m) if m.len() == 0 => None,
        Ok(m) if m.len() > 64 * 1024 => Some(INTERNET_ZONE.to_vec()),
        _ => Some(fs::read(&sp).ok().filter(|z| !z.is_empty() && z.len() <= 64 * 1024).unwrap_or_else(|| INTERNET_ZONE.to_vec())),
    }
}

fn apply_zone(p: &Path, zone: &[u8], rep: &mut MotwReport) {
    let Ok(m) = fs::symlink_metadata(p) else {
        rep.failed.push(p.display().to_string());
        return;
    };
    if m.file_type().is_symlink() || is_reparse(&m) {
        return;
    }
    if m.is_dir() {
        match fs::read_dir(p) {
            Ok(rd) => rd.flatten().for_each(|en| apply_zone(&en.path(), zone, rep)),
            Err(_) => rep.failed.push(p.display().to_string()),
        }
        return;
    }
    match fs::write(stream_path(p, ZONE), zone) {
        Ok(()) => rep.marked += 1,
        Err(x) => rep.failed.push(format!("{} ({x})", p.display())),
    }
}

/// B-7 / CVE-2025-0411 class: files extracted from a downloaded container must keep its MotW.
pub fn motw_propagate(src: &Path, dst: &[PathBuf]) -> MotwReport {
    let mut rep = MotwReport::default();
    if let Some(z) = read_zone(src) {
        rep.had_mark = true;
        for d in dst {
            apply_zone(d, &z, &mut rep);
        }
    }
    rep
}

#[cfg(test)]
pub(crate) fn write_stream(p: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    fs::write(stream_path(p, name), data)
}

#[cfg(test)]
pub(crate) fn read_stream(p: &Path, name: &str) -> io::Result<Vec<u8>> {
    fs::read(stream_path(p, name))
}
