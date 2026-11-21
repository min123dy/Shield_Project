//! Linux file primitives: identity by fd, O_NOFOLLOW opens, 0700/0600 objects, renameat2
//! (RENAME_NOREPLACE), replace-and-keep-the-old-fd, checked unlink, lock files, and user extended
//! attributes as the counterpart of NTFS streams (`user.xdg.origin.url` = download mark).

pub use super::erase::{clear_readonly, ensure_data_dir, open_attrs, entry_info, entry_info_at, entry_info_of, is_mount_point, is_reparse_other, mount_points, open_exclusive, private_file_ok, protected, wipe_notes};
use crate::{FileId, MotwReport, NOREPLACE_DIR_REFUSED, PResult, PlatformError, Retained, Stream};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt, fs::PermissionsExt},
    path::{Path, PathBuf},
};

/// Download-origin attributes set by browsers and file managers (freedesktop convention).
pub const MARKS: [&str; 2] = ["user.xdg.origin.url", "user.xdg.referrer.url"];

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

pub fn open_no_follow(p: &Path, write: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(write).custom_flags(libc::O_NOFOLLOW);
    o.open(p)
}

pub fn file_id(f: &File) -> io::Result<FileId> {
    let m = f.metadata()?;
    Ok(FileId { vol: m.dev(), idx: m.ino(), nlink: m.nlink() as u32, special: !m.file_type().is_file() })
}

pub fn create_private_dir(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(p)?;
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(io::Error::other("private folder check failed"));
    }
    Ok(())
}

/// An existing folder only this user controls: a real folder (not a link), owned by this user,
/// not writable by group or others (security review 2026-11-08: `/tmp` fallback, shared data).
pub fn is_private_dir(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0)
}

/// Opens a folder itself (O_NOFOLLOW: a symlink is refused). Linux can't stop a rename while it
/// is open; callers compare `final_path` instead.
pub fn open_dir_held(p: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(p)
}

/// Where the object behind `f` is now (from /proc/self/fd; an error when /proc is missing).
pub fn final_path(f: &File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
}

fn cname(name: &std::ffi::OsStr) -> io::Result<CString> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a single entry name"));
    }
    CString::new(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))
}

/// Names in the folder behind the held handle `dir` (fdopendir on a duplicate of its fd), so the
/// folder read is the one that was checked, whatever happens to its path (3.1.0 #10). `_path` is
/// unused here (Windows lists by path while the held folder can't be renamed).
pub fn list_dir_held(dir: &File, _path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::{ffi::OsStringExt, io::AsRawFd};
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let x = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(x);
    }
    // the duplicate shares the read position with `dir`: start from the beginning
    unsafe { libc::rewinddir(d) };
    let mut out = Vec::new();
    let res = loop {
        unsafe { *libc::__errno_location() = 0 };
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            let x = io::Error::last_os_error();
            break if x.raw_os_error().unwrap_or(0) == 0 { Ok(()) } else { Err(x) };
        }
        let n = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if n != b"." && n != b".." {
            out.push(std::ffi::OsString::from_vec(n.to_vec()));
        }
    };
    unsafe { libc::closedir(d) }; // also closes fd
    res.map(|()| out)
}

/// Kind of the entry `name` of the held folder `dir`, without following a link (fstatat
/// AT_SYMLINK_NOFOLLOW relative to the handle).
pub fn entry_kind_at(dir: &File, name: &std::ffi::OsStr, _path: &Path) -> io::Result<crate::EntryKind> {
    use std::os::unix::io::AsRawFd;
    let c = cname(name)?;
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFLNK => crate::EntryKind::Link,
        libc::S_IFDIR => crate::EntryKind::Dir,
        libc::S_IFREG => crate::EntryKind::File,
        _ => crate::EntryKind::Other,
    })
}

fn open_at(dir: &File, name: &std::ffi::OsStr, flags: libc::c_int) -> io::Result<File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = cname(name)?;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens and holds the sub-folder `name` of the held folder `dir` (openat O_DIRECTORY|O_NOFOLLOW).
pub fn open_dir_at(dir: &File, name: &std::ffi::OsStr, _path: &Path) -> io::Result<File> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

/// Opens the file `name` of the held folder `dir` for reading (openat O_NOFOLLOW|O_NONBLOCK, so a
/// FIFO put in its place can't block) and refuses anything that is not a regular file.
pub fn open_file_at(dir: &File, name: &std::ffi::OsStr, _path: &Path) -> io::Result<File> {
    let f = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// Opens `p` for reading as a regular file only: O_NOFOLLOW|O_NONBLOCK (a FIFO can't block the
/// open), then fstat on the handle. Folders, devices, FIFOs, sockets and links are refused
/// (3.1.0 #14: "open in Shield" now receives any path).
pub fn open_regular(p: &Path) -> io::Result<File> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

pub fn create_private_file(p: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)
}

/// 0600 for files, 0700 for folders; a symlink is refused (chmod would follow it).
pub fn restrict_permissions(p: &Path) -> PResult<()> {
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() {
        return Err(PlatformError::Failed("refusing to change a symlink".into()));
    }
    fs::set_permissions(p, fs::Permissions::from_mode(if m.is_dir() { 0o700 } else { 0o600 }))?;
    Ok(())
}

pub fn is_reparse(m: &fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

pub fn is_hidden(name: &str, _md: Option<&fs::Metadata>) -> bool {
    name.starts_with('.')
}

fn sync_dir(p: &Path) {
    if let Some(d) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(f) = File::open(d) {
            let _ = f.sync_all();
        }
    }
}

/// rename(2) that fails with AlreadyExists instead of replacing (renameat2 RENAME_NOREPLACE).
/// File systems without renameat2 fall back to `rename_noreplace_fallback`.
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (a, b) = (cpath(from)?, cpath(to)?);
    let r = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), libc::RENAME_NOREPLACE) };
    if r == 0 {
        sync_dir(to);
        return Ok(());
    }
    let x = io::Error::last_os_error();
    if !matches!(x.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) {
        return Err(x);
    }
    rename_noreplace_fallback(from, to)
}

/// Whether a folder may be moved with a plain rename(2) into a folder with this owner and mode
/// (3.1.0 #11). Between "does the name exist" and rename(2) nobody else may be able to create the
/// name: so only into a folder owned by this user that neither group nor others can write.
pub fn dir_fallback_ok(parent_uid: u32, parent_mode: u32, euid: u32) -> bool {
    parent_uid == euid && parent_mode & 0o022 == 0
}

/// Without renameat2: files are hard-linked to the new name (link(2) fails with EEXIST, so it
/// never replaces) and then unlinked; folders only where `dir_fallback_ok` allows, otherwise the
/// move is refused with `NOREPLACE_DIR_REFUSED`.
pub fn rename_noreplace_fallback(from: &Path, to: &Path) -> io::Result<()> {
    if fs::symlink_metadata(from)?.is_dir() {
        let parent = match to.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let pm = fs::metadata(parent)?;
        if !dir_fallback_ok(pm.uid(), pm.mode(), unsafe { libc::geteuid() }) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, NOREPLACE_DIR_REFUSED));
        }
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists"));
        }
        fs::rename(from, to)?;
    } else {
        fs::hard_link(from, to)?;
        if let Err(x) = fs::remove_file(from) {
            // keep exactly one name: undo the link rather than leave two
            let _ = fs::remove_file(to);
            return Err(x);
        }
    }
    sync_dir(to);
    Ok(())
}

/// Atomic replace (rename(2)) plus a sync of the folder so the new name survives a crash.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)?;
    sync_dir(to);
    Ok(())
}

/// Opens the old `target`, renames `new` over it and returns the still-open old file: its data
/// stays allocated until the fd is closed, so the caller can overwrite it after the swap.
pub fn replace_keep_old(new: &Path, target: &Path, _backup: &Path) -> io::Result<Retained> {
    let old = open_no_follow(target, true)?;
    if !old.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    rename_replace(new, target)?;
    Ok(Retained::Open(old))
}

/// Unlinks `p` only if it still names the object behind `f` (same device and inode).
pub fn delete_checked(f: File, p: &Path) -> io::Result<()> {
    let a = f.metadata()?;
    let b = fs::symlink_metadata(p)?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(io::Error::other("file changed before deletion"));
    }
    fs::remove_file(p)?;
    drop(f);
    sync_dir(p);
    Ok(())
}

pub fn open_lock_file(p: &Path) -> io::Result<File> {
    if let Some(d) = p.parent() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
    }
    OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)
}

pub fn path_key(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// "/" first, then the home folder and removable media mount points.
pub fn roots() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/")];
    if let Some(h) = dirs::home_dir() {
        v.push(h);
    }
    for base in ["/media", "/mnt"] {
        if let Ok(rd) = fs::read_dir(base) {
            v.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
    }
    if let (Ok(rd), Some(user)) = (fs::read_dir("/run/media"), std::env::var_os("USER")) {
        drop(rd);
        if let Ok(rd) = fs::read_dir(Path::new("/run/media").join(user)) {
            v.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
    }
    v
}

pub fn system_dir() -> Option<PathBuf> {
    None
}

/// Root and system folders a Shield temp folder may never be removed from.
pub fn forbidden_parent(p: &Path) -> bool {
    const SYS: [&str; 12] = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr", "/var"];
    p.parent().is_none() || SYS.iter().any(|s| p == Path::new(s)) || p.starts_with("/proc") || p.starts_with("/sys") || p.starts_with("/dev")
}

pub fn free_space(dir: &Path) -> Option<u64> {
    let c = cpath(dir).ok()?;
    let mut s: libc::statvfs = unsafe { core::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| s.f_bavail as u64 * s.f_frsize as u64)
}

fn xattr_names(p: &Path) -> io::Result<Vec<String>> {
    let c = cpath(p)?;
    let n = unsafe { libc::llistxattr(c.as_ptr(), core::ptr::null_mut(), 0) };
    if n < 0 {
        let x = io::Error::last_os_error();
        return if x.raw_os_error() == Some(libc::ENOTSUP) { Ok(Vec::new()) } else { Err(x) };
    }
    let mut buf = vec![0u8; n as usize];
    let n = unsafe { libc::llistxattr(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf.split(|&b| b == 0).filter(|s| s.starts_with(b"user.")).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
}

fn xattr_get(p: &Path, name: &str) -> io::Result<Vec<u8>> {
    let (c, n) = (cpath(p)?, CString::new(name).map_err(io::Error::other)?);
    let len = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), core::ptr::null_mut(), 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut v = vec![0u8; len as usize];
    let len = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), v.as_mut_ptr() as *mut libc::c_void, v.len()) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    v.truncate(len as usize);
    Ok(v)
}

fn xattr_set(p: &Path, name: &str, v: &[u8]) -> io::Result<()> {
    let (c, n) = (cpath(p)?, CString::new(name).map_err(io::Error::other)?);
    if unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `user.*` extended attributes of `p` (the counterpart of NTFS named streams).
pub fn list_streams(p: &Path) -> io::Result<Vec<Stream>> {
    let mut out = Vec::new();
    for name in xattr_names(p)? {
        let size = xattr_get(p, &name).map(|v| v.len() as u64).unwrap_or(0);
        let is_mark = MARKS.contains(&name.as_str());
        out.push(Stream { name, size, is_mark });
    }
    Ok(out)
}

/// Rewrites each user xattr `passes` times with data from `fill`, then removes it. Whether the
/// file system rewrites the old value in place is not guaranteed (documented).
pub fn strip_streams(p: &Path, passes: usize, fill: &mut dyn FnMut(&mut [u8], usize)) -> PResult<u64> {
    let names = xattr_names(p)?;
    for name in &names {
        let len = xattr_get(p, name).map(|v| v.len()).unwrap_or(0);
        let mut buf = vec![0u8; len];
        for pass in 0..passes.max(1) {
            fill(&mut buf, pass);
            xattr_set(p, name, &buf)?;
        }
        let (c, n) = (cpath(p)?, CString::new(name.as_str()).map_err(io::Error::other)?);
        if unsafe { libc::lremovexattr(c.as_ptr(), n.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(names.len() as u64)
}

fn apply_marks(p: &Path, marks: &[(&str, Vec<u8>)], rep: &mut MotwReport) {
    let Ok(m) = fs::symlink_metadata(p) else {
        rep.failed.push(p.display().to_string());
        return;
    };
    if m.file_type().is_symlink() {
        return;
    }
    if m.is_dir() {
        match fs::read_dir(p) {
            Ok(rd) => rd.flatten().for_each(|en| apply_marks(&en.path(), marks, rep)),
            Err(_) => rep.failed.push(p.display().to_string()),
        }
        return;
    }
    match marks.iter().try_for_each(|(n, v)| xattr_set(p, n, v)) {
        Ok(()) => rep.marked += 1,
        Err(x) => rep.failed.push(format!("{} ({x})", p.display())),
    }
}

/// Copies the download-origin attributes of `src` to everything extracted. Desktop tools that
/// honour them (file managers, some viewers) then still see where the data came from.
pub fn motw_propagate(src: &Path, dst: &[PathBuf]) -> MotwReport {
    let marks: Vec<(&str, Vec<u8>)> = MARKS.iter().filter_map(|n| xattr_get(src, n).ok().filter(|v| !v.is_empty() && v.len() <= 8192).map(|v| (*n, v))).collect();
    let mut rep = MotwReport { had_mark: !marks.is_empty(), ..Default::default() };
    if rep.had_mark {
        for d in dst {
            apply_marks(d, &marks, &mut rep);
        }
    }
    rep
}

#[cfg(test)]
pub(crate) fn set_xattr_for_test(p: &Path, name: &str, v: &[u8]) -> io::Result<()> {
    xattr_set(p, name, v)
}
