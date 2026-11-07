//! OS-neutral helpers on top of `shield_platform`: memory/CPU/free space, file identity by handle,
//! no-follow opens, private (owner-only) folders and files, renames that never overwrite, path
//! keys and overlap checks. There is no OS-specific code in this crate; see `shield-platform`.

use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

pub use shield_platform::FileId;
use shield_platform::{fs as pfs, sys as psys};

pub fn cores() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1)
}

/// The user's home / profile folder.
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// Dot names, and on Windows the hidden attribute.
pub fn is_hidden(name: &str, md: Option<&fs::Metadata>) -> bool {
    pfs::is_hidden(name, md)
}

/// Available physical memory in bytes (Linux: MemAvailable; fallback 2 GiB).
pub fn avail_mem() -> u64 {
    psys::avail_mem()
}

/// Free bytes available to this user on the volume holding `dir`.
pub fn free_space(dir: &Path) -> Option<u64> {
    pfs::free_space(dir)
}

/// Fails early with a clear message when `dir` has less than `need` bytes free.
pub fn require_space(dir: &Path, need: u64, what: &str) -> Result<(), String> {
    match free_space(dir) {
        Some(f) if f < need => Err(crate::i18n::tf("sys.no_space", &[&what, &crate::ui_fmt::human(need), &crate::ui_fmt::human(f)])),
        _ => Ok(()),
    }
}

/// Opens without following a final symlink / junction.
pub fn open_no_follow(p: &Path, write: bool) -> io::Result<File> {
    pfs::open_no_follow(p, write)
}

/// See `shield_platform::fs::open_dir_held`.
pub fn open_dir_held(p: &Path) -> io::Result<File> {
    pfs::open_dir_held(p)
}

/// See `shield_platform::fs::final_path`.
pub fn final_path(f: &File) -> io::Result<PathBuf> {
    pfs::final_path(f)
}

pub fn file_id(f: &File) -> io::Result<FileId> {
    pfs::file_id(f)
}

/// Creates a new folder only the current user can access. Fails if anything already exists at
/// `p`, then checks that the result is a real folder (not a link).
pub fn create_private_dir(p: &Path) -> io::Result<()> {
    pfs::create_private_dir(p).map_err(|x| if x.kind() == io::ErrorKind::Other { io::Error::other(crate::i18n::t("sys.private_dir_check")) } else { x })
}

/// A folder this process can trust: created now as a private folder, or already there and
/// private (`shield_platform::fs::is_private_dir`: a real folder owned by this user, on Linux not
/// writable by others). A folder somebody else made or controls is refused instead of reused.
pub fn ensure_private_dir(p: &Path) -> io::Result<()> {
    match create_private_dir(p) {
        Ok(()) => Ok(()),
        Err(_) if pfs::is_private_dir(p) => Ok(()),
        Err(x) if x.kind() == io::ErrorKind::AlreadyExists || p.exists() => Err(io::Error::other(crate::i18n::t("sys.private_dir_check"))),
        Err(x) => Err(x),
    }
}

/// True for a reparse point (symlink, junction, mount point) on Windows; symlinks elsewhere.
pub fn is_reparse(m: &fs::Metadata) -> bool {
    pfs::is_reparse(m)
}

/// Creates a NEW file only the current user can access: the permissions are part of the create
/// call, so the file never exists with inherited ones (key files, B-13).
pub fn create_private_file(p: &Path) -> io::Result<File> {
    pfs::create_private_file(p)
}

/// Rename that fails instead of replacing an existing destination (Linux: renameat2 NOREPLACE).
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    pfs::rename_noreplace(from, to)
}

/// Atomic replace of `to` by `from` (same folder), written through to disk.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    pfs::rename_replace(from, to)
}

/// Deletes the object behind `f` only if it is still the one named `p` (by handle on Windows,
/// by device + inode check on Linux).
pub fn delete_checked(f: File, p: &Path) -> io::Result<()> {
    pfs::delete_checked(f, p)
}

/// Empties the clipboard (after a password was pasted). Returns false when it could not.
pub fn clear_clipboard() -> bool {
    psys::clear_clipboard()
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
    pfs::path_key(p)
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

/// Drive roots (Windows: existing A:\ .. Z:\; Linux: /, home, removable media).
pub fn roots() -> Vec<PathBuf> {
    pfs::roots()
}

/// Folders Shield never removes a temp folder from (drive roots, Windows folder, /etc, /usr ...).
pub fn forbidden_parent(p: &Path) -> bool {
    pfs::forbidden_parent(p)
}

pub fn is_shd(p: &Path) -> bool {
    p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("shd"))
}
