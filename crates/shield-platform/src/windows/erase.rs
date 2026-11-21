//! Windows primitives for secure delete (3.1.0 final): entry lookup without following reparse
//! points (and telling symlinks / junctions apart from cloud and other reparse points), exclusive
//! opens, volume mount points, the protected system folders and what may keep old data
//! (compression, sparse, EFS, cloud, network, ReFS).

use super::fs::{file_id, wide};
use crate::{EntryInfo, EntryKind, Protected, WipeNote};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const BACKUP_SEMANTICS: u32 = 0x0200_0000;
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const READ_ATTRIBUTES: u32 = 0x80;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;

const A_DIR: u32 = 0x10;
const A_REPARSE: u32 = 0x400;
const A_SPARSE: u32 = 0x200;
const A_COMPRESSED: u32 = 0x800;
const A_OFFLINE: u32 = 0x1000;
const A_ENCRYPTED: u32 = 0x4000;
const A_RECALL_ON_OPEN: u32 = 0x0004_0000;
const A_PINNED: u32 = 0x0008_0000;
const A_UNPINNED: u32 = 0x0010_0000;
const A_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// Attributes and reparse tag of the object behind `f` (FileAttributeTagInfo).
fn attr_tag(f: &File) -> io::Result<(u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO};
    let mut i: FILE_ATTRIBUTE_TAG_INFO = unsafe { core::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandleEx(f.as_raw_handle() as _, FileAttributeTagInfo, &mut i as *mut _ as *mut _, core::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((i.FileAttributes, i.ReparseTag))
}

/// Kind from attributes + reparse tag: only symlinks and junctions are `Link`.
pub fn kind_of(attrs: u32, tag: u32) -> EntryKind {
    if attrs & A_REPARSE != 0 {
        return if tag == TAG_SYMLINK || tag == TAG_MOUNT_POINT { EntryKind::Link } else { EntryKind::Other };
    }
    if attrs & A_DIR != 0 {
        EntryKind::Dir
    } else {
        EntryKind::File
    }
}

/// Looks `p` up without following it (FILE_FLAG_OPEN_REPARSE_POINT; folders too). Only read
/// attribute access is asked for, so files in use by others can still be looked at.
pub fn entry_info(p: &Path) -> io::Result<EntryInfo> {
    let f = OpenOptions::new().access_mode(READ_ATTRIBUTES).share_mode(0x7).custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT).open(p)?;
    let id = file_id(&f)?;
    let (attrs, tag) = attr_tag(&f)?;
    let size = if attrs & (A_DIR | A_REPARSE) == 0 { f.metadata()?.len() } else { 0 };
    Ok(EntryInfo { id, kind: kind_of(attrs, tag), size, attrs })
}

/// `entry_info` of an already open handle.
pub fn entry_info_of(f: &File) -> io::Result<EntryInfo> {
    let id = file_id(f)?;
    let (attrs, tag) = attr_tag(f)?;
    let size = if attrs & (A_DIR | A_REPARSE) == 0 { f.metadata()?.len() } else { 0 };
    Ok(EntryInfo { id, kind: kind_of(attrs, tag), size, attrs })
}

/// Opens a regular file for overwriting: the reparse point itself is never followed, read, write
/// and delete access and no sharing at all (nobody else can read, write, rename or delete it while
/// it is overwritten; a file in use is a sharing error instead).
pub fn open_exclusive(p: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).access_mode(GENERIC_READ | GENERIC_WRITE | DELETE).share_mode(0).custom_flags(OPEN_REPARSE_POINT).open(p)
}

/// A handle that can only read and change attributes (not the data), not following a link: what
/// `clear_readonly` needs (`SetFileInformationByHandle` wants FILE_WRITE_ATTRIBUTES). Shared, so
/// another program holding the file open is no reason to fail here.
pub fn open_attrs(p: &Path) -> io::Result<File> {
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const SHARE_ALL: u32 = 7;
    OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES).share_mode(SHARE_ALL).custom_flags(OPEN_REPARSE_POINT).open(p)
}

/// Clears the read-only attribute of the object behind `f` (after the identity check; `f` from
/// `open_attrs`).
pub fn clear_readonly(f: &File) -> io::Result<()> {
    let mut perm = f.metadata()?.permissions();
    if perm.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        f.set_permissions(perm)?;
    }
    Ok(())
}

/// The volume path ("C:\", "D:\mnt\vol\") that holds `p`.
fn volume_path(p: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;
    let w = wide(p);
    let mut buf = vec![0u16; 1024];
    if unsafe { GetVolumePathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } == 0 {
        return None;
    }
    let n = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

fn plain(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\UNC\").map(|r| format!(r"\\{r}")).or_else(|| s.strip_prefix(r"\\?\").map(String::from)).unwrap_or(s);
    s.trim_end_matches('\\').to_lowercase()
}

/// True for a drive root, a UNC share root and a folder a volume is mounted on.
pub fn is_mount_point(p: &Path) -> bool {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if c.parent().is_none() || plain(&c).len() <= 2 {
        return true;
    }
    volume_path(&c).is_some_and(|v| plain(Path::new(&v)) == plain(&c))
}

/// Folders secure delete refuses (from the known-folder API, not from environment variables a
/// caller controls). Every existing drive root is a mount point and refused separately.
pub fn protected() -> Protected {
    use windows_sys::Win32::UI::Shell::{FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_UserProfiles, FOLDERID_Windows};
    let kf = super::install::known_folder;
    let mut p = Protected::default();
    p.subtree.extend([kf(&FOLDERID_Windows), kf(&FOLDERID_ProgramFiles), kf(&FOLDERID_ProgramFilesX86)].into_iter().flatten());
    if let Some(w) = super::fs::system_dir().and_then(|s| s.parent().map(Path::to_path_buf)) {
        p.subtree.push(w);
    }
    p.exact.extend([kf(&FOLDERID_ProgramData), kf(&FOLDERID_UserProfiles), kf(&FOLDERID_Profile)].into_iter().flatten());
    p
}

fn drive_type_remote(p: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOTE: u32 = 4;
    let s = p.to_string_lossy();
    if s.starts_with(r"\\") && !s.starts_with(r"\\?\") || s.starts_with(r"\\?\UNC\") {
        return true;
    }
    volume_path(p).is_some_and(|v| unsafe { GetDriveTypeW(wide(Path::new(&v)).as_ptr()) } == DRIVE_REMOTE)
}

fn fs_name(p: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    let v = volume_path(p)?;
    let mut name = [0u16; 64];
    let ok = unsafe { GetVolumeInformationW(wide(Path::new(&v)).as_ptr(), core::ptr::null_mut(), 0, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), name.as_mut_ptr(), name.len() as u32) };
    (ok != 0).then(|| String::from_utf16_lossy(&name[..name.iter().position(|c| *c == 0).unwrap_or(0)]))
}

/// Folders kept in sync by a cloud client (OneDrive's own variables; the attributes of cloud files
/// are checked per file as well).
fn cloud_roots() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"].iter().filter_map(std::env::var_os).map(PathBuf::from).filter(|p| p.is_absolute()).collect();
    if let Some(h) = dirs::home_dir() {
        for n in ["Dropbox", "Google Drive", "iCloudDrive", "MEGA", "Box", "pCloud Drive", "Nextcloud", "ownCloud"] {
            v.push(h.join(n));
        }
    }
    v
}

fn under(p: &Path, root: &Path) -> bool {
    let (a, b) = (plain(p), plain(root));
    !b.is_empty() && (a == b || a.starts_with(&format!("{b}\\")))
}

/// What may keep old data of this file / folder (see `WipeNote`). `volume`: also the notes of
/// the whole volume (network, ReFS); asked once per volume by the caller.
pub fn wipe_notes(p: &Path, info: &EntryInfo, volume: bool) -> Vec<WipeNote> {
    let mut v = Vec::new();
    let a = info.attrs;
    if a & A_COMPRESSED != 0 {
        v.push(WipeNote::Compressed);
    }
    if a & A_SPARSE != 0 {
        v.push(WipeNote::Sparse);
    }
    if a & A_ENCRYPTED != 0 {
        v.push(WipeNote::Encrypted);
    }
    let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if a & (A_OFFLINE | A_RECALL_ON_OPEN | A_RECALL_ON_DATA_ACCESS | A_PINNED | A_UNPINNED) != 0 || cloud_roots().iter().any(|r| under(&real, r)) {
        v.push(WipeNote::Cloud);
    }
    if volume {
        if drive_type_remote(&real) {
            v.push(WipeNote::Network);
        }
        if let Some(n) = fs_name(&real).filter(|n| n.eq_ignore_ascii_case("ReFS")) {
            v.push(WipeNote::CopyOnWrite(n));
        }
    }
    v
}

/// `entry_info` of the entry `name` of the held folder `dir` (at `path`). Windows: the held folder
/// can't be renamed or moved while open, so the lookup by path reads the held folder's entry.
pub fn entry_info_at(_dir: &File, _name: &std::ffi::OsStr, path: &Path) -> io::Result<EntryInfo> {
    entry_info(path)
}

/// A reparse point that is neither a symlink nor a junction (cloud placeholder, dedup, WOF ...).
pub fn is_reparse_other(i: &EntryInfo) -> bool {
    i.kind == EntryKind::Other && i.attrs & A_REPARSE != 0
}

/// Folders a volume is mounted on are reparse points on Windows (never entered); no extra list.
pub fn mount_points() -> Vec<PathBuf> {
    Vec::new()
}

/// The data folder (%LOCALAPPDATA%\Shield or the portable Shield_data): created when missing; a
/// junction or symlink in its place is refused (it would send settings and keys elsewhere). The
/// owner is not compared on Windows: a folder created by an elevated Shield is owned by the
/// Administrators group and is still this user's (the profile's ACL protects it).
pub fn ensure_data_dir(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p)?;
    let m = std::fs::symlink_metadata(p)?;
    if !m.is_dir() || super::fs::is_reparse(&m) {
        return Err(io::Error::other(format!("{} is not a real folder (a junction, link or file)", p.display())));
    }
    Ok(())
}

/// Windows: the profile folder's ACL protects the settings files (see `ensure_data_dir`).
pub fn private_file_ok(_f: &File, _key: bool) -> bool {
    true
}
