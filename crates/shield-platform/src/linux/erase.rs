//! Linux primitives for secure delete (3.1.0 final): entry lookup with lstat (links never
//! followed), exclusive-ish opens (O_NOFOLLOW | O_NONBLOCK, refused unless a regular file), mount
//! points, the protected system folders and what may keep old data (copy-on-write and network
//! file systems, tmpfs, sparse files, cloud-synced folders).

use crate::{EntryInfo, EntryKind, FileId, Protected, WipeNote};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn info_of(m: &fs::Metadata) -> EntryInfo {
    let ft = m.file_type();
    let kind = if ft.is_symlink() {
        EntryKind::Link
    } else if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    EntryInfo { id: FileId { vol: m.dev(), idx: m.ino(), nlink: m.nlink() as u32, special: !ft.is_file() }, kind, size: if ft.is_file() { m.len() } else { 0 }, attrs: 0 }
}

/// Looks `p` up without following a final symlink (lstat).
pub fn entry_info(p: &Path) -> io::Result<EntryInfo> {
    Ok(info_of(&fs::symlink_metadata(p)?))
}

/// `entry_info` of an open handle (fstat).
pub fn entry_info_of(f: &File) -> io::Result<EntryInfo> {
    Ok(info_of(&f.metadata()?))
}

/// Opens a regular file for overwriting: O_NOFOLLOW (a symlink is refused), O_NONBLOCK (a FIFO
/// put in its place can't block the open), then fstat must say "regular file". Linux has no
/// mandatory sharing modes; the identity check by the caller covers a swapped file.
pub fn open_exclusive(p: &Path) -> io::Result<File> {
    let f = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// A read handle without following a link (fchmod works on it for the owner).
pub fn open_attrs(p: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(p)
}

/// Gives the owner write permission on the object behind `f` (fchmod; only after the identity
/// check). Linux can write a file without it as its owner only after this.
pub fn clear_readonly(f: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = f.metadata()?.permissions().mode();
    if mode & 0o200 == 0 {
        f.set_permissions(fs::Permissions::from_mode((mode | 0o200) & 0o7777))?;
    }
    Ok(())
}

/// "/" and every folder whose device differs from its parent's (a mount point; bind mounts of a
/// folder of the same file system are not seen this way).
pub fn is_mount_point(p: &Path) -> bool {
    let c = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let Some(parent) = c.parent() else { return true };
    match (fs::symlink_metadata(&c), fs::symlink_metadata(parent)) {
        (Ok(a), Ok(b)) => a.dev() != b.dev() || (a.dev() == b.dev() && a.ino() == b.ino()),
        _ => false,
    }
}

/// Fixed system folders (the folder and everything below it) and folders only refused themselves.
pub fn protected() -> Protected {
    let mut p = Protected::default();
    for s in ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/boot", "/dev", "/proc", "/sys", "/run", "/snap", "/efi"] {
        p.subtree.push(PathBuf::from(s));
    }
    for s in ["/", "/home", "/root", "/var", "/opt", "/srv", "/media", "/mnt", "/tmp", "/var/tmp", "/lost+found"] {
        p.exact.push(PathBuf::from(s));
    }
    if let Some(h) = dirs::home_dir() {
        p.exact.push(h);
    }
    p
}

const BTRFS: i64 = 0x9123_683E;
const ZFS: i64 = 0x2FC1_2FC1;
const BCACHEFS: i64 = 0xCA45_1A4E;
const OVERLAY: i64 = 0x794C_7630;
const NILFS: i64 = 0x3434;
const F2FS: i64 = 0xF2F5_2010;
const TMPFS: i64 = 0x0102_1994;
const NFS: i64 = 0x6969;
const CIFS: i64 = 0xFF53_4D42;
const SMB2: i64 = 0xFE53_4D42;
const SMB: i64 = 0x517B;
const FUSE: i64 = 0x6573_5546;
const CEPH: i64 = 0x00C3_6400;
const AFS: i64 = 0x5346_414F;

fn fs_type(p: &Path) -> Option<i64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { core::mem::zeroed() };
    (unsafe { libc::statfs(c.as_ptr(), &mut s) } == 0).then_some(s.f_type as i64)
}

fn cloud_roots() -> Vec<PathBuf> {
    let Some(h) = dirs::home_dir() else { return vec![] };
    ["Dropbox", "Nextcloud", "ownCloud", "OneDrive", "Google Drive", "GoogleDrive", "pCloudDrive", "MEGA", "Insync", "Seafile", "SpiderOak Hive", "Sync"].iter().map(|n| h.join(n)).collect()
}

/// What may keep old data of this file / folder (see `WipeNote`). `volume`: also the notes of
/// the file system holding it (asked once per file system by the caller).
pub fn wipe_notes(p: &Path, info: &EntryInfo, volume: bool) -> Vec<WipeNote> {
    let mut v = Vec::new();
    if info.kind == EntryKind::File {
        if let Ok(m) = fs::symlink_metadata(p) {
            // fewer allocated 512-byte blocks than the length: holes (sparse)
            if m.blocks().saturating_mul(512) < m.len() {
                v.push(WipeNote::Sparse);
            }
        }
    }
    let real = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if cloud_roots().iter().any(|r| real.starts_with(r)) {
        v.push(WipeNote::Cloud);
    }
    if volume {
        let dir = if info.kind == EntryKind::Dir { real.clone() } else { real.parent().map(Path::to_path_buf).unwrap_or_else(|| real.clone()) };
        match fs_type(&dir) {
            Some(BTRFS) => v.push(WipeNote::CopyOnWrite("btrfs".into())),
            Some(ZFS) => v.push(WipeNote::CopyOnWrite("ZFS".into())),
            Some(BCACHEFS) => v.push(WipeNote::CopyOnWrite("bcachefs".into())),
            Some(OVERLAY) => v.push(WipeNote::CopyOnWrite("overlayfs".into())),
            Some(NILFS) => v.push(WipeNote::CopyOnWrite("NILFS2".into())),
            Some(F2FS) => v.push(WipeNote::CopyOnWrite("F2FS".into())),
            Some(TMPFS) => v.push(WipeNote::RamBacked),
            Some(NFS | CIFS | SMB2 | SMB | CEPH | AFS) => v.push(WipeNote::Network),
            Some(FUSE) => v.push(WipeNote::Network),
            _ => {}
        }
    }
    v
}

/// `entry_info` of the entry `name` of the held folder `dir`: fstatat relative to the handle with
/// AT_SYMLINK_NOFOLLOW, so a folder on the way that was swapped for a link is never followed.
pub fn entry_info_at(dir: &File, name: &std::ffi::OsStr, _path: &Path) -> io::Result<EntryInfo> {
    use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a single entry name"));
    }
    let c = std::ffi::CString::new(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))?;
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fmt = st.st_mode & libc::S_IFMT;
    let kind = match fmt {
        libc::S_IFLNK => EntryKind::Link,
        libc::S_IFDIR => EntryKind::Dir,
        libc::S_IFREG => EntryKind::File,
        _ => EntryKind::Other,
    };
    Ok(EntryInfo {
        id: FileId { vol: st.st_dev, idx: st.st_ino, nlink: st.st_nlink as u32, special: fmt != libc::S_IFREG },
        kind,
        size: if fmt == libc::S_IFREG { st.st_size as u64 } else { 0 },
        attrs: 0,
    })
}

/// Linux has no reparse points.
pub fn is_reparse_other(_i: &EntryInfo) -> bool {
    false
}

/// Every mount point (from /proc/self/mountinfo, read with a size limit): bind mounts of a folder
/// of the same file system have the same device number and are only found this way.
pub fn mount_points() -> Vec<PathBuf> {
    match crate::bounded::read_text_limited(Path::new("/proc/self/mountinfo"), super::storage::MOUNTINFO_MAX) {
        Ok(t) => super::storage::parse_mountinfo(&t).into_iter().map(|m| m.point).collect(),
        Err(_) => Vec::new(),
    }
}

/// The config / data folder (3.1.0 final, review D): created as a 0700 folder when missing; an
/// existing one must be a real folder (not a link) owned by this user, and is set to 0700 when
/// group or others had any access. Anything else is an error (never "use it anyway").
pub fn ensure_data_dir(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(p) {
        Ok(()) => {}
        Err(x) if x.kind() == io::ErrorKind::AlreadyExists => {}
        Err(x) => return Err(x),
    }
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::other(format!("{} is not a real folder (a link or a file)", p.display())));
    }
    if m.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::other(format!("{} belongs to another user (uid {})", p.display(), m.uid())));
    }
    if m.mode() & 0o077 != 0 {
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A settings file or key file opened for reading is this user's own and not writable by others
/// (`key`: not readable by others either, 0600). A file that fails this is not used.
pub fn private_file_ok(f: &File, key: bool) -> bool {
    f.metadata().is_ok_and(|m| m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & if key { 0o077 } else { 0o022 } == 0)
}
