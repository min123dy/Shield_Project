//! Linux storage: mount lookup (/proc/self/mountinfo), SSD/HDD from /sys/block/*/queue/rotational
//! through partitions, device-mapper (dm-crypt / LVM) and NVMe; FITRIM; snapshot detection for
//! btrfs, ZFS, LVM, Timeshift and Snapper; free-space overwrite by a fill file.

use super::sys::run_quiet;
use crate::{PResult, PlatformError, SnapshotInfo, SnapshotKind, SnapshotState, StorageKind, TrimNote, TrimReport};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mount {
    pub point: PathBuf,
    pub fstype: String,
    pub source: String,
}

/// Undoes the octal escapes of mountinfo (\040 = space, \011 = tab, \012 = newline, \134 = \).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let (a, b) = l.split_once(" - ")?;
            let a: Vec<&str> = a.split(' ').collect();
            let mut b = b.split(' ');
            Some(Mount { point: PathBuf::from(unescape(a.get(4)?)), fstype: b.next()?.to_string(), source: unescape(b.next()?) })
        })
        .collect()
}

/// The mount that holds `p` (longest matching mount point; the last one wins on stacked mounts).
pub(crate) fn mount_of(p: &Path) -> Option<Mount> {
    let c = fs::canonicalize(p).or_else(|_| p.parent().map(fs::canonicalize).unwrap_or(Ok(p.to_path_buf()))).ok()?;
    let all = parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").ok()?);
    let mut best: Option<Mount> = None;
    for m in all {
        if c.starts_with(&m.point) && best.as_ref().is_none_or(|b| m.point.components().count() >= b.point.components().count()) {
            best = Some(m);
        }
    }
    best
}

pub fn volume_label(p: &Path) -> String {
    mount_of(p).map(|m| m.point.display().to_string()).unwrap_or_else(|| p.display().to_string())
}

/// /sys/dev/block/MAJ:MIN of the block device behind `p`; via the mount source when st_dev is an
/// anonymous device (btrfs subvolumes, major 0).
fn block_dir(p: &Path) -> Option<PathBuf> {
    let md = fs::metadata(p).or_else(|_| p.parent().map(fs::metadata).unwrap_or_else(|| fs::metadata(p))).ok()?;
    let mut dev = md.dev();
    if libc::major(dev) == 0 {
        let m = mount_of(p)?;
        if !m.source.starts_with("/dev/") {
            return None;
        }
        dev = fs::metadata(&m.source).ok()?.rdev();
    }
    let d = PathBuf::from(format!("/sys/dev/block/{}:{}", libc::major(dev), libc::minor(dev)));
    fs::canonicalize(d).ok()
}

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn slaves(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir.join("slaves")).map(|rd| rd.flatten().filter_map(|e| fs::canonicalize(e.path()).ok()).collect()).unwrap_or_default()
}

/// Some(true) = rotational. Device-mapper stacks are followed to their real disks: any rotational
/// member makes the whole volume count as HDD-like (overwrite applies there), all flash = SSD.
fn rotational(dir: &Path, depth: u32) -> Option<bool> {
    if depth > 8 {
        return None;
    }
    let sl = slaves(dir);
    if !sl.is_empty() {
        let r: Vec<Option<bool>> = sl.iter().map(|s| rotational(s, depth + 1)).collect();
        return if r.contains(&Some(true)) {
            Some(true)
        } else if r.iter().all(|x| *x == Some(false)) {
            Some(false)
        } else {
            None
        };
    }
    let own = read_trim(&dir.join("queue/rotational")).or_else(|| dir.parent().and_then(|p| read_trim(&p.join("queue/rotational"))));
    own.map(|v| v == "1")
}

fn dm_uuid(dir: &Path) -> Option<String> {
    read_trim(&dir.join("dm/uuid"))
}

fn has_crypt(dir: &Path, depth: u32) -> bool {
    depth <= 8 && (dm_uuid(dir).is_some_and(|u| u.starts_with("CRYPT-")) || slaves(dir).iter().any(|s| has_crypt(s, depth + 1)))
}

pub fn detect(p: &Path) -> StorageKind {
    match block_dir(p).and_then(|d| rotational(&d, 0)) {
        Some(true) => StorageKind::Hdd,
        Some(false) => StorageKind::Ssd,
        None => StorageKind::Unknown,
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}
/// _IOWR('X', 121, struct fstrim_range)
const FITRIM: u64 = 0xC018_5879;

pub fn trim(p: &Path) -> PResult<TrimReport> {
    use std::os::unix::fs::OpenOptionsExt;
    let m = mount_of(p).ok_or(PlatformError::Unsupported("mount point not found"))?;
    let volume = m.point.display().to_string();
    let crypt = block_dir(p).is_some_and(|d| has_crypt(&d, 0));
    let f = fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(&m.point)?;
    let mut r = FstrimRange { start: 0, len: u64::MAX, minlen: 0 };
    let rc = unsafe { libc::ioctl(std::os::unix::io::AsRawFd::as_raw_fd(&f), FITRIM as _, &mut r) };
    if rc == 0 {
        return Ok(TrimReport { volume, elevated: false, note: None });
    }
    let x = io::Error::last_os_error();
    match x.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Err(PlatformError::NeedsPrivilege { hint: format!("sudo fstrim -v {}", shell_quote(&volume)) }),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) | Some(libc::EINVAL) if crypt => Ok(TrimReport { volume, elevated: false, note: Some(TrimNote::DiscardDisabled) }),
        Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) => Err(PlatformError::Unsupported("file system or device without discard")),
        _ => Err(x.into()),
    }
}

/// Overwrites the free space of the volume holding `dir` with one pass of pseudo-random data
/// (not compressible) in a private fill file, then deletes it. Refused on RAM file systems.
pub fn wipe_free_space(dir: &Path, cancelled: &dyn Fn() -> bool) -> PResult<Option<String>> {
    let m = mount_of(dir).ok_or(PlatformError::Unsupported("mount point not found"))?;
    if matches!(m.fstype.as_str(), "tmpfs" | "ramfs" | "devtmpfs" | "proc" | "sysfs") {
        return Err(PlatformError::Unsupported("RAM file system"));
    }
    let mut seed = crate::cpu::cycle_counter().unwrap_or(0) ^ std::process::id() as u64 ^ 0x9E37_79B9_7F4A_7C15;
    let path = dir.join(format!(".shield-free-{seed:016x}"));
    let mut f = super::fs::create_private_file(&path)?;
    let mut buf = vec![0u8; 1 << 20];
    let res = loop {
        if cancelled() {
            break Ok(None);
        }
        for c in buf.chunks_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            c.copy_from_slice(&seed.to_le_bytes()[..c.len()]);
        }
        match f.write_all(&buf) {
            Ok(()) => {}
            Err(x) if matches!(x.raw_os_error(), Some(libc::ENOSPC) | Some(libc::EDQUOT) | Some(libc::EFBIG)) => break Ok(Some(m.point.display().to_string())),
            Err(x) => break Err(x.into()),
        }
    };
    let _ = f.sync_all();
    drop(f);
    let _ = fs::remove_file(&path);
    res
}

fn count_dir(p: &str) -> Option<u64> {
    fs::read_dir(p).ok().map(|rd| rd.flatten().count() as u64)
}

fn lvm_state(dir: &Path) -> Option<SnapshotState> {
    let chain: Vec<PathBuf> = std::iter::once(dir.to_path_buf()).chain(slaves(dir)).collect();
    let lv = chain.iter().find(|d| dm_uuid(d).is_some_and(|u| u.starts_with("LVM-")))?;
    let name = read_trim(&lv.join("dm/name"))?;
    // an LV with snapshots is remapped as "snapshot-origin" on top of "<name>-real"
    let real = format!("{name}-real");
    let any = fs::read_dir("/sys/block").ok()?.flatten().any(|e| read_trim(&e.path().join("dm/name")).as_deref() == Some(real.as_str()));
    Some(if any { SnapshotState::Found(None) } else { SnapshotState::NoneFound })
}

fn zfs_state(dataset: &str) -> SnapshotState {
    let args = [OsStr::new("list"), OsStr::new("-H"), OsStr::new("-t"), OsStr::new("snapshot"), OsStr::new("-o"), OsStr::new("name"), OsStr::new("-d"), OsStr::new("1"), OsStr::new(dataset)];
    match run_quiet(&["/usr/sbin/zfs", "/sbin/zfs", "/usr/bin/zfs"], &args, Duration::from_secs(3)) {
        Some(out) => match out.lines().filter(|l| !l.trim().is_empty()).count() as u64 {
            0 => SnapshotState::NoneFound,
            n => SnapshotState::Found(Some(n)),
        },
        None => SnapshotState::Unknown,
    }
}

fn btrfs_state(point: &Path) -> SnapshotState {
    // listing snapshots needs root; without it the answer is "unknown", never "none"
    let args = [OsStr::new("subvolume"), OsStr::new("list"), OsStr::new("-s"), point.as_os_str()];
    match run_quiet(&["/usr/bin/btrfs", "/usr/sbin/btrfs", "/sbin/btrfs", "/bin/btrfs"], &args, Duration::from_secs(3)) {
        Some(out) => match out.lines().filter(|l| !l.trim().is_empty()).count() as u64 {
            0 => SnapshotState::NoneFound,
            n => SnapshotState::Found(Some(n)),
        },
        None => SnapshotState::Unknown,
    }
}

/// Snapshot mechanisms that may keep old copies of `p`. Nothing is ever deleted.
pub fn snapshots(p: &Path) -> SnapshotInfo {
    let m = mount_of(p);
    let volume = m.as_ref().map(|m| m.point.display().to_string()).unwrap_or_else(|| p.display().to_string());
    let mut found = Vec::new();
    if let Some(m) = &m {
        match m.fstype.as_str() {
            "btrfs" => found.push((SnapshotKind::Btrfs, btrfs_state(&m.point))),
            "zfs" => found.push((SnapshotKind::Zfs, zfs_state(&m.source))),
            _ => {}
        }
    }
    if let Some(s) = block_dir(p).and_then(|d| lvm_state(&d)) {
        found.push((SnapshotKind::Lvm, s));
    }
    let ts_dirs = ["/timeshift/snapshots", "/timeshift-btrfs/snapshots", "/run/timeshift/backup/timeshift/snapshots", "/run/timeshift/backup/timeshift-btrfs/snapshots"];
    let ts_count: Option<u64> = ts_dirs.iter().filter_map(|d| count_dir(d)).reduce(|a, b| a + b);
    if ts_count.is_some() || Path::new("/etc/timeshift/timeshift.json").exists() || Path::new("/etc/timeshift.json").exists() {
        found.push((SnapshotKind::Timeshift, match ts_count {
            Some(0) => SnapshotState::NoneFound,
            Some(n) => SnapshotState::Found(Some(n)),
            None => SnapshotState::Unknown,
        }));
    }
    if count_dir("/etc/snapper/configs").is_some_and(|n| n > 0) {
        let dir = m.as_ref().map(|m| m.point.join(".snapshots")).unwrap_or_else(|| PathBuf::from("/.snapshots"));
        found.push((SnapshotKind::Snapper, match fs::read_dir(&dir) {
            Ok(rd) => match rd.flatten().count() as u64 {
                0 => SnapshotState::NoneFound,
                n => SnapshotState::Found(Some(n)),
            },
            Err(_) => SnapshotState::Unknown,
        }));
    }
    SnapshotInfo { volume, found }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mountinfo_parse_and_unescape() {
        let t = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
                 40 22 0:35 / /mnt/my\\040disk rw - btrfs /dev/mapper/vg-root rw,ssd\n";
        let m = parse_mountinfo(t);
        assert_eq!(m.len(), 2);
        assert_eq!(m[1].point, PathBuf::from("/mnt/my disk"));
        assert_eq!((m[1].fstype.as_str(), m[1].source.as_str()), ("btrfs", "/dev/mapper/vg-root"));
        assert_eq!(unescape("a\\134b\\011"), "a\\b\t");
        assert_eq!(unescape("bad\\9"), "bad\\9");
    }
    #[test]
    fn quote_for_hint() {
        assert_eq!(shell_quote("/mnt/it's"), "'/mnt/it'\\''s'");
    }
}
