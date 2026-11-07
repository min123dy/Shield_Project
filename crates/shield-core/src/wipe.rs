//! Shredding policy (3.0): 3 or 7 overwrite passes, key material always 7, old container data
//! after rekey / password change / add / remove, snapshot warnings before and TRIM after every
//! shred on flash storage, free-space overwrite.
//!
//! None of this can guarantee physical erasure on SSDs / flash (wear levelling, spare cells), on
//! copy-on-write file systems (btrfs, ZFS), on volumes with snapshots (VSS, btrfs, ZFS, LVM,
//! Timeshift, Snapper) or in cloud-synced folders. The messages say so.

use crate::entropy::{bulk_rng, rand_hex};
use crate::i18n::{t, tf};
use crate::manifest::FileRec;
use crate::progress::*;
use crate::sysinfo::{file_id, open_no_follow};
use rand::RngCore;
use shield_platform::{platform, PlatformError, Retained, SnapshotKind, SnapshotState, TrimNote};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub use shield_platform::StorageKind as Disk;

/// Number of overwrite passes the user chose.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Passes {
    Three,
    #[default]
    Seven,
}

/// 00, FF, random, 55, AA, random, random.
pub const PATTERNS7: [Option<u8>; 7] = [Some(0), Some(0xFF), None, Some(0x55), Some(0xAA), None, None];
/// 00, FF, random.
pub const PATTERNS3: [Option<u8>; 3] = [Some(0), Some(0xFF), None];

/// Key material (old key slots, the header of a replaced container, key files): always 7 passes.
pub const KEY_PASSES: Passes = Passes::Seven;

impl Passes {
    pub fn count(self) -> usize {
        self.patterns().len()
    }
    pub fn patterns(self) -> &'static [Option<u8>] {
        match self {
            Passes::Three => &PATTERNS3,
            Passes::Seven => &PATTERNS7,
        }
    }
    pub fn from_count(n: u64) -> Option<Passes> {
        match n {
            3 => Some(Passes::Three),
            7 => Some(Passes::Seven),
            _ => None,
        }
    }
}

/// Cleared by tests (and only there): a TRIM may open a UAC prompt on Windows.
pub static TRIM_ENABLED: AtomicBool = AtomicBool::new(!cfg!(test));

pub fn detect_disk(p: &Path) -> Disk {
    platform().detect_storage_kind(p)
}

/// "C:" or the mount point holding `p`.
pub fn volume_label(p: &Path) -> String {
    shield_platform::sys::volume_label(p)
}

/// The nearest existing folder of `p` (what the storage queries need).
fn existing_dir(p: &Path) -> PathBuf {
    let mut c = if p.is_dir() { p.to_path_buf() } else { p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.to_path_buf()) };
    while !c.exists() {
        match c.parent() {
            Some(x) if !x.as_os_str().is_empty() => c = x.to_path_buf(),
            _ => return std::env::temp_dir(),
        }
    }
    c
}

fn kind_name(k: SnapshotKind) -> &'static str {
    match k {
        SnapshotKind::Vss => t("wipe.snap_vss"),
        SnapshotKind::Btrfs => "btrfs",
        SnapshotKind::Zfs => "ZFS",
        SnapshotKind::Lvm => "LVM",
        SnapshotKind::Timeshift => "Timeshift",
        SnapshotKind::Snapper => "Snapper",
    }
}

/// What the user must know before anything on these paths is overwritten or deleted.
#[derive(Clone, Debug, Default)]
pub struct Exposure {
    /// One line per volume: snapshots found (emphasised) or that could not be checked.
    pub snapshot_lines: Vec<String>,
    /// Snapshots were really found on at least one volume (UI shows a strong warning).
    pub snapshots_found: bool,
    /// Some volume is flash / unknown storage: overwriting is not guaranteed there.
    pub not_guaranteed: bool,
}

/// Checks every distinct volume of `paths` for snapshots and storage type. Nothing is deleted;
/// Windows shadow copies are never touched (removing them needs administrator rights and is the
/// user's decision).
pub fn exposure(paths: &[&Path]) -> Exposure {
    let mut vols: BTreeMap<String, PathBuf> = BTreeMap::new();
    for p in paths {
        let d = existing_dir(p);
        vols.entry(volume_label(&d)).or_insert(d);
    }
    let mut ex = Exposure::default();
    for d in vols.values() {
        let s = platform().snapshot_warning(d);
        for (k, st) in &s.found {
            match st {
                SnapshotState::Found(n) => {
                    ex.snapshots_found = true;
                    let n = n.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
                    ex.snapshot_lines.push(tf("wipe.snap_found", &[&s.volume, &kind_name(*k), &n]));
                }
                SnapshotState::Unknown => ex.snapshot_lines.push(tf("wipe.snap_unknown", &[&s.volume, &kind_name(*k)])),
                SnapshotState::NoneFound => {}
            }
        }
        if detect_disk(d) != Disk::Hdd {
            ex.not_guaranteed = true;
        }
    }
    ex
}

impl Exposure {
    /// One message fragment (starts with " · ") for results, empty when there is nothing to say.
    pub fn note(&self) -> String {
        let mut s = String::new();
        for l in &self.snapshot_lines {
            s += &format!(" \u{00B7} {l}");
        }
        if self.not_guaranteed {
            s += t("eng.no_guarantee");
        }
        s
    }
}

/// TRIM of the volume holding `p`, as a result line. Never an error for the job: the caller adds
/// the text to the result.
pub fn trim(p: &Path) -> (bool, String) {
    let d = existing_dir(p);
    let vol = volume_label(&d);
    if !TRIM_ENABLED.load(Ordering::Relaxed) {
        return (true, tf("wipe.trim_skipped", &[&vol]));
    }
    match platform().run_trim(&d) {
        Ok(r) if r.note == Some(TrimNote::DiscardDisabled) => (false, tf("wipe.trim_luks", &[&r.volume])),
        Ok(r) if r.elevated => (true, tf("wipe.trim_done_admin", &[&r.volume])),
        Ok(r) => (true, tf("wipe.trim_done", &[&r.volume])),
        Err(PlatformError::Declined) => (false, t("wipe.trim_denied").to_string()),
        Err(PlatformError::NeedsPrivilege { hint }) => (false, tf("wipe.trim_needs_root", &[&vol, &hint])),
        Err(PlatformError::Unsupported(w)) => (false, tf("wipe.trim_unsupported", &[&vol, &w])),
        Err(x) => (false, tf("wipe.trim_failed", &[&vol, &x])),
    }
}

/// Last step of every shred: TRIM each distinct flash (or unknown) volume of `paths`.
/// Returns the result fragment (" · ..."); failures are shown, never fatal.
pub fn trim_after_shred(paths: &[&Path]) -> String {
    let mut seen = BTreeMap::new();
    for p in paths {
        let d = existing_dir(p);
        seen.entry(volume_label(&d)).or_insert(d);
    }
    let mut s = String::new();
    for d in seen.values() {
        if detect_disk(d) == Disk::Hdd {
            continue;
        }
        set_stage(ST_TRIM);
        s += &format!(" \u{00B7} {}", trim(d).1);
    }
    s
}

/// Overwrites the free space of the volume that holds `dir` (Windows cipher /w; Linux fill file).
pub fn wipe_free_space(dir: &Path) -> R<String> {
    match shield_platform::sys::wipe_free_space(dir, &cancelled) {
        Ok(Some(v)) => Ok(tf("wipe.free_done", &[&v])),
        Ok(None) => Err(cancelled_msg()),
        Err(PlatformError::Unsupported(w)) => Err(tf("wipe.free_unsupported", &[&w])),
        Err(x) => Err(tf("wipe.free_failed", &[&x])),
    }
}

/// Writes `len` bytes from offset `from` with every pattern, syncing after each pass.
fn overwrite(f: &mut File, from: u64, len: u64, pats: &[Option<u8>], progress: bool) -> Result<(), String> {
    let s = |x: std::io::Error| x.to_string();
    let mut rng = bulk_rng()?;
    let mut buf = vec![0u8; 1 << 20];
    for p in pats {
        f.seek(SeekFrom::Start(from)).map_err(s)?;
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            match p {
                Some(b) => buf[..n].fill(*b),
                None => rng.fill_bytes(&mut buf[..n]),
            }
            f.write_all(&buf[..n]).map_err(s)?;
            left -= n as u64;
            if progress {
                progress_add(n as u64);
            }
        }
        f.flush().map_err(s)?;
        f.sync_all().map_err(s)?;
    }
    Ok(())
}

pub enum ShredSkip {
    Changed,
    HardLink,
    Failed(String),
}

/// Overwrites through one checked handle, truncates, renames randomly and deletes.
/// Refuses: anything that is no longer the listed object (ID, size, time), hard links (other names
/// would keep the data), links/reparse points (handled as the link itself, never the target).
/// `streams`: also overwrite the extra streams (B-9). This happens after the identity check,
/// because writing a stream changes the file's modification time. Returns their number.
pub fn shred_checked(r: &FileRec, passes: Passes, streams: bool) -> Result<u64, ShredSkip> {
    let fail = |x: String| ShredSkip::Failed(x);
    let open = || open_no_follow(&r.path, true);
    let mut f = match open() {
        Ok(f) => f,
        Err(x) if x.kind() == std::io::ErrorKind::PermissionDenied => {
            // read-only attribute: check identity first, then clear it
            let ro = open_no_follow(&r.path, false).map_err(|x| fail(x.to_string()))?;
            let id = file_id(&ro).map_err(|x| fail(x.to_string()))?;
            if id.vol != r.id.vol || id.idx != r.id.idx || id.special {
                return Err(ShredSkip::Changed);
            }
            let mut perm = ro.metadata().map_err(|x| fail(x.to_string()))?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            drop(ro);
            fs::set_permissions(&r.path, perm).map_err(|x| fail(x.to_string()))?;
            open().map_err(|x| fail(x.to_string()))?
        }
        Err(x) => return Err(fail(x.to_string())),
    };
    let id = file_id(&f).map_err(|x| fail(x.to_string()))?;
    let md = f.metadata().map_err(|x| fail(x.to_string()))?;
    if id.special || id.vol != r.id.vol || id.idx != r.id.idx || md.len() != r.size || md.modified().ok() != r.mtime {
        return Err(ShredSkip::Changed);
    }
    if id.nlink > 1 {
        return Err(ShredSkip::HardLink);
    }
    let n_streams = if streams { crate::ads::overwrite_streams(&r.path, passes).map_err(fail)? } else { 0 };
    overwrite(&mut f, 0, md.len(), passes.patterns(), true).map_err(fail)?;
    f.set_len(0).map_err(|x| fail(x.to_string()))?;
    f.sync_all().map_err(|x| fail(x.to_string()))?;
    drop(f);
    delete_renamed(&r.path, (r.id.vol, r.id.idx)).map_err(|x| match x {
        Some(m) => fail(m),
        None => ShredSkip::Changed,
    })?;
    Ok(n_streams)
}

/// Hides the name (random rename), re-checks the identity by handle and deletes that object.
/// Err(None): the object under the new name is not the expected one (renamed back).
fn delete_renamed(path: &Path, id: (u64, u64)) -> Result<(), Option<String>> {
    let np = path.with_file_name(rand_hex().map_err(Some)?);
    fs::rename(path, &np).map_err(|x| Some(x.to_string()))?;
    let g = open_no_follow(&np, true).map_err(|x| Some(x.to_string()))?;
    let gid = file_id(&g).map_err(|x| Some(x.to_string()))?;
    if (gid.vol, gid.idx) != id {
        drop(g);
        let _ = fs::rename(&np, path);
        return Err(None);
    }
    crate::sysinfo::delete_checked(g, &np).map_err(|x| Some(x.to_string()))
}

/// Destroys the old contents of a replaced container (rekey, password change by rebuild, add,
/// remove): the first `key_len` bytes (key slots + meta) with KEY_PASSES, the rest with `passes`,
/// then deletes it. Windows: the ReplaceFileW backup file; Linux: the still-open old inode.
pub fn shred_retained(ret: Retained, key_len: u64, passes: Passes) -> Result<(), String> {
    let (mut f, path) = match ret {
        Retained::Path(p) => (open_no_follow(&p, true).map_err(|x| x.to_string())?, Some(p)),
        Retained::Open(f) => (f, None),
    };
    let len = f.metadata().map_err(|x| x.to_string())?.len();
    let k = key_len.min(len);
    overwrite(&mut f, 0, k, KEY_PASSES.patterns(), false)?;
    overwrite(&mut f, k, len - k, passes.patterns(), true)?;
    f.set_len(0).map_err(|x| x.to_string())?;
    f.sync_all().map_err(|x| x.to_string())?;
    match path {
        Some(p) => {
            let id = file_id(&f).map_err(|x| x.to_string())?;
            drop(f);
            delete_renamed(&p, (id.vol, id.idx)).map_err(|x| x.unwrap_or_else(|| t("wipe.backup_changed").to_string()))
        }
        None => Ok(()), // already unlinked: closing the fd frees it
    }
}

/// Swaps `new` in for `target` and shreds the old contents (see `shred_retained`). The swap itself
/// is atomic; a shred failure is returned as a warning (the new container is in place either way).
pub fn replace_and_shred(new: &Path, target: &Path, passes: Passes) -> R<Option<String>> {
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let backup = dir.join(format!(".shd_{}.old", rand_hex()?));
    let ret = shield_platform::fs::replace_keep_old(new, target, &backup).map_err(|x| tf("eng.replace_failed", &[&x]))?;
    set_stage(ST_SHRED);
    let key_len = crate::format::HEADER as u64;
    Ok(shred_retained(ret, key_len, passes).err().map(|x| tf("wipe.old_not_shredded", &[&x])))
}

/// Result of removing a Shield-created tree: overwrite and delete failures are reported apart, so
/// "deleted but not overwritten" is never shown as a clean removal.
#[derive(Default, Debug)]
pub struct TreeReport {
    pub overwrite_failed: Vec<String>,
    pub delete_failed: Vec<String>,
}

impl TreeReport {
    pub fn ok(&self) -> bool {
        self.overwrite_failed.is_empty() && self.delete_failed.is_empty()
    }
    pub fn message(&self) -> String {
        let mut m = Vec::new();
        if !self.overwrite_failed.is_empty() {
            m.push(tf("wipe.tree_overwrite_failed", &[&self.overwrite_failed.len(), &self.overwrite_failed.join(", ")]));
        }
        if !self.delete_failed.is_empty() {
            m.push(tf("wipe.tree_delete_failed", &[&self.delete_failed.len(), &self.delete_failed.join(", ")]));
        }
        m.join(" / ")
    }
}

/// Opens for writing; a read-only attribute (set by an extracted file's own attributes) is cleared
/// once and the open retried.
fn open_for_overwrite(p: &Path) -> std::io::Result<File> {
    match open_no_follow(p, true) {
        Err(x) if x.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut perm = fs::symlink_metadata(p)?.permissions();
            if !perm.readonly() {
                return Err(x);
            }
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            fs::set_permissions(p, perm)?;
            open_no_follow(p, true)
        }
        r => r,
    }
}

/// Overwrites one file with zeros and truncates it. Every error is returned.
fn overwrite_once(p: &Path, len: u64) -> std::io::Result<()> {
    let mut f = open_for_overwrite(p)?;
    let buf = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        f.write_all(&buf[..n])?;
        left -= n as u64;
    }
    f.flush()?;
    f.sync_all()?;
    f.set_len(0)?;
    f.sync_all()
}

fn shred_tree_into(p: &Path, rep: &mut TreeReport) {
    let name = || p.display().to_string();
    let m = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => return,
        Err(x) => return rep.delete_failed.push(format!("{} ({x})", name())),
    };
    if m.file_type().is_symlink() || (crate::sysinfo::is_reparse(&m) && !m.is_file()) {
        // a link is removed as a link, never followed
        if let Err(x) = fs::remove_file(p).or_else(|_| fs::remove_dir(p)) {
            rep.delete_failed.push(format!("{} ({x})", name()));
        }
        return;
    }
    if m.is_dir() {
        match fs::read_dir(p) {
            Ok(rd) => {
                for en in rd {
                    match en {
                        Ok(en) => shred_tree_into(&en.path(), rep),
                        Err(x) => rep.delete_failed.push(format!("{} ({x})", name())),
                    }
                }
            }
            Err(x) => return rep.delete_failed.push(format!("{} ({x})", name())),
        }
        if let Err(x) = fs::remove_dir(p) {
            rep.delete_failed.push(format!("{} ({x})", name()));
        }
        return;
    }
    if let Err(x) = overwrite_once(p, m.len()) {
        rep.overwrite_failed.push(format!("{} ({x})", name()));
    }
    if let Err(x) = fs::remove_file(p) {
        rep.delete_failed.push(format!("{} ({x})", name()));
    }
}

/// Removes a folder tree that Shield itself created (staging): files are overwritten once and
/// deleted; links are removed, never followed. Ok only when every file was overwritten and every
/// object deleted.
pub fn shred_own_tree_report(p: &Path) -> TreeReport {
    let mut rep = TreeReport::default();
    shred_tree_into(p, &mut rep);
    rep
}

pub fn shred_own_tree(p: &Path) -> R<()> {
    let rep = shred_own_tree_report(p);
    if rep.ok() {
        Ok(())
    } else {
        Err(rep.message())
    }
}

#[cfg(test)]
#[path = "wipe_tests.rs"]
mod tests;
