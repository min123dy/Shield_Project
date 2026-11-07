//! The fixed target list of an encryption, its SHA3-512 fingerprints, the comparison with the
//! restored archive and the shredding of exactly (and only) the listed, unchanged files.

use crate::i18n::tf;
use crate::progress::*;
use crate::sysinfo::{file_id, final_path, open_dir_held, open_no_follow, FileId};
use sha3::{Digest, Sha3_512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

pub struct FileRec {
    /// Archive entry name ("Docs/a.txt").
    pub rel: String,
    pub path: PathBuf,
    pub id: FileId,
    pub size: u64,
    pub mtime: Option<SystemTime>,
    pub hash: Option<[u8; 64]>,
}

#[derive(Default)]
pub struct Manifest {
    pub dirs: Vec<(String, PathBuf)>,
    pub files: Vec<FileRec>,
    /// Links, junctions and special files that were not included.
    pub skipped: u64,
    pub total: u64,
}

/// Reader that hashes (SHA3-512), counts, reports progress and aborts on cancel.
pub struct HashingReader<Rd> {
    pub inner: Rd,
    pub h: Sha3_512,
    pub n: u64,
}
impl<Rd> HashingReader<Rd> {
    pub fn new(inner: Rd) -> Self {
        HashingReader { inner, h: Sha3_512::new(), n: 0 }
    }
    pub fn digest(self) -> [u8; 64] {
        let mut a = [0u8; 64];
        a.copy_from_slice(&self.h.finalize());
        a
    }
}
impl<Rd: Read> Read for HashingReader<Rd> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, cancelled_msg()));
        }
        let n = self.inner.read(b)?;
        self.h.update(&b[..n]);
        self.n += n as u64;
        progress_add(n as u64);
        Ok(n)
    }
}

fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{a}/{b}"),
    }
}

impl Manifest {
    /// Fixes the list of `src` (a file or a folder; entries named "<its name>/...", below
    /// `prefix`). A link given as the top item is resolved (like before); nothing below follows.
    pub fn scan(src: &Path, prefix: &str, m: &mut Manifest) -> R<()> {
        let base = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        Self::scan_named(src, prefix, &base, m)
    }

    /// `scan` with an explicit top-level entry name (multi-item bundles rename colliding names).
    pub fn scan_named(src: &Path, prefix: &str, base: &str, m: &mut Manifest) -> R<()> {
        let is_link = fs::symlink_metadata(src).map_err(|x| format!("{}: {x}", src.display()))?.file_type().is_symlink();
        let real = if is_link { fs::canonicalize(src).map_err(e)? } else { src.to_path_buf() };
        walk(&real, &join(prefix, base), m, None)
    }

    /// Opens a listed file for reading and confirms it is still the same, unchanged object.
    pub fn open_checked(r: &FileRec) -> R<File> {
        let f = open_no_follow(&r.path, false).map_err(|x| format!("{}: {x}", r.path.display()))?;
        let id = file_id(&f).map_err(e)?;
        let md = f.metadata().map_err(e)?;
        if id.vol != r.id.vol || id.idx != r.id.idx || md.len() != r.size || md.modified().ok() != r.mtime {
            return Err(tf("man.changed", &[&r.path.display()]));
        }
        Ok(f)
    }

    /// Expected restore result: (path -> (size, SHA3-512)) and the folder set. Every listed file
    /// must have been hashed while packing.
    pub fn expected(&self, files: &mut Digests, dirs: &mut BTreeSet<String>) -> R<()> {
        for r in &self.files {
            let h = r.hash.ok_or_else(|| tf("man.no_hash", &[&r.rel]))?;
            files.insert(r.rel.clone(), (r.size, h));
        }
        dirs.extend(self.dirs.iter().map(|(d, _)| d.clone()));
        Ok(())
    }
}

pub type Digests = BTreeMap<String, (u64, [u8; 64])>;

/// Compares the restored archive with the expected list: same paths, sizes and SHA3-512.
pub fn compare(want: &Digests, want_dirs: &BTreeSet<String>, got: &Digests, got_dirs: &BTreeSet<String>) -> R<()> {
    let fail = |w: String| Err(tf("man.verify_failed", &[&w]));
    if got.len() != want.len() {
        return fail(tf("man.count_mismatch", &[&want.len(), &got.len()]));
    }
    for (name, (size, h)) in want {
        match got.get(name) {
            Some((sz, g)) if sz == size && crate::password::ct_eq(g, h) => {}
            _ => return fail(tf("man.content_differs", &[&name])),
        }
    }
    if let Some(d) = want_dirs.iter().find(|d| !got_dirs.contains(*d)) {
        return fail(tf("man.dir_missing", &[&d]));
    }
    Ok(())
}

/// True when `child` (where an opened entry really is) lies directly in `parent` (where its
/// held folder really is). Unknown on either side (Linux without /proc) counts as inside.
fn directly_in(child: &io::Result<PathBuf>, parent: Option<&Path>) -> bool {
    match (child, parent) {
        (Ok(c), Some(p)) => c.parent() == Some(p),
        _ => true,
    }
}

/// `parent_real`: where the folder being listed really is (from its held handle). Every entry
/// listed must really be in it: a folder replaced by a link or junction between the check and
/// the listing would otherwise list - and after encryption shred - files somewhere else
/// (security review 2026-11-08). Windows also keeps the held folder from being renamed.
fn walk(p: &Path, name: &str, m: &mut Manifest, parent_real: Option<&Path>) -> R<()> {
    check_cancel()?;
    let md = fs::symlink_metadata(p).map_err(|x| format!("{}: {x}", p.display()))?;
    if md.file_type().is_symlink() {
        m.skipped += 1;
        return Ok(());
    }
    if m.files.len() as u64 + m.dirs.len() as u64 >= crate::format::MAX_FILES {
        return Err(tf("man.too_many", &[&crate::format::MAX_FILES]));
    }
    let name = name.to_string();
    if md.is_dir() {
        let held = open_dir_held(p).map_err(|x| tf("man.moved_while_listing", &[&p.display(), &x]))?;
        let real = final_path(&held);
        if !directly_in(&real, parent_real) {
            return Err(tf("man.moved_while_listing", &[&p.display(), &"folder"]));
        }
        if !name.is_empty() {
            m.dirs.push((name.clone(), p.to_path_buf()));
        }
        let mut kids: Vec<PathBuf> = fs::read_dir(p).map_err(e)?.map(|d| d.map(|d| d.path())).collect::<Result<_, _>>().map_err(e)?;
        kids.sort();
        let real = real.ok();
        for k in kids {
            let kn = k.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            walk(&k, &join(&name, &kn), m, real.as_deref())?;
        }
        drop(held);
    } else if md.is_file() {
        let f = open_no_follow(p, false).map_err(|x| format!("{}: {x}", p.display()))?;
        let id = file_id(&f).map_err(e)?;
        if id.special {
            m.skipped += 1; // reparse point that looked like a file
            return Ok(());
        }
        if !directly_in(&final_path(&f), parent_real) {
            return Err(tf("man.moved_while_listing", &[&p.display(), &"file"]));
        }
        let fm = f.metadata().map_err(e)?;
        // B-11: the same limits decryption enforces, checked while the list is fixed
        if fm.len() > crate::format::MAX_ENTRY {
            return Err(tf("man.file_too_big", &[&p.display(), &crate::ui_fmt::human(crate::format::MAX_ENTRY)]));
        }
        m.total = m
            .total
            .checked_add(fm.len())
            .filter(|t| *t <= crate::format::MAX_TOTAL)
            .ok_or_else(|| tf("man.total_too_big", &[&crate::ui_fmt::human(crate::format::MAX_TOTAL)]))?;
        m.files.push(FileRec { rel: name, path: p.to_path_buf(), id, size: fm.len(), mtime: fm.modified().ok(), hash: None });
    } else {
        m.skipped += 1;
    }
    Ok(())
}

#[derive(Default, Debug)]
pub struct ShredReport {
    pub shredded: u64,
    pub changed: Vec<PathBuf>,
    pub hardlinked: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    pub dirs_removed: u64,
    pub dirs_kept: Vec<PathBuf>,
    /// Alternate data streams overwritten before their files were deleted (B-9).
    pub streams: u64,
}

impl ShredReport {
    pub fn summary(&self, passes: crate::wipe::Passes) -> String {
        let mut s = tf("man.shredded", &[&self.shredded, &passes.count()]);
        if self.streams > 0 {
            s += &tf("man.streams_shredded", &[&self.streams]);
        }
        if !self.changed.is_empty() {
            s += &tf("man.changed_kept", &[&self.changed.len()]);
        }
        if !self.hardlinked.is_empty() {
            s += &tf("man.hardlinks_kept", &[&self.hardlinked.len()]);
        }
        if !self.failed.is_empty() {
            s += &tf("man.shred_failed", &[&self.failed.len(), &self.failed[0].1]);
        }
        if !self.dirs_kept.is_empty() {
            s += &tf("man.dirs_kept", &[&self.dirs_kept.len()]);
        }
        s
    }
}

/// Overwrites + deletes exactly the listed files that are still unchanged, then removes listed
/// folders that became empty. Hard links, links and changed files are left alone and reported.
/// `with_streams`: the user chose to include alternate data streams; they are overwritten too
/// (otherwise deleting the file frees them without overwriting).
pub fn shred_listed(m: &Manifest, passes: crate::wipe::Passes, with_streams: bool) -> ShredReport {
    let mut rep = ShredReport::default();
    for r in &m.files {
        match crate::wipe::shred_checked(r, passes, with_streams) {
            Ok(n) => {
                rep.shredded += 1;
                rep.streams += n;
            }
            Err(crate::wipe::ShredSkip::Changed) => rep.changed.push(r.path.clone()),
            Err(crate::wipe::ShredSkip::HardLink) => rep.hardlinked.push(r.path.clone()),
            Err(crate::wipe::ShredSkip::Failed(x)) => rep.failed.push((r.path.clone(), x)),
        }
    }
    let mut dirs: Vec<&(String, PathBuf)> = m.dirs.iter().collect();
    dirs.sort_by_key(|(n, _)| std::cmp::Reverse(n.matches('/').count()));
    for (_, d) in dirs {
        match fs::symlink_metadata(d) {
            Ok(md) if md.is_dir() && !md.file_type().is_symlink() => {
                if fs::remove_dir(d).is_ok() {
                    rep.dirs_removed += 1;
                } else {
                    rep.dirs_kept.push(d.clone());
                }
            }
            _ => {}
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scan_counts_and_limits_share_the_constants() {
        let d = std::env::temp_dir().join(format!("shield_man_{}", crate::entropy::rand_hex().unwrap()));
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("sub").join("a.txt"), b"abc").unwrap();
        let mut m = Manifest::default();
        Manifest::scan(&d, "", &mut m).unwrap();
        assert_eq!((m.files.len(), m.dirs.len(), m.total), (1, 2, 3));
        // the running total is checked against MAX_TOTAL: start just below the limit
        let mut near = Manifest { total: crate::format::MAX_TOTAL - 1, ..Default::default() };
        assert!(Manifest::scan(&d, "", &mut near).is_err(), "total above MAX_TOTAL is refused at scan time");
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn entries_outside_the_listed_folder_are_refused() {
        // security review 2026-11-08: a folder swapped for a link or junction between the check
        // and the listing gives entries that are really elsewhere; they must stop the scan
        let d = std::env::temp_dir().join(format!("shield_man_{}", crate::entropy::rand_hex().unwrap()));
        let (sel, out) = (d.join("sel"), d.join("out"));
        fs::create_dir_all(sel.join("sub")).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(sel.join("sub").join("a.txt"), b"abc").unwrap();
        fs::write(out.join("secret.txt"), b"not selected").unwrap();
        let mut m = Manifest::default();
        Manifest::scan(&sel, "", &mut m).unwrap();
        assert_eq!(m.files.len(), 1, "a normal folder lists as before");
        // what the swap amounts to: `sel/sub` really lies somewhere else than the folder listed
        let elsewhere = final_path(&open_dir_held(&out).unwrap()).unwrap();
        let mut m = Manifest::default();
        let err = walk(&sel.join("sub"), "sub", &mut m, Some(&elsewhere)).unwrap_err();
        assert!(err.contains("sub"), "{err}");
        let err = walk(&sel.join("sub").join("a.txt"), "a.txt", &mut m, Some(&elsewhere)).unwrap_err();
        assert!(err.contains("a.txt"), "{err}");
        assert!(m.files.is_empty(), "nothing from elsewhere was listed");
        // the real parent is accepted
        let here = final_path(&open_dir_held(&sel.join("sub")).unwrap()).unwrap();
        walk(&sel.join("sub").join("a.txt"), "a.txt", &mut m, Some(&here)).unwrap();
        assert_eq!(m.files.len(), 1);
        // Windows: while a folder is held it can't be renamed, so it can't be swapped at all
        if cfg!(windows) {
            let held = open_dir_held(&sel.join("sub")).unwrap();
            assert!(fs::rename(sel.join("sub"), sel.join("moved")).is_err(), "held folder renamed");
            drop(held);
            fs::rename(sel.join("sub"), sel.join("moved")).unwrap();
        }
        let _ = fs::remove_dir_all(d);
    }
}
