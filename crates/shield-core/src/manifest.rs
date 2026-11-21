//! The fixed target list of an encryption, its SHA3-512 fingerprints, the comparison with the
//! restored archive and the shredding of exactly (and only) the listed, unchanged files.

use crate::i18n::tf;
use crate::progress::*;
use crate::sysinfo::{entry_kind_at, file_id, final_path, list_dir_held, open_dir_at, open_dir_held, open_file_at, open_no_follow, EntryKind, FileId};
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
    /// Where each selected item really is (from its handle while it was listed); every listed
    /// file is checked to still be below one of them before it is shredded (3.1.0 #10).
    pub roots: Vec<PathBuf>,
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
        walk(&real, &join(prefix, base), m, At::Top)
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

/// Where the object behind an open handle really is. Tests can replace it (3.1.0 #10) to act out
/// a system that can't say (Linux without /proc).
fn real_of(f: &File) -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(over) = tests::REAL_OVERRIDE.with(|c| c.get()) {
        return over(f);
    }
    final_path(f)
}

/// True only when `child` (where an opened entry really is) is known and lies directly in
/// `parent` (where its held folder really is). Anything unknown - the entry's real path could not
/// be read (Linux without /proc) or the parent's is missing - is a failure: 3.0.0 counted it as
/// "inside" (fail-open; 3.1.0 #10).
fn directly_in(child: &io::Result<PathBuf>, parent: Option<&Path>) -> bool {
    match (child, parent) {
        (Ok(c), Some(p)) => c.parent() == Some(p),
        // no `_ => true`: an unknown side is never taken as inside
        (Err(_), _) | (Ok(_), None) => false,
    }
}

/// Where `walk` is: the selected item itself, or an entry of an already held (and checked) folder.
enum At<'a> {
    /// The selected file or folder. It has no listed parent to compare with (by design); its own
    /// real path must still be readable and becomes a root for the check before shredding.
    Top,
    /// Entry `name` of the held folder `dir`, which really is at `real` (None = unknown: refused).
    In { dir: &'a File, name: &'a std::ffi::OsStr, real: Option<&'a Path> },
}

fn moved(p: &Path, what: &dyn std::fmt::Display) -> String {
    tf("man.moved_while_listing", &[&p.display(), what])
}

/// Every entry listed must really be in the folder being listed. 3.1.0 #10: entries are looked
/// up and opened relative to the held folder handle (Linux: fdopendir/fstatat/openat with
/// O_NOFOLLOW; Windows: the held folder can't be renamed while open), and the real path of every
/// opened folder and file is compared with its parent's. A real path that can't be read stops the
/// whole scan (nothing is encrypted or shredded), it is never taken as "inside".
fn walk(p: &Path, name: &str, m: &mut Manifest, at: At<'_>) -> R<()> {
    check_cancel()?;
    let kind = match &at {
        At::Top => {
            let md = fs::symlink_metadata(p).map_err(|x| format!("{}: {x}", p.display()))?;
            if md.file_type().is_symlink() || crate::sysinfo::is_reparse(&md) {
                EntryKind::Link
            } else if md.is_dir() {
                EntryKind::Dir
            } else if md.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            }
        }
        At::In { dir, name: n, .. } => entry_kind_at(dir, n, p).map_err(|x| moved(p, &x))?,
    };
    if matches!(kind, EntryKind::Link | EntryKind::Other) {
        m.skipped += 1;
        return Ok(());
    }
    if m.files.len() as u64 + m.dirs.len() as u64 >= crate::format::MAX_FILES {
        return Err(tf("man.too_many", &[&crate::format::MAX_FILES]));
    }
    // the parent's real path; At::In without one is refused (never taken as inside)
    let check = |real: &io::Result<PathBuf>, what: &str| -> R<()> {
        let ok = match &at {
            At::Top => real.is_ok(),
            At::In { real: parent, .. } => directly_in(real, *parent),
        };
        if ok {
            Ok(())
        } else {
            let why = match real {
                Err(x) => format!("{what}: {x}"),
                Ok(_) => what.to_string(),
            };
            Err(moved(p, &why))
        }
    };
    let name = name.to_string();
    if kind == EntryKind::Dir {
        let held = match &at {
            At::Top => open_dir_held(p),
            At::In { dir, name: n, .. } => open_dir_at(dir, n, p),
        }
        .map_err(|x| moved(p, &x))?;
        let real = real_of(&held);
        check(&real, "folder")?;
        let real = real.map_err(e)?;
        if matches!(at, At::Top) {
            m.roots.push(real.clone());
        }
        if !name.is_empty() {
            m.dirs.push((name.clone(), p.to_path_buf()));
        }
        let mut kids = list_dir_held(&held, p).map_err(|x| moved(p, &x))?;
        kids.sort();
        for k in kids {
            let kn = k.to_string_lossy().into_owned();
            walk(&p.join(&k), &join(&name, &kn), m, At::In { dir: &held, name: &k, real: Some(&real) })?;
        }
        drop(held);
    } else {
        let f = match &at {
            At::Top => open_no_follow(p, false),
            At::In { dir, name: n, .. } => open_file_at(dir, n, p),
        }
        .map_err(|x| format!("{}: {x}", p.display()))?;
        let id = file_id(&f).map_err(e)?;
        if id.special {
            m.skipped += 1; // reparse point that looked like a file
            return Ok(());
        }
        let real = real_of(&f);
        check(&real, "file")?;
        if matches!(at, At::Top) {
            m.roots.push(real.map_err(e)?);
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
    }
    Ok(())
}

/// 3.1.0 #10: right before shredding, every listed original must still really lie in (or be) one
/// of the selected items, judged by where its handle really is. One that can't be confirmed stops
/// the whole shred (the encrypted result stays; nothing is overwritten).
fn recheck_roots(m: &Manifest) -> Result<(), String> {
    for r in &m.files {
        let f = open_no_follow(&r.path, false).map_err(|x| format!("{}: {x}", r.path.display()))?;
        let real = real_of(&f).map_err(|x| format!("{}: {x}", r.path.display()))?;
        if !m.roots.iter().any(|root| real.starts_with(root)) {
            return Err(r.path.display().to_string());
        }
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
    /// Nothing was shredded: an original could not be confirmed to still be where it was listed
    /// (3.1.0 #10). Holds the path or reason.
    pub refused: Option<String>,
}

impl ShredReport {
    /// Some original was not shredded as asked (failed overwrite/delete, or the whole shred refused).
    pub fn is_failure(&self) -> bool {
        !self.failed.is_empty() || self.refused.is_some()
    }

    pub fn summary(&self, passes: crate::wipe::Passes) -> String {
        if let Some(why) = &self.refused {
            return tf("man.shred_refused", &[why]);
        }
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
    if let Err(why) = recheck_roots(m) {
        rep.refused = Some(why);
        return rep;
    }
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

    use std::cell::Cell;
    use std::ffi::OsStr;

    type RealFn = fn(&File) -> io::Result<PathBuf>;
    thread_local! {
        /// Replaces `final_path` for the current test thread (3.1.0 #10 injection).
        pub(super) static REAL_OVERRIDE: Cell<Option<RealFn>> = const { Cell::new(None) };
    }

    fn no_proc(_: &File) -> io::Result<PathBuf> {
        Err(io::Error::new(io::ErrorKind::NotFound, "/proc not mounted (simulated)"))
    }

    /// Runs `f` with real paths unavailable, as on Linux without /proc.
    fn without_real_paths<T>(f: impl FnOnce() -> T) -> T {
        REAL_OVERRIDE.with(|c| c.set(Some(no_proc)));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        REAL_OVERRIDE.with(|c| c.set(None));
        r.unwrap_or_else(|p| std::panic::resume_unwind(p))
    }

    fn tdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("shield_man_{}", crate::entropy::rand_hex().unwrap()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn directly_in_is_fail_closed() {
        let p = PathBuf::from("/a/b");
        assert!(directly_in(&Ok(p.join("c")), Some(&p)));
        assert!(!directly_in(&Ok(PathBuf::from("/x/c")), Some(&p)), "elsewhere");
        assert!(!directly_in(&Err(io::Error::other("unknown")), Some(&p)), "child real path unknown");
        assert!(!directly_in(&Ok(p.join("c")), None), "parent real path unknown");
        assert!(!directly_in(&Err(io::Error::other("unknown")), None));
    }

    #[test]
    fn unknown_real_path_stops_the_scan() {
        // (1)/(3) 3.1.0 #10: with no way to learn where an entry really is (Linux without /proc)
        // the list is not made at all; 3.0.0 counted it as inside
        let d = tdir();
        fs::create_dir_all(d.join("sel").join("sub")).unwrap();
        fs::write(d.join("sel").join("sub").join("a.txt"), b"abc").unwrap();
        fs::write(d.join("one.txt"), b"abc").unwrap();
        for item in [d.join("sel"), d.join("one.txt")] {
            let mut m = Manifest::default();
            let err = without_real_paths(|| Manifest::scan(&item, "", &mut m)).unwrap_err();
            assert!(err.contains("simulated"), "{err}");
            assert!(m.files.is_empty());
        }
        // the same folder lists normally when real paths are available
        let mut m = Manifest::default();
        Manifest::scan(&d.join("sel"), "", &mut m).unwrap();
        assert_eq!((m.files.len(), m.roots.len()), (1, 1));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn entry_of_a_folder_without_known_real_path_is_refused() {
        // (2) an entry whose parent folder's real path is unknown is never taken as inside
        let d = tdir();
        fs::write(d.join("a.txt"), b"abc").unwrap();
        fs::create_dir_all(d.join("sub")).unwrap();
        let held = open_dir_held(&d).unwrap();
        for n in ["a.txt", "sub"] {
            let mut m = Manifest::default();
            let at = At::In { dir: &held, name: OsStr::new(n), real: None };
            assert!(walk(&d.join(n), n, &mut m, at).is_err(), "{n}");
            assert!(m.files.is_empty() && m.dirs.is_empty());
        }
        drop(held);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn shred_is_refused_when_originals_cannot_be_rechecked() {
        // (3) the list was fine, but just before shredding the real paths can't be confirmed:
        // nothing is overwritten or deleted
        let d = tdir();
        fs::create_dir_all(d.join("sel")).unwrap();
        fs::write(d.join("sel").join("a.txt"), b"keep me").unwrap();
        let mut m = Manifest::default();
        Manifest::scan(&d.join("sel"), "", &mut m).unwrap();
        let rep = without_real_paths(|| shred_listed(&m, crate::wipe::Passes::Three, false));
        assert!(rep.refused.is_some() && rep.is_failure() && rep.shredded == 0, "{rep:?}");
        assert_eq!(fs::read(d.join("sel").join("a.txt")).unwrap(), b"keep me");
        assert!(rep.summary(crate::wipe::Passes::Three).contains("a.txt"));
        // a list whose roots don't cover the file (e.g. built by hand) is refused too
        let mut other = Manifest::default();
        Manifest::scan(&d.join("sel"), "", &mut other).unwrap();
        other.roots = vec![d.join("elsewhere")];
        assert!(shred_listed(&other, crate::wipe::Passes::Three, false).refused.is_some());
        assert!(d.join("sel").join("a.txt").is_file());
        // with real paths the same list is shredded
        let rep = shred_listed(&m, crate::wipe::Passes::Three, false);
        assert!(!rep.is_failure() && rep.shredded == 1, "{rep:?}");
        assert!(!d.join("sel").join("a.txt").exists());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn encrypt_with_shred_does_nothing_without_real_paths() {
        // (3) end to end: no list -> no container, no shred, original untouched
        let d = tdir();
        fs::create_dir_all(d.join("sel")).unwrap();
        fs::write(d.join("sel").join("a.txt"), b"original").unwrap();
        let c = crate::engine::tests_support::cred("manifest test password", 0);
        let mut o = crate::engine::tests_support::opts();
        o.shred_src = true;
        let dst = d.join("sel.shd");
        assert!(without_real_paths(|| crate::engine::do_encrypt(&d.join("sel"), &dst, &c, &o)).is_err());
        assert!(!dst.exists(), "no container was written");
        assert_eq!(fs::read(d.join("sel").join("a.txt")).unwrap(), b"original");
        let _ = fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn links_and_fifos_inside_are_skipped_not_followed() {
        // (4) a symlink to a folder outside the selection is not listed (unchanged from 3.0.0);
        // a FIFO is skipped without blocking the scan
        let d = tdir();
        let (sel, out) = (d.join("sel"), d.join("out"));
        fs::create_dir_all(&sel).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(sel.join("a.txt"), b"abc").unwrap();
        fs::write(out.join("secret.txt"), b"not selected").unwrap();
        std::os::unix::fs::symlink(&out, sel.join("link")).unwrap();
        std::os::unix::fs::symlink(out.join("secret.txt"), sel.join("flink")).unwrap();
        let fifo_ok = std::process::Command::new("mkfifo").arg(sel.join("pipe")).status().is_ok_and(|s| s.success());
        let mut m = Manifest::default();
        Manifest::scan(&sel, "", &mut m).unwrap();
        assert_eq!(m.files.iter().map(|f| f.rel.as_str()).collect::<Vec<_>>(), vec!["sel/a.txt"]);
        assert_eq!(m.skipped, 2 + fifo_ok as u64);
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
        let (held_sel, held_sub) = (open_dir_held(&sel).unwrap(), open_dir_held(&sel.join("sub")).unwrap());
        let mut m = Manifest::default();
        let at = At::In { dir: &held_sel, name: OsStr::new("sub"), real: Some(&elsewhere) };
        let err = walk(&sel.join("sub"), "sub", &mut m, at).unwrap_err();
        assert!(err.contains("sub"), "{err}");
        let at = At::In { dir: &held_sub, name: OsStr::new("a.txt"), real: Some(&elsewhere) };
        let err = walk(&sel.join("sub").join("a.txt"), "a.txt", &mut m, at).unwrap_err();
        assert!(err.contains("a.txt"), "{err}");
        assert!(m.files.is_empty(), "nothing from elsewhere was listed");
        // the real parent is accepted
        let here = final_path(&held_sub).unwrap();
        let at = At::In { dir: &held_sub, name: OsStr::new("a.txt"), real: Some(&here) };
        walk(&sel.join("sub").join("a.txt"), "a.txt", &mut m, at).unwrap();
        assert_eq!(m.files.len(), 1);
        drop((held_sel, held_sub));
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
