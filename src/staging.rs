//! Plaintext staging folders (`.shd_<24 hex>_x`) used while extracting.
//! They are created owner-only (Windows DACL: current user + SYSTEM; Unix 0700) and recorded in a
//! journal (`staging.lst` in the Shield data folder) BEFORE they are created; if the journal can't
//! be written, nothing is extracted. They are removed on success, error, cancel or panic (Drop);
//! the journal entry is removed only after a complete overwrite + delete. An entry that still
//! exists at the next start means plaintext may be on disk; the UI tells the user and offers
//! removal.
//!
//! Journal line: `<pid>\t<process start time>\t<parent>\t<folder name>`. The pid + start time pair
//! identifies the owning process even after pid reuse. Every read-modify-write of the journal runs
//! under a cross-process lock (`staging.lck`) and is written to a unique temp file
//! (pid + random) that atomically replaces the journal.

use crate::entropy::rand_hex;
use crate::i18n::{t, tf};
use crate::lock::{acquire, FileLock, Mode};
use crate::progress::*;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

const TAB: char = 0x09 as char;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub start: u64,
    pub parent: PathBuf,
    pub name: String,
}

impl Entry {
    pub fn path(&self) -> PathBuf {
        self.parent.join(&self.name)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests that damage the journal use their own file so parallel tests are not affected.
    pub(crate) static JOURNAL_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn journal() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(p) = JOURNAL_OVERRIDE.with(|o| o.borrow().clone()) {
            return p;
        }
        std::env::temp_dir().join("shield_test_journal").join("staging.lst")
    }
    #[cfg(not(test))]
    crate::settings::data_dir().join("staging.lst")
}

fn journal_lock() -> R<FileLock> {
    let j = journal();
    acquire(&j.with_extension("lck"), Mode::Exclusive, Duration::from_secs(10)).map_err(|x| tf("stage.journal_lock", &[&x]))
}

/// Strict name check: only folders Shield names itself are ever removed.
pub fn is_stage_name(n: &str) -> bool {
    const HEX: usize = 24; // rand_hex(): 12 random bytes
    n.len() == 5 + HEX + 2
        && n.starts_with(".shd_")
        && n.ends_with("_x")
        && n[5..5 + HEX].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn parse(s: &str) -> R<Vec<Entry>> {
    let mut v = Vec::new();
    for (i, l) in s.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let f: Vec<&str> = l.split(TAB).collect();
        let bad = || tf("stage.journal_corrupt_line", &[&(i + 1)]);
        if f.len() != 4 || !is_stage_name(f[3]) || f[2].is_empty() {
            return Err(bad());
        }
        v.push(Entry {
            pid: f[0].parse().map_err(|_| bad())?,
            start: f[1].parse().map_err(|_| bad())?,
            parent: PathBuf::from(f[2]),
            name: f[3].to_string(),
        });
    }
    Ok(v)
}

/// Missing journal = empty. Unreadable or corrupt = error (never treated as "no leftovers").
fn read_list() -> R<Vec<Entry>> {
    match fs::read(journal()) {
        Ok(b) => {
            let s = String::from_utf8(b).map_err(|_| t("stage.journal_corrupt").to_string())?;
            parse(&s).map_err(|x| tf("stage.journal_corrupt_detail", &[&x]))
        }
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(x) => Err(tf("stage.journal_read", &[&x])),
    }
}

fn write_list(v: &[Entry]) -> R<()> {
    let j = journal();
    let dir = j.parent().ok_or_else(|| t("stage.journal_write").to_string())?;
    fs::create_dir_all(dir).map_err(|x| tf("stage.journal_write_detail", &[&x]))?;
    let tmp = dir.join(format!("staging.{}.{}.tmp", std::process::id(), rand_hex()?));
    let r = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        for en in v {
            if en.parent.to_string_lossy().contains(['\t', '\n', '\r']) {
                return Err(std::io::Error::other("tab/newline in path"));
            }
            writeln!(f, "{}{TAB}{}{TAB}{}{TAB}{}", en.pid, en.start, en.parent.display(), en.name)?;
        }
        f.sync_all()?;
        drop(f);
        crate::sysinfo::rename_replace(&tmp, &j)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r.map_err(|x| tf("stage.journal_write_detail", &[&x]))
}

fn modify(f: impl FnOnce(&mut Vec<Entry>)) -> R<()> {
    let _g = journal_lock()?;
    let mut v = read_list()?;
    f(&mut v);
    write_list(&v)
}

/// Start time of a process (FILETIME), or None when it does not exist (any more).
#[cfg(windows)]
pub fn process_start(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return None;
        }
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut x, mut k, mut u) = (z, z, z, z);
        let mut code = 0u32;
        let ok = GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) != 0 && GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        (ok && code == 259).then_some((c.dwHighDateTime as u64) << 32 | c.dwLowDateTime as u64)
    }
}

#[cfg(not(windows))]
pub fn process_start(pid: u32) -> Option<u64> {
    (pid == std::process::id()).then_some(1)
}

fn owner_alive(en: &Entry) -> bool {
    process_start(en.pid).is_some_and(|s| s == en.start)
}

/// Records a staging folder in the journal under `pid`/`start` (tests use a dead owner).
pub(crate) fn register_as(pid: u32, start: u64, p: &Path) -> R<()> {
    let name = p.file_name().and_then(|n| n.to_str()).filter(|n| is_stage_name(n)).ok_or_else(|| t("stage.bad_name").to_string())?;
    let parent = p.parent().ok_or_else(|| t("stage.bad_name").to_string())?.to_path_buf();
    let en = Entry { pid, start, parent, name: name.to_string() };
    modify(|v| v.push(en))
}

fn me() -> (u32, u64) {
    let pid = std::process::id();
    (pid, process_start(pid).unwrap_or(0))
}

fn unregister(p: &Path) -> R<()> {
    modify(|v| v.retain(|en| en.path() != p))
}

/// Staging folders left by an earlier (killed) run that still exist. Folders of a running owner
/// (this window or another Shield window) are not reported. A corrupt journal is an error.
pub fn leftovers() -> R<Vec<Entry>> {
    let _g = journal_lock()?;
    let v = read_list()?;
    // a running owner may have registered a folder it has not created yet: keep its entries
    let (keep, gone): (Vec<_>, Vec<_>) =
        v.into_iter().partition(|en| owner_alive(en) || fs::symlink_metadata(en.path()).is_ok());
    if !gone.is_empty() {
        write_list(&keep)?;
    }
    Ok(keep.into_iter().filter(|en| !owner_alive(en)).collect())
}

/// Parents a staging folder may never be removed from, whatever the journal says.
fn forbidden_parent(p: &Path) -> bool {
    let key = crate::sysinfo::path_key(p);
    let sys = crate::sysinfo::path_key(&crate::sysinfo::system_dir());
    p.parent().is_none() || key.trim_end_matches(['\\', '/']).len() <= 3 || (cfg!(windows) && key.starts_with(&sys))
}

/// Checks done right before removing a journal entry's folder: the strict name, a real folder (not
/// a link/junction), resolving to exactly the recorded parent, which is not a root/system folder.
pub fn removable(en: &Entry) -> R<PathBuf> {
    let p = en.path();
    let m = fs::symlink_metadata(&p).map_err(e)?;
    if !is_stage_name(&en.name) || !m.is_dir() || m.file_type().is_symlink() || crate::sysinfo::is_reparse(&m) {
        return Err(tf("stage.not_ours", &[&p.display()]));
    }
    let real_parent = fs::canonicalize(&en.parent).map_err(e)?;
    let real = fs::canonicalize(&p).map_err(e)?;
    if forbidden_parent(&real_parent)
        || crate::sysinfo::path_key(&real) != crate::sysinfo::path_key(&real_parent.join(&en.name))
    {
        return Err(tf("stage.not_ours", &[&p.display()]));
    }
    Ok(p)
}

/// Removes leftover folders. The journal entry goes only after a complete removal.
/// Returns (removed, failures).
pub fn remove_leftovers(v: &[Entry]) -> (usize, Vec<String>) {
    let mut ok = 0;
    let mut bad = Vec::new();
    for en in v {
        let p = match removable(en) {
            Ok(p) => p,
            Err(x) => {
                bad.push(x);
                continue;
            }
        };
        match crate::wipe::shred_own_tree(&p).and_then(|_| unregister(&p)) {
            Ok(()) => ok += 1,
            Err(x) => bad.push(format!("{}: {x}", p.display())),
        }
    }
    (ok, bad)
}

/// Recovery when the journal itself is damaged: keeps a copy (`staging.lst.bad`), starts a new
/// empty journal and returns the staging folders found directly inside `scan_dir`.
pub fn reset_journal(scan_dir: Option<&Path>) -> R<Vec<Entry>> {
    let _g = journal_lock()?;
    let j = journal();
    if j.exists() {
        fs::copy(&j, j.with_extension("lst.bad")).map_err(|x| tf("stage.journal_write_detail", &[&x]))?;
    }
    write_list(&[])?;
    let mut found = Vec::new();
    if let Some(d) = scan_dir {
        for en in fs::read_dir(d).map_err(e)?.flatten() {
            let name = en.file_name().to_string_lossy().into_owned();
            if is_stage_name(&name) {
                found.push(Entry { pid: 0, start: 0, parent: d.to_path_buf(), name });
            }
        }
    }
    Ok(found)
}

/// A private staging folder; removed (contents overwritten once) when dropped unless `finish`ed.
pub struct Stage {
    pub path: PathBuf,
    done: bool,
}

impl Stage {
    /// Journal first, folder second: a crash between the two leaves an entry for a missing folder
    /// (cleaned silently), never a folder without an entry.
    pub fn create(parent: &Path) -> R<Stage> {
        let path = parent.join(format!(".shd_{}_x", rand_hex()?));
        let (pid, start) = me();
        register_as(pid, start, &path).map_err(|x| tf("stage.not_recorded", &[&x]))?;
        if let Err(x) = crate::sysinfo::create_private_dir(&path) {
            let _ = unregister(&path);
            return Err(tf("stage.create_failed", &[&x]));
        }
        let st = Stage { path, done: false };
        // the folder must really be where we asked (no redirection through links)
        let real = fs::canonicalize(&st.path).map_err(e)?;
        let want = fs::canonicalize(parent).map_err(e)?.join(st.path.file_name().unwrap_or_default());
        if crate::sysinfo::path_key(&real) != crate::sysinfo::path_key(&want) {
            return Err(t("stage.verify_failed").into()); // Drop removes it
        }
        Ok(st)
    }

    /// Removes the (now empty or remaining) folder. An error means plaintext may remain; the journal
    /// entry then stays so the next start reports it.
    pub fn finish(mut self) -> R<()> {
        self.done = true;
        let r = if fs::symlink_metadata(&self.path).is_ok() { crate::wipe::shred_own_tree(&self.path) } else { Ok(()) };
        r.and_then(|_| unregister(&self.path)).map_err(|x| tf("stage.cleanup_failed", &[&self.path.display(), &x]))
    }

    /// Cleanup on an error path: returns a warning text when removal failed.
    pub fn abort(self) -> Option<String> {
        self.finish().err()
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.done && crate::wipe::shred_own_tree(&self.path).is_ok() {
            let _ = unregister(&self.path);
        }
    }
}

#[cfg(test)]
#[path = "staging_tests.rs"]
mod tests;
