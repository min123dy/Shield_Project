//! Plaintext staging folders (`.shd_<random>_x`) used while extracting.
//! They are created owner-only (Windows DACL: current user + SYSTEM; Unix 0700), recorded in a
//! small journal (%LOCALAPPDATA%\Shield\staging.lst) and removed on success, error, cancel or
//! panic (Drop). A journal entry that still exists at the next start means Shield was killed while
//! plaintext was on disk; the UI then tells the user and offers to remove it.

use crate::entropy::rand_hex;
use crate::progress::*;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

const TAB: char = 0x09 as char;
static JOURNAL_LOCK: Mutex<()> = Mutex::new(());

fn journal() -> Option<PathBuf> {
    if cfg!(test) {
        return Some(std::env::temp_dir().join("shield_test_staging.lst"));
    }
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("HOME")).map(PathBuf::from)?;
    Some(base.join("Shield").join("staging.lst"))
}

/// Journal line: "<owner pid><TAB><path>". The pid keeps another running Shield window's active
/// staging folder from being reported (and removed) as a leftover.
fn read_list() -> Vec<(u32, PathBuf)> {
    journal()
        .and_then(|j| fs::read_to_string(j).ok())
        .map(|s| {
            s.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| match l.split_once(TAB) {
                    Some((pid, p)) => (pid.parse().unwrap_or(0), PathBuf::from(p)),
                    None => (0, PathBuf::from(l)),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return false;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        ok && code == 259 // STILL_ACTIVE
    }
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    pid != 0 && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
}

#[cfg(not(any(windows, unix)))]
fn pid_alive(_pid: u32) -> bool {
    false
}

fn write_list(v: &[(u32, PathBuf)]) {
    let Some(j) = journal() else { return };
    if let Some(d) = j.parent() {
        let _ = fs::create_dir_all(d);
    }
    let tmp = j.with_extension("tmp");
    if let Ok(mut f) = fs::File::create(&tmp) {
        for (pid, p) in v {
            let _ = writeln!(f, "{pid}{TAB}{}", p.display());
        }
        let _ = f.sync_all();
        drop(f);
        let _ = crate::sysinfo::rename_replace(&tmp, &j);
    }
}

pub(crate) fn register_as(pid: u32, p: &Path) {
    let _g = JOURNAL_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    let mut v = read_list();
    v.push((pid, p.to_path_buf()));
    write_list(&v);
}

fn register(p: &Path) {
    register_as(std::process::id(), p);
}

fn unregister(p: &Path) {
    let _g = JOURNAL_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    let v: Vec<(u32, PathBuf)> = read_list().into_iter().filter(|x| x.1 != p).collect();
    write_list(&v);
}

/// Staging folders left behind by an earlier (killed) run that still exist. Folders owned by a
/// process that is still running (this one or another Shield window) are not reported.
pub fn leftovers() -> Vec<PathBuf> {
    let _g = JOURNAL_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    let v = read_list();
    let (exists, gone): (Vec<_>, Vec<_>) = v.into_iter().partition(|(_, p)| fs::symlink_metadata(p).is_ok());
    if !gone.is_empty() {
        write_list(&exists);
    }
    exists.into_iter().filter(|(pid, _)| !pid_alive(*pid)).map(|(_, p)| p).collect()
}

/// Removes leftover folders (only names that look like ours). Returns (removed, failures).
pub fn remove_leftovers(v: &[PathBuf]) -> (usize, Vec<String>) {
    let mut ok = 0;
    let mut bad = Vec::new();
    for p in v {
        let ours = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(".shd_") && n.ends_with("_x"));
        if !ours {
            bad.push(format!("{}: Shield 임시 폴더 이름이 아니어서 건너뜀", p.display()));
            continue;
        }
        match crate::wipe::shred_own_tree(p) {
            Ok(()) => {
                ok += 1;
                unregister(p);
            }
            Err(x) => bad.push(format!("{}: {x}", p.display())),
        }
    }
    (ok, bad)
}

/// A private staging folder; removed (contents overwritten once) when dropped unless `finish`ed.
pub struct Stage {
    pub path: PathBuf,
    done: bool,
}

impl Stage {
    pub fn create(parent: &Path) -> R<Stage> {
        let path = parent.join(format!(".shd_{}_x", rand_hex()?));
        crate::sysinfo::create_private_dir(&path).map_err(|x| format!("임시 폴더를 만들 수 없습니다: {x}"))?;
        // the folder must really be where we asked (no redirection through links)
        let real = fs::canonicalize(&path).map_err(e)?;
        let want = fs::canonicalize(parent).map_err(e)?.join(path.file_name().unwrap_or_default());
        if crate::sysinfo::path_key(&real) != crate::sysinfo::path_key(&want) {
            let _ = fs::remove_dir(&path);
            return Err("임시 폴더 경로 검증 실패".into());
        }
        register(&path);
        Ok(Stage { path, done: false })
    }

    /// Removes the (now empty or remaining) folder. An error means plaintext may remain.
    pub fn finish(mut self) -> R<()> {
        self.done = true;
        let r = if fs::symlink_metadata(&self.path).is_ok() { crate::wipe::shred_own_tree(&self.path) } else { Ok(()) };
        match r {
            Ok(()) => {
                unregister(&self.path);
                Ok(())
            }
            Err(x) => Err(format!("임시 폴더 정리 실패: {} ({x}) — 평문이 남아 있을 수 있으니 직접 삭제하세요.", self.path.display())),
        }
    }

    /// Cleanup on an error path: returns a warning text when removal failed.
    pub fn abort(self) -> Option<String> {
        self.finish().err()
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.done && crate::wipe::shred_own_tree(&self.path).is_ok() {
            unregister(&self.path);
        }
    }
}
