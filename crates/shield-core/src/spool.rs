//! Collects an Explorer multi-selection into one window (design 3.0 §5).
//!
//! For a classic shell verb Windows starts one process per selected item (`--encrypt-multi
//! "%1"`). Each process drops its path into a private spool folder; the process that holds the
//! leader lock waits until no new paths arrive for a short moment, takes all of them and opens
//! one window. Linux file managers pass the whole selection at once (`%F`); the same code then
//! simply finds a single entry.
//!
//! Only paths are spooled (no secrets). The folder lives in the private data folder; entries
//! older than a minute, malformed ones and paths that are not absolute existing items are
//! ignored and removed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const QUIET: Duration = Duration::from_millis(700);
const MAX_WAIT: Duration = Duration::from_secs(8);
const FOLLOW_WAIT: Duration = Duration::from_secs(20);
const MAX_AGE: Duration = Duration::from_secs(60);
const MAX_ITEMS: usize = 10_000;

pub fn dir(base: &Path) -> PathBuf {
    base.join("spool")
}

fn write_entry(d: &Path, items: &[PathBuf]) -> std::io::Result<PathBuf> {
    let name = format!("{}.{}.lst", std::process::id(), crate::entropy::rand_hex().map_err(std::io::Error::other)?);
    let tmp = d.join(format!("{name}.tmp"));
    let mut f = crate::sysinfo::create_private_file(&tmp)?;
    for p in items {
        f.write_all(p.to_string_lossy().as_bytes())?;
        f.write_all(b"\n")?;
    }
    f.sync_all()?;
    drop(f);
    let fin = d.join(name);
    crate::sysinfo::rename_noreplace(&tmp, &fin)?;
    Ok(fin)
}

fn entries(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(d).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "lst")).collect()).unwrap_or_default();
    v.sort();
    v
}

fn take(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in entries(d) {
        let fresh = fs::metadata(&e).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|a| a < MAX_AGE);
        let text = if fresh { fs::read(&e).ok().filter(|b| b.len() < 4 << 20) } else { None };
        let _ = fs::remove_file(&e);
        for l in text.as_deref().map(String::from_utf8_lossy).unwrap_or_default().lines() {
            let p = PathBuf::from(l);
            if out.len() < MAX_ITEMS && p.is_absolute() && fs::symlink_metadata(&p).is_ok() && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// What this process does with its share of the selection.
#[derive(Debug, PartialEq, Eq)]
pub enum Role {
    /// Open one window for these items (the whole selection, in Explorer's order of arrival).
    Lead(Vec<PathBuf>),
    /// Another process took our items: exit quietly.
    Done,
}

/// Spools `items` in `base` and either becomes the leader (collecting everybody's items) or
/// leaves them to the current leader.
pub fn gather(base: &Path, items: &[PathBuf]) -> std::io::Result<Role> {
    let d = dir(base);
    // a spool folder somebody else made or controls is not used: its lists would add items
    // (security review 2026-11-08); this window then just takes its own items
    if crate::sysinfo::ensure_private_dir(&d).is_err() {
        return Ok(Role::Lead(items.to_vec()));
    }
    let lock = shield_platform::fs::open_lock_file(&d.join("leader.lck"))?;
    let mine = write_entry(&d, items)?;
    let start = Instant::now();
    loop {
        if lock.try_lock().is_ok() {
            if !mine.exists() {
                // a leader that just finished took our entry
                let _ = lock.unlock();
                return Ok(Role::Done);
            }
            let (mut n, mut last_change, t0) = (entries(&d).len(), Instant::now(), Instant::now());
            while last_change.elapsed() < QUIET && t0.elapsed() < MAX_WAIT {
                std::thread::sleep(Duration::from_millis(100));
                let m = entries(&d).len();
                if m != n {
                    (n, last_change) = (m, Instant::now());
                }
            }
            let all = take(&d);
            let _ = lock.unlock();
            return Ok(Role::Lead(all));
        }
        if !mine.exists() {
            return Ok(Role::Done);
        }
        if start.elapsed() > FOLLOW_WAIT {
            // the leader seems stuck: handle our own items
            let _ = fs::remove_file(&mine);
            return Ok(Role::Lead(items.to_vec()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PathBuf {
        let d = std::env::temp_dir().join(format!("shield_spool_{}", crate::entropy::rand_hex().unwrap()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn many_processes_end_up_in_one_list() {
        let b = base();
        let files: Vec<PathBuf> = (0..6).map(|i| b.join(format!("f{i}.txt"))).collect();
        for f in &files {
            fs::write(f, b"x").unwrap();
        }
        let hs: Vec<_> = files
            .iter()
            .cloned()
            .map(|f| {
                let b = b.clone();
                std::thread::spawn(move || gather(&b, &[f]).unwrap())
            })
            .collect();
        let roles: Vec<Role> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        let leads: Vec<&Vec<PathBuf>> = roles.iter().filter_map(|r| if let Role::Lead(v) = r { Some(v) } else { None }).collect();
        let total: usize = leads.iter().map(|v| v.len()).sum();
        assert_eq!(total, files.len(), "every item handled exactly once: {roles:?}");
        assert!(leads.len() <= 2, "one window (two at worst when the last arrives late): {roles:?}");
        assert!(entries(&dir(&b)).is_empty());
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn junk_and_stale_entries_are_dropped() {
        let b = base();
        let d = dir(&b);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("x.lst"), "relative/path\n/definitely/not/here\n").unwrap();
        let real = b.join("real.txt");
        fs::write(&real, b"x").unwrap();
        assert_eq!(gather(&b, std::slice::from_ref(&real)).unwrap(), Role::Lead(vec![real]));
        let _ = fs::remove_dir_all(b);
    }
}
