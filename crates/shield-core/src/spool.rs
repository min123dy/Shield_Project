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
//! ignored and removed, and counted (`Role::Lead::dropped`) so the window can say so instead of
//! silently showing fewer items (3.1.0 final, review F). Each action has its own spool folder, so
//! "encrypt" and "secure delete" selections made at the same time never mix. Spooled paths are
//! untrusted input: the window checks them again (secure delete scans and confirms them anew).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const QUIET: Duration = Duration::from_millis(700);
const MAX_WAIT: Duration = Duration::from_secs(8);
const FOLLOW_WAIT: Duration = Duration::from_secs(20);
const MAX_AGE: Duration = Duration::from_secs(60);
const MAX_ITEMS: usize = 10_000;

/// Which shell verb the selection belongs to (one spool folder each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Encrypt,
    Wipe,
}

pub fn dir(base: &Path, kind: Kind) -> PathBuf {
    base.join(match kind {
        Kind::Encrypt => "spool",
        Kind::Wipe => "spool_wipe",
    })
}

/// A path given by a file manager or on the command line, made absolute (3.1.0 final, review F):
/// `file://` URIs are decoded (local only: empty host or `localhost`), relative names are joined
/// to `cwd`, `.` components are removed. Links are not resolved (nothing is followed). None for
/// what can't be a local path (another host, bad escapes, non-UTF-8 after decoding, NUL).
pub fn normalize_arg(a: &str, cwd: &Path) -> Option<PathBuf> {
    let s = match a.strip_prefix("file://") {
        Some(rest) => {
            let rest = rest.strip_prefix("localhost").unwrap_or(rest);
            if !rest.starts_with('/') {
                return None;
            }
            let dec = percent_decode(rest)?;
            // file:///C:/x on Windows
            let b = dec.as_bytes();
            if b.len() > 2 && b[2] == b':' && b[1].is_ascii_alphabetic() {
                dec[1..].to_string()
            } else {
                dec
            }
        }
        None => a.to_string(),
    };
    if s.is_empty() || s.contains('\0') {
        return None;
    }
    let p = PathBuf::from(s);
    let p = if p.is_absolute() { p } else { cwd.join(p) };
    std::path::absolute(&p).ok()
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn write_entry(d: &Path, items: &[PathBuf]) -> std::io::Result<PathBuf> {
    let name = format!("{}.{}.lst", std::process::id(), crate::entropy::rand_hex().map_err(std::io::Error::other)?);
    let tmp = d.join(format!("{name}.tmp"));
    let mut f = crate::sysinfo::create_private_file(&tmp)?;
    for p in items {
        // NUL-terminated records (3.1.0 final, 4-8): a path can't contain NUL but can contain a
        // newline, and a newline-separated list split "/home/u/a<LF>b" into "/home/u/a" (maybe
        // another, existing file) and "b". A path that is not UTF-8 is written as an empty record,
        // counted as dropped, instead of being changed into a different name.
        f.write_all(p.to_str().unwrap_or_default().as_bytes())?;
        f.write_all(b"\0")?;
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

/// Every fresh entry's paths (absolute, existing, at most `MAX_ITEMS`) and how many lines were
/// dropped (relative, missing, over the limit, unreadable entries).
fn take(d: &Path) -> (Vec<PathBuf>, usize) {
    let mut out = Vec::new();
    let mut dropped = 0usize;
    for e in entries(d) {
        let fresh = fs::metadata(&e).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|a| a < MAX_AGE);
        let text = if fresh { shield_platform::bounded::read_file_limited(&e, (4 << 20) - 1).ok() } else { None };
        let _ = fs::remove_file(&e);
        let Some(text) = text else {
            if fresh {
                dropped += 1;
            }
            continue;
        };
        let mut recs: Vec<&[u8]> = text.split(|&b| b == 0).collect();
        // every record is terminated: what follows the last NUL is empty
        if recs.last().is_some_and(|r| r.is_empty()) {
            recs.pop();
        }
        for r in recs {
            let Some(l) = std::str::from_utf8(r).ok().filter(|l| !l.is_empty()) else {
                dropped += 1;
                continue;
            };
            let p = PathBuf::from(l);
            if out.contains(&p) {
                continue;
            }
            if out.len() < MAX_ITEMS && p.is_absolute() && fs::symlink_metadata(&p).is_ok() {
                out.push(p);
            } else {
                dropped += 1;
            }
        }
    }
    (out, dropped)
}

/// What this process does with its share of the selection.
#[derive(Debug, PartialEq, Eq)]
pub enum Role {
    /// Open one window for these items (the whole selection, in Explorer's order of arrival).
    /// `dropped`: spooled names that were not usable (relative, gone, too many); the window says so.
    Lead { items: Vec<PathBuf>, dropped: usize },
    /// Another process took our items: exit quietly.
    Done,
}

/// Spools `items` in `base` and either becomes the leader (collecting everybody's items) or
/// leaves them to the current leader.
pub fn gather(base: &Path, kind: Kind, items: &[PathBuf]) -> std::io::Result<Role> {
    let d = dir(base, kind);
    let own = || Role::Lead { items: items.to_vec(), dropped: 0 };
    // a spool folder somebody else made or controls is not used: its lists would add items
    // (security review 2026-11-08); this window then just takes its own items
    if crate::sysinfo::ensure_private_dir(&d).is_err() {
        return Ok(own());
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
            let (all, dropped) = take(&d);
            let _ = lock.unlock();
            return Ok(Role::Lead { items: all, dropped });
        }
        if !mine.exists() {
            return Ok(Role::Done);
        }
        if start.elapsed() > FOLLOW_WAIT {
            // the leader seems stuck: handle our own items
            let _ = fs::remove_file(&mine);
            return Ok(own());
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
                std::thread::spawn(move || gather(&b, Kind::Encrypt, &[f]).unwrap())
            })
            .collect();
        let roles: Vec<Role> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        let leads: Vec<&Vec<PathBuf>> = roles.iter().filter_map(|r| if let Role::Lead { items, .. } = r { Some(items) } else { None }).collect();
        let total: usize = leads.iter().map(|v| v.len()).sum();
        assert_eq!(total, files.len(), "every item handled exactly once: {roles:?}");
        assert!(leads.len() <= 2, "one window (two at worst when the last arrives late): {roles:?}");
        assert!(entries(&dir(&b, Kind::Encrypt)).is_empty());
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn junk_and_stale_entries_are_dropped() {
        let b = base();
        let d = dir(&b, Kind::Encrypt);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("x.lst"), "relative/path\0/definitely/not/here\0").unwrap();
        let real = b.join("real.txt");
        fs::write(&real, b"x").unwrap();
        // review F: the two unusable lines are counted, not silently lost
        assert_eq!(gather(&b, Kind::Encrypt, std::slice::from_ref(&real)).unwrap(), Role::Lead { items: vec![real], dropped: 2 });
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn encrypt_and_wipe_selections_never_mix() {
        let b = base();
        let (x, y) = (b.join("x.txt"), b.join("y.txt"));
        fs::write(&x, b"x").unwrap();
        fs::write(&y, b"y").unwrap();
        let hx = {
            let (b, x) = (b.clone(), x.clone());
            std::thread::spawn(move || gather(&b, Kind::Encrypt, &[x]).unwrap())
        };
        let w = gather(&b, Kind::Wipe, std::slice::from_ref(&y)).unwrap();
        assert_eq!(w, Role::Lead { items: vec![y], dropped: 0 });
        assert_eq!(hx.join().unwrap(), Role::Lead { items: vec![x], dropped: 0 });
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn names_with_newlines_stay_one_item() {
        // 3.1.0 final 4-8: entries are NUL-separated; a name with a newline is not split into
        // "<folder>/a" (which may be another, existing file) and "b"
        let b = base();
        let other = b.join("a");
        fs::write(&other, b"other file").unwrap();
        let name = if cfg!(unix) { "a\nb.txt" } else { "a b.txt" };
        let real = b.join(name);
        fs::write(&real, b"x").unwrap();
        assert_eq!(gather(&b, Kind::Wipe, std::slice::from_ref(&real)).unwrap(), Role::Lead { items: vec![real], dropped: 0 });
        // an old newline-separated list (one record that names nothing) and a non-UTF-8 record
        // plus an empty one are dropped and counted, never split into existing names
        let d = dir(&b, Kind::Wipe);
        fs::write(d.join("old.lst"), format!("{}\n{}\n", other.display(), other.display())).unwrap();
        fs::write(d.join("bad.lst"), b"\xff\xfe\0\0").unwrap();
        let mine = b.join("mine.txt");
        fs::write(&mine, b"x").unwrap();
        assert_eq!(gather(&b, Kind::Wipe, std::slice::from_ref(&mine)).unwrap(), Role::Lead { items: vec![mine], dropped: 3 });
        let _ = fs::remove_dir_all(b);
    }

    #[test]
    fn file_manager_arguments_become_absolute_paths() {
        // review F: Nautilus may pass names relative to the folder it shows, and URIs
        let cwd = std::env::temp_dir().join("shield_cwd");
        let n = |a: &str| normalize_arg(a, &cwd);
        assert_eq!(n("a b.txt"), Some(cwd.join("a b.txt")), "spaces");
        assert_eq!(n("say 'hi'.txt"), Some(cwd.join("say 'hi'.txt")), "quotes");
        if cfg!(unix) {
            assert_eq!(n("say \"hi\".txt"), Some(cwd.join("say \"hi\".txt")), "double quotes");
            assert_eq!(n("line\nbreak.txt"), Some(cwd.join("line\nbreak.txt")), "newline in a name");
            assert_eq!(n("file:///home/u/My%20File%22.txt"), Some(PathBuf::from("/home/u/My File\".txt")));
            assert_eq!(n("file://localhost/tmp/x"), Some(PathBuf::from("/tmp/x")));
        } else {
            assert_eq!(n("file:///C:/Users/u/My%20File.txt"), Some(PathBuf::from(r"C:\Users\u\My File.txt")));
        }
        assert_eq!(n("./sub/x"), Some(cwd.join("sub").join("x")), "dot removed");
        assert_eq!(n("-starts-with-dash"), Some(cwd.join("-starts-with-dash")));
        let abs = std::env::temp_dir().join("abs.txt");
        assert_eq!(n(&abs.to_string_lossy()), Some(abs.clone()));
        assert_eq!(n("file://otherhost/share/x"), None, "remote host");
        assert_eq!(n("file:///bad%zz"), None, "bad escape");
        assert_eq!(n(""), None);
        assert_eq!(n("nul\0byte"), None);
    }
}
