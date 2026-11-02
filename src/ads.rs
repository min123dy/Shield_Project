//! NTFS alternate data streams (ADS).
//!
//! * B-7 Mark of the Web: files extracted from a container that came from the internet must carry
//!   the container's `Zone.Identifier` stream, or SmartScreen / Office Protected View would treat
//!   them as local, trusted files. This is the class of bug fixed in 7-Zip as CVE-2025-0411 (MotW
//!   not propagated from an archive to its extracted files).
//! * B-9 Shredding: overwriting a file's main stream does not touch its named streams; deleting the
//!   file then frees them unread-but-not-overwritten. Before shredding, streams are listed with
//!   `FindFirstStreamW` so the user can include them (overwritten here) or abort.

use crate::i18n::tf;
use crate::progress::*;
use std::path::{Path, PathBuf};

pub const ZONE: &str = "Zone.Identifier";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub name: String,
    pub size: u64,
}

/// Named streams of `p` (the unnamed main stream is not included).
#[cfg(windows)]
pub fn list_streams(p: &Path) -> std::io::Result<Vec<Stream>> {
    use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA};
    let w = crate::sysinfo::wide(p);
    let mut d: WIN32_FIND_STREAM_DATA = unsafe { core::mem::zeroed() };
    let h = unsafe { FindFirstStreamW(w.as_ptr(), FindStreamInfoStandard, &mut d as *mut _ as _, 0) };
    if h == INVALID_HANDLE_VALUE {
        let x = std::io::Error::last_os_error();
        // ERROR_HANDLE_EOF: no streams at all (e.g. a folder); 87: FS without stream support
        return match x.raw_os_error() {
            Some(c) if c == ERROR_HANDLE_EOF as i32 || c == 87 || c == 1 => Ok(Vec::new()),
            _ => Err(x),
        };
    }
    let mut out = Vec::new();
    loop {
        let n = d.cStreamName.iter().position(|&c| c == 0).unwrap_or(d.cStreamName.len());
        let full = String::from_utf16_lossy(&d.cStreamName[..n]);
        // ":name:$DATA"; "::$DATA" is the main stream
        let name = full.strip_suffix(":$DATA").unwrap_or(&full);
        let name = name.strip_prefix(':').unwrap_or(name).to_string();
        if !name.is_empty() {
            out.push(Stream { name, size: d.StreamSize.max(0) as u64 });
        }
        if unsafe { FindNextStreamW(h, &mut d as *mut _ as _) } == 0 {
            let x = std::io::Error::last_os_error();
            unsafe { FindClose(h) };
            return if x.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) { Ok(out) } else { Err(x) };
        }
    }
}

#[cfg(not(windows))]
pub fn list_streams(_p: &Path) -> std::io::Result<Vec<Stream>> {
    Ok(Vec::new())
}

fn stream_path(p: &Path, name: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(":");
    s.push(name);
    PathBuf::from(s)
}

/// What the pre-shred check found.
#[derive(Default, Debug)]
pub struct AdsScan {
    /// Files with streams other than Zone.Identifier (real hidden data).
    pub data: Vec<(PathBuf, Vec<Stream>)>,
    /// Files whose only stream is Zone.Identifier (download marker; reduced warning).
    pub zone_only: Vec<PathBuf>,
    /// Files whose streams could not be listed.
    pub errors: Vec<String>,
}

impl AdsScan {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.zone_only.is_empty() && self.errors.is_empty()
    }
}

pub fn scan<'a>(files: impl Iterator<Item = &'a Path>) -> R<AdsScan> {
    let mut s = AdsScan::default();
    for p in files {
        check_cancel()?;
        match list_streams(p) {
            Ok(v) if v.is_empty() => {}
            Ok(v) if v.iter().all(|x| x.name.eq_ignore_ascii_case(ZONE)) => s.zone_only.push(p.to_path_buf()),
            Ok(v) => s.data.push((p.to_path_buf(), v)),
            Err(x) => s.errors.push(format!("{}: {x}", p.display())),
        }
    }
    Ok(s)
}

/// Overwrites every named stream of `p` (`passes` times, then truncates it). Returns the count.
pub fn overwrite_streams(p: &Path, passes: usize) -> Result<u64, String> {
    use std::io::{Seek, SeekFrom, Write};
    let streams = list_streams(p).map_err(|x| tf("ads.list_failed", &[&p.display(), &x]))?;
    let mut rng = crate::entropy::bulk_rng()?;
    let mut buf = vec![0u8; 1 << 16];
    for st in &streams {
        let sp = stream_path(p, &st.name);
        let r = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(&sp)?;
            for pat in crate::wipe::PATTERNS.iter().take(passes.clamp(1, 7)) {
                f.seek(SeekFrom::Start(0))?;
                let mut left = st.size;
                while left > 0 {
                    let n = left.min(buf.len() as u64) as usize;
                    match pat {
                        Some(b) => buf[..n].fill(*b),
                        None => rand::RngCore::fill_bytes(&mut rng, &mut buf[..n]),
                    }
                    f.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                f.sync_all()?;
            }
            f.set_len(0)?;
            f.sync_all()
        })();
        r.map_err(|x| tf("ads.overwrite_failed", &[&p.display(), &st.name, &x]))?;
    }
    Ok(streams.len() as u64)
}

/// Reads the container's Mark of the Web (None when it has none).
pub fn read_zone(container: &Path) -> Option<Vec<u8>> {
    if !cfg!(windows) {
        return None;
    }
    std::fs::read(stream_path(container, ZONE)).ok().filter(|z| !z.is_empty() && z.len() <= 64 * 1024)
}

/// Writes `zone` as the Zone.Identifier of `dest` and of every file below it (folders don't carry
/// one). Returns the paths that could not be marked.
pub fn apply_zone(dest: &Path, zone: &[u8]) -> Vec<String> {
    let mut failed = Vec::new();
    apply_into(dest, zone, &mut failed);
    failed
}

fn apply_into(p: &Path, zone: &[u8], failed: &mut Vec<String>) {
    let Ok(m) = std::fs::symlink_metadata(p) else {
        failed.push(p.display().to_string());
        return;
    };
    if m.file_type().is_symlink() {
        return;
    }
    if m.is_dir() {
        match std::fs::read_dir(p) {
            Ok(rd) => rd.flatten().for_each(|en| apply_into(&en.path(), zone, failed)),
            Err(_) => failed.push(p.display().to_string()),
        }
        return;
    }
    if let Err(x) = std::fs::write(stream_path(p, ZONE), zone) {
        failed.push(format!("{} ({x})", p.display()));
    }
}

/// Propagates the container's MotW to everything extracted (`items`). Failures are a warning, or
/// an error in strict mode (Settings > Security).
pub fn propagate(container: &Path, items: &[PathBuf], strict: bool) -> R<Option<String>> {
    let Some(zone) = read_zone(container) else { return Ok(None) };
    let failed: Vec<String> = items.iter().flat_map(|i| apply_zone(i, &zone)).collect();
    if failed.is_empty() {
        return Ok(None);
    }
    let msg = tf("ads.motw_failed", &[&failed.len(), &failed.first().cloned().unwrap_or_default()]);
    if strict {
        Err(msg)
    } else {
        Ok(Some(msg))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("shield_ads_{}", crate::entropy::rand_hex().unwrap()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    #[test]
    fn lists_classifies_and_overwrites_streams() {
        let d = dir();
        let plain = d.join("plain.txt");
        let zone = d.join("zone.txt");
        let hidden = d.join("hidden.txt");
        for f in [&plain, &zone, &hidden] {
            std::fs::write(f, b"main").unwrap();
        }
        std::fs::write(stream_path(&zone, ZONE), b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
        std::fs::write(stream_path(&hidden, "secret"), b"hidden data").unwrap();
        assert!(list_streams(&plain).unwrap().is_empty());
        assert_eq!(list_streams(&hidden).unwrap(), vec![Stream { name: "secret".into(), size: 11 }]);
        let s = scan([plain.as_path(), zone.as_path(), hidden.as_path()].into_iter()).unwrap();
        assert_eq!(s.zone_only, vec![zone.clone()]);
        assert_eq!(s.data.len(), 1);
        assert_eq!(overwrite_streams(&hidden, 1).unwrap(), 1);
        assert_eq!(std::fs::read(stream_path(&hidden, "secret")).unwrap().len(), 0, "stream emptied");
        let _ = std::fs::remove_dir_all(d);
    }
    #[test]
    fn motw_is_copied_to_every_extracted_file() {
        let d = dir();
        let c = d.join("box.shd");
        std::fs::write(&c, b"x").unwrap();
        let out = d.join("out");
        std::fs::create_dir_all(out.join("sub")).unwrap();
        std::fs::write(out.join("a.docx"), b"a").unwrap();
        std::fs::write(out.join("sub").join("b.exe"), b"b").unwrap();
        assert_eq!(propagate(&c, std::slice::from_ref(&out), true).unwrap(), None, "no MotW on the container: nothing to do");
        let z = b"[ZoneTransfer]\r\nZoneId=3\r\n";
        std::fs::write(stream_path(&c, ZONE), z).unwrap();
        assert_eq!(propagate(&c, std::slice::from_ref(&out), true).unwrap(), None);
        assert_eq!(std::fs::read(stream_path(&out.join("a.docx"), ZONE)).unwrap(), z);
        assert_eq!(std::fs::read(stream_path(&out.join("sub").join("b.exe"), ZONE)).unwrap(), z);
        // a missing target: warning normally, error in strict mode
        let gone = d.join("gone.txt");
        assert!(propagate(&c, std::slice::from_ref(&gone), false).unwrap().is_some());
        assert!(propagate(&c, &[gone], true).is_err());
        let _ = std::fs::remove_dir_all(d);
    }
}
