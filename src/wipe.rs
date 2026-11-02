//! Shredding, disk type detection, free-space overwrite and TRIM.
//! None of this can guarantee physical erasure on SSDs (wear levelling, spare cells), on volumes
//! with snapshots (VSS) or in cloud-synced folders (the provider keeps versions).

use crate::entropy::{bulk_rng, rand_hex};
use crate::i18n::{t, tf};
use crate::manifest::FileRec;
use crate::progress::*;
use crate::sysinfo::{file_id, open_no_follow};
use rand::RngCore;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disk {
    Ssd,
    Hdd,
    Unknown,
}

/// 00, FF, random, 55, AA, random, random.
pub const PATTERNS: [Option<u8>; 7] = [Some(0), Some(0xFF), None, Some(0x55), Some(0xAA), None, None];

fn plain_path(p: &Path) -> String {
    let s = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().into_owned();
    s.strip_prefix(r"\\?\").map(String::from).unwrap_or(s)
}

pub fn drive_letter(p: &Path) -> Option<char> {
    let s = plain_path(p);
    let mut it = s.chars();
    let a = it.next()?;
    (it.next() == Some(':') && a.is_ascii_alphabetic()).then(|| a.to_ascii_uppercase())
}

/// Absolute path of a System32 tool (System32 from GetSystemDirectoryW, not from the environment).
#[cfg(windows)]
fn sys32(rel: &str) -> PathBuf {
    crate::sysinfo::system_dir().join(rel)
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<(i32, String)> {
    use std::os::windows::process::CommandExt;
    let o = std::process::Command::new(sys32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode_ps(script)])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&o.stderr));
    Some((o.status.code().unwrap_or(-1), text))
}

/// PowerShell -EncodedCommand payload: base64 of UTF-16LE (no quoting/injection issues).
#[cfg(windows)]
fn encode_ps(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Media type of the disk that holds `p` (Windows: via the Storage cmdlets).
pub fn detect_disk(p: &Path) -> Disk {
    #[cfg(windows)]
    {
        if let Some(l) = drive_letter(p) {
            let cmd = format!("(Get-Partition -DriveLetter {l} | Get-Disk | Get-PhysicalDisk).MediaType");
            if let Some((0, out)) = powershell(&cmd) {
                let o = out.to_uppercase();
                if o.contains("SSD") {
                    return Disk::Ssd;
                }
                if o.contains("HDD") {
                    return Disk::Hdd;
                }
            }
        }
    }
    let _ = p;
    Disk::Unknown
}

/// Asks the volume to TRIM all free space (Optimize-Volume -ReTrim). Needs administrator rights:
/// tries directly first, then once through a UAC prompt. Not cancellable once started.
#[cfg(windows)]
pub fn trim_volume(l: char) -> R<String> {
    if !l.is_ascii_alphabetic() {
        return Err(t("wipe.bad_drive").into());
    }
    let inner = format!("try {{ Optimize-Volume -DriveLetter {l} -ReTrim -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 3 }}");
    if let Some((0, _)) = powershell(&inner) {
        return Ok(tf("wipe.trim_done", &[&l]));
    }
    let exe = sys32(r"WindowsPowerShell\v1.0\powershell.exe");
    let elevate = format!(
        "try {{ $p = Start-Process -FilePath '{}' -Verb RunAs -Wait -PassThru -WindowStyle Hidden \
         -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{}' -ErrorAction Stop; exit $p.ExitCode }} \
         catch {{ exit 2 }}",
        exe.display().to_string().replace('\'', "''"),
        encode_ps(&inner)
    );
    match powershell(&elevate) {
        Some((0, _)) => Ok(tf("wipe.trim_done_admin", &[&l])),
        Some((2, _)) => Err(t("wipe.trim_denied").into()),
        _ => Err(tf("wipe.trim_failed", &[&l])),
    }
}

#[cfg(not(windows))]
pub fn trim_volume(_l: char) -> R<String> {
    Err(t("wipe.windows_only").into())
}

/// Overwrites the free space of the volume that holds `dir` (cipher /w: 0x00, 0xFF, random).
#[cfg(windows)]
pub fn wipe_free_space(dir: &Path) -> R<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    let l = drive_letter(dir).ok_or_else(|| t("wipe.no_drive").to_string())?;
    let mut child = std::process::Command::new(sys32("cipher.exe"))
        .arg(format!("/w:{}", plain_path(dir)))
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(e)?;
    let ok = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) => {
                if cancelled() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(cancelled_msg());
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(x) => return Err(e(x)),
        }
    };
    if ok {
        Ok(tf("wipe.free_done", &[&l]))
    } else {
        Err(t("wipe.cipher_failed").into())
    }
}

#[cfg(not(windows))]
pub fn wipe_free_space(_dir: &Path) -> R<String> {
    Err(t("wipe.windows_only").into())
}

pub enum ShredSkip {
    Changed,
    HardLink,
    Failed(String),
}

/// Overwrites through one checked handle, truncates, renames randomly and deletes.
/// Refuses: anything that is no longer the listed object (ID, size, time), hard links (other names
/// would keep the data), links/reparse points (handled as the link itself, never the target).
/// `streams`: also overwrite the alternate data streams (B-9). This happens after the identity
/// check, because writing a stream changes the file's modification time. Returns their number.
pub fn shred_checked(r: &FileRec, passes: usize, streams: bool) -> Result<u64, ShredSkip> {
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
    let len = md.len();
    let mut rng = bulk_rng().map_err(fail)?;
    let mut buf = vec![0u8; 1 << 20];
    for p in PATTERNS.iter().take(passes.clamp(1, 7)) {
        f.seek(SeekFrom::Start(0)).map_err(|x| fail(x.to_string()))?;
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            match p {
                Some(b) => buf[..n].fill(*b),
                None => rng.fill_bytes(&mut buf[..n]),
            }
            f.write_all(&buf[..n]).map_err(|x| fail(x.to_string()))?;
            left -= n as u64;
            progress_add(n as u64);
        }
        f.flush().map_err(|x| fail(x.to_string()))?;
        f.sync_all().map_err(|x| fail(x.to_string()))?;
    }
    f.set_len(0).map_err(|x| fail(x.to_string()))?;
    f.sync_all().map_err(|x| fail(x.to_string()))?;
    drop(f);
    // hide the name, then delete the object we verified again by handle
    let np = r.path.with_file_name(rand_hex().map_err(fail)?);
    fs::rename(&r.path, &np).map_err(|x| fail(x.to_string()))?;
    let g = open_no_follow(&np, true).map_err(|x| fail(x.to_string()))?;
    let gid = file_id(&g).map_err(|x| fail(x.to_string()))?;
    if gid.vol != r.id.vol || gid.idx != r.id.idx {
        drop(g);
        let _ = fs::rename(&np, &r.path);
        return Err(ShredSkip::Changed);
    }
    #[cfg(windows)]
    {
        crate::sysinfo::delete_by_handle(&g).map_err(|x| fail(x.to_string()))?;
        drop(g);
        Ok(n_streams)
    }
    #[cfg(not(windows))]
    {
        drop(g);
        fs::remove_file(&np).map_err(|x| fail(x.to_string())).map(|_| n_streams)
    }
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
fn open_for_overwrite(p: &Path) -> std::io::Result<fs::File> {
    match fs::OpenOptions::new().write(true).open(p) {
        Err(x) if x.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut perm = fs::symlink_metadata(p)?.permissions();
            if !perm.readonly() {
                return Err(x);
            }
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            fs::set_permissions(p, perm)?;
            fs::OpenOptions::new().write(true).open(p)
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
    if m.file_type().is_symlink() {
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
#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn base64_utf16() {
        assert_eq!(super::encode_ps("ab"), "YQBiAA==");
        assert_eq!(super::encode_ps("abc"), "YQBiAGMA");
    }
    #[test]
    fn own_tree_reports_and_clears_read_only() {
        let d = std::env::temp_dir().join(format!("shield_tree_{}", crate::entropy::rand_hex().unwrap()));
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let f = d.join("sub").join("ro.txt");
        std::fs::write(&f, b"secret").unwrap();
        let mut perm = std::fs::metadata(&f).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&f, perm).unwrap();
        let rep = super::shred_own_tree_report(&d);
        assert!(rep.ok(), "{}", rep.message());
        assert!(!d.exists());
    }
    #[test]
    fn own_tree_reports_an_undeletable_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = std::env::temp_dir().join(format!("shield_tree_{}", crate::entropy::rand_hex().unwrap()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("busy.bin");
        std::fs::write(&f, b"secret").unwrap();
        // another handle without FILE_SHARE_WRITE|DELETE: overwrite and delete must both fail
        let h = std::fs::OpenOptions::new().read(true).share_mode(1).open(&f).unwrap();
        let rep = super::shred_own_tree_report(&d);
        assert!(!rep.ok());
        assert!(!rep.overwrite_failed.is_empty() && !rep.delete_failed.is_empty(), "{rep:?}");
        assert!(super::shred_own_tree(&d).is_err());
        drop(h);
        assert!(super::shred_own_tree(&d).is_ok());
    }
    #[test]
    fn system_dir_from_api() {
        assert!(super::sys32("cipher.exe").is_file());
    }
}
