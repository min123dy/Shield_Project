//! Shredding, disk type detection, free-space overwrite and TRIM.
//! None of this can guarantee physical erasure on SSDs (wear levelling, spare cells), on volumes
//! with snapshots (VSS) or in cloud-synced folders (the provider keeps versions).

use crate::entropy::{bulk_rng, rand_hex};
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
        return Err("잘못된 드라이브 문자".into());
    }
    let inner = format!("try {{ Optimize-Volume -DriveLetter {l} -ReTrim -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 3 }}");
    if let Some((0, _)) = powershell(&inner) {
        return Ok(format!("{l}: TRIM 요청 완료"));
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
        Some((0, _)) => Ok(format!("{l}: TRIM 요청 완료 (관리자 권한)")),
        Some((2, _)) => Err("관리자 권한 요청이 거부되어 TRIM을 실행하지 못했습니다.".into()),
        _ => Err(format!("{l}: TRIM 실패 (SSD가 아니거나 TRIM을 지원하지 않는 드라이브일 수 있습니다)")),
    }
}

#[cfg(not(windows))]
pub fn trim_volume(_l: char) -> R<String> {
    Err("TRIM은 Windows에서만 지원됩니다.".into())
}

/// Overwrites the free space of the volume that holds `dir` (cipher /w: 0x00, 0xFF, random).
#[cfg(windows)]
pub fn wipe_free_space(dir: &Path) -> R<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    let l = drive_letter(dir).ok_or_else(|| "드라이브를 확인할 수 없습니다.".to_string())?;
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
                    return Err(CANCELLED.into());
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(x) => return Err(e(x)),
        }
    };
    if ok {
        Ok(format!("{l}: 여유 공간 덮어쓰기 완료"))
    } else {
        Err("cipher /w 실패".into())
    }
}

#[cfg(not(windows))]
pub fn wipe_free_space(_dir: &Path) -> R<String> {
    Err("여유 공간 덮어쓰기는 Windows에서만 지원됩니다.".into())
}

pub enum ShredSkip {
    Changed,
    HardLink,
    Failed(String),
}

/// Overwrites through one checked handle, truncates, renames randomly and deletes.
/// Refuses: anything that is no longer the listed object (ID, size, time), hard links (other names
/// would keep the data), links/reparse points (handled as the link itself, never the target).
pub fn shred_checked(r: &FileRec, passes: usize) -> Result<(), ShredSkip> {
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
        Ok(())
    }
    #[cfg(not(windows))]
    {
        drop(g);
        fs::remove_file(&np).map_err(|x| fail(x.to_string()))
    }
}

/// Removes a folder tree that Shield itself created (staging): files are overwritten once and
/// deleted; links are removed, never followed.
pub fn shred_own_tree(p: &Path) -> R<()> {
    let m = fs::symlink_metadata(p).map_err(e)?;
    if m.file_type().is_symlink() {
        return fs::remove_file(p).or_else(|_| fs::remove_dir(p)).map_err(e);
    }
    if m.is_dir() {
        let mut first_err = None;
        for en in fs::read_dir(p).map_err(e)? {
            if let Err(x) = en.map_err(e).and_then(|en| shred_own_tree(&en.path())) {
                first_err.get_or_insert(x);
            }
        }
        if let Some(x) = first_err {
            return Err(x);
        }
        return fs::remove_dir(p).map_err(e);
    }
    let len = m.len();
    if let Ok(mut f) = fs::OpenOptions::new().write(true).open(p) {
        let buf = vec![0u8; 1 << 20];
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            if f.write_all(&buf[..n]).is_err() {
                break;
            }
            left -= n as u64;
        }
        let _ = f.set_len(0);
        let _ = f.sync_all();
    }
    fs::remove_file(p).map_err(e)
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn base64_utf16() {
        assert_eq!(super::encode_ps("ab"), "YQBiAA==");
        assert_eq!(super::encode_ps("abc"), "YQBiAGMA");
    }
    #[test]
    fn system_dir_from_api() {
        assert!(super::sys32("cipher.exe").is_file());
    }
}
