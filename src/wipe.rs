//! Shredding, disk type detection, free-space overwrite and TRIM.
//! None of this can guarantee physical erasure on SSDs (wear levelling, spare cells, snapshots).

use crate::entropy::{fill_random, rand_hex};
use crate::progress::*;
use std::{
    fs::{self, OpenOptions},
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

/// Absolute path of a System32 tool, so a planted cipher.exe/powershell.exe elsewhere is never run.
#[cfg(windows)]
fn sys32(rel: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(rel)
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
        return Ok(format!("{l}: TRIM 완료"));
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
        Some((0, _)) => Ok(format!("{l}: TRIM 완료 (관리자 권한)")),
        Some((2, _)) => Err("관리자 권한 요청이 거부되어 TRIM을 실행하지 못했습니다.".into()),
        _ => Err(format!("{l}: TRIM 실패 (SSD가 아니거나 TRIM을 지원하지 않는 드라이브일 수 있습니다)")),
    }
}

#[cfg(not(windows))]
pub fn trim_volume(_l: char) -> R<String> {
    Err("TRIM은 Windows에서만 지원됩니다.".into())
}

/// Overwrites the free space of the volume that holds `dir` (cipher /w: 0x00, 0xFF, random).
/// Cancellable. Takes a long time: it fills the whole free space three times.
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

/// Bytes that `shred_tree` will write (for the progress bar).
pub fn shred_bytes(p: &Path, passes: usize) -> u64 {
    crate::archive::tree_size(p, false).saturating_mul(passes as u64)
}

/// Overwrite (up to 7 passes), truncate, rename randomly, delete.
pub fn shred(path: &Path, passes: usize) -> R<()> {
    let md = fs::metadata(path).map_err(e)?;
    if md.permissions().readonly() {
        let mut perm = md.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        fs::set_permissions(path, perm).map_err(e)?;
    }
    let len = md.len();
    let mut f = OpenOptions::new().write(true).open(path).map_err(e)?;
    let mut buf = vec![0u8; 1 << 20];
    for p in PATTERNS.iter().take(passes.clamp(1, 7)) {
        f.seek(SeekFrom::Start(0)).map_err(e)?;
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            match p {
                Some(b) => buf[..n].fill(*b),
                None => fill_random(&mut buf[..n]),
            }
            f.write_all(&buf[..n]).map_err(e)?;
            left -= n as u64;
            progress_add(n as u64);
        }
        f.flush().map_err(e)?;
        f.sync_all().map_err(e)?;
    }
    f.set_len(0).map_err(e)?;
    f.sync_all().map_err(e)?;
    drop(f);
    let np = path.with_file_name(rand_hex());
    fs::rename(path, &np).map_err(e)?;
    fs::remove_file(&np).map_err(e)
}

/// Shreds every file below `p`, then removes directories. Symlinks are removed, never followed.
pub fn shred_tree(p: &Path, passes: usize) -> R<()> {
    let m = fs::symlink_metadata(p).map_err(e)?;
    if m.file_type().is_symlink() {
        return fs::remove_file(p).or_else(|_| fs::remove_dir(p)).map_err(e);
    }
    if m.is_dir() {
        for en in fs::read_dir(p).map_err(e)? {
            shred_tree(&en.map_err(e)?.path(), passes)?;
        }
        return fs::remove_dir(p).map_err(e);
    }
    shred(p, passes)
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn base64_utf16() {
        // "ab" -> 61 00 62 00
        assert_eq!(super::encode_ps("ab"), "YQBiAA==");
        assert_eq!(super::encode_ps("abc"), "YQBiAGMA");
    }
}
