//! Linux system helpers: memory, process start times, UI language, dark mode, local time, fonts,
//! "sealing" (none: Linux has no per-user DPAPI equivalent without a keyring daemon), pkexec and
//! small bounded subprocess runs.

use crate::{Civil, PResult, Sealed};
use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// MemAvailable from /proc/meminfo (what the kernel thinks can be allocated without swapping).
pub fn avail_mem() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                let r = l.strip_prefix("MemAvailable:")?;
                r.trim().trim_end_matches("kB").trim().parse::<u64>().ok().map(|k| k * 1024)
            })
        })
        .unwrap_or(2 << 30)
}

/// Start time (clock ticks since boot, /proc/<pid>/stat field 22) of a live process.
/// None when the process does not exist or is a zombie.
pub fn process_start(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // the command name (field 2) may contain spaces and ')': split after the LAST ')'
    let rest = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    if matches!(f.first(), Some(&"Z") | Some(&"X") | None) {
        return None;
    }
    f.get(19)?.parse().ok()
}

/// No portable way without a display-server client; the GUI clears the clipboard through its own
/// toolkit instead. Always false here.
pub fn clear_clipboard() -> bool {
    false
}

pub fn system_lang_is_korean() -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("ko"))
}

/// Runs a program (absolute path candidates only: no PATH lookup) with a time limit and returns
/// its stdout when it exits with 0.
pub(crate) fn run_quiet(candidates: &[&str], args: &[&OsStr], limit: Duration) -> Option<String> {
    let prog = candidates.iter().map(Path::new).find(|p| p.is_file())?;
    let mut child = Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).env("LC_ALL", "C").spawn().ok()?;
    let t0 = Instant::now();
    loop {
        match child.try_wait().ok()? {
            Some(st) if st.success() => {
                let mut out = String::new();
                io::Read::read_to_string(child.stdout.as_mut()?, &mut out).ok()?;
                return Some(out);
            }
            Some(_) => return None,
            None if t0.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// GTK_THEME "...:dark", else GNOME's color-scheme = 'prefer-dark'.
pub fn system_dark() -> bool {
    if let Ok(t) = std::env::var("GTK_THEME") {
        return t.to_ascii_lowercase().contains("dark");
    }
    let args = [OsStr::new("get"), OsStr::new("org.gnome.desktop.interface"), OsStr::new("color-scheme")];
    run_quiet(&["/usr/bin/gsettings", "/bin/gsettings"], &args, Duration::from_millis(800)).is_some_and(|s| s.contains("dark"))
}

/// Title bars belong to the window manager on Linux.
pub fn dark_title_bar(_dark: bool) {}

pub fn local_time(secs: i64) -> Option<Civil> {
    // the type comes from localtime_r (time_t; i64 on every supported target, musl included)
    #[allow(clippy::useless_conversion)]
    let t = secs.try_into().ok()?;
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    Some(Civil { y: tm.tm_year as i64 + 1900, mo: tm.tm_mon as u32 + 1, d: tm.tm_mday as u32, h: tm.tm_hour as u32, mi: tm.tm_min as u32, s: tm.tm_sec.min(59) as u32 })
}

/// Fonts with Hangul in the usual distribution locations, best first: (path, face index).
/// In the Noto CJK collections face 1 is the Korean one.
pub fn font_candidates() -> Vec<(PathBuf, u32)> {
    const C: [(&str, u32); 12] = [
        ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 1),
        ("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", 1),
        ("/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc", 1),
        ("/usr/share/fonts/opentype/noto/NotoSansCJKkr-Regular.otf", 0),
        ("/usr/share/fonts/noto-cjk/NotoSansCJKkr-Regular.otf", 0),
        ("/usr/share/fonts/google-noto-sans-cjk-fonts/NotoSansCJK-Regular.ttc", 1),
        ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", 0),
        ("/usr/share/fonts/nanum/NanumGothic.ttf", 0),
        ("/usr/share/fonts/naver-nanum/NanumGothic.ttf", 0),
        ("/usr/share/fonts/truetype/unfonts-core/UnDotum.ttf", 0),
        ("/usr/share/fonts/truetype/baekmuk/gulim.ttf", 0),
        ("/usr/share/fonts/TTF/NanumGothic.ttf", 0),
    ];
    let mut v: Vec<(PathBuf, u32)> = C.iter().map(|(p, i)| (PathBuf::from(p), *i)).collect();
    if let Some(d) = dirs::font_dir() {
        v.push((d.join("NanumGothic.ttf"), 0));
        v.push((d.join("NotoSansCJK-Regular.ttc"), 1));
    }
    v
}

/// No OS sealing service is used on Linux: the bytes come back unchanged with
/// `os_protected = false`, and the caller relies on a 0600 file (documented as weaker).
pub fn seal(data: &[u8]) -> PResult<Sealed> {
    Ok(Sealed { bytes: data.to_vec(), os_protected: false })
}

pub fn unseal(data: &[u8]) -> PResult<Vec<u8>> {
    Ok(data.to_vec())
}

/// Runs `program args...` as root through polkit (pkexec, absolute path) and waits.
pub fn run_privileged(program: &Path, args: &[&OsStr]) -> io::Result<i32> {
    let pk = ["/usr/bin/pkexec", "/bin/pkexec"].iter().map(Path::new).find(|p| p.is_file()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "pkexec not installed"))?;
    let st = Command::new(pk).arg(program).args(args).stdin(Stdio::null()).status()?;
    Ok(st.code().unwrap_or(1))
}

pub fn stdin_is_console() -> bool {
    unsafe { libc::isatty(0) == 1 }
}
