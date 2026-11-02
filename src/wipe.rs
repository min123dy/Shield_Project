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

/// Media type of the disk that holds `p`. Windows: asks the storage stack whether the device incurs
/// a seek penalty (IOCTL_STORAGE_QUERY_PROPERTY, the same source as Get-PhysicalDisk's MediaType).
pub fn detect_disk(p: &Path) -> Disk {
    #[cfg(windows)]
    if let Some(l) = drive_letter(p) {
        return match seek_penalty(l) {
            Some(true) => Disk::Hdd,
            Some(false) => Disk::Ssd,
            None => Disk::Unknown,
        };
    }
    let _ = p;
    Disk::Unknown
}

/// StorageDeviceSeekPenaltyProperty of volume `l:`. None when the device does not report it
/// (virtual disks, some USB bridges, volumes spanning several disks).
#[cfg(windows)]
fn seek_penalty(l: char) -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    use windows_sys::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceSeekPenaltyProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY,
        STORAGE_PROPERTY_QUERY,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    if !l.is_ascii_alphabetic() {
        return None;
    }
    let dev: Vec<u16> = format!(r"\\.\{l}:").encode_utf16().chain(Some(0)).collect();
    unsafe {
        // access 0: a property query needs no read/write access, hence no administrator rights
        let h = CreateFileW(dev.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, core::ptr::null(), OPEN_EXISTING, 0, 0);
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let q = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceSeekPenaltyProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut d: DEVICE_SEEK_PENALTY_DESCRIPTOR = core::mem::zeroed();
        let mut n = 0u32;
        let ok = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &q as *const _ as _,
            core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            &mut d as *mut _ as _,
            core::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut n,
            core::ptr::null_mut(),
        );
        CloseHandle(h);
        let need = core::mem::offset_of!(DEVICE_SEEK_PENALTY_DESCRIPTOR, IncursSeekPenalty) + 1;
        (ok != 0 && n as usize >= need).then_some(d.IncursSeekPenalty != 0)
    }
}

/// Hidden command line of the elevated TRIM helper: `shield.exe --retrim <letter>`.
#[cfg(windows)]
pub const RETRIM_ARG: &str = "--retrim";

/// Exit code of a helper that really trimmed. Not 0: a Shield that ignored `--retrim` and opened
/// its normal window also exits with 0, and that must never be reported as a finished TRIM.
#[cfg(windows)]
const RETRIM_OK: i32 = 0x5452; // "TR"

/// Asks the volume to TRIM all free space through the Storage Management API (WMI
/// MSFT_Volume.Optimize with ReTrim, what Optimize-Volume -ReTrim calls). Needs administrator
/// rights: tries directly first, then once through a UAC prompt that runs this executable as
/// `--retrim <letter>`. Not cancellable once started.
#[cfg(windows)]
pub fn trim_volume(l: char) -> R<String> {
    if !l.is_ascii_alphabetic() {
        return Err(t("wipe.bad_drive").into());
    }
    let l = l.to_ascii_uppercase();
    if retrim_wmi(l).is_ok() {
        return Ok(tf("wipe.trim_done", &[&l]));
    }
    const ERROR_CANCELLED: i32 = 1223; // the user declined the UAC prompt
    match run_elevated(&format!("{RETRIM_ARG} {l}")) {
        Ok(c) if c == RETRIM_OK as u32 => Ok(tf("wipe.trim_done_admin", &[&l])),
        Err(x) if x.raw_os_error() == Some(ERROR_CANCELLED) => Err(t("wipe.trim_denied").into()),
        _ => Err(tf("wipe.trim_failed", &[&l])),
    }
}

/// Entry point of the elevated helper. Accepts exactly one drive letter; exit code RETRIM_OK on
/// success, 2 on a bad argument, 3 when the TRIM request failed.
#[cfg(windows)]
pub fn retrim_main(arg: Option<&str>) -> i32 {
    let mut c = arg.unwrap_or("").chars();
    match (c.next(), c.next()) {
        (Some(l), None) if l.is_ascii_alphabetic() => match retrim_wmi(l.to_ascii_uppercase()) {
            Ok(()) => RETRIM_OK,
            Err(_) => 3,
        },
        _ => 2,
    }
}

/// `__Path` of the MSFT_Volume mounted at `l:` (ROOT\Microsoft\Windows\Storage).
#[cfg(windows)]
fn volume_path(con: &wmi::WMIConnection, l: char) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct Vol {
        __Path: String,
    }
    if !l.is_ascii_alphabetic() {
        return Err(t("wipe.bad_drive").into()); // also keeps the WQL literal injection-free
    }
    let v: Vec<Vol> = con
        .raw_query(format!("SELECT __Path FROM MSFT_Volume WHERE DriveLetter = '{l}'"))
        .map_err(|x| x.to_string())?;
    v.into_iter().next().map(|v| v.__Path).ok_or_else(|| t("wipe.no_drive").to_string())
}

#[cfg(windows)]
fn retrim_wmi(l: char) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    #[allow(non_camel_case_types)]
    struct MSFT_Volume;
    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct OptimizeIn {
        ReTrim: bool,
    }
    #[derive(serde::Deserialize)]
    #[allow(non_snake_case)]
    struct OptimizeOut {
        ReturnValue: u32,
    }
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Storage").map_err(|x| x.to_string())?;
    let path = volume_path(&con, l)?;
    let out: OptimizeOut = con
        .exec_instance_method::<MSFT_Volume, _>(&path, "Optimize", OptimizeIn { ReTrim: true })
        .map_err(|x| x.to_string())?;
    match out.ReturnValue {
        0 => Ok(()),
        n => Err(format!("MSFT_Volume.Optimize: {n}")),
    }
}

/// Runs this executable elevated (UAC "runas", hidden window) with `params` and waits for it.
/// Returns its exit code; the error carries ERROR_CANCELLED when the prompt was declined.
#[cfg(windows)]
fn run_elevated(params: &str) -> std::io::Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let exe = crate::sysinfo::wide(&std::env::current_exe()?);
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, params) = (w("runas"), w(params));
    unsafe {
        let mut i: SHELLEXECUTEINFOW = core::mem::zeroed();
        i.cbSize = core::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        i.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        i.lpVerb = verb.as_ptr();
        i.lpFile = exe.as_ptr();
        i.lpParameters = params.as_ptr();
        i.nShow = SW_HIDE;
        if ShellExecuteExW(&mut i) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if i.hProcess == 0 {
            return Err(std::io::Error::other("no process handle"));
        }
        WaitForSingleObject(i.hProcess, INFINITE);
        let mut code = 1u32;
        let r = if GetExitCodeProcess(i.hProcess, &mut code) == 0 { Err(std::io::Error::last_os_error()) } else { Ok(code) };
        CloseHandle(i.hProcess);
        r
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
    fn disk_type_from_ioctl() {
        // the system drive always reports a seek penalty on real hardware; VMs may not
        let d = super::detect_disk(&std::env::temp_dir());
        assert!(matches!(d, super::Disk::Ssd | super::Disk::Hdd | super::Disk::Unknown));
        assert_eq!(super::seek_penalty('1'), None);
    }
    #[test]
    fn retrim_helper_rejects_bad_arguments() {
        for a in [None, Some(""), Some("CD"), Some("C:"), Some("1"), Some("C' OR 1=1")] {
            assert_eq!(super::retrim_main(a), 2, "{a:?}");
        }
    }
    #[test]
    fn msft_volume_of_the_system_drive() {
        let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Storage").unwrap();
        let l = super::drive_letter(&crate::sysinfo::system_dir()).unwrap();
        let p = super::volume_path(&con, l).unwrap();
        assert!(p.contains("MSFT_Volume"), "{p}");
        assert!(super::volume_path(&con, '1').is_err());
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
