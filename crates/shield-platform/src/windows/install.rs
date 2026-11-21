//! Update installation on Windows (3.1.0 #1: no swap between verification and installation).
//!
//! 3.0.0 handed the verified MSI in the user's %TEMP% to msiexec, which then asked for UAC: any
//! program running as the user could replace the file while the prompts were open and have it
//! installed with administrator rights. Now:
//!
//! 1. The normal (unelevated) Shield starts the *installed* `shield-gui.exe` (below Program
//!    Files, writable by administrators only) elevated with
//!    `--install-update "<msi>" "<msi.sig>" "<manifest>" "<manifest.sig>"` and waits for it.
//!    A portable or development copy is never elevated (`installed_helper_exe`).
//! 2. The elevated helper (shield-core `update::helper_main`) treats those paths as untrusted:
//!    it reads them without following links, copies the bytes into a new folder
//!    `%ProgramData%\Shield\update\<random>` that only SYSTEM and Administrators can access
//!    (protected DACL, no inheritance), verifies the copies with its own embedded release keys
//!    and version, and installs only from the copy. `%ProgramData%\Shield` is created by the MSI
//!    with that DACL; an existing folder is used only when an administrator account owns it
//!    (`secure_parent`, 3.1.0 review 2 #3).
//! 3. msiexec must not run while a Shield program file is in use, so the helper copies itself
//!    into that folder, starts the copy (`--install-update-run <folder>`, still elevated) and
//!    exits; the normal Shield exits too. The copy runs System32's msiexec on the copied MSI,
//!    waits for it, then deletes the files (its own .exe and the folder at the next restart, and
//!    at the next update).

use crate::{PResult, PlatformError};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// What the caller does after a successful start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installed {
    /// The installer runs on its own; exit now.
    ExitNow,
    /// Installed in place; the package was consumed. Restart to use the new version.
    Done,
}

/// Elevated helper: `shield-gui.exe --install-update <4 files>` (handled in shield-core).
pub const HELPER_ARG: &str = "--install-update";
/// Second stage, run from the private folder: `--install-update-run <folder>`.
pub const RUN_ARG: &str = "--install-update-run";
/// File names inside the private folder.
pub const PKG_FILE: &str = "package.msi";
const RUN_EXE: &str = "shield-update-run.exe";
const ERROR_CANCELLED: i32 = 1223;

/// Windows installs updates only through the elevated helper (`run_update_helper`).
pub fn install_package(_pkg: &Path, _check: &dyn Fn(&Path) -> bool) -> PResult<Installed> {
    Err(PlatformError::Unsupported("Windows installs updates only through the elevated helper"))
}

/// Installer kind this build updates with (asset name suffix).
pub fn package_kind() -> Option<&'static str> {
    Some("msi")
}


pub(crate) fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    let mut p: windows_sys::core::PWSTR = core::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(id, 0, 0, &mut p) };
    let out = if hr == 0 && !p.is_null() {
        let mut n = 0;
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        Some(PathBuf::from(std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(p, n) })))
    } else {
        None
    };
    unsafe { CoTaskMemFree(p as _) };
    out
}

pub(crate) fn program_files() -> Option<PathBuf> {
    known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)
}

fn program_data() -> Option<PathBuf> {
    known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData)
}

/// True when `exe` really lies below `root` (both resolved, case-insensitive).
pub(crate) fn below(exe: &Path, root: &Path) -> bool {
    match (fs::canonicalize(exe), fs::canonicalize(root)) {
        (Ok(e), Ok(r)) => {
            let (e, r) = (super::fs::path_key(&e), super::fs::path_key(&r));
            e.starts_with(&format!("{}\\", r.trim_end_matches('\\')))
        }
        _ => false,
    }
}

/// The installed `shield-gui.exe` next to this program, only when this program runs from below
/// Program Files (a folder only administrators can write). A portable or development copy is
/// refused: elevating a program its user can replace would elevate whatever was put there.
fn installed_helper_exe() -> PResult<PathBuf> {
    let me = std::env::current_exe()?;
    let pf = program_files().ok_or(PlatformError::Failed("Program Files folder".into()))?;
    let exe = me.parent().ok_or(PlatformError::Failed("no program folder".into()))?.join("shield-gui.exe");
    if !below(&me, &pf) || !below(&exe, &pf) || !exe.is_file() {
        return Err(PlatformError::Unsupported("only an installed Shield (below Program Files) installs updates"));
    }
    Ok(exe)
}

/// One quoted command-line argument. Paths with a quote, or ending in a backslash (it would
/// escape the closing quote), are refused rather than escaped.
pub(crate) fn quote_arg(p: &Path) -> io::Result<String> {
    let s = p.to_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not Unicode"))?;
    if s.contains('"') || s.ends_with('\\') || s.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path not allowed on the helper command line"));
    }
    Ok(format!("\"{s}\""))
}

/// Unelevated side: starts the installed helper elevated (one UAC prompt) and waits for it.
/// Returns its exit code; a declined prompt is `PlatformError::Declined`.
pub fn run_update_helper(files: &[&Path; 4]) -> PResult<i32> {
    let exe = installed_helper_exe()?;
    let mut params = String::from(HELPER_ARG);
    for f in files {
        params.push(' ');
        params.push_str(&quote_arg(f)?);
    }
    match super::sys::run_elevated_installed(&exe, &params) {
        Ok(c) => Ok(c as i32),
        Err(x) if x.raw_os_error() == Some(ERROR_CANCELLED) => Err(PlatformError::Declined),
        Err(x) => Err(x.into()),
    }
}

/// The process token is elevated (UAC "run as administrator").
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, &mut e as *mut _ as _, core::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len);
        CloseHandle(tok);
        ok != 0 && e.TokenIsElevated != 0
    }
}

/// The helper may only run elevated.
pub fn update_helper_allowed() -> bool {
    is_elevated()
}

/// 3.1.0 review 2 #1 on Windows: no owner rule. The copies go into a folder only SYSTEM and
/// Administrators can open (`ADMIN_DACL`), so reading a file through the helper never makes it
/// readable to anyone new; and under "over the shoulder" elevation the elevated account is not
/// the one that downloaded the files, so an owner comparison would refuse every such update.
pub fn update_input_owner_ok(_m: &fs::Metadata) -> bool {
    true
}

/// DACL of the private update folders: SYSTEM and Administrators only, not inherited.
pub(crate) const ADMIN_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Creates a NEW folder with `ADMIN_DACL` (fails if anything exists at `p`), then checks it is a
/// real folder.
pub(crate) fn create_admin_dir(p: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let w = super::fs::wide(p);
    let ok = super::fs::with_sd(ADMIN_DACL, |sd| unsafe {
        let a = windows_sys::Win32::Security::SECURITY_ATTRIBUTES { nLength: core::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        CreateDirectoryW(w.as_ptr(), &a) != 0
    })?;
    if !ok {
        return Err(io::Error::last_os_error());
    }
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || super::fs::is_reparse(&m) {
        return Err(io::Error::other("private folder check failed"));
    }
    Ok(())
}

/// Owners an existing update folder may have (3.1.0 review 2 #3): SYSTEM, Administrators,
/// TrustedInstaller. Anything else was made by a normal account and is never taken over.
pub(crate) fn trusted_owner_sid(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544" | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
}

/// Opens the folder itself (never what a junction or link points to) for reading and replacing
/// its owner / DACL.
fn open_dir_no_follow(p: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new().access_mode(READ_CONTROL | WRITE_DAC).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(p)
}

/// String SID of the owner of the object behind `f`.
pub(crate) fn owner_sid(f: &File) -> io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    unsafe {
        let mut owner: windows_sys::Win32::Foundation::PSID = core::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        let rc = GetSecurityInfo(f.as_raw_handle() as _, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut sd);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut s: windows_sys::core::PWSTR = core::ptr::null_mut();
        let out = if ConvertSidToStringSidW(owner, &mut s) != 0 && !s.is_null() {
            let mut n = 0;
            while *s.add(n) != 0 {
                n += 1;
            }
            let v = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            windows_sys::Win32::Foundation::LocalFree(s as _);
            Ok(v)
        } else {
            Err(io::Error::last_os_error())
        };
        windows_sys::Win32::Foundation::LocalFree(sd as _);
        out
    }
}

/// `%ProgramData%\Shield` and `...\update`: created with `ADMIN_DACL` (the MSI creates
/// `%ProgramData%\Shield` that way on installation). An existing folder (users may create folders
/// in ProgramData) is used only when it is a real folder - checked on a handle that does not
/// follow junctions or links, so it cannot be swapped between check and change - owned by
/// SYSTEM, Administrators or TrustedInstaller; its DACL is then reset to `ADMIN_DACL` through
/// that same handle. 3.1.0 review 2 #3: 3.1.0's first version took any existing folder over by
/// path (SetNamedSecurityInfoW after a symlink_metadata check: a junction swapped in between
/// redirected the change to another folder) and made itself the owner; a folder a normal account
/// made could also still be reached by that account through handles it opened before the takeover.
fn secure_parent(p: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    match create_admin_dir(p) {
        Ok(()) => return Ok(()),
        Err(x) if x.kind() != io::ErrorKind::AlreadyExists => return Err(x),
        Err(_) => {}
    }
    let f = open_dir_no_follow(p)?;
    let m = f.metadata()?;
    if !m.is_dir() || super::fs::is_reparse(&m) {
        return Err(io::Error::other(format!("{} is not a real folder", p.display())));
    }
    let owner = owner_sid(&f)?;
    if !trusted_owner_sid(&owner) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} was created by another account ({owner}); an administrator has to delete it", p.display())));
    }
    let rc = super::fs::with_sd(ADMIN_DACL, |sd| unsafe {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = core::ptr::null_mut();
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 || present == 0 {
            return u32::MAX;
        }
        SetSecurityInfo(f.as_raw_handle() as _, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, core::ptr::null_mut(), core::ptr::null_mut(), dacl, core::ptr::null())
    })?;
    match rc {
        0 => Ok(()),
        u32::MAX => Err(io::Error::other("security descriptor")),
        n => Err(io::Error::from_raw_os_error(n as i32)),
    }
}

/// Test hook: `secure_parent` for a folder of the test's choice.
#[cfg(test)]
pub(crate) fn secure_parent_for_test(p: &Path) -> io::Result<()> {
    secure_parent(p)
}

fn update_root() -> io::Result<PathBuf> {
    Ok(program_data().ok_or_else(|| io::Error::other("ProgramData folder"))?.join("Shield").join("update"))
}

/// Removes folders that earlier updates left in the update root (best effort; an old second
/// stage's .exe stays until it was deleted at a restart).
fn remove_stale(root: &Path) {
    let Ok(rd) = fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d.as_secs() > 3600);
        if old && e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

/// A new private folder for one installation: `%ProgramData%\Shield\update\<random>`, only
/// SYSTEM and Administrators can access it, and it did not exist before. Elevated only.
pub fn update_private_dir(rand_name: &str) -> io::Result<PathBuf> {
    let root = update_root()?;
    secure_parent(root.parent().ok_or_else(|| io::Error::other("no parent"))?)?;
    secure_parent(&root)?;
    remove_stale(&root);
    let d = root.join(rand_name);
    create_admin_dir(&d)?;
    Ok(d)
}

/// Protected machine-wide monotonic update state, shared by privileged package updates.
/// Both the containing Shield folder and update folder use the protected SYSTEM/Administrators DACL.
pub fn update_state_path() -> io::Result<PathBuf> {
    let root = update_root()?;
    secure_parent(root.parent().ok_or_else(|| io::Error::other("no parent"))?)?;
    secure_parent(&root)?;
    Ok(root.join("update_seen.txt"))
}

/// A new file in the private folder (it inherits the folder's protected DACL).
pub fn create_update_file(p: &Path) -> io::Result<File> {
    fs::OpenOptions::new().write(true).create_new(true).open(p)
}

pub fn remove_private_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Elevated helper, after the copies in `dir` were verified: copies this (installed) program
/// into `dir`, starts that copy as the second stage and returns at once (0). The second stage
/// runs msiexec while no installed Shield file is in use.
pub fn install_from_private(pkg: &Path, dir: &Path) -> PResult<i32> {
    use std::os::windows::process::CommandExt;
    if pkg.parent() != Some(dir) || pkg.file_name() != Some(std::ffi::OsStr::new(PKG_FILE)) {
        return Err(PlatformError::Failed("package outside the private folder".into()));
    }
    let run = dir.join(RUN_EXE);
    fs::copy(std::env::current_exe()?, &run)?;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    std::process::Command::new(&run)
        .raw_arg(RUN_ARG)
        .raw_arg(quote_arg(dir)?)
        .creation_flags(DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(0)
}

/// Checks the second stage's arguments: one folder directly in the update root, which holds this
/// running program and the package. Returns the package path.
pub(crate) fn check_run_args(args: &[String], me: &Path, root: &Path) -> Result<PathBuf, i32> {
    let [dir] = args else { return Err(2) };
    let dir = PathBuf::from(dir);
    if !dir.is_absolute() || dir.parent().map(super::fs::path_key) != Some(super::fs::path_key(root)) {
        return Err(2);
    }
    if me.parent().map(super::fs::path_key) != Some(super::fs::path_key(&dir)) {
        return Err(2);
    }
    let pkg = dir.join(PKG_FILE);
    match fs::symlink_metadata(&pkg) {
        Ok(m) if m.is_file() && !super::fs::is_reparse(&m) => Ok(pkg),
        _ => Err(3),
    }
}

/// Second stage (`--install-update-run <folder>`): elevated, runs System32's msiexec on the
/// verified copy and waits; then removes the copies (this .exe and the folder at the next restart).
pub fn run_stage2(args: &[String]) -> i32 {
    use std::os::windows::process::CommandExt;
    if !is_elevated() {
        return 71;
    }
    let (Ok(me), Ok(root)) = (std::env::current_exe(), update_root()) else { return 2 };
    let pkg = match check_run_args(args, &me, &root) {
        Ok(p) => p,
        Err(c) => return c,
    };
    let dir = pkg.parent().map(Path::to_path_buf).unwrap_or_default();
    let code = (|| -> io::Result<i32> {
        let msiexec = super::fs::system_dir().ok_or_else(|| io::Error::other("System32"))?.join("msiexec.exe");
        let st = std::process::Command::new(msiexec).raw_arg("/i").raw_arg(quote_arg(&pkg)?).status()?;
        Ok(st.code().unwrap_or(1))
    })()
    .unwrap_or(1);
    // everything but this running .exe goes now; the .exe and the folder at the next restart
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path() != me {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    delete_at_restart(&me);
    delete_at_restart(&dir);
    code
}

fn delete_at_restart(p: &Path) {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    let w = super::fs::wide(p);
    unsafe { MoveFileExW(w.as_ptr(), core::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// SDDL of the DACL of `p` (tests).
#[cfg(test)]
pub(crate) fn dacl_sddl(p: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let w = super::fs::wide(p);
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut sd);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut s: *mut u16 = core::ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut s, core::ptr::null_mut());
        windows_sys::Win32::Foundation::LocalFree(sd as _);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        windows_sys::Win32::Foundation::LocalFree(s as _);
        Ok(out)
    }
}
