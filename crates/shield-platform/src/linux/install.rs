//! Update installation on Linux.
//! * Installed from the .deb (`/usr/bin/shield`): 3.1.0 #1 - the verified .deb in the user's
//!   runtime folder is no longer handed to `pkexec apt-get` (a program running as the user could
//!   swap it during the password prompt). pkexec runs only Shield's own root-owned
//!   `/usr/bin/shield update-install <deb> <deb.sig> <manifest> <manifest.sig>`. That helper
//!   (shield-core `update::helper_main`) treats the paths as untrusted, copies the bytes into a new
//!   root-owned folder `/var/lib/shield/update/<random>`, verifies the copies with its own
//!   embedded keys and version and installs only the copy (`apt-get install -y`, `dpkg -i` when
//!   apt-get is missing). polkit policy: installer/linux/com.shield.update.policy.
//!   3.1.0 review 2 #1: only files owned by the user who ran pkexec (PKEXEC_UID) are read, so the
//!   helper cannot be used to copy a file only root may read. The folders are 0711 (others may
//!   pass through but not list them) and the copies 0600; only after the copies were verified is
//!   package.deb made 0644, because apt reads it as its `_apt` user.
//! * Running as an AppImage (`$APPIMAGE` set): the new AppImage is written next to the old one
//!   (0755, fsync), its SHA-256 compared once more with the signed manifest, and renamed over it.
//!   No privileges needed when the file is the user's own.
//! * Anything else (static console binary, cargo install): not updated automatically.

use crate::{PResult, PlatformError};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installed {
    ExitNow,
    Done,
}

/// The privileged helper: `/usr/bin/shield update-install <4 files>` (handled in shield-core).
pub const HELPER_ARG: &str = "update-install";
/// The only program pkexec runs for an update (installed by the .deb, owned by root).
pub const HELPER_EXE: &str = "/usr/bin/shield";
/// Root of the private copies.
pub const UPDATE_ROOT: &str = "/var/lib/shield/update";
/// Mode of UPDATE_ROOT and of each private folder: others may open a known name inside (apt's
/// `_apt` user reads the verified package) but cannot list the random folder names.
pub const PRIVATE_DIR_MODE: u32 = 0o711;
pub const PKG_FILE: &str = "package.deb";

/// The AppImage being run, when it is a regular file owned by this user.
fn appimage() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("APPIMAGE")?);
    let m = fs::symlink_metadata(&p).ok()?;
    (p.is_absolute() && m.file_type().is_file() && m.uid() == unsafe { libc::geteuid() }).then_some(p)
}

fn from_deb() -> bool {
    std::env::current_exe().is_ok_and(|e| e.starts_with("/usr/bin") || e.starts_with("/usr/lib/shield")) && Path::new("/var/lib/dpkg/info/shield.list").exists()
}

pub fn package_kind() -> Option<&'static str> {
    if appimage().is_some() {
        Some("AppImage")
    } else if from_deb() {
        Some("deb")
    } else {
        None
    }
}


fn replace_appimage(new: &Path, target: &Path, check: &dyn Fn(&Path) -> bool) -> io::Result<()> {
    let dir = target.parent().ok_or_else(|| io::Error::other("no folder"))?;
    let tmp = dir.join(format!(".{}.new", target.file_name().unwrap_or(OsStr::new("Shield")).to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let r = (|| {
        let mut src = File::open(new)?;
        let mut dst = fs::OpenOptions::new().write(true).create_new(true).mode(0o700).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        io::copy(&mut src, &mut dst)?;
        dst.flush()?;
        dst.set_permissions(fs::Permissions::from_mode(0o755))?;
        dst.sync_all()?;
        drop(dst);
        // 3.1.0 #1: the file about to replace the program is the one the manifest lists
        if !check(&tmp) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "copied AppImage does not match the signed manifest"));
        }
        fs::rename(&tmp, target)?;
        File::open(dir)?.sync_all()
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

/// AppImage only (the user's own file; no privileges). `check(copy)` must confirm the copy
/// written next to the AppImage before it is renamed over it. A .deb goes through
/// `run_update_helper`.
pub fn install_package(pkg: &Path, check: &dyn Fn(&Path) -> bool) -> PResult<Installed> {
    let ext = pkg.extension().and_then(OsStr::to_str).unwrap_or("");
    match (ext, package_kind()) {
        ("AppImage", Some("AppImage")) => {
            let target = appimage().ok_or(PlatformError::Unsupported("not running as an AppImage"))?;
            replace_appimage(pkg, &target, check).map_err(|x| if x.kind() == io::ErrorKind::InvalidData { PlatformError::Failed(x.to_string()) } else { x.into() })?;
            Ok(Installed::Done)
        }
        _ => Err(PlatformError::Unsupported("this installation cannot be updated automatically")),
    }
}

/// A root-owned folder nobody else can change: a real folder (no symlink), owner root (uid 0),
/// not writable by group or others (3.1.0 #1).
pub fn root_dir_ok(uid: u32, mode: u32, is_dir: bool, is_symlink: bool) -> bool {
    is_dir && !is_symlink && uid == 0 && mode & 0o022 == 0
}

/// The helper may only run as root started by pkexec (PKEXEC_UID is the invoking user's uid).
pub fn helper_allowed(euid: u32, pkexec_uid: Option<&OsStr>) -> bool {
    euid == 0 && pkexec_uid.and_then(OsStr::to_str).is_some_and(|u| !u.is_empty() && u.bytes().all(|c| c.is_ascii_digit()))
}

pub fn update_helper_allowed() -> bool {
    helper_allowed(unsafe { libc::geteuid() }, std::env::var_os("PKEXEC_UID").as_deref())
}

/// The user an update input file must belong to: the one who ran pkexec (PKEXEC_UID), or - when
/// not started by pkexec (tests; the helper itself refuses to run then) - the real uid.
pub fn input_owner_ok(file_uid: u32, pkexec_uid: Option<&OsStr>, real_uid: u32) -> bool {
    match pkexec_uid {
        Some(u) => u.to_str().filter(|u| !u.is_empty() && u.bytes().all(|c| c.is_ascii_digit())).and_then(|u| u.parse::<u32>().ok()) == Some(file_uid),
        None => file_uid == real_uid,
    }
}

/// 3.1.0 review 2 #1: an update input file (metadata of the path, then of the opened handle)
/// belongs to the user who asked for the update.
pub fn update_input_owner_ok(m: &fs::Metadata) -> bool {
    input_owner_ok(m.uid(), std::env::var_os("PKEXEC_UID").as_deref(), unsafe { libc::getuid() })
}

fn dir_ok(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| root_dir_ok(m.uid(), m.mode(), m.is_dir(), m.file_type().is_symlink()))
}

/// `p` is a root-owned folder with `mode` (created now if missing; an existing root-owned one
/// gets `mode` too).
fn ensure_root_dir(p: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(mode).create(p) {
        Ok(()) => {}
        Err(x) if x.kind() == io::ErrorKind::AlreadyExists => {}
        Err(x) => return Err(x),
    }
    if !dir_ok(p) {
        return Err(io::Error::other(format!("{} is not a root-owned folder others can't write", p.display())));
    }
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

/// A new private folder `/var/lib/shield/update/<rand_name>` (root, 0711; it must not exist).
/// Every folder above it must be root-owned and not writable by others. Root only.
pub fn update_private_dir(rand_name: &str) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let root = Path::new(UPDATE_ROOT);
    for a in ["/var", "/var/lib"] {
        if !dir_ok(Path::new(a)) {
            return Err(io::Error::other(format!("{a} is not a root-owned folder")));
        }
    }
    ensure_root_dir(root.parent().ok_or_else(|| io::Error::other("no parent"))?, 0o755)?;
    ensure_root_dir(root, PRIVATE_DIR_MODE)?;
    let d = root.join(rand_name);
    fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&d)?; // fails if it exists
    fs::set_permissions(&d, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    if !dir_ok(&d) {
        return Err(io::Error::other("private folder check failed"));
    }
    Ok(d)
}

/// Protected machine-wide monotonic update state, shared by privileged package updates.
/// The directory is root-owned and not writable by group or other users.
pub fn update_state_path() -> io::Result<PathBuf> {
    let root = Path::new(UPDATE_ROOT);
    for a in ["/var", "/var/lib"] {
        if !dir_ok(Path::new(a)) {
            return Err(io::Error::other(format!("{a} is not a root-owned folder")));
        }
    }
    ensure_root_dir(root.parent().ok_or_else(|| io::Error::other("no parent"))?, 0o755)?;
    ensure_root_dir(root, PRIVATE_DIR_MODE)?;
    Ok(root.join("update_seen.txt"))
}

/// A new file in the private folder, readable by root only (0600) until it was verified.
pub fn create_update_file(p: &Path) -> io::Result<File> {
    let f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}

/// After verification only: the package copy becomes 0644 so apt's `_apt` user can read it
/// (through the handle; never through a link).
pub fn open_to_apt(pkg: &Path) -> io::Result<()> {
    let f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(pkg)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("package copy is not a regular file"));
    }
    f.set_permissions(fs::Permissions::from_mode(0o644))
}

pub fn remove_private_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Root, after the copies in `dir` were verified: installs the copied .deb, waits, then removes
/// the private folder. Returns the package manager's exit code.
pub fn install_from_private(pkg: &Path, dir: &Path) -> PResult<i32> {
    use std::process::{Command, Stdio};
    if pkg.parent() != Some(dir) || pkg.file_name() != Some(OsStr::new(PKG_FILE)) {
        return Err(PlatformError::Failed("package outside the private folder".into()));
    }
    if let Err(x) = open_to_apt(pkg) {
        remove_private_dir(dir);
        return Err(x.into());
    }
    let apt = Path::new("/usr/bin/apt-get");
    let st = if apt.is_file() {
        Command::new(apt).args(["install", "-y"]).arg(pkg).stdin(Stdio::null()).status()
    } else {
        Command::new("/usr/bin/dpkg").arg("-i").arg(pkg).stdin(Stdio::null()).status()
    };
    remove_private_dir(dir);
    Ok(st?.code().unwrap_or(1))
}

/// Unprivileged side: `pkexec /usr/bin/shield update-install <4 files>` and wait (exit code).
/// Only for a .deb installation, and only when /usr/bin/shield is root's own program.
pub fn run_update_helper(files: &[&Path; 4]) -> PResult<i32> {
    if package_kind() != Some("deb") {
        return Err(PlatformError::Unsupported("this installation cannot be updated automatically"));
    }
    let exe = Path::new(HELPER_EXE);
    let ok = fs::symlink_metadata(exe).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0) && dir_ok(Path::new("/usr/bin"));
    if !ok {
        return Err(PlatformError::Failed(format!("{HELPER_EXE} is not a root-owned program")));
    }
    let mut args: Vec<&OsStr> = vec![OsStr::new(HELPER_ARG)];
    args.extend(files.iter().map(|f| f.as_os_str()));
    Ok(super::sys::run_privileged(exe, &args)?)
}
