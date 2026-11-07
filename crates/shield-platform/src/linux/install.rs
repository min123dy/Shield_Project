//! Update installation on Linux.
//! * Installed from the .deb (`/usr/bin/shield`): `pkexec apt-get install <deb>` (dpkg -i when
//!   apt-get is missing). pkexec asks for the administrator password; Shield waits for it.
//! * Running as an AppImage (`$APPIMAGE` set): the new AppImage is written next to the old one
//!   (0755, fsync) and renamed over it. No privileges needed when the file is the user's own.
//! * Anything else (static console binary, cargo install): not updated automatically.

use crate::{PResult, PlatformError};
use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installed {
    ExitNow,
    Done,
}

/// The AppImage being run, when it is a regular file owned by this user.
fn appimage() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("APPIMAGE")?);
    let m = std::fs::symlink_metadata(&p).ok()?;
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

fn replace_appimage(new: &Path, target: &Path) -> io::Result<()> {
    let dir = target.parent().ok_or_else(|| io::Error::other("no folder"))?;
    let tmp = dir.join(format!(".{}.new", target.file_name().unwrap_or(OsStr::new("Shield")).to_string_lossy()));
    let _ = std::fs::remove_file(&tmp);
    let r = (|| {
        let mut src = std::fs::File::open(new)?;
        let mut dst = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        io::copy(&mut src, &mut dst)?;
        dst.flush()?;
        dst.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        dst.sync_all()?;
        drop(dst);
        std::fs::rename(&tmp, target)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

pub fn install_package(pkg: &Path) -> PResult<Installed> {
    let ext = pkg.extension().and_then(OsStr::to_str).unwrap_or("");
    match (ext, package_kind()) {
        ("AppImage", Some("AppImage")) => {
            let target = appimage().ok_or(PlatformError::Unsupported("not running as an AppImage"))?;
            replace_appimage(pkg, &target)?;
            Ok(Installed::Done)
        }
        ("deb", Some("deb")) => {
            let apt = Path::new("/usr/bin/apt-get");
            let code = if apt.is_file() {
                super::sys::run_privileged(apt, &[OsStr::new("install"), OsStr::new("-y"), pkg.as_os_str()])?
            } else {
                super::sys::run_privileged(Path::new("/usr/bin/dpkg"), &[OsStr::new("-i"), pkg.as_os_str()])?
            };
            match code {
                0 => Ok(Installed::Done),
                126 | 127 => Err(PlatformError::Declined),
                c => Err(PlatformError::Failed(format!("package manager exit code {c}"))),
            }
        }
        _ => Err(PlatformError::Unsupported("this installation cannot be updated automatically")),
    }
}
