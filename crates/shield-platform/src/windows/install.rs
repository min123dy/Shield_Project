//! Update installation on Windows: the signed MSI is handed to `msiexec` from System32 (never
//! found through PATH). Windows Installer shows its own UI and UAC prompt; Shield exits so the
//! files can be replaced. The download folder is removed at the next start (`cleanup` in core).

use crate::{PResult, PlatformError};
use std::path::Path;
use std::process::{Command, Stdio};

/// What the caller does after a successful start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installed {
    /// The installer runs on its own; exit now (do not delete the package yet).
    ExitNow,
    /// Installed in place; the package was consumed. Restart to use the new version.
    Done,
}

pub fn install_package(pkg: &Path) -> PResult<Installed> {
    if !pkg.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")) {
        return Err(PlatformError::Unsupported("only .msi packages on Windows"));
    }
    let msiexec = super::fs::system_dir().ok_or(PlatformError::Failed("System32".into()))?.join("msiexec.exe");
    Command::new(msiexec).arg("/i").arg(pkg).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    Ok(Installed::ExitNow)
}

/// Installer kind this build updates with (asset name suffix).
pub fn package_kind() -> Option<&'static str> {
    Some("msi")
}
