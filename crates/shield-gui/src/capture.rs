//! E-1 screen capture protection and E-4 dark title bar: thin wrappers over the platform crate
//! (Windows: SetWindowDisplayAffinity + DWM attributes; Linux: not available, the setting is
//! shown greyed out).
//!
//! Limits (shown in Settings): this blocks *software* capture through the normal Windows APIs only.
//! It does not stop a camera or phone, a capture card, a remote desktop/VM host that captures
//! below Windows, a kernel driver, or malware running as the same user.

pub use shield_platform::CaptureState as Applied;
use shield_platform::{platform, Os, PlatformError};

/// Whether this OS can protect windows at all.
pub fn supported() -> bool {
    platform().os() == Os::Windows
}

pub fn apply(on: bool) -> Result<Applied, String> {
    platform().set_capture_protection(None, on).map_err(|e| match e {
        PlatformError::Unsupported(_) => crate::i18n::t("set.capture_unsupported").to_string(),
        e => e.to_string(),
    })
}

pub fn dark_title_bar(dark: bool) {
    shield_platform::sys::dark_title_bar(dark)
}

pub fn system_dark() -> bool {
    shield_platform::sys::system_dark()
}
