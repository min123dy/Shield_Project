//! What the build embedded (see build.rs): version, GitHub repository, release signing key, and
//! the integrity self-check of the running program (design 3.0 §3, §4).

use crate::sigverify::{Cert, Verified};
use std::sync::OnceLock;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO_URL: &str = env!("SHIELD_REPO_URL");
const RELEASE_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/release_key.asc"));

fn valid_part(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

/// (owner, repo) of `https://github.com/<owner>/<repo>[/][.git]`; anything else is None.
pub fn parse_repo(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://github.com/")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (o, r) = rest.split_once('/')?;
    (valid_part(o) && valid_part(r)).then(|| (o.to_string(), r.to_string()))
}

/// The repository this build belongs to (checked again at run time; build.rs already refused
/// anything that is not an https GitHub URL).
pub fn repo() -> Option<(String, String)> {
    parse_repo(REPO_URL)
}

/// Canonical https link opened by "Developer info" (only github.com, only https).
pub fn repo_url() -> Option<String> {
    repo().map(|(o, r)| format!("https://github.com/{o}/{r}"))
}

/// The embedded release key, parsed once. None when the build has no key or it is unusable.
pub fn release_key() -> Option<&'static Cert> {
    static K: OnceLock<Option<Cert>> = OnceLock::new();
    K.get_or_init(|| (!RELEASE_KEY.is_empty()).then(|| Cert::parse(RELEASE_KEY).ok()).flatten()).as_ref()
}

/// Release key fingerprint for the info and settings screens.
pub fn fingerprint() -> Option<String> {
    release_key().map(Cert::fingerprint)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfCheck {
    /// `<program>.sig` is a good signature by the embedded key.
    Verified(Verified),
    /// No `<program>.sig` next to the program (e.g. a development build).
    NoSignature,
    /// This build has no release key.
    NoKey,
    /// The signature does not match: the program file was changed.
    Invalid(String),
}

/// Integrity check of the running program: verifies `<exe>.sig` against the embedded key. This
/// detects a modified or corrupted program file, not a modified program that also replaced the
/// embedded key (documented: check the fingerprint against the one published by the developer).
pub fn self_check() -> SelfCheck {
    let Some(key) = release_key() else { return SelfCheck::NoKey };
    let Ok(exe) = std::env::current_exe() else { return SelfCheck::NoSignature };
    let mut sig = exe.clone().into_os_string();
    sig.push(".sig");
    let sig = std::path::PathBuf::from(sig);
    if !sig.is_file() {
        return SelfCheck::NoSignature;
    }
    match key.verify_file(&exe, &sig) {
        Ok(v) => SelfCheck::Verified(v),
        Err(e) => SelfCheck::Invalid(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls_are_strict() {
        assert_eq!(parse_repo("https://github.com/raven/shield"), Some(("raven".into(), "shield".into())));
        assert_eq!(parse_repo("https://github.com/raven/shield.git"), Some(("raven".into(), "shield".into())));
        assert_eq!(parse_repo("https://github.com/raven/shield/"), Some(("raven".into(), "shield".into())));
        for bad in [
            "http://github.com/a/b",
            "https://github.com.evil.example/a/b",
            "https://gist.github.com/a/b",
            "https://github.com/a",
            "https://github.com/a/b/c",
            "https://github.com/../b",
            "https://github.com/a/b?x=1",
            "https://github.com/a/b#x",
            "https://github.com/a%2fb/c",
            "https://github.com/a/b c",
            "https://user@github.com/a/b",
            "javascript:alert(1)",
        ] {
            assert_eq!(parse_repo(bad), None, "{bad}");
        }
    }

    #[test]
    fn embedded_key_parses_when_present() {
        if !RELEASE_KEY.is_empty() {
            assert!(release_key().is_some(), "the embedded key must be usable");
            assert_eq!(fingerprint().unwrap().len(), 49);
        }
        // a test binary has no .sig next to it
        assert!(matches!(self_check(), SelfCheck::NoSignature | SelfCheck::NoKey));
    }
}
