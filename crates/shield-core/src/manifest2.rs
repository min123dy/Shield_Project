//! Release manifest v2 (3.1.0 final, review B): freshness, rollback and key revocation.
//!
//! Every release keeps publishing the v1 manifest `Shield_v<V>_release.txt` unchanged, because
//! 3.0.0 clients parse it with their own strict parser (`compat_tests`). Next to it the workflow
//! publishes `Shield_v<V>_release_v2.txt` (+ `.sig`), which 3.1.0 final and later require for an
//! automatic installation:
//!
//! ```text
//! Shield release manifest 2
//! version 3.1.1
//! release_id 1794000000
//! issued_at 1794000000
//! expires_at 1825536000
//! min_allowed_version 3.1.1
//! revoked_key 0123456789ABCDEF0123456789ABCDEF01234567      (zero or more)
//! sha256 <64 hex> <file name>                               (one per package)
//! ```
//!
//! Fields come in exactly this order, each once (revoked_key and sha256 lines repeat), LF line
//! ends, nothing else. What the client checks:
//! * `issued_at` not more than `MAX_CLOCK_SKEW` in the future, `expires_at` later than now and at
//!   most `MAX_VALIDITY` after `issued_at`: an old signed manifest can't be replayed forever
//!   (freeze / replay), a wrong clock by up to a day is tolerated.
//! * `min_allowed_version <= version`, and the version is newer than the running one.
//! * The key that signed the manifest is not in its own `revoked_key` list.
//! * Rollback (`Seen`, unprivileged side only): the highest `release_id`, the highest
//!   `min_allowed_version` and the revoked keys of every manifest whose signature was good are
//!   remembered in `update_seen.txt` next to the settings; a manifest with a smaller release_id, a
//!   version below a minimum seen before, or signed by a key revoked before, is refused.
//!   Limits (documented): the file belongs to the user, so a program running as that user can
//!   delete it (it could also replace Shield itself); the privileged helper checks the manifest
//!   itself (signature, freshness, own revocation list, version) but not this file; 3.0.0
//!   clients read only v1 and get none of this.

use crate::update::Version;
use std::path::{Path, PathBuf};

pub const HEAD: &str = "Shield release manifest 2";
/// How far `issued_at` may lie in the future (wrong clocks, time zones).
pub const MAX_CLOCK_SKEW: i64 = 24 * 3600;
/// Longest validity of one manifest (the workflow writes 365 days).
pub const MAX_VALIDITY: i64 = 400 * 86400;
/// Most revoked keys listed / remembered.
pub const MAX_REVOKED: usize = 64;
/// Largest `update_seen.txt` read.
const MAX_SEEN: u64 = 16 << 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: Version,
    pub release_id: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub min_allowed: Version,
    /// Primary key fingerprints, 40 upper-case hex digits.
    pub revoked: Vec<String>,
    /// SHA-256 listed for the requested file.
    pub sha256: [u8; 32],
}

fn msg(key: &'static str) -> String {
    crate::i18n::t(key).to_string()
}

/// "8898 D3D9 ..." or "8898d3d9..." as 40 upper-case hex digits (None when it isn't one).
pub fn norm_fpr(s: &str) -> Option<String> {
    let f: String = s.chars().filter(|c| *c != ' ').collect::<String>().to_ascii_uppercase();
    (f.len() == 40 && f.bytes().all(|c| c.is_ascii_hexdigit())).then_some(f)
}

fn hex32(h: &str) -> Option<[u8; 32]> {
    if h.len() != 64 || !h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(d)
}

fn num(s: &str) -> Option<u64> {
    // plain decimal, no sign, no leading zeros, fits i64
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

/// Parses a v2 manifest strictly and returns the entry for `file`.
pub fn parse(text: &str, file: &str) -> Result<Manifest, String> {
    let bad = || msg("upd.bad_manifest");
    if text.contains('\r') || !text.ends_with('\n') {
        return Err(bad());
    }
    let mut lines = text.lines();
    if lines.next() != Some(HEAD) {
        return Err(bad());
    }
    let mut field = |name: &str| -> Result<&str, String> { lines.next().and_then(|l| l.strip_prefix(name)).and_then(|l| l.strip_prefix(' ')).ok_or_else(bad) };
    let version = Version::parse(field("version")?).ok_or_else(bad)?;
    let release_id = num(field("release_id")?).ok_or_else(bad)?;
    let issued_at = num(field("issued_at")?).ok_or_else(bad)? as i64;
    let expires_at = num(field("expires_at")?).ok_or_else(bad)? as i64;
    let min_allowed = Version::parse(field("min_allowed_version")?).ok_or_else(bad)?;
    let mut revoked = Vec::new();
    let mut found = None;
    let mut names = std::collections::HashSet::new();
    let mut in_hashes = false;
    for l in text.lines().skip(6) {
        let mut p = l.split(' ');
        match (p.next(), p.next(), p.next(), p.next()) {
            (Some("revoked_key"), Some(f), None, None) if !in_hashes => {
                let f = norm_fpr(f).filter(|n| n == f).ok_or_else(bad)?;
                if revoked.contains(&f) || revoked.len() >= MAX_REVOKED {
                    return Err(bad());
                }
                revoked.push(f);
            }
            (Some("sha256"), Some(h), Some(name), None) => {
                in_hashes = true;
                let d = hex32(h).ok_or_else(bad)?;
                if name.is_empty() || !names.insert(name) {
                    return Err(bad()); // one name, two hashes
                }
                if name == file {
                    found = Some(d);
                }
            }
            _ => return Err(bad()),
        }
    }
    let sha256 = found.ok_or_else(|| crate::i18n::tf("upd.not_in_manifest", &[&file]))?;
    Ok(Manifest { version, release_id, issued_at, expires_at, min_allowed, revoked, sha256 })
}

fn when(secs: i64) -> String {
    crate::ui_fmt::date(std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs.max(0) as u64)))
}

/// Unix time now (0 when the clock is before 1970).
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Checks that need no stored state: validity window, versions, the signer not revoked by the
/// manifest itself. `signer`: primary fingerprint of the key that made the manifest signature.
pub fn check(m: &Manifest, now: i64, current: Version, signer: &str) -> Result<(), String> {
    if m.issued_at > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(crate::i18n::tf("upd.m_future", &[&when(m.issued_at)]));
    }
    if m.expires_at <= m.issued_at || m.expires_at - m.issued_at > MAX_VALIDITY {
        return Err(msg("upd.bad_manifest"));
    }
    if now >= m.expires_at {
        return Err(crate::i18n::tf("upd.m_expired", &[&when(m.expires_at)]));
    }
    if m.min_allowed > m.version || m.version <= current {
        return Err(crate::i18n::tf("upd.version_mismatch", &[&m.version]));
    }
    let s = norm_fpr(signer).ok_or_else(|| msg("upd.bad_manifest"))?;
    if m.revoked.contains(&s) {
        return Err(msg("upd.m_revoked"));
    }
    Ok(())
}

/// What earlier good manifests said (see module docs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub release_id: u64,
    pub min_allowed: Option<Version>,
    pub revoked: Vec<String>,
}

impl Seen {
    /// Refuses `m` (signed by `signer`) when it is older than what was seen, or its key was revoked.
    pub fn check(&self, m: &Manifest, signer: &str) -> Result<(), String> {
        if m.release_id < self.release_id || self.min_allowed.is_some_and(|v| m.version < v) {
            return Err(msg("upd.m_rollback"));
        }
        if norm_fpr(signer).is_some_and(|s| self.revoked.contains(&s)) {
            return Err(msg("upd.m_revoked"));
        }
        Ok(())
    }

    /// `self` plus `m` (only ever grows).
    pub fn merged(&self, m: &Manifest) -> Seen {
        let mut r = self.revoked.clone();
        for f in &m.revoked {
            if !r.contains(f) && r.len() < MAX_REVOKED {
                r.push(f.clone());
            }
        }
        Seen { release_id: self.release_id.max(m.release_id), min_allowed: Some(self.min_allowed.map_or(m.min_allowed, |v| v.max(m.min_allowed))), revoked: r }
    }

    pub fn to_text(&self) -> String {
        let mut s = format!("release_id {}\n", self.release_id);
        if let Some(v) = self.min_allowed {
            s.push_str(&format!("min_allowed_version {v}\n"));
        }
        for f in &self.revoked {
            s.push_str(&format!("revoked_key {f}\n"));
        }
        s
    }

    /// Unknown or broken lines are skipped: a damaged file can only make the state smaller (what
    /// deleting it does too), never accept something a good state would refuse.
    pub fn parse(text: &str) -> Seen {
        let mut s = Seen::default();
        for l in text.lines() {
            match l.split_once(' ') {
                Some(("release_id", v)) => s.release_id = s.release_id.max(num(v).unwrap_or(0)),
                Some(("min_allowed_version", v)) => {
                    if let Some(v) = Version::parse(v) {
                        s.min_allowed = Some(s.min_allowed.map_or(v, |o| o.max(v)));
                    }
                }
                Some(("revoked_key", f)) => {
                    if let Some(f) = norm_fpr(f) {
                        if !s.revoked.contains(&f) && s.revoked.len() < MAX_REVOKED {
                            s.revoked.push(f);
                        }
                    }
                }
                _ => {}
            }
        }
        s
    }

    /// Strict counterpart for the protected machine-wide state: reject corruption rather than
    /// silently discarding a rollback floor. The canonical serializer is the format definition.
    pub fn parse_strict(text: &str) -> Result<Seen, String> {
        if text.contains('\r') || !text.ends_with('\n') {
            return Err("invalid update state line endings".into());
        }
        let parsed = Self::parse(text);
        if parsed.to_text() != text {
            return Err("invalid or non-canonical update state".into());
        }
        Ok(parsed)
    }
}

/// `update_seen.txt` next to the settings file.
pub fn seen_path() -> Result<PathBuf, String> {
    Ok(crate::settings::data_dir()?.join("update_seen.txt"))
}

pub fn load_seen(p: &Path) -> Seen {
    match shield_platform::bounded::read_file_limited(p, MAX_SEEN) {
        Ok(b) => Seen::parse(&String::from_utf8_lossy(&b)),
        Err(_) => Seen::default(),
    }
}

/// Writes `s` (private file, replaced atomically).
pub fn save_seen(p: &Path, s: &Seen) -> Result<(), String> {
    use std::io::Write;
    let dir = p.parent().ok_or("no folder")?;
    std::fs::create_dir_all(dir).map_err(|x| x.to_string())?;
    let tmp = dir.join(format!("update_seen.{}.tmp", crate::entropy::rand_hex()?));
    let r = (|| -> std::io::Result<()> {
        let mut f = crate::sysinfo::create_private_file(&tmp)?;
        f.write_all(s.to_text().as_bytes())?;
        f.sync_all()?;
        drop(f);
        crate::sysinfo::rename_replace(&tmp, p)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|x| x.to_string())
}

/// Reads the protected machine-wide rollback floor. Missing is the first-run state; every other
/// read or parse error is fail-closed because ignoring it would lower the rollback floor.
pub fn lock_machine_seen(p: &Path) -> Result<std::fs::File, String> {
    use std::time::{Duration, Instant};
    let lock_path = p.with_file_name("update_seen.lock");
    // The parent directory is protected by the elevated platform helper before this is called.
    // The OS releases this advisory lock when the process exits or crashes.
    let file = shield_platform::fs::open_lock_file(&lock_path).map_err(|e| e.to_string())?;
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.to_string()),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err("another privileged update still holds the rollback-state lock".into());
            }
        }
    }
}

pub fn load_machine_seen(p: &Path) -> Result<Seen, String> {
    match shield_platform::bounded::read_file_limited(p, MAX_SEEN) {
        Ok(b) => {
            let text = std::str::from_utf8(&b).map_err(|_| "update state is not UTF-8".to_string())?;
            Seen::parse_strict(text)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Seen::default()),
        Err(e) => Err(e.to_string()),
    }
}

/// Stores the protected machine-wide rollback floor with the platform's privileged file
/// creation policy (Linux root-only mode; Windows inherited SYSTEM/Administrators DACL).
pub fn save_machine_seen(p: &Path, s: &Seen) -> Result<(), String> {
    use std::io::Write;
    let dir = p.parent().ok_or("no folder")?;
    let tmp = dir.join(format!("update_seen.{}.tmp", crate::entropy::rand_hex()?));
    let r = (|| -> std::io::Result<()> {
        let mut f = shield_platform::sys::create_update_file(&tmp)?;
        f.write_all(s.to_text().as_bytes())?;
        f.sync_all()?;
        drop(f);
        crate::sysinfo::rename_replace(&tmp, p)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|x| x.to_string())
}

#[cfg(test)]
#[path = "manifest2_tests.rs"]
mod tests;
