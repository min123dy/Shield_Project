//! Settings password and tamper detection (design 3.0 §8).
//!
//! * The password is never stored. Argon2id (128 MiB, t = 3, p = 4, random 16-byte salt) gives a
//!   64-byte key; HKDF-SHA3-512 turns it into a verifier (stored) and the MAC key.
//! * The MAC (HMAC-SHA3-512) covers the canonical text of the protected values
//!   (`Settings::protected_text`, which includes salt and verifier). The MAC key is kept next to
//!   the settings in `settings.key`: sealed with DPAPI on Windows; a 0600 file on Linux (weaker:
//!   any program running as the same user can read it - documented).
//! * At start-up a missing or wrong MAC (or a key file without password entries) means the file
//!   was edited outside Shield: the protected values go back to their defaults, the password
//!   entry is dropped and the UI says so. Entering the password also re-derives the MAC key, so a
//!   replaced key file is noticed then.
//! * Without a password entry only the defaults are valid (all a save without the password can
//!   write; removing the password returns them to the defaults). So deleting the `auth_*` lines
//!   together with `settings.key` gives the defaults and the warning, never values someone wrote
//!   into the file (security review 2026-11-08). A 2.x file (schema 1, no settings password
//!   existed) going back to the defaults is the 3.0 migration and is not reported.
//! * Wrong passwords: the delay before the next try doubles (1 s .. 30 s) within the process; the
//!   real protection is the Argon2id cost.
//! * Forgotten password: "delete settings file" resets everything (containers are not affected).

use crate::i18n::coded;
use crate::password::ct_eq;
use crate::settings::Settings;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha3::Sha3_512;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;

pub const C_NEED_PW: &str = "E_SET_PW";
pub const C_WRONG_PW: &str = "E_SET_PW_WRONG";
const KDF_KIB: u32 = 128 * 1024;
static FAILS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, PartialEq, Eq)]
pub struct Auth {
    pub salt: [u8; 16],
    pub verifier: [u8; 32],
    /// MAC of the protected text as read from / written to the file.
    pub mac: [u8; 64],
}

/// 3.0.0 §6: a password-derived verifier never appears in debug output or panic messages.
impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Auth { .. }")
    }
}

/// Proof that the settings password was entered in this process (holds the MAC key).
pub struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    verifier: [u8; 32],
    /// Verifier of the password this one replaced (set by `set_password` with a current unlock).
    prev: Option<[u8; 32]>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

impl Auth {
    /// Salt and verifier (what the MAC covers; the MAC itself is not part of it).
    pub fn text(&self) -> String {
        format!("{}:{}", hex(&self.salt), hex(&self.verifier))
    }
    pub fn to_toml(&self) -> String {
        format!("auth_salt = \"{}\"\nauth_verifier = \"{}\"\nauth_mac = \"{}\"\n", hex(&self.salt), hex(&self.verifier), hex(&self.mac))
    }
    /// One `auth_*` line. A malformed value stays zero, which makes the entry incomplete and the
    /// load-time check fail (protected values reset).
    pub fn parse_line(a: &mut Option<Auth>, k: &str, v: &str) {
        let cur = a.get_or_insert(Auth { salt: [0; 16], verifier: [0; 32], mac: [0; 64] });
        match k {
            "auth_salt" => cur.salt = unhex::<16>(v).unwrap_or([0; 16]),
            "auth_verifier" => cur.verifier = unhex::<32>(v).unwrap_or([0; 32]),
            "auth_mac" => cur.mac = unhex::<64>(v).unwrap_or([0; 64]),
            _ => {}
        }
    }
    fn complete(&self) -> bool {
        self.salt != [0; 16] && self.verifier != [0; 32]
    }
}

fn derive(pw: &[u8], salt: &[u8; 16]) -> Result<([u8; 32], Zeroizing<[u8; 32]>), String> {
    let params = Params::new(KDF_KIB, 3, 4, Some(64)).map_err(|x| x.to_string())?;
    let mut k = Zeroizing::new([0u8; 64]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pw, salt, &mut k[..]).map_err(|x| x.to_string())?;
    let hk = Hkdf::<Sha3_512>::new(Some(b"SHIELD-SET-v3"), &k[..]);
    let (mut v, mut m) = ([0u8; 32], Zeroizing::new([0u8; 32]));
    hk.expand(b"verify", &mut v).map_err(|x| x.to_string())?;
    hk.expand(b"mac", &mut m[..]).map_err(|x| x.to_string())?;
    Ok((v, m))
}

fn mac_over(key: &[u8; 32], label: &[u8], text: &str) -> [u8; 64] {
    let mut m = <Hmac<Sha3_512> as Mac>::new_from_slice(key).expect("any key length");
    m.update(label);
    m.update(text.as_bytes());
    m.finalize().into_bytes().into()
}

fn mac_of(key: &[u8; 32], s: &Settings) -> [u8; 64] {
    mac_over(key, b"SHIELD-SET-MAC-v2\n", &s.protected_text())
}

/// MAC written by 3.0.0 before `lock_on_focus_loss` became protected (accepted on load; the next
/// save writes the v2 MAC). That option is then not covered until the next save; switching it
/// off gives its default.
fn mac_of_v1(key: &[u8; 32], s: &Settings) -> [u8; 64] {
    let text = s.protected_text().replace(&format!("lock_on_focus_loss={}\n", s.lock_on_focus_loss), "");
    mac_over(key, b"SHIELD-SET-MAC-v1\n", &text)
}

pub fn key_path(settings: &Path) -> PathBuf {
    settings.with_file_name("settings.key")
}

fn read_key(settings: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let b = std::fs::read(key_path(settings)).ok()?;
    let (flag, blob) = b.split_first()?;
    let raw = Zeroizing::new(if *flag == 1 { shield_platform::sys::unseal(blob).ok()? } else { blob.to_vec() });
    (raw.len() == 32).then(|| {
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&raw);
        k
    })
}

fn write_key(settings: &Path, key: &[u8; 32]) -> Result<(), String> {
    let s = shield_platform::sys::seal(key).map_err(|x| x.to_string())?;
    let mut b = Zeroizing::new(vec![u8::from(s.os_protected)]);
    b.extend_from_slice(&s.bytes);
    let dir = settings.parent().ok_or("no folder")?;
    std::fs::create_dir_all(dir).map_err(|x| x.to_string())?;
    let tmp = dir.join(format!("settings.key.{}.tmp", crate::entropy::rand_hex()?));
    let r = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = crate::sysinfo::create_private_file(&tmp)?;
        f.write_all(&b)?;
        f.sync_all()?;
        drop(f);
        crate::sysinfo::rename_replace(&tmp, &key_path(settings))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|x| x.to_string())
}

pub fn forget_key(settings: &Path) {
    let _ = std::fs::remove_file(key_path(settings));
}

/// Load-time check (see module docs). Resets the protected values when the MAC does not match,
/// or when there is no password entry but the protected values are not the defaults. `legacy`:
/// the file is from 2.x (older schema).
pub fn check(s: &mut Settings, p: &Path, legacy: bool) {
    let key = read_key(p);
    let key_file = key_path(p).exists();
    let ok = match (&s.auth, &key) {
        (None, None) => !key_file && s.protected_is_default(),
        (Some(a), Some(k)) => a.complete() && (ct_eq(&mac_of(k, s), &a.mac) || ct_eq(&mac_of_v1(k, s), &a.mac)),
        _ => false,
    };
    if !ok {
        let migration = legacy && s.auth.is_none() && !key_file;
        s.reset_protected();
        s.auth = None;
        s.tampered = !migration;
    }
}

/// Delay before the next password attempt (0 before the first failure).
pub fn retry_delay() -> Duration {
    match FAILS.load(Ordering::Relaxed) {
        0 => Duration::ZERO,
        n => Duration::from_secs((1u64 << (n - 1).min(5)).min(30)),
    }
}

/// Checks the settings password (waiting `retry_delay` first).
pub fn unlock(s: &Settings, pw: &[u8]) -> Result<Unlocked, String> {
    let a = s.auth.as_ref().ok_or_else(|| coded(C_NEED_PW, "set.pw_none"))?;
    std::thread::sleep(retry_delay());
    let (v, key) = derive(pw, &a.salt)?;
    if !ct_eq(&v, &a.verifier) {
        FAILS.fetch_add(1, Ordering::Relaxed);
        return Err(coded(C_WRONG_PW, "set.pw_wrong"));
    }
    FAILS.store(0, Ordering::Relaxed);
    Ok(Unlocked { key, verifier: v, prev: None })
}

/// Sets (or replaces, with the current unlock) the settings password. The caller saves with the
/// returned unlock.
pub fn set_password(s: &mut Settings, new_pw: &[u8], current: Option<&Unlocked>) -> Result<Unlocked, String> {
    if s.auth.is_some() && current.is_none_or(|u| s.auth.as_ref().is_none_or(|a| !ct_eq(&u.verifier, &a.verifier))) {
        return Err(coded(C_NEED_PW, "set.pw_needed"));
    }
    // 3.0.0 §1: only an empty password is refused here; short or simple ones were confirmed by
    // the user after the warnings of `password::check_new` (the GUI never gets here without it)
    if new_pw.is_empty() {
        return Err(crate::i18n::t("pw.b_empty").to_string());
    }
    let mut salt = [0u8; 16];
    crate::entropy::fill_random(&mut salt)?;
    let (v, key) = derive(new_pw, &salt)?;
    let prev = current.map(|c| c.verifier);
    s.auth = Some(Auth { salt, verifier: v, mac: [0; 64] });
    Ok(Unlocked { key, verifier: v, prev })
}

/// Removes the password (needs the current unlock). The protected values go back to their
/// defaults: without a password nothing else is valid (see `check`).
pub fn clear_password(s: &mut Settings, u: &Unlocked) -> Result<(), String> {
    match &s.auth {
        Some(a) if ct_eq(&u.verifier, &a.verifier) => {
            s.auth = None;
            s.reset_protected();
            Ok(())
        }
        _ => Err(coded(C_NEED_PW, "set.pw_needed")),
    }
}

/// Save-time rule: protected values may only change with the password; without a password set,
/// the first protected change must set one.
pub fn authorize(s: &Settings, p: &Path, u: Option<&Unlocked>) -> Result<(), String> {
    let disk = Settings::load_from(p);
    if let Some(u) = u {
        let disk_ok = match &disk.auth {
            None => true,
            Some(a) => ct_eq(&a.verifier, &u.verifier) || u.prev.is_some_and(|pv| ct_eq(&pv, &a.verifier)),
        };
        let new_ok = s.auth.as_ref().is_none_or(|a| ct_eq(&a.verifier, &u.verifier));
        return if disk_ok && new_ok { Ok(()) } else { Err(coded(C_NEED_PW, "set.pw_needed")) };
    }
    // unchanged, or back to the (safe) defaults: no password needed
    let mut safe = Settings::default();
    safe.auth.clone_from(&disk.auth);
    if s.auth == disk.auth && (disk.protected_text() == s.protected_text() || safe.protected_text() == s.protected_text()) {
        return Ok(());
    }
    Err(coded(C_NEED_PW, if disk.auth.is_some() { "set.pw_needed" } else { "set.pw_setup_needed" }))
}

/// Copy of `s` with the MAC filled in; writes the (sealed) key file when unlocked.
pub fn with_mac(s: &Settings, p: &Path, u: Option<&Unlocked>) -> Result<Settings, String> {
    let mut c = s.clone();
    if c.auth.is_none() {
        forget_key(p);
        return Ok(c);
    }
    let key = match u {
        Some(u) => {
            write_key(p, &u.key)?;
            Zeroizing::new(*u.key)
        }
        None => read_key(p).ok_or_else(|| coded(C_NEED_PW, "set.pw_needed"))?,
    };
    let m = mac_of(&key, &c);
    if let Some(a) = c.auth.as_mut() {
        a.mac = m;
    }
    Ok(c)
}

#[cfg(test)]
#[path = "settings_auth_tests.rs"]
mod tests;
