//! Best-effort memory and process hardening. None of this stops a kernel-level, administrator or
//! physical attacker, and it does not fully stop a malicious program running as the same user.
//! It removes cheap paths (swap of secrets, crash dumps, DLL planting, some same-user tools).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// Set when any VirtualLock/mlock call failed (shown in the UI).
pub static LOCK_FAILED: AtomicBool = AtomicBool::new(false);
/// Set when the Argon2 work memory could not be locked (it may be paged out while hashing).
pub static KDF_LOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Locks a small secret buffer in RAM; failures are recorded and reported, never fatal.
pub fn lock_mem(p: *const u8, l: usize) -> bool {
    let ok = shield_platform::mem::lock(p, l);
    if !ok {
        LOCK_FAILED.store(true, Ordering::Relaxed);
    }
    ok
}
pub fn unlock_mem(p: *const u8, l: usize) {
    shield_platform::mem::unlock(p, l)
}

/// Locks a large region (Argon2 work memory); see `shield_platform::mem::lock_large`.
pub fn lock_large(p: *const u8, l: usize) -> bool {
    let ok = shield_platform::mem::lock_large(p, l);
    if !ok {
        KDF_LOCK_FAILED.store(true, Ordering::Relaxed);
    }
    ok
}
pub fn unlock_large(p: *const u8, l: usize, was_locked: bool) {
    shield_platform::mem::unlock_large(p, l, was_locked)
}

pub use shield_platform::{HardenItem, HardenReport};
/// What `harden_process` managed to apply (shown on the information tab and by `shield version`).
pub static REPORT: Mutex<Option<HardenReport>> = Mutex::new(None);

/// Protections that are not in effect (3.0.0 §4: a security feature that failed is not silently
/// skipped; the windows and the console ask before a job that handles secrets).
pub fn degraded() -> Vec<String> {
    let rep = REPORT.lock().unwrap_or_else(|x| x.into_inner()).clone();
    degraded_from(rep.as_ref(), LOCK_FAILED.load(Ordering::Relaxed) || KDF_LOCK_FAILED.load(Ordering::Relaxed))
}

/// `degraded` for a given report (testable without touching the process).
pub fn degraded_from(rep: Option<&HardenReport>, lock_failed: bool) -> Vec<String> {
    use crate::i18n::{t, tf};
    let mut v = Vec::new();
    if lock_failed {
        v.push(t("harden.item_lock").to_string());
    }
    for (it, ok) in rep.map(|r| r.items.as_slice()).unwrap_or(&[]) {
        if !ok {
            let k = match it {
                HardenItem::ProcessDacl => "algo.dacl",
                HardenItem::DllSearch => "algo.dll",
                HardenItem::ImageLoadPolicy => "algo.image",
                HardenItem::NoCoreDumps => "algo.crash",
                HardenItem::NotDumpable => "algo.dumpable",
            };
            v.push(tf("harden.item_failed", &[&t(k)]));
        }
    }
    v
}

/// Call once at start-up, before any window or DLL-using code (Windows: process DACL, DLL search
/// order, image load policy; Linux: no core dumps, not dumpable).
pub fn harden_process() {
    let rep = shield_platform::platform().secure_memory_init();
    *REPORT.lock().unwrap_or_else(|x| x.into_inner()) = Some(rep);
}

// ---------------------------------------------------------------- secret input buffer

pub const SECRET_CAP: usize = 256;
pub const C_TOO_LONG: &str = "E_PW_TOO_LONG";

/// Fixed, heap-pinned, page-locked (best effort) password buffer. It never reallocates, so no
/// stale copies are left behind, and it is zeroized on clear/drop. Bytes are stored as typed
/// (UTF-8); `take` returns the NFC-normalized form used by every operation.
pub struct SecretBuf {
    buf: Box<[u8; SECRET_CAP]>,
    len: usize,
    /// More than SECRET_CAP bytes were typed/pasted. Sticky until `clear`: a cut password is never
    /// used (`take` refuses it), and deleting characters does not turn it into the intended one.
    pub overflow: bool,
    /// Text arrived through a paste (the clipboard may still hold it).
    pub pasted: bool,
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBuf {
    pub fn new() -> Self {
        let buf = Box::new([0u8; SECRET_CAP]);
        lock_mem(buf.as_ptr(), SECRET_CAP);
        Self { buf, len: 0, overflow: false, pasted: false }
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
    pub fn char_count(&self) -> usize {
        self.as_str().chars().count()
    }
    pub fn push_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch.is_control() {
                continue;
            }
            let mut t = [0u8; 4];
            let b = ch.encode_utf8(&mut t).as_bytes();
            if self.len + b.len() > SECRET_CAP {
                self.overflow = true;
                t.zeroize();
                break;
            }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
            t.zeroize();
        }
    }
    pub fn pop(&mut self) {
        if let Some(n) = self.as_str().chars().next_back().map(|c| c.len_utf8()) {
            let st = self.len - n;
            self.buf[st..self.len].zeroize();
            self.len = st;
        }
    }
    pub fn clear(&mut self) {
        (*self.buf).zeroize();
        self.len = 0;
        self.overflow = false;
        self.pasted = false;
    }
    /// NFC-normalized copy (zeroizing). Used for confirmation checks and by `take`.
    pub fn normalized(&self) -> Zeroizing<Vec<u8>> {
        crate::password::normalize(self.as_str())
    }
    /// Moves the secret out (NFC-normalized, zeroizing) and clears this buffer. Input longer than
    /// SECRET_CAP bytes (before or after normalization) is refused, never truncated (B-14).
    pub fn take(&mut self) -> Result<Zeroizing<Vec<u8>>, String> {
        let v = self.normalized();
        let too_long = self.overflow || v.len() > SECRET_CAP;
        self.clear();
        if too_long {
            return Err(crate::i18n::coded(C_TOO_LONG, "err.pw_too_long"));
        }
        Ok(v)
    }
    /// Constant-time comparison of the normalized forms.
    pub fn ct_eq(&self, o: &Self) -> bool {
        crate::password::ct_eq(&self.normalized(), &o.normalized())
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.clear();
        unlock_mem(self.buf.as_ptr(), SECRET_CAP);
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    #[test]
    fn long_password_is_refused_not_truncated() {
        let mut b = SecretBuf::new();
        b.push_str(&"a".repeat(SECRET_CAP));
        assert!(!b.overflow);
        assert_eq!(b.clone_for_test(), "a".repeat(SECRET_CAP));
        b.push_str("b");
        assert!(b.overflow);
        b.pop();
        assert!(b.overflow, "deleting a character does not undo the cut");
        let err = b.take().unwrap_err();
        assert!(crate::i18n::has_code(&err, C_TOO_LONG), "{err}");
        assert!(b.is_empty() && !b.overflow, "buffer cleared");
        b.push_str("ok password");
        assert_eq!(&b.take().unwrap()[..], b"ok password");
    }
    #[test]
    fn failed_protections_are_listed_for_the_confirmation() {
        // mock reports: nothing failed -> no question; each failure -> one line
        let all_ok = HardenReport { items: vec![(HardenItem::NoCoreDumps, true), (HardenItem::NotDumpable, true)] };
        assert!(degraded_from(Some(&all_ok), false).is_empty());
        assert!(degraded_from(None, false).is_empty());
        let bad = HardenReport { items: vec![(HardenItem::NoCoreDumps, false), (HardenItem::NotDumpable, true), (HardenItem::ProcessDacl, false)] };
        let v = degraded_from(Some(&bad), true);
        assert_eq!(v.len(), 3, "{v:?}");
        assert_eq!(v[0], crate::i18n::t("harden.item_lock"));
        assert_eq!(v[1], crate::i18n::tf("harden.item_failed", &[&crate::i18n::t("algo.crash")]));
        assert_eq!(v[2], crate::i18n::tf("harden.item_failed", &[&crate::i18n::t("algo.dacl")]));
    }
    impl SecretBuf {
        fn clone_for_test(&self) -> String {
            self.as_str().to_string()
        }
    }
}
