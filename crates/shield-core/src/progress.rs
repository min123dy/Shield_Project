//! Shared progress / cancel state between the worker thread and the UI.

use crate::i18n::{coded, has_code, t};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

pub type R<T> = Result<T, String>;
pub fn e<E: ToString>(x: E) -> String {
    x.to_string()
}

pub static CANCEL: AtomicBool = AtomicBool::new(false);
pub static STAGE: AtomicU8 = AtomicU8::new(0);
pub static PROG_DONE: AtomicU64 = AtomicU64::new(0);
pub static PROG_TOTAL: AtomicU64 = AtomicU64::new(0);
/// True while Argon2id runs (no byte progress is available for it).
pub static KDF_BUSY: AtomicBool = AtomicBool::new(false);

pub const ST_COMPRESS: u8 = 1;
pub const ST_ENCRYPT: u8 = 2;
pub const ST_VERIFY: u8 = 3;
pub const ST_DECRYPT: u8 = 4;
pub const ST_EXTRACT: u8 = 5;
pub const ST_SHRED: u8 = 6;
pub const ST_WIPE_FREE: u8 = 7;
pub const ST_REWRAP: u8 = 8;
pub const ST_TRIM: u8 = 9;
pub const ST_OPEN: u8 = 10;
pub const ST_CHECK: u8 = 11;
pub const ST_REBUILD: u8 = 12;
pub const ST_REPLACE: u8 = 13;
pub const ST_SCAN: u8 = 14;
pub const ST_LOCK: u8 = 15;
pub const ST_ADS: u8 = 16;

pub const C_CANCELLED: &str = "E_CANCELLED";

pub fn cancelled_msg() -> String {
    coded(C_CANCELLED, "err.cancelled")
}

pub fn is_cancel(msg: &str) -> bool {
    has_code(msg, C_CANCELLED)
}

pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}
pub fn check_cancel() -> R<()> {
    if cancelled() {
        Err(cancelled_msg())
    } else {
        Ok(())
    }
}
pub fn set_stage(n: u8) {
    STAGE.store(n, Ordering::Relaxed);
    PROG_DONE.store(0, Ordering::Relaxed);
    PROG_TOTAL.store(0, Ordering::Relaxed);
}
pub fn stage_label(n: u8) -> &'static str {
    t(match n {
        ST_COMPRESS => "stage.compress",
        ST_ENCRYPT => "stage.encrypt",
        ST_VERIFY => "stage.verify",
        ST_DECRYPT => "stage.decrypt",
        ST_EXTRACT => "stage.extract",
        ST_SHRED => "stage.shred",
        ST_WIPE_FREE => "stage.wipe_free",
        ST_REWRAP => "stage.rewrap",
        ST_TRIM => "stage.trim",
        ST_OPEN => "stage.open",
        ST_CHECK => "stage.check",
        ST_REBUILD => "stage.rebuild",
        ST_REPLACE => "stage.replace",
        ST_SCAN => "stage.scan",
        ST_LOCK => "stage.lock",
        ST_ADS => "stage.ads",
        _ => "stage.prepare",
    })
}
pub fn stage_short(n: u8) -> &'static str {
    t(match n {
        ST_COMPRESS => "stage_s.compress",
        ST_ENCRYPT => "stage_s.encrypt",
        ST_VERIFY => "stage_s.verify",
        ST_DECRYPT => "stage_s.decrypt",
        ST_EXTRACT => "stage_s.extract",
        ST_SHRED => "stage_s.shred",
        ST_WIPE_FREE => "stage_s.wipe_free",
        ST_REWRAP => "stage_s.rewrap",
        ST_TRIM => "stage_s.trim",
        ST_OPEN => "stage_s.open",
        ST_CHECK => "stage_s.check",
        ST_REBUILD => "stage_s.rebuild",
        ST_REPLACE => "stage_s.replace",
        ST_SCAN => "stage_s.scan",
        ST_LOCK => "stage_s.lock",
        ST_ADS => "stage_s.ads",
        _ => "stage_s.none",
    })
}
/// Shredding half-way would leave a half-destroyed original; an elevated TRIM can't be stopped;
/// the final rename of a rebuilt container must not be interrupted.
pub fn stage_cancellable(n: u8) -> bool {
    !matches!(n, ST_SHRED | ST_TRIM | ST_REPLACE)
}
pub fn progress_start(total: u64) {
    PROG_TOTAL.store(total, Ordering::Relaxed);
    PROG_DONE.store(0, Ordering::Relaxed);
}
pub fn progress_add(n: u64) {
    PROG_DONE.fetch_add(n, Ordering::Relaxed);
}

/// Marks a key derivation as running for as long as the guard lives.
pub struct KdfGuard;
impl Default for KdfGuard {
    fn default() -> Self {
        Self::new()
    }
}
impl KdfGuard {
    pub fn new() -> Self {
        KDF_BUSY.store(true, Ordering::Relaxed);
        KdfGuard
    }
}
impl Drop for KdfGuard {
    fn drop(&mut self) {
        KDF_BUSY.store(false, Ordering::Relaxed);
    }
}
