//! Shared progress / cancel state between the worker thread and the UI.

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

pub const CANCELLED: &str = "취소되었습니다.";

pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}
pub fn check_cancel() -> R<()> {
    if cancelled() {
        Err(CANCELLED.into())
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
    match n {
        ST_COMPRESS => "압축 중 (7z/LZMA2, 암호화된 임시 공간 사용)",
        ST_ENCRYPT => "암호화 중",
        ST_VERIFY => "암호화 결과 검증 중",
        ST_DECRYPT => "복호화 중",
        ST_EXTRACT => "압축 해제 중",
        ST_SHRED => "원본 파쇄 중 (취소 불가)",
        ST_WIPE_FREE => "여유 공간 덮어쓰기 중 (오래 걸릴 수 있음)",
        ST_REWRAP => "키 재봉인 중",
        ST_TRIM => "TRIM 실행 중 (취소 불가)",
        _ => "준비 중",
    }
}
/// Shredding half-way would leave a half-destroyed original; an elevated TRIM can't be stopped.
pub fn stage_cancellable(n: u8) -> bool {
    !matches!(n, ST_SHRED | ST_TRIM)
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
