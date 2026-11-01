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
pub const ST_OPEN: u8 = 10;
pub const ST_CHECK: u8 = 11;
pub const ST_REBUILD: u8 = 12;
pub const ST_REPLACE: u8 = 13;
pub const ST_SCAN: u8 = 14;

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
        ST_COMPRESS => "압축 중 (암호화된 임시 공간 사용, 원본 지문 SHA3-512 계산)",
        ST_ENCRYPT => "암호화 중 (XChaCha20-Poly1305)",
        ST_VERIFY => "검증 중 (전체 인증 → 복원 → 원본과 SHA3-512 비교)",
        ST_DECRYPT => "복호화·전체 인증 중",
        ST_EXTRACT => "압축 해제 중 (경로·자원 제한 검사)",
        ST_SHRED => "원본 파쇄 중 (취소 불가)",
        ST_WIPE_FREE => "여유 공간 덮어쓰기 중 (오래 걸릴 수 있음)",
        ST_REWRAP => "키 재봉인 중",
        ST_TRIM => "TRIM 실행 중 (취소 불가)",
        ST_OPEN => "컨테이너 여는 중 (헤더·메타 인증, 7z 목록 읽기)",
        ST_CHECK => "본문 전체 무결성 검사 중",
        ST_REBUILD => "컨테이너 재구성 중 (기존 항목 + 추가 항목)",
        ST_REPLACE => "원자적 교체 중 (취소 불가)",
        ST_SCAN => "대상 목록 고정 중",
        _ => "준비 중",
    }
}
pub fn stage_short(n: u8) -> &'static str {
    match n {
        ST_COMPRESS => "압축",
        ST_ENCRYPT => "암호화",
        ST_VERIFY => "검증",
        ST_DECRYPT => "복호화",
        ST_EXTRACT => "압축 해제",
        ST_SHRED => "원본 파쇄",
        ST_WIPE_FREE => "여유 공간 덮어쓰기",
        ST_REWRAP => "키 재봉인",
        ST_TRIM => "TRIM",
        ST_OPEN => "열기",
        ST_CHECK => "무결성 검사",
        ST_REBUILD => "재구성",
        ST_REPLACE => "교체",
        ST_SCAN => "목록 고정",
        _ => "",
    }
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
