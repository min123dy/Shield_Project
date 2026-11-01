//! Automatic choice of the compression method and strength (always applied while encrypting).
//!
//! Inputs: total size, available physical memory, CPU cores and the user's choice.
//! - LZMA2: dictionary = largest power of two <= (memory budget / 12 / threads), clamped to
//!   64 KiB..64 MiB and never larger than the input. Small inputs get a high preset (9), large ones
//!   lower presets. Inputs >= 64 MiB use the multi-threaded LZMA2 encoder (<= 4 threads).
//! - Zstandard: used for very large inputs (>= 4 GiB), when memory does not allow a useful LZMA2
//!   dictionary (< 4 MiB), or when the user picks "빠름". sevenz-rust2 0.24 only exposes the level
//!   (no window/thread options), so levels are capped at 19 (zstd's window for those levels stays
//!   far below the 128 MiB decoder limit) and encoding is single-threaded.
//! - Files that already look compressed (by extension or a 64 KiB byte-entropy sample) are stored
//!   without compression (Copy) to save time.

use crate::format::{COMP_COPY, COMP_LZMA2, COMP_ZSTD, MAX_LZMA_DICT};
use sevenz_rust2::encoder_options::{Lzma2Options, ZstandardOptions};
use sevenz_rust2::{EncoderConfiguration, EncoderMethod};
use std::{fs::File, io::Read, path::Path};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strength {
    Auto,
    Fast,
    Balanced,
    Max,
}

impl Strength {
    pub const ALL: [Strength; 4] = [Strength::Auto, Strength::Fast, Strength::Balanced, Strength::Max];
    pub fn label(self) -> &'static str {
        match self {
            Strength::Auto => "자동 (권장)",
            Strength::Fast => "빠름 (Zstandard)",
            Strength::Balanced => "균형",
            Strength::Max => "최대 (느림)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub method: u8,
    pub level: u32,
    /// LZMA2 dictionary bytes (0 for Zstandard/Copy).
    pub dict: u32,
    pub threads: u32,
}

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn floor_pow2(x: u64) -> u64 {
    if x == 0 {
        0
    } else {
        1 << (63 - x.leading_zeros())
    }
}

pub fn plan(total: u64, avail_mem: u64, cores: u32, s: Strength) -> Plan {
    let budget = (avail_mem / 4).max(64 * MIB);
    let zstd = |level: u32| Plan { method: COMP_ZSTD, level, dict: 0, threads: 1 };
    if s == Strength::Fast {
        return zstd(3);
    }
    let threads = if total >= 64 * MIB { cores.clamp(1, 4) } else { 1 };
    let fit = floor_pow2(budget / 12 / threads as u64);
    let cap = floor_pow2(total.max(64 << 10)).max(64 << 10);
    let need_round_up = cap < total.max(64 << 10);
    let input_cap = if need_round_up { cap * 2 } else { cap };
    let dict = fit.min(MAX_LZMA_DICT as u64).min(input_cap).max(64 << 10);
    let too_big = total >= 4 * GIB;
    let starved = dict < 4 * MIB && total > 4 * MIB;
    if s != Strength::Max && (too_big || starved) {
        let level = match s {
            Strength::Balanced => 9,
            _ if total < GIB => 9,
            _ if total < 16 * GIB => 6,
            _ => 3,
        };
        return zstd(level);
    }
    let level = match s {
        Strength::Max => 9,
        Strength::Balanced => 6,
        _ if total <= 256 * MIB => 9,
        _ if total <= GIB => 7,
        _ if total <= 4 * GIB => 6,
        _ => 5,
    };
    // the dictionary may need to shrink so that every thread's encoder fits in the budget
    let threads = threads.min((budget / (dict * 12)).max(1) as u32);
    Plan { method: COMP_LZMA2, level, dict: dict as u32, threads }
}

/// 7z coder configuration for a plan.
pub fn methods(p: &Plan) -> Vec<EncoderConfiguration> {
    match p.method {
        COMP_ZSTD => vec![ZstandardOptions::from_level(p.level.clamp(1, 19)).into()],
        COMP_COPY => vec![EncoderConfiguration::new(EncoderMethod::COPY)],
        _ => {
            let mut o = if p.threads > 1 {
                Lzma2Options::from_level_mt(p.level, p.threads, (p.dict as u64 * 4).max(4 * MIB))
            } else {
                Lzma2Options::from_level(p.level)
            };
            o.set_dictionary_size(p.dict);
            vec![o.into()]
        }
    }
}

pub fn copy_methods() -> Vec<EncoderConfiguration> {
    vec![EncoderConfiguration::new(EncoderMethod::COPY)]
}

const PACKED_EXT: &[&str] = &[
    "7z", "zip", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "cab", "jar", "apk", "docx", "xlsx", "pptx", "odt",
    "jpg", "jpeg", "png", "gif", "webp", "heic", "avif", "mp3", "aac", "m4a", "ogg", "opus", "flac", "mp4", "m4v",
    "mkv", "mov", "avi", "webm", "wmv", "pdf", "shd", "msi", "dmg", "iso",
];

/// True when a file is very likely incompressible: known compressed type, or a 64 KiB sample whose
/// byte entropy is above 7.95 bits/byte. Files below 64 KiB are always compressed.
pub fn looks_compressed(p: &Path, size: u64) -> bool {
    if size < 64 * 1024 {
        return false;
    }
    let ext = p.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if PACKED_EXT.contains(&ext.as_str()) {
        return true;
    }
    let Ok(mut f) = File::open(p) else { return false };
    let mut buf = vec![0u8; 64 * 1024];
    let Ok(n) = f.read(&mut buf) else { return false };
    if n < 4096 {
        return false;
    }
    let mut hist = [0u32; 256];
    for &b in &buf[..n] {
        hist[b as usize] += 1;
    }
    let h: f64 = hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let q = c as f64 / n as f64;
            -q * q.log2()
        })
        .sum();
    h > 7.95
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_inputs_get_strong_lzma2() {
        let p = plan(10 * MIB, 8 * GIB, 8, Strength::Auto);
        assert_eq!((p.method, p.level, p.threads), (COMP_LZMA2, 9, 1));
        assert_eq!(p.dict as u64, 16 * MIB); // never above the (rounded-up) input size
        let tiny = plan(1000, 8 * GIB, 8, Strength::Auto);
        assert_eq!(tiny.dict, 64 << 10);
    }
    #[test]
    fn medium_and_large_inputs() {
        let p = plan(600 * MIB, 16 * GIB, 8, Strength::Auto);
        assert_eq!((p.method, p.level), (COMP_LZMA2, 7));
        assert!(p.dict as u64 <= 64 * MIB && p.threads >= 1 && p.threads <= 4);
        let big = plan(6 * GIB, 16 * GIB, 8, Strength::Auto);
        assert_eq!(big.method, COMP_ZSTD);
        let max = plan(6 * GIB, 16 * GIB, 8, Strength::Max);
        assert_eq!((max.method, max.level), (COMP_LZMA2, 9));
    }
    #[test]
    fn low_memory_switches_to_zstd_and_fast_choice() {
        let p = plan(500 * MIB, 128 * MIB, 4, Strength::Auto); // budget 64 MiB -> dict < 4 MiB
        assert_eq!(p.method, COMP_ZSTD);
        assert_eq!(plan(MIB, 8 * GIB, 8, Strength::Fast), Plan { method: COMP_ZSTD, level: 3, dict: 0, threads: 1 });
        let small_low = plan(2 * MIB, 128 * MIB, 4, Strength::Auto); // small input still LZMA2
        assert_eq!(small_low.method, COMP_LZMA2);
    }
}
