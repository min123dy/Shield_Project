//! Shield v2 file format (no magic bytes; the whole file looks random).
//!
//! ```text
//! [slot0 88][slot1 88][nonce prefix 15][meta ciphertext 512 + tag 16][chunk 1]...[chunk n]
//! slot   = salt 16 | nonce 24 | XChaCha20-Poly1305_KEK(DEK 32) 48     AAD = SLOT_AAD
//! KEK    = Argon2id(NFC password, salt, secret = key file digest, m = 256 MiB, p = 4, t = 3 + PIM)
//! nonce  = prefix 15 | flag 1 (0 data, 1 last data, 2 meta) | counter 8 BE (chunks start at 1)
//! meta   : AAD = META_LABEL | prefix                     (fixed 512 B plaintext, see `Meta`)
//! chunk i: AAD = DATA_LABEL | meta tag, plaintext 64 KiB (last one shorter), counter = i + 1
//! ```
//! One slot holds the wrapped DEK (random position), the other is random bytes. The DEK is unique
//! per file, so (key, nonce) pairs never repeat; the meta block is written exactly once.
//! Memory cost and lanes are constants of format version 2 (they are needed before the meta can be
//! read). Changing them means a new format version with a new SLOT_AAD label.

use zeroize::Zeroizing;

pub const FORMAT_VERSION: u16 = 2;
pub const AEAD_XCHACHA20_POLY1305: u8 = 1;
pub const HASH_SHA3_512: u8 = 1;
pub const KDF_ARGON2ID_13: u8 = 1;

pub const COMP_COPY: u8 = 0;
pub const COMP_LZMA2: u8 = 1;
pub const COMP_ZSTD: u8 = 2;

pub const SALT: usize = 16;
pub const XNONCE: usize = 24;
pub const TAG: usize = 16;
pub const KEY: usize = 32;
pub const SLOT: usize = SALT + XNONCE + KEY + TAG; // 88
pub const SLOTS: usize = SLOT * 2;
pub const PREFIX: usize = 15;
pub const META_PT: usize = 512;
pub const META_CT: usize = META_PT + TAG;
pub const HEADER: usize = SLOTS + PREFIX + META_CT; // 719
pub const CHUNK: usize = 64 * 1024;
pub const NAME_MAX: usize = 255;

pub const KDF_MEM_KIB: u32 = 256 * 1024;
pub const KDF_LANES: u32 = 4;
pub const BASE_T: u32 = 3;
/// PIM 0..=64 -> Argon2 passes 3..=67 over 256 MiB.
pub const MAX_PIM: u32 = 64;
/// Default for new files: 3 + 12 = 15 passes over 256 MiB.
pub const DEFAULT_PIM: u32 = 12;

pub const SLOT_AAD: &[u8] = b"SHIELD-v2-SLOT|XChaCha20-Poly1305|Argon2id-1.3|m=262144KiB|p=4";
pub const META_LABEL: &[u8] = b"SHIELD-v2-META";
pub const DATA_LABEL: &[u8] = b"SHIELD-v2-DATA";

pub const FLAG_ARCHIVE: u32 = 1;
pub const FLAG_DIR: u32 = 2;
/// Some entries were stored without compression (already-compressed data).
pub const FLAG_SOME_STORED: u32 = 4;
const KNOWN_FLAGS: u32 = FLAG_ARCHIVE | FLAG_DIR | FLAG_SOME_STORED;

pub const NONCE_DATA: u8 = 0;
pub const NONCE_LAST: u8 = 1;
pub const NONCE_META: u8 = 2;

/// Limits applied to authenticated metadata (PCC-002 / PCC-005).
pub const MAX_FILES: u64 = 1_000_000;
pub const MAX_LZMA_DICT: u32 = 64 << 20;

pub const BAD: &str = "실패: 비밀번호/PIM/키 파일이 틀렸거나 파일이 손상되었습니다(또는 Shield 2 파일이 아님).";
pub const UNSUPPORTED: &str =
    "지원하지 않는 형식입니다: 인증은 성공했지만 이 Shield가 모르는 버전·알고리즘·설정입니다. 더 새로운 Shield가 필요할 수 있습니다.";
pub const SIZE_MISMATCH: &str = "파일 크기가 헤더와 맞지 않습니다: 잘렸거나 뒤에 데이터가 덧붙었습니다. 복호화를 중단했습니다.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub version: u16,
    pub aead: u8,
    pub hash: u8,
    pub kdf: u8,
    pub kdf_mem_kib: u32,
    pub kdf_lanes: u32,
    pub comp_method: u8,
    pub comp_level: u8,
    pub comp_dict: u32,
    pub chunk: u32,
    pub real_len: u64,
    pub padded_len: u64,
    pub flags: u32,
    pub file_count: u64,
    pub dir_count: u64,
    pub total_unpacked: u64,
    pub created: u64,
    pub name: String,
}

impl Meta {
    /// A v2 meta block with the constants filled in.
    pub fn new(name: &str, flags: u32) -> Self {
        Meta {
            version: FORMAT_VERSION,
            aead: AEAD_XCHACHA20_POLY1305,
            hash: HASH_SHA3_512,
            kdf: KDF_ARGON2ID_13,
            kdf_mem_kib: KDF_MEM_KIB,
            kdf_lanes: KDF_LANES,
            comp_method: COMP_LZMA2,
            comp_level: 6,
            comp_dict: 0,
            chunk: CHUNK as u32,
            real_len: 0,
            padded_len: 0,
            flags,
            file_count: 0,
            dir_count: 0,
            total_unpacked: 0,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            name: truncate_name(name),
        }
    }
}

/// Longest valid UTF-8 prefix of at most NAME_MAX bytes.
pub fn truncate_name(n: &str) -> String {
    let mut k = n.len().min(NAME_MAX);
    while !n.is_char_boundary(k) {
        k -= 1;
    }
    n[..k].to_string()
}

pub fn encode_meta(m: &Meta) -> Zeroizing<[u8; META_PT]> {
    let mut b = Zeroizing::new([0u8; META_PT]);
    b[0..2].copy_from_slice(&m.version.to_le_bytes());
    b[2] = m.aead;
    b[3] = m.hash;
    b[4] = m.kdf;
    b[6..10].copy_from_slice(&m.kdf_mem_kib.to_le_bytes());
    b[10..14].copy_from_slice(&m.kdf_lanes.to_le_bytes());
    b[14] = m.comp_method;
    b[15] = m.comp_level;
    b[16..20].copy_from_slice(&m.comp_dict.to_le_bytes());
    b[20..24].copy_from_slice(&m.chunk.to_le_bytes());
    b[24..32].copy_from_slice(&m.real_len.to_le_bytes());
    b[32..40].copy_from_slice(&m.padded_len.to_le_bytes());
    b[40..44].copy_from_slice(&m.flags.to_le_bytes());
    b[44..52].copy_from_slice(&m.file_count.to_le_bytes());
    b[52..60].copy_from_slice(&m.total_unpacked.to_le_bytes());
    b[60..68].copy_from_slice(&m.dir_count.to_le_bytes());
    b[68..76].copy_from_slice(&m.created.to_le_bytes());
    let name = truncate_name(&m.name);
    b[76] = name.len() as u8;
    b[77..77 + name.len()].copy_from_slice(name.as_bytes());
    b
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Parses and validates an *authenticated* meta block. Every error here means "authentic but not
/// understood" and is reported as an unsupported format, never as a wrong password.
pub fn decode_meta(b: &[u8]) -> Result<Meta, String> {
    if b.len() != META_PT {
        return Err(UNSUPPORTED.into());
    }
    let nl = b[76] as usize;
    let unsupported = || UNSUPPORTED.to_string();
    if b[5] != 0 || nl > NAME_MAX || b[77 + nl..].iter().any(|&x| x != 0) {
        return Err(unsupported());
    }
    let m = Meta {
        version: u16::from_le_bytes([b[0], b[1]]),
        aead: b[2],
        hash: b[3],
        kdf: b[4],
        kdf_mem_kib: u32le(b, 6),
        kdf_lanes: u32le(b, 10),
        comp_method: b[14],
        comp_level: b[15],
        comp_dict: u32le(b, 16),
        chunk: u32le(b, 20),
        real_len: u64le(b, 24),
        padded_len: u64le(b, 32),
        flags: u32le(b, 40),
        file_count: u64le(b, 44),
        total_unpacked: u64le(b, 52),
        dir_count: u64le(b, 60),
        created: u64le(b, 68),
        name: String::from_utf8(b[77..77 + nl].to_vec()).map_err(|_| unsupported())?,
    };
    let comp_ok = match m.comp_method {
        COMP_COPY => m.comp_level == 0,
        COMP_LZMA2 => m.comp_level <= 9 && m.comp_dict <= MAX_LZMA_DICT,
        COMP_ZSTD => (1..=22).contains(&m.comp_level),
        _ => false,
    };
    let ok = m.version == FORMAT_VERSION
        && m.aead == AEAD_XCHACHA20_POLY1305
        && m.hash == HASH_SHA3_512
        && m.kdf == KDF_ARGON2ID_13
        && m.kdf_mem_kib == KDF_MEM_KIB
        && m.kdf_lanes == KDF_LANES
        && m.chunk == CHUNK as u32
        && comp_ok
        && m.flags & !KNOWN_FLAGS == 0
        && m.flags & FLAG_ARCHIVE != 0
        && m.padded_len > 0
        && m.real_len > 0
        && m.real_len <= m.padded_len
        && m.padded_len - m.real_len <= pad_max(m.real_len)
        && m.file_count <= MAX_FILES
        && m.dir_count <= MAX_FILES;
    if ok {
        Ok(m)
    } else {
        Err(unsupported())
    }
}

pub fn nonce(prefix: &[u8; PREFIX], flag: u8, ctr: u64) -> [u8; XNONCE] {
    let mut n = [0u8; XNONCE];
    n[..PREFIX].copy_from_slice(prefix);
    n[PREFIX] = flag;
    n[PREFIX + 1..].copy_from_slice(&ctr.to_be_bytes());
    n
}

pub fn meta_aad(prefix: &[u8; PREFIX]) -> Vec<u8> {
    [META_LABEL, &prefix[..]].concat()
}

pub fn data_aad(meta_tag: &[u8; TAG]) -> Vec<u8> {
    [DATA_LABEL, &meta_tag[..]].concat()
}

pub fn chunk_count(padded_len: u64) -> u64 {
    padded_len.div_ceil(CHUNK as u64)
}

/// Exact file size implied by `padded_len` (None on overflow).
pub fn expected_size(padded_len: u64) -> Option<u64> {
    chunk_count(padded_len).checked_mul(TAG as u64)?.checked_add(padded_len)?.checked_add(HEADER as u64)
}

/// Upper bound of the random length padding: clamp(real_len / 16, 64 KiB, 1 GiB).
pub fn pad_max(real_len: u64) -> u64 {
    (real_len / 16).clamp(64 << 10, 1 << 30)
}

pub fn comp_name(method: u8) -> &'static str {
    match method {
        COMP_COPY => "무압축 저장 (Copy)",
        COMP_LZMA2 => "LZMA2",
        COMP_ZSTD => "Zstandard",
        _ => "알 수 없음",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Meta {
        let mut m = Meta::new("가나다.txt", FLAG_ARCHIVE);
        m.real_len = 1000;
        m.padded_len = 5000;
        m.file_count = 1;
        m
    }
    #[test]
    fn meta_roundtrip_and_strict_checks() {
        let m = sample();
        assert_eq!(decode_meta(&encode_meta(&m)[..]).unwrap(), m);
        for f in [
            |m: &mut Meta| m.version = 3,
            |m: &mut Meta| m.aead = 9,
            |m: &mut Meta| m.kdf_mem_kib = 128 * 1024,
            |m: &mut Meta| m.kdf_lanes = 2,
            |m: &mut Meta| m.comp_method = 7,
            |m: &mut Meta| m.flags |= 0x80,
            |m: &mut Meta| m.padded_len = 10,
            |m: &mut Meta| m.padded_len = 1 << 40,
            |m: &mut Meta| m.chunk = 4096,
        ] {
            let mut x = sample();
            f(&mut x);
            assert_eq!(decode_meta(&encode_meta(&x)[..]).unwrap_err(), UNSUPPORTED);
        }
        let mut raw = encode_meta(&m);
        raw[500] = 1; // reserved area must be zero
        assert!(decode_meta(&raw[..]).is_err());
        let long = "가".repeat(200);
        assert_eq!(truncate_name(&long).chars().count(), 85);
    }
    #[test]
    fn sizes() {
        assert_eq!(HEADER, 719);
        assert_eq!(expected_size(1), Some(719 + 1 + 16));
        assert_eq!(expected_size(CHUNK as u64 + 1), Some(719 + CHUNK as u64 + 1 + 32));
        assert_eq!(expected_size(u64::MAX), None);
        assert_eq!(pad_max(0), 64 << 10);
        assert_eq!(pad_max(1 << 40), 1 << 30);
    }
}
