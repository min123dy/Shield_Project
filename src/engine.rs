//! Shield engine (envelope encryption, fully streamed).
//!
//! File layout (no magic bytes):
//!   slot0(64) | slot1(64) | AEAD_DEK(meta, 265 B)(281) | AEAD_DEK chunks (<=64KiB + 16 tag each)
//!   slot  = salt(16) | AEAD_KEK(DEK 32 B)(48)       <- the "wrapped key" part
//!   KEK   = Argon2id(password, salt, secret = keyfile digest, m=128MiB, t=3+PIM, p=2)
//!   DEK   = 32 random bytes per file (encrypts the data)
//!   meta  = len u64 | flags u8 (bit0 = 7z archive, bit1 = folder) | name_len u8 | name[255]
//! One slot holds the real wrapped DEK, the other random bytes. Changing the password writes the
//! new wrapped DEK into the spare slot, verifies it, then overwrites the old slot 7 times.
//! Data nonce = 0,0,0 | last_flag | counter(8, BE); safe because the DEK is unique per file.
//! Memory use is constant (64 KiB chunks + Argon2 128 MiB); the 7z archive lives only in `SecTemp`.
//!
//! PIM: the KDF formula is unchanged since 1.0, so every existing file still opens. 1.0 defaulted
//! to PIM 0 (3 passes); new files default to `DEFAULT_PIM`. When the default PIM fails, PIM 0 is
//! tried as well, so files made with the old default keep working without the user knowing.

use crate::archive::{archive_into, component_ok, extract_from, validate_archive};
use crate::entropy::{fill_random, rand_hex};
pub use crate::keyfile::{generate_keyfile, keyfile_opt};
use crate::progress::*;
use crate::sectemp::SecTemp;
use crate::wipe::{detect_disk, drive_letter, shred_bytes, shred_tree, trim_volume, wipe_free_space, Disk, PATTERNS};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const SALT: usize = 16;
const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const SLOT: usize = SALT + 32 + TAG; // 64
const SLOTS_LEN: usize = SLOT * 2;
const NAME_MAX: usize = 255;
const META_PT: usize = 8 + 1 + 1 + NAME_MAX;
const META: usize = META_PT + TAG;
const MEM_KIB: u32 = 128 * 1024;
const BASE_T: u32 = 3;
const LANES: u32 = 2;
/// PIM range 0..=64 -> Argon2 passes 3..=67 at 128 MiB.
pub const MAX_PIM: u32 = 64;
/// Default for new files: 3+12 = 15 passes over 128 MiB (~1.9 GiB of memory-hard work per guess).
pub const DEFAULT_PIM: u32 = 12;
/// Default of Shield 1.0, still accepted on decryption.
const LEGACY_PIM: u32 = 0;
const WRAP_AAD: &[u8] = b"SHIELD-WRAP-v2";
const BAD: &str = "실패: 비밀번호/PIM/키 파일이 틀렸거나 파일이 손상되었습니다.";

/// Minimum password length for new credentials. Below the default PIM the KDF is cheaper per guess,
/// so a longer password is required (same idea as VeraCrypt's rule for small PIMs).
pub fn min_password_len(pim: u32, has_keyfile: bool) -> usize {
    match (has_keyfile, pim >= DEFAULT_PIM) {
        (true, _) => 0,
        (false, true) => 12,
        (false, false) => 20,
    }
}

// ------------------------------------------------------------ credentials

pub struct Cred {
    pub pw: Zeroizing<Vec<u8>>,
    pub kf: Option<Zeroizing<[u8; 64]>>,
    pub pim: u32,
}

pub struct Opts {
    pub shred_src: bool,
    pub force7: bool,
    /// After shredding: TRIM the volume (skipped on HDDs).
    pub trim_after: bool,
    /// After shredding: overwrite the free space of the volume (slow, optional).
    pub wipe_free_after: bool,
}

// ------------------------------------------------------------ key wrapping

fn kek(c: &Cred, pim: u32, salt: &[u8]) -> R<ChaCha20Poly1305> {
    if c.pw.is_empty() && c.kf.is_none() {
        return Err("비밀번호 또는 키 파일이 필요합니다.".into());
    }
    let _busy = KdfGuard::new();
    let params = Params::new(MEM_KIB, BASE_T + pim, LANES, None).map_err(e)?;
    let secret: &[u8] = match &c.kf {
        Some(k) => &k[..],
        None => &[],
    };
    let a = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).map_err(e)?;
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(&c.pw, salt, &mut *out).map_err(e)?;
    Ok(ChaCha20Poly1305::new(Key::from_slice(&*out)))
}

fn wrap_nonce() -> Nonce {
    *Nonce::from_slice(&[0u8; 12]) // KEK is unique per random salt
}

fn make_slot(c: &Cred, dek: &[u8; 32]) -> R<[u8; SLOT]> {
    let mut slot = [0u8; SLOT];
    fill_random(&mut slot[..SALT]);
    let k = kek(c, c.pim, &slot[..SALT])?;
    let ct = k.encrypt(&wrap_nonce(), Payload { msg: dek, aad: WRAP_AAD }).map_err(e)?;
    slot[SALT..].copy_from_slice(&ct);
    Ok(slot)
}

fn open_slot(c: &Cred, pim: u32, slot: &[u8]) -> R<Zeroizing<[u8; 32]>> {
    let k = kek(c, pim, &slot[..SALT])?;
    let pt = Zeroizing::new(
        k.decrypt(&wrap_nonce(), Payload { msg: &slot[SALT..], aad: WRAP_AAD })
            .map_err(|_| BAD.to_string())?,
    );
    if pt.len() != 32 {
        return Err(BAD.into());
    }
    let mut d = Zeroizing::new([0u8; 32]);
    d.copy_from_slice(&pt);
    Ok(d)
}

/// Tries both slots (and the 1.0 default PIM when the current default was given).
/// Returns (slot index, DEK, PIM that worked).
fn unlock(c: &Cred, slots: &[u8]) -> R<(usize, Zeroizing<[u8; 32]>, u32)> {
    if c.pim > MAX_PIM {
        return Err(format!("PIM은 0~{MAX_PIM} 범위여야 합니다."));
    }
    let mut pims = vec![c.pim];
    if c.pim == DEFAULT_PIM {
        pims.push(LEGACY_PIM);
    }
    for pim in pims {
        for i in 0..2 {
            check_cancel()?;
            if let Ok(k) = open_slot(c, pim, &slots[i * SLOT..(i + 1) * SLOT]) {
                return Ok((i, k, pim));
            }
        }
    }
    Err(BAD.into())
}

fn nonce(last: bool, ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[3] = last as u8;
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    *Nonce::from_slice(&n)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

// ------------------------------------------------------------ metadata

pub struct Meta {
    pub len: u64,
    pub flags: u8,
    pub name: String,
}

fn meta_encode(m: &Meta) -> [u8; META_PT] {
    let mut b = [0u8; META_PT];
    b[..8].copy_from_slice(&m.len.to_le_bytes());
    b[8] = m.flags;
    let mut n = m.name.len().min(NAME_MAX);
    while !m.name.is_char_boundary(n) {
        n -= 1; // keep a valid UTF-8 prefix of overlong names
    }
    b[9] = n as u8;
    b[10..10 + n].copy_from_slice(&m.name.as_bytes()[..n]);
    b
}

fn meta_decode(b: &[u8]) -> R<Meta> {
    if b.len() != META_PT {
        return Err(BAD.into());
    }
    let n = b[9] as usize;
    Ok(Meta {
        len: u64::from_le_bytes(b[..8].try_into().unwrap()),
        flags: b[8],
        name: String::from_utf8(b[10..10 + n].to_vec()).unwrap_or_default(),
    })
}

fn expected_size(len: u64) -> Option<u64> {
    len.div_ceil(CHUNK as u64)
        .checked_mul(TAG as u64)?
        .checked_add(len)?
        .checked_add((SLOTS_LEN + META) as u64)
}

/// Reads and authenticates the header; returns (file, slot index, DEK, meta, PIM used).
fn open_header<F: Read>(f: &mut F, total: u64, c: &Cred) -> R<(usize, Zeroizing<[u8; 32]>, Meta, u32)> {
    let mut head = vec![0u8; SLOTS_LEN + META];
    f.read_exact(&mut head).map_err(|_| BAD.to_string())?;
    let (idx, dek, pim) = unlock(c, &head[..SLOTS_LEN])?;
    let ci = ChaCha20Poly1305::new(Key::from_slice(&*dek));
    let mp = Zeroizing::new(ci.decrypt(&nonce(false, 0), &head[SLOTS_LEN..]).map_err(|_| BAD.to_string())?);
    let m = meta_decode(&mp)?;
    if expected_size(m.len) != Some(total) {
        return Err(BAD.into()); // truncated or extended
    }
    Ok((idx, dek, m, pim))
}

// ------------------------------------------------------------ AEAD stream layer

fn encrypt_stream<Rd: Read>(inf: &mut Rd, len: u64, dst: &Path, c: &Cred, flags: u8, name: &str) -> R<()> {
    let mut dek = Zeroizing::new([0u8; 32]);
    fill_random(&mut *dek);
    let slot0 = make_slot(c, &dek)?;
    let mut slot1 = [0u8; SLOT];
    fill_random(&mut slot1);
    let ci = ChaCha20Poly1305::new(Key::from_slice(&*dek));

    progress_start(len);
    let tmp = dst.with_file_name(format!(".shd_{}.part", rand_hex()));
    let res = (|| -> R<()> {
        let mut out =
            BufWriter::with_capacity(1 << 20, OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(e)?);
        out.write_all(&slot0).map_err(e)?;
        out.write_all(&slot1).map_err(e)?;
        let meta = Zeroizing::new(meta_encode(&Meta { len, flags, name: name.to_string() }));
        out.write_all(&ci.encrypt(&nonce(false, 0), &meta[..]).map_err(e)?).map_err(e)?;
        let n = len.div_ceil(CHUNK as u64);
        let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
        for i in 0..n {
            check_cancel()?;
            let sz = (len - i * CHUNK as u64).min(CHUNK as u64) as usize;
            inf.read_exact(&mut buf[..sz]).map_err(e)?;
            let ct = ci.encrypt(&nonce(i == n - 1, i + 1), &buf[..sz]).map_err(e)?;
            out.write_all(&ct).map_err(e)?;
            progress_add(sz as u64);
        }
        out.flush().map_err(e)?;
        out.get_ref().sync_all().map_err(e)
    })();
    if let Err(x) = res {
        let _ = fs::remove_file(&tmp);
        return Err(x);
    }
    fs::rename(&tmp, dst).map_err(e)
}

/// Authenticates chunk by chunk and writes plaintext into `out`. Returns (meta, PIM used).
fn decrypt_stream<W: Write>(src: &Path, c: &Cred, out: &mut W) -> R<(Meta, u32)> {
    let f = File::open(src).map_err(e)?;
    let total = f.metadata().map_err(e)?.len();
    let mut f = BufReader::with_capacity(1 << 20, f);
    let (_, dek, m, pim) = open_header(&mut f, total, c)?;
    let ci = ChaCha20Poly1305::new(Key::from_slice(&*dek));
    progress_start(m.len);
    let n = m.len.div_ceil(CHUNK as u64);
    let mut buf = vec![0u8; CHUNK + TAG];
    for i in 0..n {
        check_cancel()?;
        let sz = (m.len - i * CHUNK as u64).min(CHUNK as u64) as usize;
        f.read_exact(&mut buf[..sz + TAG]).map_err(|_| BAD.to_string())?;
        let pt = Zeroizing::new(ci.decrypt(&nonce(i == n - 1, i + 1), &buf[..sz + TAG]).map_err(|_| BAD.to_string())?);
        out.write_all(&pt).map_err(e)?;
        progress_add(sz as u64);
    }
    out.flush().map_err(e)?;
    Ok((m, pim))
}

fn legacy_note(pim: u32, asked: u32) -> &'static str {
    if pim != asked {
        " · 구버전 기본값(PIM 0)으로 열렸습니다. '비밀번호 변경'으로 새 기본 PIM을 적용하는 것을 권장합니다."
    } else {
        ""
    }
}

// ------------------------------------------------------------ password change

/// Re-wraps the file key under new credentials; the data is not touched (instant for any size).
/// 1) unwrap DEK with old creds  2) write new wrapped DEK into the spare slot, fsync
/// 3) re-read, verify the new creds open it AND yield the same DEK  4) overwrite the old slot 7 times.
/// A crash at any point leaves at least one valid slot.
pub fn do_change_password(path: &Path, old: &Cred, new: &Cred) -> R<String> {
    set_stage(ST_REWRAP);
    if new.pim > MAX_PIM {
        return Err(format!("PIM은 0~{MAX_PIM} 범위여야 합니다."));
    }
    let mut f = OpenOptions::new().read(true).write(true).open(path).map_err(e)?;
    let total = f.metadata().map_err(e)?.len();
    let (idx, dek, _, _) = open_header(&mut f, total, old)?;

    let spare = 1 - idx;
    let new_slot = make_slot(new, &dek)?;
    f.seek(SeekFrom::Start((spare * SLOT) as u64)).map_err(e)?;
    f.write_all(&new_slot).map_err(e)?;
    f.flush().map_err(e)?;
    f.sync_all().map_err(e)?;

    let mut head2 = vec![0u8; SLOTS_LEN];
    f.seek(SeekFrom::Start(0)).map_err(e)?;
    f.read_exact(&mut head2).map_err(e)?;
    let fail = || "새 키 검증 실패: 기존 키 슬롯은 그대로 유지됩니다.".to_string();
    let k2 = open_slot(new, new.pim, &head2[spare * SLOT..(spare + 1) * SLOT]).map_err(|_| fail())?;
    if !ct_eq(&k2[..], &dek[..]) {
        return Err(fail());
    }

    // point of no return: not cancellable
    for p in PATTERNS {
        let mut b = [0u8; SLOT];
        match p {
            Some(v) => b.fill(v),
            None => fill_random(&mut b),
        }
        f.seek(SeekFrom::Start((idx * SLOT) as u64)).map_err(e)?;
        f.write_all(&b).map_err(e)?;
        f.flush().map_err(e)?;
        f.sync_all().map_err(e)?;
    }
    Ok("비밀번호 변경 완료: 기존 키 슬롯을 7회 덮어써 파기했습니다.".into())
}

// ------------------------------------------------------------ high level

fn guard(src: &Path, dst: &Path) -> R<()> {
    let s = fs::canonicalize(src).map_err(e)?;
    let dp = dst.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let d = fs::canonicalize(dp).map_err(e)?.join(dst.file_name().ok_or_else(|| "잘못된 출력 경로".to_string())?);
    if d == s || d.starts_with(&s) {
        return Err("출력 파일이 원본과 같거나 원본 폴더 안에 있습니다.".into());
    }
    Ok(())
}

/// Compress (7z/LZMA2, inside an encrypted scratch file) -> encrypt (streamed) -> verify -> optional
/// shred -> optional TRIM / free-space overwrite.
pub fn do_encrypt(src: &Path, dst: &Path, c: &Cred, o: &Opts) -> R<String> {
    guard(src, dst)?;
    if o.shred_src && fs::symlink_metadata(src).map_err(e)?.file_type().is_symlink() {
        // the archive follows the link, but shredding would only remove the link itself
        return Err("바로가기/링크(정션)는 원본 파쇄와 함께 쓸 수 없습니다. 링크 대상 폴더를 직접 선택하세요.".into());
    }
    let is_dir = fs::metadata(src).map_err(e)?.is_dir();
    let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let flags = 1 | if is_dir { 2 } else { 0 };
    let disk = if o.shred_src { detect_disk(src) } else { Disk::Unknown };
    let parent = src.parent().map(Path::to_path_buf);
    let outdir = dst.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new(".")).to_path_buf();

    set_stage(ST_COMPRESS);
    let mut st = SecTemp::create(&outdir).map_err(e)?;
    let skipped = archive_into(src, &mut st)?;
    st.flush().map_err(e)?;
    let len = st.len();
    st.seek(SeekFrom::Start(0)).map_err(e)?;

    set_stage(ST_ENCRYPT);
    encrypt_stream(&mut st, len, dst, c, flags, &name)?;
    drop(st); // crypto-erase of the scratch file

    set_stage(ST_VERIFY);
    if let Err(x) = decrypt_stream(dst, c, &mut io::sink()) {
        let _ = fs::remove_file(dst);
        return Err(format!("검증 실패: 결과 파일을 삭제했고 원본은 그대로입니다. ({x})"));
    }

    let mut msg = String::from("암호화·검증 완료");
    if skipped > 0 {
        msg += &format!(" · 바로가기/링크 {skipped}개는 포함하지 않음");
    }
    if !o.shred_src {
        return Ok(msg);
    }
    let passes = if o.force7 || disk != Disk::Ssd { 7 } else { 1 };
    set_stage(ST_SHRED); // from here on: no cancel
    progress_start(shred_bytes(src, passes));
    shred_tree(src, passes)?;
    msg += &format!(" · 원본 {passes}회 덮어쓰기 파쇄");

    let letter = parent.as_deref().and_then(drive_letter);
    if o.wipe_free_after {
        if let Some(p) = &parent {
            set_stage(ST_WIPE_FREE);
            match wipe_free_space(p) {
                Ok(m) => msg += &format!(" · {m}"),
                Err(x) if x == CANCELLED => msg += " · 여유 공간 덮어쓰기 취소됨",
                Err(x) => msg += &format!(" · 여유 공간 덮어쓰기 실패({x})"),
            }
        }
    }
    if o.trim_after && disk != Disk::Hdd {
        if let Some(l) = letter {
            set_stage(ST_TRIM);
            match trim_volume(l) {
                Ok(m) => msg += &format!(" · {m}"),
                Err(x) => msg += &format!(" · {x}"),
            }
        }
    }
    if disk == Disk::Unknown {
        msg += " · 디스크 종류를 확인하지 못해 7회 덮어썼습니다";
    }
    Ok(msg)
}

fn safe_name(n: &str) -> Option<String> {
    (component_ok(n) && Path::new(n).file_name().and_then(|f| f.to_str()) == Some(n)).then(|| n.to_string())
}

/// `name` if nothing with that name exists in `dir`, otherwise "stem (decrypted).ext",
/// "stem (decrypted 2).ext", ... Folders get the suffix at the end of the whole name.
fn free_name(dir: &Path, name: &str, is_dir: bool) -> (PathBuf, bool) {
    let p = dir.join(name);
    if fs::symlink_metadata(&p).is_err() {
        return (p, false);
    }
    let path = Path::new(name);
    let (stem, ext) = match (is_dir, path.file_stem(), path.extension()) {
        (false, Some(s), Some(x)) => (s.to_string_lossy().into_owned(), format!(".{}", x.to_string_lossy())),
        _ => (name.to_string(), String::new()),
    };
    let mut i = 1u32;
    loop {
        let n = if i == 1 { format!("{stem} (decrypted){ext}") } else { format!("{stem} (decrypted {i}){ext}") };
        let q = dir.join(n);
        if fs::symlink_metadata(&q).is_err() {
            return (q, true);
        }
        i += 1;
    }
}

pub fn do_decrypt(src: &Path, outdir: &Path, c: &Cred) -> R<String> {
    let fname = src.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fallback = safe_name(fname.strip_suffix(".shd").unwrap_or(fname)).unwrap_or_else(|| "decrypted".to_string());

    set_stage(ST_DECRYPT);
    let mut st = SecTemp::create(outdir).map_err(e)?;
    let (meta, pim) = decrypt_stream(src, c, &mut st)?;
    if meta.flags & 1 == 0 {
        return Err(BAD.into());
    }
    st.flush().map_err(e)?;
    let len = st.len();
    st.seek(SeekFrom::Start(0)).map_err(e)?;

    set_stage(ST_EXTRACT);
    let total = validate_archive(&mut st, len)?;
    let stage = outdir.join(format!(".shd_{}_x", rand_hex()));
    let r = fs::create_dir(&stage).map_err(e).and_then(|_| extract_from(&mut st, &stage, total));
    drop(st); // crypto-erase of the scratch file
    if let Err(x) = r {
        let _ = shred_tree(&stage, 1); // partial plaintext
        return Err(x);
    }

    // Restore the original name when the destination has nothing with that name.
    let want = safe_name(&meta.name).unwrap_or(fallback);
    let is_dir = meta.flags & 2 != 0;
    let mut items: Vec<PathBuf> = fs::read_dir(&stage).map_err(e)?.flatten().map(|d| d.path()).collect();
    let single_ok = items.len() == 1
        && items[0].is_dir() == is_dir
        && (!is_dir || items[0].file_name().and_then(|n| n.to_str()) == Some(want.as_str()));
    let (item, is_stage) = if single_ok { (items.remove(0), false) } else { (stage.clone(), true) };
    let (dest, renamed) = free_name(outdir, &want, is_dir || is_stage);
    fs::rename(&item, &dest).map_err(e)?;
    if !is_stage {
        let _ = fs::remove_dir(&stage);
    }
    Ok(format!(
        "복호화 완료: {}{}{}",
        dest.display(),
        if renamed { " (같은 이름이 이미 있어 '(decrypted)'를 붙임)" } else { "" },
        legacy_note(pim, c.pim)
    ))
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
