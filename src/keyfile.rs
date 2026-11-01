//! Key files: any file(s) whose full contents are mixed into the KDF as the Argon2 secret.
//! Each file is hashed with SHA3-512; the sorted digests are hashed again with a label into the
//! 64-byte secret. The effective strength is capped by that 512-bit digest. Hashes, hasher states
//! (sha3 "zeroize" feature) and read buffers are zeroized.

use crate::entropy::fill_random;
use crate::progress::{e, R};
use sha3::{Digest, Sha3_512};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const KF_DEFAULT_KIB: u32 = 1;
pub const KF_MAX_KIB: u32 = 1024;

/// Hashes one key file; rejects empty files and files made of one repeated byte.
fn hash_one(p: &Path) -> R<Zeroizing<[u8; 64]>> {
    let m = fs::metadata(p).map_err(|x| format!("키 파일을 열 수 없습니다: {} ({x})", p.display()))?;
    if !m.is_file() || m.len() == 0 {
        return Err(format!("키 파일을 사용할 수 없습니다 (빈 파일이거나 일반 파일이 아님): {}", p.display()));
    }
    let mut f = File::open(p).map_err(e)?;
    let mut h = Sha3_512::new();
    let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut first: Option<u8> = None;
    let mut uniform = true;
    loop {
        let n = f.read(&mut buf).map_err(e)?;
        if n == 0 {
            break;
        }
        let b0 = *first.get_or_insert(buf[0]);
        uniform &= buf[..n].iter().all(|&b| b == b0);
        h.update(&buf[..n]);
    }
    if uniform {
        return Err(format!("키 파일 품질 검사 실패 (모든 바이트가 같음): {}", p.display()));
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// Order-independent digest of all key files.
pub fn keyfile_material(files: &[PathBuf]) -> R<Zeroizing<[u8; 64]>> {
    let mut hs: Zeroizing<Vec<[u8; 64]>> = Zeroizing::new(Vec::with_capacity(files.len()));
    for p in files {
        hs.push(*hash_one(p)?);
    }
    let n = hs.len();
    hs.sort();
    hs.dedup();
    if hs.len() != n {
        return Err("내용이 같은 키 파일이 중복되었습니다.".into());
    }
    let mut h = Sha3_512::new();
    h.update(b"SHIELD-KF-v2");
    h.update((n as u32).to_le_bytes());
    for x in hs.iter() {
        h.update(x);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

pub fn keyfile_opt(files: &[PathBuf]) -> R<Option<Zeroizing<[u8; 64]>>> {
    if files.is_empty() {
        Ok(None)
    } else {
        keyfile_material(files).map(Some)
    }
}

/// Blocks a key file that is (or lies inside) one of `targets` — encrypting or shredding it would
/// destroy the key needed to decrypt.
pub fn check_overlap(keyfiles: &[PathBuf], targets: &[&Path]) -> R<()> {
    for k in keyfiles {
        for t in targets {
            if crate::sysinfo::is_within(k, t) {
                return Err(format!(
                    "키 파일이 작업 대상과 겹칩니다: {} — 키 파일을 대상 밖으로 옮긴 뒤 다시 시도하세요.",
                    k.display()
                ));
            }
        }
    }
    Ok(())
}

/// Generates a random key file of `kib` KiB (1..=1024). Never overwrites an existing file; access
/// is restricted to the current user. Random data is drawn 32 bytes per call so every call mixes
/// fresh OS entropy.
pub fn generate_keyfile(path: &Path, kib: u32) -> R<()> {
    if !(1..=KF_MAX_KIB).contains(&kib) {
        return Err(format!("키 파일 크기는 1~{KF_MAX_KIB} KiB 범위여야 합니다 (입력: {kib})."));
    }
    let mut k = Zeroizing::new(vec![0u8; kib as usize * 1024]);
    for c in k.chunks_mut(32) {
        fill_random(c)?;
    }
    if k.iter().all(|&b| b == k[0]) {
        return Err("난수 품질 검사 실패: 키 파일을 만들지 않았습니다.".into());
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|x| format!("키 파일을 만들 수 없습니다 (같은 이름이 있으면 덮어쓰지 않습니다): {x}"))?;
    let w = f.write_all(&k).and_then(|_| f.sync_all());
    drop(f);
    if let Err(x) = w {
        let _ = fs::remove_file(path);
        return Err(e(x));
    }
    crate::sysinfo::restrict_file(path).map_err(|x| format!("키 파일은 만들었지만 접근 권한 제한에 실패했습니다: {x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("shield_kf_{}", crate::entropy::rand_hex().unwrap()));
        fs::create_dir_all(&d).unwrap();
        d
    }
    #[test]
    fn generate_sizes_and_no_overwrite() {
        let d = dir();
        let p = d.join("k.key");
        generate_keyfile(&p, KF_DEFAULT_KIB).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().len(), 1024);
        assert!(generate_keyfile(&p, 1).is_err(), "overwrite refused");
        assert!(generate_keyfile(&d.join("a"), 0).is_err());
        assert!(generate_keyfile(&d.join("b"), KF_MAX_KIB + 1).is_err());
        generate_keyfile(&d.join("c"), KF_MAX_KIB).unwrap();
        assert_eq!(fs::metadata(d.join("c")).unwrap().len(), 1024 * 1024);
        let _ = fs::remove_dir_all(d);
    }
    #[test]
    fn duplicates_empty_uniform_and_overlap() {
        let d = dir();
        fs::write(d.join("a"), b"key material one").unwrap();
        fs::write(d.join("b"), b"key material one").unwrap();
        fs::write(d.join("c"), b"").unwrap();
        fs::write(d.join("u"), [7u8; 100]).unwrap();
        assert!(keyfile_material(&[d.join("a"), d.join("b")]).is_err());
        assert!(keyfile_material(&[d.join("c")]).is_err());
        assert!(keyfile_material(&[d.join("u")]).is_err());
        let one = keyfile_material(&[d.join("a")]).unwrap();
        fs::write(d.join("x"), b"other").unwrap();
        let ab = keyfile_material(&[d.join("a"), d.join("x")]).unwrap();
        let ba = keyfile_material(&[d.join("x"), d.join("a")]).unwrap();
        assert_eq!(*ab, *ba);
        assert_ne!(*one, *ab);
        assert!(check_overlap(&[d.join("a")], &[d.as_path()]).is_err());
        assert!(check_overlap(&[d.join("a")], &[d.join("a").as_path()]).is_err());
        assert!(check_overlap(&[d.join("a")], &[d.join("x").as_path()]).is_ok());
        let _ = fs::remove_dir_all(d);
    }
}
