//! Key files: any file(s) whose full contents are mixed into the KDF as the Argon2 secret.

use crate::entropy::fill_random;
use crate::progress::{e, R};
use sha2::{Digest, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Order-independent digest of all key files (each fully hashed with SHA-512).
pub fn keyfile_material(files: &[PathBuf]) -> R<Zeroizing<[u8; 64]>> {
    let mut hs: Vec<[u8; 64]> = Vec::new();
    for p in files {
        let m = fs::metadata(p).map_err(e)?;
        if !m.is_file() || m.len() == 0 {
            return Err(format!("키 파일을 사용할 수 없습니다: {}", p.display()));
        }
        let mut h = Sha512::new();
        io::copy(&mut File::open(p).map_err(e)?, &mut h).map_err(e)?;
        let mut a = [0u8; 64];
        a.copy_from_slice(h.finalize().as_slice());
        hs.push(a);
    }
    let n = hs.len();
    hs.sort();
    hs.dedup();
    if hs.len() != n {
        return Err("내용이 같은 키 파일이 중복되었습니다.".into());
    }
    let mut h = Sha512::new();
    h.update(b"SHIELD-KF-v1");
    h.update((n as u32).to_le_bytes());
    for x in &hs {
        h.update(x);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(h.finalize().as_slice());
    Ok(out)
}

pub fn keyfile_opt(files: &[PathBuf]) -> R<Option<Zeroizing<[u8; 64]>>> {
    if files.is_empty() {
        Ok(None)
    } else {
        keyfile_material(files).map(Some)
    }
}

/// 128 random bytes (OS entropy + mouse pool). Never overwrites an existing file.
pub fn generate_keyfile(path: &Path) -> R<()> {
    let mut k = Zeroizing::new([0u8; 128]);
    fill_random(&mut *k);
    let mut f = OpenOptions::new().write(true).create_new(true).open(path).map_err(e)?;
    f.write_all(&*k).map_err(e)?;
    f.sync_all().map_err(e)
}
