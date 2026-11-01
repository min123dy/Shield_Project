//! Encrypted scratch file with random access (Read + Write + Seek).
//! The 7z archive is built/read through this, so plaintext archives never touch the disk.
//!
//! Blocks of 64 KiB are sealed with XChaCha20-Poly1305 under an ephemeral key that exists only in
//! (locked, best effort) RAM. Every block write uses a fresh counter. The AAD binds the label, the
//! block index and the counter, and the expected counter of every block is kept in memory, so a
//! block moved to another index, an older version of a block (replay), a hole inside the written
//! range or a truncated file are all detected. Blocks past the end start as zeros.
//! `destroy` (and, best effort, Drop) zeroizes the key first ("crypto-erase"), then deletes the
//! file; a failed delete is reported to the caller.

use crate::entropy::{fill_random, rand_hex};
use crate::harden::{lock_mem, unlock_mem};
use crate::progress::cancelled;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const BLK: usize = 64 * 1024;
const TAG: usize = 16;
const SLOT: u64 = (8 + BLK + TAG) as u64;
const LABEL: &[u8] = b"SHIELD-v2-SECTEMP";

pub struct SecTemp {
    f: Option<File>,
    path: PathBuf,
    key: Box<[u8; 32]>,
    ctr: u64,
    /// Expected counter per block (0 = never written).
    expect: Vec<u64>,
    size: u64,
    pos: u64,
    cache: Zeroizing<Vec<u8>>,
    cidx: Option<u64>,
    dirty: bool,
    destroyed: bool,
}

fn ioerr(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("임시 저장소: {m}"))
}

fn nonce(c: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&c.to_be_bytes());
    XNonce::from(n)
}

fn aad(idx: u64, c: u64) -> [u8; 33] {
    let mut a = [0u8; 33];
    a[..17].copy_from_slice(LABEL);
    a[17..25].copy_from_slice(&idx.to_le_bytes());
    a[25..].copy_from_slice(&c.to_le_bytes());
    a
}

impl SecTemp {
    /// Creates `.shd_<random>.tmp` in `dir` (never overwrites).
    pub fn create(dir: &Path) -> io::Result<Self> {
        let hex = rand_hex().map_err(io::Error::other)?;
        let path = dir.join(format!(".shd_{hex}.tmp"));
        let f = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mut key = Box::new([0u8; 32]);
        if let Err(m) = fill_random(&mut *key) {
            drop(f);
            let _ = fs::remove_file(&path);
            return Err(io::Error::other(m));
        }
        lock_mem(key.as_ptr(), 32);
        Ok(Self {
            f: Some(f),
            path,
            key,
            ctr: 0,
            expect: Vec::new(),
            size: 0,
            pos: 0,
            cache: Zeroizing::new(vec![0u8; BLK]),
            cidx: None,
            dirty: false,
            destroyed: false,
        })
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    fn file(&mut self) -> io::Result<&mut File> {
        self.f.as_mut().ok_or_else(|| ioerr("이미 파기됨"))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.key).into())
    }

    fn flush_cache(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let idx = self.cidx.ok_or_else(|| ioerr("블록 없음"))?;
        self.ctr = self.ctr.checked_add(1).ok_or_else(|| ioerr("카운터 한계"))?;
        let c = self.ctr;
        let mut buf = Zeroizing::new(self.cache.to_vec());
        let tag = self.cipher().encrypt_in_place_detached(&nonce(c), &aad(idx, c), &mut buf).map_err(|_| ioerr("암호화"))?;
        let f = self.file()?;
        f.seek(SeekFrom::Start(idx * SLOT))?;
        f.write_all(&c.to_le_bytes())?;
        f.write_all(&buf)?;
        f.write_all(&tag)?;
        let i = idx as usize;
        if self.expect.len() <= i {
            self.expect.resize(i + 1, 0);
        }
        self.expect[i] = c;
        self.dirty = false;
        Ok(())
    }

    /// Loads block `idx` into the cache. `for_write`: a block never written may start as zeros.
    fn load(&mut self, idx: u64, for_write: bool) -> io::Result<()> {
        if self.cidx == Some(idx) {
            return Ok(());
        }
        self.flush_cache()?;
        self.cache.fill(0);
        let want = self.expect.get(idx as usize).copied().unwrap_or(0);
        if want != 0 {
            let off = idx * SLOT;
            let f = self.file()?;
            if f.metadata()?.len() < off + SLOT {
                return Err(ioerr("임시 파일이 잘렸습니다"));
            }
            let mut raw = Zeroizing::new(vec![0u8; SLOT as usize]);
            f.seek(SeekFrom::Start(off))?;
            f.read_exact(&mut raw)?;
            let c = u64::from_le_bytes(raw[..8].try_into().unwrap());
            if c != want {
                return Err(ioerr("블록 카운터 불일치 (교체/재생 의심)"));
            }
            let (body, tag) = raw[8..].split_at_mut(BLK);
            self.cipher()
                .decrypt_in_place_detached(&nonce(c), &aad(idx, c), body, &Tag::clone_from_slice(tag))
                .map_err(|_| ioerr("블록 인증 실패"))?;
            self.cache.copy_from_slice(body);
        } else if !for_write && idx * (BLK as u64) < self.size {
            return Err(ioerr("기록되지 않은 블록(구멍)을 읽으려 했습니다"));
        }
        self.cidx = Some(idx);
        self.dirty = false;
        Ok(())
    }

    /// Crypto-erase + delete. Returns an error when the file could not be removed.
    pub fn destroy(mut self) -> io::Result<()> {
        self.wipe()
    }

    fn wipe(&mut self) -> io::Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        (*self.key).zeroize();
        unlock_mem(self.key.as_ptr(), 32);
        self.cache.zeroize();
        if let Some(f) = self.f.take() {
            let _ = f.set_len(0);
            drop(f);
        }
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(x) if x.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(x) => Err(io::Error::new(
                x.kind(),
                format!("임시 파일 삭제 실패: {} ({x}) — 내용은 키가 파기되어 읽을 수 없지만 직접 삭제하세요.", self.path.display()),
            )),
        }
    }
}

impl Write for SecTemp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, crate::progress::CANCELLED));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / BLK as u64;
        let off = (self.pos % BLK as u64) as usize;
        self.load(idx, true)?;
        let n = (BLK - off).min(buf.len());
        self.cache[off..off + n].copy_from_slice(&buf[..n]);
        self.dirty = true;
        self.pos += n as u64;
        self.size = self.size.max(self.pos);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_cache()?;
        self.file()?.flush()
    }
}

impl Read for SecTemp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / BLK as u64;
        let off = (self.pos % BLK as u64) as usize;
        self.load(idx, false)?;
        let n = (BLK - off).min(buf.len()).min((self.size - self.pos) as usize);
        buf[..n].copy_from_slice(&self.cache[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SecTemp {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let np: i128 = match p {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
        };
        if !(0..=(1i128 << 60)).contains(&np) {
            return Err(ioerr("잘못된 위치"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

impl Drop for SecTemp {
    fn drop(&mut self) {
        let _ = self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> (SecTemp, Vec<u8>) {
        let mut t = SecTemp::create(&std::env::temp_dir()).unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        t.write_all(&data).unwrap();
        t.flush().unwrap();
        (t, data)
    }

    fn raw(t: &SecTemp) -> File {
        OpenOptions::new().read(true).write(true).open(&t.path).unwrap()
    }

    #[test]
    fn random_access_roundtrip() {
        let (mut t, data) = filled();
        t.seek(SeekFrom::Start(70_000)).unwrap();
        t.write_all(&[9u8; 10]).unwrap();
        t.seek(SeekFrom::Start(0)).unwrap();
        let mut out = Vec::new();
        t.read_to_end(&mut out).unwrap();
        let mut exp = data.clone();
        exp[70_000..70_010].fill(9);
        assert_eq!(out, exp);
        assert_eq!(t.len(), 200_000);
        t.destroy().unwrap();
    }

    #[test]
    fn swapped_blocks_are_rejected() {
        let (mut t, _) = filled();
        let mut f = raw(&t);
        let mut a = vec![0u8; SLOT as usize];
        let mut b = vec![0u8; SLOT as usize];
        f.read_exact(&mut a).unwrap();
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&b).unwrap();
        f.write_all(&a).unwrap();
        drop(f);
        t.cidx = None;
        t.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 16];
        assert!(t.read(&mut buf).is_err());
    }

    #[test]
    fn replayed_old_block_is_rejected() {
        let (mut t, _) = filled();
        let mut old = vec![0u8; SLOT as usize];
        raw(&t).read_exact(&mut old).unwrap();
        t.seek(SeekFrom::Start(5)).unwrap();
        t.write_all(b"new").unwrap();
        t.flush().unwrap();
        let mut f = raw(&t);
        f.write_all(&old).unwrap(); // restore the previous, validly sealed version
        drop(f);
        t.cidx = None;
        t.seek(SeekFrom::Start(0)).unwrap();
        assert!(t.read(&mut [0u8; 8]).is_err());
    }

    #[test]
    fn truncation_and_holes_are_errors() {
        let (mut t, _) = filled();
        raw(&t).set_len(SLOT).unwrap();
        t.cidx = None;
        t.seek(SeekFrom::Start(BLK as u64 * 2)).unwrap();
        assert!(t.read(&mut [0u8; 8]).is_err(), "truncated");

        let mut h = SecTemp::create(&std::env::temp_dir()).unwrap();
        h.write_all(b"x").unwrap();
        h.seek(SeekFrom::Start(BLK as u64 * 3)).unwrap();
        h.write_all(b"y").unwrap();
        h.flush().unwrap();
        h.seek(SeekFrom::Start(BLK as u64 + 10)).unwrap();
        assert!(h.read(&mut [0u8; 4]).is_err(), "hole");
        h.seek(SeekFrom::Start(0)).unwrap();
        let mut one = [0u8; 1];
        h.read_exact(&mut one).unwrap();
        assert_eq!(&one, b"x");
    }

    #[test]
    fn destroy_reports_and_removes() {
        let (t, _) = filled();
        let p = t.path.clone();
        t.destroy().unwrap();
        assert!(!p.exists());
    }

    /// Another program holding the file without delete sharing: destroy must report it, not hide it.
    #[cfg(windows)]
    #[test]
    fn destroy_reports_delete_failure() {
        use std::os::windows::fs::OpenOptionsExt;
        let (t, _) = filled();
        let p = t.path.clone();
        let blocker = OpenOptions::new().read(true).share_mode(0x1 | 0x2).open(&p).unwrap(); // READ|WRITE, no DELETE
        let err = t.destroy().unwrap_err().to_string();
        assert!(err.contains("임시 파일 삭제 실패"), "{err}");
        assert_eq!(fs::metadata(&p).unwrap().len(), 0, "content truncated even when delete fails");
        drop(blocker);
        fs::remove_file(&p).unwrap();
    }
}
