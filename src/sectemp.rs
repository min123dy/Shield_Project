//! Encrypted scratch file with random access (Read + Write + Seek).
//! The 7z archive is built/read through this, so plaintext archives never touch the disk.
//! Blocks of 64 KiB are sealed with ChaCha20-Poly1305 under an ephemeral key that exists only in
//! RAM. Every block write uses a fresh counter nonce (no nonce reuse). Dropping the object zeroizes
//! the key ("crypto-erase": the leftover ciphertext, even if the SSD keeps it, is unreadable)
//! and deletes the file.

use crate::entropy::fill_random;
use crate::progress::cancelled;
use crate::harden::{lock_mem, unlock_mem};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
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

pub struct SecTemp {
    f: File,
    path: PathBuf,
    key: Box<[u8; 32]>,
    ctr: u64,
    size: u64,
    pos: u64,
    cache: Zeroizing<Vec<u8>>,
    cidx: Option<u64>,
    dirty: bool,
}

fn ioerr(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

fn nonce(c: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&c.to_be_bytes());
    *Nonce::from_slice(&n)
}

impl SecTemp {
    pub fn create(dir: &Path) -> io::Result<Self> {
        let mut r = [0u8; 8];
        fill_random(&mut r);
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!(".shd_{hex}.tmp"));
        let f = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mut key = Box::new([0u8; 32]);
        fill_random(&mut *key);
        lock_mem(key.as_ptr(), 32);
        Ok(Self {
            f,
            path,
            key,
            ctr: 0,
            size: 0,
            pos: 0,
            cache: Zeroizing::new(vec![0u8; BLK]),
            cidx: None,
            dirty: false,
        })
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key[..]))
    }

    fn flush_cache(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let idx = self.cidx.ok_or_else(|| ioerr("no block"))?;
        self.ctr += 1;
        let c = self.ctr;
        let ct = self
            .cipher()
            .encrypt(&nonce(c), self.cache.as_slice())
            .map_err(|_| ioerr("encrypt"))?;
        self.f.seek(SeekFrom::Start(idx * SLOT))?;
        self.f.write_all(&c.to_le_bytes())?;
        self.f.write_all(&ct)?;
        self.dirty = false;
        Ok(())
    }

    fn load(&mut self, idx: u64) -> io::Result<()> {
        if self.cidx == Some(idx) {
            return Ok(());
        }
        self.flush_cache()?;
        self.cache.fill(0);
        let off = idx * SLOT;
        if off + SLOT <= self.f.metadata()?.len() {
            let mut raw = Zeroizing::new(vec![0u8; SLOT as usize]);
            self.f.seek(SeekFrom::Start(off))?;
            self.f.read_exact(&mut raw)?;
            let c = u64::from_le_bytes(raw[..8].try_into().unwrap());
            if c != 0 {
                let pt = Zeroizing::new(
                    self.cipher().decrypt(&nonce(c), &raw[8..]).map_err(|_| ioerr("temp auth"))?,
                );
                self.cache.copy_from_slice(&pt);
            } // counter 0 = never written (sparse hole) -> zeros
        }
        self.cidx = Some(idx);
        self.dirty = false;
        Ok(())
    }
}

impl Write for SecTemp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / BLK as u64;
        let off = (self.pos % BLK as u64) as usize;
        self.load(idx)?;
        let n = (BLK - off).min(buf.len());
        self.cache[off..off + n].copy_from_slice(&buf[..n]);
        self.dirty = true;
        self.pos += n as u64;
        self.size = self.size.max(self.pos);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_cache()?;
        self.f.flush()
    }
}

impl Read for SecTemp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / BLK as u64;
        let off = (self.pos % BLK as u64) as usize;
        self.load(idx)?;
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
        if np < 0 {
            return Err(ioerr("negative seek"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

impl Drop for SecTemp {
    fn drop(&mut self) {
        (*self.key).zeroize(); // crypto-erase first
        unlock_mem(self.key.as_ptr(), 32);
        let _ = self.f.set_len(0);
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_access_roundtrip() {
        let dir = std::env::temp_dir();
        let mut t = SecTemp::create(&dir).unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        t.write_all(&data).unwrap();
        t.seek(SeekFrom::Start(70_000)).unwrap();
        t.write_all(&[9u8; 10]).unwrap(); // overwrite inside an already written block
        t.seek(SeekFrom::Start(0)).unwrap();
        let mut out = Vec::new();
        t.read_to_end(&mut out).unwrap();
        let mut exp = data.clone();
        exp[70_000..70_010].fill(9);
        assert_eq!(out, exp);
        assert_eq!(t.len(), 200_000);
    }
}
