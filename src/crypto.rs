//! Key derivation, key slots, the authenticated chunk stream and the random-access ChunkReader.
//! Plaintext is only produced from a chunk after that chunk's tag verified (PCC-004); the
//! extraction paths additionally authenticate the whole body first (into SecTemp).

use crate::entropy::{fill_random, rand_upto};
use crate::format::*;
use crate::harden::{lock_large, lock_mem, unlock_large, unlock_mem};
use crate::progress::*;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
};
use zeroize::Zeroizing;

/// Credentials. `pw` is already NFC-normalized (see password::normalize).
pub struct Cred {
    pub pw: Zeroizing<Vec<u8>>,
    pub kf: Option<Zeroizing<[u8; 64]>>,
    pub pim: u32,
}

impl Cred {
    pub fn duplicate(&self) -> Cred {
        Cred { pw: self.pw.clone(), kf: self.kf.clone(), pim: self.pim }
    }
    pub fn is_empty(&self) -> bool {
        self.pw.is_empty() && self.kf.is_none()
    }
}

/// Validates the KDF parameters before any work (they are needed before authentication).
pub fn kdf_params(pim: u32) -> R<Params> {
    if pim > MAX_PIM {
        return Err(format!("PIM은 0~{MAX_PIM} 범위여야 합니다."));
    }
    let p = Params::new(KDF_MEM_KIB, BASE_T + pim, KDF_LANES, Some(KEY)).map_err(e)?;
    if p.m_cost() != KDF_MEM_KIB || p.p_cost() != KDF_LANES || p.t_cost() != BASE_T + pim || p.output_len() != Some(KEY) {
        return Err("KDF 매개변수 검증 실패".into());
    }
    Ok(p)
}

/// KEK = Argon2id(password, salt, secret = key file digest). The 256 MiB work memory is supplied by
/// us so it can be locked in RAM (best effort) and is zeroized right after use.
fn kek(c: &Cred, salt: &[u8]) -> R<XChaCha20Poly1305> {
    if c.is_empty() {
        return Err("비밀번호 또는 키 파일이 필요합니다.".into());
    }
    let params = kdf_params(c.pim)?;
    let _busy = KdfGuard::new();
    let secret: &[u8] = c.kf.as_ref().map(|k| &k[..]).unwrap_or(&[]);
    let a = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params.clone()).map_err(e)?;
    let mut mem: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    mem.try_reserve_exact(params.block_count())
        .map_err(|_| "메모리가 부족해 키를 유도할 수 없습니다 (Argon2id 256 MiB 필요).".to_string())?;
    mem.resize(params.block_count(), Block::default());
    let bytes = mem.len() * core::mem::size_of::<Block>();
    let locked = lock_large(mem.as_ptr() as *const u8, bytes);
    let mut out = Zeroizing::new([0u8; KEY]);
    lock_mem(out.as_ptr(), KEY);
    let r = a.hash_password_into_with_memory(&c.pw, salt, &mut *out, &mut mem[..]);
    // zeroize while still locked, then unlock, then free
    mem.iter_mut().for_each(zeroize::Zeroize::zeroize);
    unlock_large(mem.as_ptr() as *const u8, bytes, locked);
    drop(mem);
    r.map_err(e)?;
    let k = XChaCha20Poly1305::new_from_slice(&*out).map_err(e);
    unlock_mem(out.as_ptr(), KEY);
    k
}

pub fn make_slot(c: &Cred, dek: &[u8; KEY]) -> R<[u8; SLOT]> {
    let mut slot = [0u8; SLOT];
    fill_random(&mut slot[..SALT + XNONCE])?;
    let k = kek(c, &slot[..SALT])?;
    let mut buf = Zeroizing::new([0u8; KEY]);
    buf.copy_from_slice(dek);
    let n = XNonce::clone_from_slice(&slot[SALT..SALT + XNONCE]);
    let tag = k.encrypt_in_place_detached(&n, SLOT_AAD, &mut buf[..]).map_err(e)?;
    slot[SALT + XNONCE..SALT + XNONCE + KEY].copy_from_slice(&buf[..]);
    slot[SALT + XNONCE + KEY..].copy_from_slice(&tag);
    Ok(slot)
}

pub fn open_slot(c: &Cred, slot: &[u8]) -> R<Option<Zeroizing<[u8; KEY]>>> {
    if slot.len() != SLOT {
        return Ok(None);
    }
    let k = kek(c, &slot[..SALT])?;
    let mut d = Zeroizing::new([0u8; KEY]);
    d.copy_from_slice(&slot[SALT + XNONCE..SALT + XNONCE + KEY]);
    let n = XNonce::clone_from_slice(&slot[SALT..SALT + XNONCE]);
    let tag = Tag::clone_from_slice(&slot[SALT + XNONCE + KEY..]);
    Ok(k.decrypt_in_place_detached(&n, SLOT_AAD, &mut d[..], &tag).ok().map(|_| d))
}

/// Tries both slots. Returns (slot index, DEK).
fn unlock(c: &Cred, slots: &[u8]) -> R<(usize, Zeroizing<[u8; KEY]>)> {
    kdf_params(c.pim)?;
    for i in 0..2 {
        check_cancel()?;
        if let Some(k) = open_slot(c, &slots[i * SLOT..(i + 1) * SLOT])? {
            return Ok((i, k));
        }
    }
    Err(BAD.into())
}

/// Everything learned from an authenticated header.
pub struct Header {
    pub slot_idx: usize,
    pub dek: Zeroizing<[u8; KEY]>,
    pub prefix: [u8; PREFIX],
    pub meta_tag: [u8; TAG],
    pub meta: Meta,
    pub file_len: u64,
}

impl Header {
    pub fn cipher(&self) -> DataCipher {
        DataCipher::new(&self.dek, self.prefix, &self.meta_tag, self.meta.padded_len)
    }
    pub fn n_chunks(&self) -> u64 {
        chunk_count(self.meta.padded_len)
    }
}

/// Reads slots + meta, authenticates, validates the meta and the exact file size.
pub fn read_header(f: &mut File, c: &Cred) -> R<Header> {
    let file_len = f.metadata().map_err(e)?.len();
    if file_len < (HEADER + TAG + 1) as u64 {
        return Err(BAD.into());
    }
    let mut head = Zeroizing::new(vec![0u8; HEADER]);
    f.seek(SeekFrom::Start(0)).map_err(e)?;
    f.read_exact(&mut head).map_err(|_| BAD.to_string())?;
    let (slot_idx, dek) = unlock(c, &head[..SLOTS])?;
    let mut prefix = [0u8; PREFIX];
    prefix.copy_from_slice(&head[SLOTS..SLOTS + PREFIX]);
    let mc = &head[SLOTS + PREFIX..HEADER];
    let mut meta_tag = [0u8; TAG];
    meta_tag.copy_from_slice(&mc[META_PT..]);
    let mut mp = Zeroizing::new([0u8; META_PT]);
    mp.copy_from_slice(&mc[..META_PT]);
    let ci = XChaCha20Poly1305::new_from_slice(&dek[..]).map_err(e)?;
    ci.decrypt_in_place_detached(
        &XNonce::from(nonce(&prefix, NONCE_META, 0)),
        &meta_aad(&prefix),
        &mut mp[..],
        &Tag::clone_from_slice(&meta_tag),
    )
    .map_err(|_| BAD.to_string())?;
    let meta = decode_meta(&mp[..])?; // authentic from here on: errors are "unsupported"
    if expected_size(meta.padded_len) != Some(file_len) {
        return Err(SIZE_MISMATCH.into());
    }
    Ok(Header { slot_idx, dek, prefix, meta_tag, meta, file_len })
}

/// Chunk sealing/opening for one file.
pub struct DataCipher {
    aead: XChaCha20Poly1305,
    prefix: [u8; PREFIX],
    aad: Vec<u8>,
    n: u64,
}

impl DataCipher {
    pub fn new(dek: &[u8; KEY], prefix: [u8; PREFIX], meta_tag: &[u8; TAG], padded_len: u64) -> Self {
        DataCipher {
            aead: XChaCha20Poly1305::new(dek.into()),
            prefix,
            aad: data_aad(meta_tag),
            n: chunk_count(padded_len),
        }
    }
    fn nonce(&self, i: u64) -> XNonce {
        let flag = if i + 1 == self.n { NONCE_LAST } else { NONCE_DATA };
        XNonce::from(nonce(&self.prefix, flag, i + 1))
    }
    /// Encrypts `buf` in place and returns the tag.
    pub fn seal(&self, i: u64, buf: &mut [u8]) -> R<Tag> {
        self.aead.encrypt_in_place_detached(&self.nonce(i), &self.aad, buf).map_err(e)
    }
    /// Verifies and decrypts in place; on failure the buffer is zeroed (no unauthenticated output).
    pub fn open(&self, i: u64, buf: &mut [u8], tag: &[u8]) -> R<()> {
        if i >= self.n || tag.len() != TAG {
            return Err(BAD.into());
        }
        self.aead
            .decrypt_in_place_detached(&self.nonce(i), &self.aad, buf, &Tag::clone_from_slice(tag))
            .map_err(|_| {
                buf.iter_mut().for_each(|b| *b = 0);
                BAD.to_string()
            })
    }
}

/// Encrypts exactly `meta.real_len` bytes from `inp` (+ random padding) into `out`.
/// Fills in `meta.padded_len`. Returns the header values of the new file (no KDF needed to reopen).
pub fn encrypt_stream<Rd: Read, W: Write>(inp: &mut Rd, out: &mut W, c: &Cred, meta: &mut Meta) -> R<Header> {
    if meta.real_len == 0 {
        return Err("내부 오류: 빈 입력".into());
    }
    let mut dek = Zeroizing::new([0u8; KEY]);
    fill_random(&mut dek[..])?;
    let mut prefix = [0u8; PREFIX];
    fill_random(&mut prefix)?;
    let pad = rand_upto(pad_max(meta.real_len))?;
    meta.padded_len = meta.real_len.checked_add(pad).ok_or("크기 오류")?;
    let mut which = [0u8; 1];
    fill_random(&mut which)?;
    let real = (which[0] & 1) as usize;
    let mut slots = [0u8; SLOTS];
    fill_random(&mut slots)?;
    let s = make_slot(c, &dek)?;
    slots[real * SLOT..(real + 1) * SLOT].copy_from_slice(&s);

    let ci = XChaCha20Poly1305::new_from_slice(&dek[..]).map_err(e)?;
    let mut mp = encode_meta(meta);
    let mtag = ci
        .encrypt_in_place_detached(&XNonce::from(nonce(&prefix, NONCE_META, 0)), &meta_aad(&prefix), &mut mp[..])
        .map_err(e)?;
    let mut meta_tag = [0u8; TAG];
    meta_tag.copy_from_slice(&mtag);
    out.write_all(&slots).map_err(e)?;
    out.write_all(&prefix).map_err(e)?;
    out.write_all(&mp[..]).map_err(e)?;
    out.write_all(&meta_tag).map_err(e)?;

    let dc = DataCipher::new(&dek, prefix, &meta_tag, meta.padded_len);
    let n = chunk_count(meta.padded_len);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut left_real = meta.real_len;
    progress_start(meta.padded_len);
    for i in 0..n {
        check_cancel()?;
        let sz = (meta.padded_len - i * CHUNK as u64).min(CHUNK as u64) as usize;
        let take = left_real.min(sz as u64) as usize;
        inp.read_exact(&mut buf[..take]).map_err(|x| format!("입력 읽기 실패: {x}"))?;
        buf[take..sz].fill(0);
        left_real -= take as u64;
        let tag = dc.seal(i, &mut buf[..sz])?;
        out.write_all(&buf[..sz]).map_err(e)?;
        out.write_all(&tag).map_err(e)?;
        progress_add(sz as u64);
    }
    out.flush().map_err(e)?;
    Ok(Header { slot_idx: real, dek, prefix, meta_tag, meta: meta.clone(), file_len: expected_size(meta.padded_len).unwrap_or(0) })
}

/// Authenticates every chunk (including the padding) in order and writes the first `real_len`
/// plaintext bytes to `out`. Each chunk is written only after its own tag verified.
pub fn stream_body<W: Write>(f: &mut File, h: &Header, out: &mut W) -> R<()> {
    f.seek(SeekFrom::Start(HEADER as u64)).map_err(e)?;
    let mut r = BufReader::with_capacity(1 << 20, &mut *f);
    let dc = h.cipher();
    let n = h.n_chunks();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK + TAG]);
    let mut left = h.meta.real_len;
    progress_start(h.meta.padded_len);
    for i in 0..n {
        check_cancel()?;
        let sz = (h.meta.padded_len - i * CHUNK as u64).min(CHUNK as u64) as usize;
        r.read_exact(&mut buf[..sz + TAG]).map_err(|_| BAD.to_string())?;
        let (body, tag) = buf[..sz + TAG].split_at_mut(sz);
        dc.open(i, body, tag)?;
        let take = left.min(sz as u64) as usize;
        if body[take..].iter().any(|&b| b != 0) {
            return Err(BAD.into()); // padding must be zeros
        }
        out.write_all(&body[..take]).map_err(e)?;
        left -= take as u64;
        progress_add(sz as u64);
    }
    let mut extra = [0u8; 1];
    if r.read(&mut extra).map_err(e)? != 0 {
        return Err(SIZE_MISMATCH.into());
    }
    out.flush().map_err(e)
}

/// Read + Seek view of the plaintext (0..real_len). Each chunk is authenticated when loaded; a few
/// decrypted chunks are cached in zeroizing buffers, nothing is written to disk.
pub struct ChunkReader {
    f: File,
    dc: DataCipher,
    real_len: u64,
    padded_len: u64,
    pos: u64,
    cache: Vec<(u64, Zeroizing<Vec<u8>>)>,
}

const CACHE: usize = 4;

impl ChunkReader {
    pub fn new(f: File, h: &Header) -> Self {
        ChunkReader { f, dc: h.cipher(), real_len: h.meta.real_len, padded_len: h.meta.padded_len, pos: 0, cache: Vec::new() }
    }
    fn chunk(&mut self, i: u64) -> io::Result<usize> {
        if let Some(k) = self.cache.iter().position(|(x, _)| *x == i) {
            return Ok(k);
        }
        let sz = (self.padded_len - i * CHUNK as u64).min(CHUNK as u64) as usize;
        let mut buf = Zeroizing::new(vec![0u8; sz + TAG]);
        self.f.seek(SeekFrom::Start(HEADER as u64 + i * (CHUNK + TAG) as u64))?;
        self.f.read_exact(&mut buf)?;
        let (body, tag) = buf.split_at_mut(sz);
        self.dc.open(i, body, tag).map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?;
        buf.truncate(sz);
        if self.cache.len() >= CACHE {
            self.cache.remove(0);
        }
        self.cache.push((i, buf));
        Ok(self.cache.len() - 1)
    }
}

impl Read for ChunkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.real_len || out.is_empty() {
            return Ok(0);
        }
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, CANCELLED));
        }
        let i = self.pos / CHUNK as u64;
        let off = (self.pos % CHUNK as u64) as usize;
        let k = self.chunk(i)?;
        let data = &self.cache[k].1;
        let n = (data.len() - off).min(out.len()).min((self.real_len - self.pos) as usize);
        out[..n].copy_from_slice(&data[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ChunkReader {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let np = match p {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
            SeekFrom::End(d) => self.real_len as i128 + d as i128,
        };
        if np < 0 || np > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}
