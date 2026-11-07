//! Key operations on an existing container: password change (slot re-wrap, old slot destroyed with
//! KEY_PASSES) and full key replacement (re-encryption under a new DEK; the old container's data
//! is overwritten with the chosen passes after the atomic swap, its key area always 7 times).

use crate::archive;
use crate::crypto::{encrypt_stream, make_slot, open_slot, read_header, stream_body};
use crate::engine::{parent_dir, PartGuard};
use crate::entropy::rand_hex;
use crate::format::*;
use crate::i18n::{t, tf};
use crate::lock::{lock_container, Mode};
use crate::progress::*;
use crate::sectemp::SecTemp;
use crate::sysinfo;
use crate::wipe::{Passes, KEY_PASSES};
use crate::crypto::Cred;
use sha3::{Digest, Sha3_512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Seek, SeekFrom, Write},
    path::Path,
};

/// Re-wraps the file key under new credentials; the data is not touched (instant for any size).
///
/// 1. unwrap DEK with old creds
/// 2. write the new wrapped DEK into the spare slot, fsync
/// 3. re-read, verify the new creds open it AND yield the same DEK
/// 4. overwrite the old slot with KEY_PASSES (7, whatever the chosen pass count: it is key
///    material)
///
/// A crash at any point leaves at least one valid slot.
pub fn do_change_password(path: &Path, old: &Cred, new: &Cred) -> R<String> {
    set_stage(ST_REWRAP);
    crate::crypto::kdf_params(new.pim)?;
    if new.is_empty() {
        return Err(t("eng.need_new").into());
    }
    let _lock = lock_container(path, Mode::Exclusive)?; // held until the old slot is destroyed
    let mut f = OpenOptions::new().read(true).write(true).open(path).map_err(e)?;
    let h = read_header(&mut f, old)?;
    let spare = 1 - h.slot_idx;
    let new_slot = make_slot(new, &h.dek)?;
    f.seek(SeekFrom::Start((spare * SLOT) as u64)).map_err(e)?;
    f.write_all(&new_slot).map_err(e)?;
    f.sync_all().map_err(e)?;

    let mut head2 = [0u8; SLOTS];
    f.seek(SeekFrom::Start(0)).map_err(e)?;
    io::Read::read_exact(&mut f, &mut head2).map_err(e)?;
    let fail = || t("eng.new_key_failed").to_string();
    let k2 = open_slot(new, &head2[spare * SLOT..(spare + 1) * SLOT])?.ok_or_else(fail)?;
    if !crate::password::ct_eq(&k2[..], &h.dek[..]) {
        return Err(fail());
    }
    // point of no return: not cancellable
    let mut rng = crate::entropy::bulk_rng()?;
    for p in KEY_PASSES.patterns() {
        let mut b = [0u8; SLOT];
        match p {
            Some(v) => b.fill(*v),
            None => rand::RngCore::fill_bytes(&mut rng, &mut b),
        }
        f.seek(SeekFrom::Start((h.slot_idx * SLOT) as u64)).map_err(e)?;
        f.write_all(&b).map_err(e)?;
        f.sync_all().map_err(e)?;
    }
    Ok(t("eng.pw_changed").into())
}

/// Writer that hashes everything going through it (SHA3-512).
struct HashWriter<W> {
    w: W,
    h: Sha3_512,
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.w.write(b)?;
        self.h.update(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn stamp(p: &Path) -> R<(u64, Option<std::time::SystemTime>)> {
    let m = fs::metadata(p).map_err(e)?;
    Ok((m.len(), m.modified().ok()))
}

/// Full key replacement: a new DEK, salts, nonce prefix and padding; the whole body is re-encrypted
/// (optionally under new credentials) and verified before the original is atomically replaced.
/// The old file's contents are then overwritten (`passes`; its key area KEY_PASSES) and deleted.
pub fn do_full_rekey(path: &Path, old: &Cred, new: &Cred, passes: Passes) -> R<String> {
    if new.is_empty() {
        return Err(t("eng.need_new").into());
    }
    let _lock = lock_container(path, Mode::Exclusive)?; // held through the final rename
    let before = stamp(path)?;
    let dir = parent_dir(path);
    set_stage(ST_DECRYPT);
    let mut f = File::open(path).map_err(e)?;
    let h = read_header(&mut f, old)?;
    sysinfo::require_space(&dir, h.meta.real_len.saturating_mul(2).saturating_add(64 << 20), t("eng.space_rekey"))?;
    let st = SecTemp::create(&dir).map_err(e)?;
    let mut hw = HashWriter { w: st, h: Sha3_512::new() };
    stream_body(&mut f, &h, &mut hw)?;
    drop(f);
    let want: [u8; 64] = hw.h.finalize().into();
    let mut st = hw.w;
    st.flush().map_err(e)?;
    let len = st.len();
    archive::inspect(&mut st, len)?;
    st.seek(SeekFrom::Start(0)).map_err(e)?;

    set_stage(ST_ENCRYPT);
    let part = PartGuard::new(dir.join(format!(".shd_{}.part", rand_hex()?)));
    let out = OpenOptions::new().write(true).create_new(true).open(&part.path).map_err(e)?;
    let mut w = BufWriter::with_capacity(1 << 20, out);
    let mut meta = h.meta.clone();
    let nh = encrypt_stream(&mut st, &mut w, new, &mut meta)?;
    w.into_inner().map_err(|x| e(x.into_error()))?.sync_all().map_err(e)?;
    let warn = st.destroy().err().map(|x| x.to_string());

    set_stage(ST_VERIFY);
    let mut g = File::open(&part.path).map_err(e)?;
    let vh = read_header(&mut g, new).map_err(|x| tf("eng.rekey_verify", &[&x]))?;
    if !crate::password::ct_eq(&vh.dek[..], &nh.dek[..]) {
        return Err(tf("eng.rekey_verify", &[&t("eng.key_differs")]));
    }
    let mut hw2 = HashWriter { w: io::sink(), h: Sha3_512::new() };
    stream_body(&mut g, &vh, &mut hw2)?;
    let got: [u8; 64] = hw2.h.finalize().into();
    if !crate::password::ct_eq(&got, &want) {
        return Err(tf("eng.rekey_verify", &[&t("eng.content_differs")]));
    }
    drop(g);
    if stamp(path)? != before {
        return Err(t("eng.changed_meanwhile").into());
    }
    set_stage(ST_REPLACE);
    let shred_warn = crate::wipe::replace_and_shred(&part.path, path, passes)?;
    part.keep();
    let mut msg = tf("eng.rekey_done_passes", &[&passes.count()]);
    for w in [warn, shred_warn].into_iter().flatten() {
        msg += &format!(" · {w}");
    }
    msg += &crate::wipe::trim_after_shred(&[path]);
    Ok(msg)
}

