//! High-level operations: encrypt (with full restore verification before any shredding), decrypt,
//! password change (slot re-wrap) and full key replacement (re-encryption under a new DEK).
//! File format: see format.rs. Low-level crypto: crypto.rs.

use crate::archive;
use crate::compress::{self, Strength};
use crate::crypto::{encrypt_stream, make_slot, open_slot, read_header, stream_body, ChunkReader, Cred, Header};
use crate::entropy::rand_hex;
use crate::format::*;
use crate::i18n::{t, tf};
use crate::lock::{lock_container, Mode};
use crate::manifest::{compare, shred_listed, Digests, Manifest};
use std::collections::BTreeSet;
use crate::progress::*;
use crate::sectemp::SecTemp;
use crate::staging::Stage;
use crate::sysinfo::{self, rename_noreplace, rename_replace};
use crate::ui_fmt::human;
use crate::wipe::{detect_disk, drive_letter, trim_volume, wipe_free_space, Disk, PATTERNS};
use sha3::{Digest, Sha3_512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub use crate::format::DEFAULT_PIM;

/// Minimum password length for new credentials. Below the default PIM the KDF is cheaper per guess,
/// so a longer password is required (same idea as VeraCrypt's rule for small PIMs).
pub fn min_password_len(pim: u32, has_keyfile: bool) -> usize {
    match (has_keyfile, pim >= DEFAULT_PIM) {
        (true, _) => 0,
        (false, true) => 12,
        (false, false) => 20,
    }
}

pub struct Opts {
    pub shred_src: bool,
    pub force7: bool,
    pub trim_after: bool,
    pub wipe_free_after: bool,
    pub strength: Strength,
    /// Key file paths (only for the overlap check; the digest is in `Cred`).
    pub keyfiles: Vec<PathBuf>,
    /// What to do with alternate data streams of files that will be shredded (B-9).
    pub streams: StreamPolicy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamPolicy {
    /// Stop with `C_ADS` when a file to be shredded has streams other than Zone.Identifier
    /// (the UI then asks; Zone.Identifier-only files are overwritten with a short note).
    Ask,
    /// The user chose to overwrite every stream before the files are deleted.
    Include,
}

pub const C_ADS: &str = "E_ADS";

/// Decryption options.
#[derive(Clone, Copy, Default)]
pub struct DecOpts {
    /// Settings > Security > strict Mark of the Web: failing to copy it is an error.
    pub strict_motw: bool,
}

/// Removes a temporary output file unless `keep` was called (errors, cancel, panic).
pub struct PartGuard {
    pub path: PathBuf,
    keep: bool,
}
impl PartGuard {
    pub fn keep(mut self) {
        self.keep = true;
    }
}
impl Drop for PartGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn parent_dir(p: &Path) -> PathBuf {
    p.parent().filter(|x| !x.as_os_str().is_empty()).unwrap_or_else(|| Path::new(".")).to_path_buf()
}

fn comp_desc(m: &Meta) -> String {
    let base = match m.comp_method {
        COMP_LZMA2 => tf("eng.lzma2_desc", &[&m.comp_level, &human(m.comp_dict as u64)]),
        COMP_ZSTD => tf("eng.zstd_desc", &[&m.comp_level]),
        _ => comp_name(m.comp_method).to_string(),
    };
    if m.flags & FLAG_SOME_STORED != 0 {
        base + t("eng.some_stored")
    } else {
        base
    }
}

/// Records the compression choice in the meta block.
pub fn set_comp(meta: &mut Meta, plan: &compress::Plan, stored: u64) {
    meta.comp_method = plan.method;
    meta.comp_level = plan.level as u8;
    meta.comp_dict = plan.dict;
    if stored > 0 {
        meta.flags |= FLAG_SOME_STORED;
    }
}

/// Encrypts a finished 7z archive held in SecTemp into a new `.part` file in `outdir`, then
/// destroys the SecTemp. Returns the new header, the part guard and a SecTemp-deletion warning.
pub fn seal_archive(mut st: SecTemp, outdir: &Path, c: &Cred, mut meta: Meta) -> R<(Header, PartGuard, Option<String>)> {
    st.flush().map_err(e)?;
    meta.real_len = st.len();
    st.seek(SeekFrom::Start(0)).map_err(e)?;
    set_stage(ST_ENCRYPT);
    let part = PartGuard { path: outdir.join(format!(".shd_{}.part", rand_hex()?)), keep: false };
    let f = OpenOptions::new().write(true).create_new(true).open(&part.path).map_err(e)?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    let h = encrypt_stream(&mut st, &mut w, c, &mut meta)?;
    let f = w.into_inner().map_err(|x| e(x.into_error()))?;
    f.sync_all().map_err(e)?;
    drop(f);
    let warn = st.destroy().err().map(|x| x.to_string());
    Ok((h, part, warn))
}

/// Re-opens the new file with the credentials (proves the key slot works), authenticates every
/// chunk, then decompresses everything and compares paths, sizes and SHA3-512 with `want`.
pub fn verify_container(part: &Path, built: &Header, c: &Cred, want: &Digests, want_dirs: &BTreeSet<String>, total: u64) -> R<()> {
    set_stage(ST_VERIFY);
    let fail = |w: &str| tf("eng.verify_failed", &[&w]);
    let mut f = File::open(part).map_err(e)?;
    let h = read_header(&mut f, c).map_err(|x| fail(&x))?;
    if !crate::password::ct_eq(&h.dek[..], &built.dek[..]) || h.meta != built.meta {
        return Err(fail(t("eng.key_differs")));
    }
    stream_body(&mut f, &h, &mut io::sink()).map_err(|x| fail(&x))?;
    let mut cr = ChunkReader::new(f, &h);
    archive::inspect(&mut cr, h.meta.real_len).map_err(|x| fail(&x))?;
    progress_start(total);
    let (files, dirs) = archive::digests(&mut cr).map_err(|x| fail(&x))?;
    compare(want, want_dirs, &files, &dirs)
}

fn check_paths(src: &Path, dst: &Path, keyfiles: &[PathBuf]) -> R<()> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(t("eng.out_exists").into());
    }
    if sysinfo::is_within(dst, src) {
        return Err(t("eng.out_inside").into());
    }
    crate::keyfile::check_overlap(keyfiles, &[src, dst])
}

/// Fix list -> compress -> encrypt -> verify -> rename -> optional shred -> optional TRIM/free space.
pub fn do_encrypt(src: &Path, dst: &Path, c: &Cred, o: &Opts) -> R<String> {
    set_stage(ST_SCAN);
    check_paths(src, dst, &o.keyfiles)?;
    if o.shred_src && fs::symlink_metadata(src).map_err(e)?.file_type().is_symlink() {
        return Err(t("eng.link_shred").into());
    }
    let mut m = Manifest::default();
    Manifest::scan(src, "", &mut m)?;
    if m.files.is_empty() && m.dirs.is_empty() {
        return Err(t("eng.nothing").into());
    }
    // B-9: checked before any work, so "abort" costs nothing
    let ads = if o.shred_src {
        set_stage(ST_ADS);
        let a = crate::ads::scan(m.files.iter().map(|r| r.path.as_path()))?;
        if o.streams == StreamPolicy::Ask && (!a.data.is_empty() || !a.errors.is_empty()) {
            let first = a.data.first().map(|(p, v)| format!("{} ({})", p.display(), v.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")));
            let detail = first.or_else(|| a.errors.first().cloned()).unwrap_or_default();
            return Err(format!("{} [{C_ADS}]", tf("eng.ads_found", &[&(a.data.len() + a.errors.len()), &detail])));
        }
        a
    } else {
        crate::ads::AdsScan::default()
    };
    let is_dir = fs::metadata(src).map_err(e)?.is_dir();
    let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let outdir = parent_dir(dst);
    sysinfo::require_space(&outdir, m.total.saturating_mul(2).saturating_add(m.total / 8).saturating_add(64 << 20), t("eng.space_enc"))?;
    let disk = if o.shred_src { detect_disk(src) } else { Disk::Unknown };
    let plan = compress::plan(m.total, sysinfo::avail_mem(), sysinfo::cores(), o.strength);
    let mut meta = Meta::new(&name, FLAG_ARCHIVE | if is_dir { FLAG_DIR } else { 0 });

    set_stage(ST_COMPRESS);
    let mut st = SecTemp::create(&outdir).map_err(e)?;
    let stored = archive::pack(&mut st, &mut m, &plan)?;
    set_comp(&mut meta, &plan, stored);
    meta.file_count = m.files.len() as u64;
    meta.dir_count = m.dirs.len() as u64;
    meta.total_unpacked = m.total;
    let (h, part, warn) = seal_archive(st, &outdir, c, meta)?;
    let (mut want, mut want_dirs) = (Digests::new(), BTreeSet::new());
    m.expected(&mut want, &mut want_dirs)?;
    verify_container(&part.path, &h, c, &want, &want_dirs, m.total)?;
    rename_noreplace(&part.path, dst).map_err(|x| tf("eng.save_failed", &[&x]))?;
    part.keep();

    let mut msg = tf("eng.enc_done", &[&comp_desc(&h.meta), &m.files.len()]);
    if m.skipped > 0 {
        msg += &tf("eng.skipped", &[&m.skipped]);
    }
    if let Some(w) = warn {
        msg += &format!(" · {w}");
    }
    if !o.shred_src {
        return Ok(msg);
    }
    let passes = if o.force7 || disk != Disk::Ssd { 7 } else { 1 };
    set_stage(ST_SHRED); // from here on: no cancel
    progress_start(m.total.saturating_mul(passes as u64));
    let rep = shred_listed(&m, passes, !ads.is_empty());
    msg += &format!(" · {}", rep.summary(passes));
    // the result file is saved either way, but a failed overwrite/delete is reported as a failure
    let mut failed = !rep.failed.is_empty();
    if !ads.zone_only.is_empty() {
        msg += &tf("eng.zone_only", &[&ads.zone_only.len()]);
    }
    if disk != Disk::Hdd {
        msg += t("eng.no_guarantee");
    }
    let parent = src.parent().map(Path::to_path_buf);
    if o.wipe_free_after {
        if let Some(p) = &parent {
            set_stage(ST_WIPE_FREE);
            match wipe_free_space(p) {
                Ok(t) => msg += &format!(" · {t}"),
                Err(x) if is_cancel(&x) => msg += t("eng.wipe_cancelled"),
                Err(x) => {
                    failed = true;
                    msg += &tf("eng.wipe_failed", &[&x]);
                }
            }
        }
    }
    if o.trim_after && disk != Disk::Hdd {
        if let Some(l) = parent.as_deref().and_then(drive_letter) {
            set_stage(ST_TRIM);
            match trim_volume(l) {
                Ok(t) => msg += &format!(" · {t}"),
                Err(x) => {
                    failed = true;
                    msg += &format!(" · {x}");
                }
            }
        }
    }
    if failed {
        Err(msg)
    } else {
        Ok(msg)
    }
}

pub fn safe_name(n: &str) -> Option<String> {
    (archive::component_ok(n) && Path::new(n).file_name().and_then(|f| f.to_str()) == Some(n)).then(|| n.to_string())
}

/// `name` if free in `dir`, otherwise "stem (decrypted).ext", "stem (decrypted 2).ext", ...
pub fn free_name(dir: &Path, name: &str, is_dir: bool, i: u32) -> PathBuf {
    if i == 0 {
        return dir.join(name);
    }
    let path = Path::new(name);
    let (stem, ext) = match (is_dir, path.file_stem(), path.extension()) {
        (false, Some(s), Some(x)) => (s.to_string_lossy().into_owned(), format!(".{}", x.to_string_lossy())),
        _ => (name.to_string(), String::new()),
    };
    dir.join(if i == 1 { format!("{stem} (decrypted){ext}") } else { format!("{stem} (decrypted {i}){ext}") })
}

/// Moves `item` to `dir/name` without overwriting (adds "(decrypted N)" when taken).
pub fn move_out(item: &Path, dir: &Path, name: &str, is_dir: bool) -> R<(PathBuf, bool)> {
    for i in 0..10_000 {
        let dest = free_name(dir, name, is_dir, i);
        if fs::symlink_metadata(&dest).is_ok() {
            continue;
        }
        match rename_noreplace(item, &dest) {
            Ok(()) => return Ok((dest, i > 0)),
            Err(x) if x.kind() == io::ErrorKind::AlreadyExists || fs::symlink_metadata(&dest).is_ok() => continue,
            Err(x) => return Err(tf("eng.move_failed", &[&x])),
        }
    }
    Err(t("eng.no_name").into())
}

/// Opens + fully authenticates into SecTemp, checks the 7z structure and limits, extracts into a
/// private staging folder, then moves the result next to the .shd (never overwriting).
pub fn do_decrypt(src: &Path, outdir: &Path, c: &Cred, o: DecOpts) -> R<String> {
    let fname = src.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fallback = safe_name(fname.strip_suffix(".shd").unwrap_or(fname)).unwrap_or_else(|| "decrypted".to_string());
    let _lock = lock_container(src, Mode::Shared)?; // before the key derivation
    set_stage(ST_DECRYPT);
    let mut f = File::open(src).map_err(e)?;
    let h = read_header(&mut f, c)?;
    if h.meta.comp_method == COMP_LZMA2 && h.meta.comp_dict as u64 > sysinfo::avail_mem() / 2 {
        return Err(tf("eng.no_mem", &[&human(h.meta.comp_dict as u64)]));
    }
    sysinfo::require_space(outdir, h.meta.real_len.saturating_add(h.meta.total_unpacked).saturating_add(64 << 20), t("eng.space_dec"))?;
    let mut st = SecTemp::create(outdir).map_err(e)?;
    stream_body(&mut f, &h, &mut st)?; // every chunk authenticated before extraction starts
    drop(f);
    st.flush().map_err(e)?;

    set_stage(ST_EXTRACT);
    let len = st.len();
    let listing = archive::inspect(&mut st, len)?;
    archive::check_against_meta(&listing, &h.meta)?; // B-1: the 7z list must match the authenticated meta
    let stage = Stage::create(outdir)?;
    let r = archive::extract(&mut st, &stage.path, h.meta.total_unpacked, &|n| Some(n.to_string()));
    let warn = st.destroy().err().map(|x| x.to_string());
    if let Err(x) = r {
        return Err(match stage.abort() {
            Some(w) => format!("{x} · {w}"),
            None => x,
        });
    }
    let want = safe_name(&h.meta.name).unwrap_or(fallback);
    let is_dir = h.meta.flags & FLAG_DIR != 0;
    let mut items: Vec<PathBuf> = fs::read_dir(&stage.path).map_err(e)?.flatten().map(|d| d.path()).collect();
    let single = items.len() == 1
        && items[0].is_dir() == is_dir
        && items[0].file_name().and_then(|n| n.to_str()) == Some(want.as_str());
    let (dest, renamed) = if single {
        let it = items.remove(0);
        let r = move_out(&it, outdir, &want, is_dir)?;
        stage.finish()?;
        r
    } else {
        // several top-level items (e.g. a whole drive was encrypted): keep them together
        let p = stage.path.clone();
        let r = move_out(&p, outdir, &want, true)?;
        stage.finish()?;
        r
    };
    let motw = crate::ads::propagate(src, std::slice::from_ref(&dest), o.strict_motw);
    let mut msg = tf("eng.dec_done", &[&dest.display(), &if renamed { t("eng.renamed") } else { "" }]);
    match motw {
        Ok(Some(w)) => msg += &format!(" · {w}"),
        Ok(None) => {}
        Err(x) => return Err(tf("eng.motw_strict", &[&dest.display(), &x])),
    }
    if let Some(w) = warn {
        msg += &format!(" · {w}");
    }
    Ok(msg)
}

/// Re-wraps the file key under new credentials; the data is not touched (instant for any size).
/// 1) unwrap DEK with old creds  2) write the new wrapped DEK into the spare slot, fsync
/// 3) re-read, verify the new creds open it AND yield the same DEK  4) overwrite the old slot 7x.
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
    for p in PATTERNS {
        let mut b = [0u8; SLOT];
        match p {
            Some(v) => b.fill(v),
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
pub fn do_full_rekey(path: &Path, old: &Cred, new: &Cred) -> R<String> {
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
    let part = PartGuard { path: dir.join(format!(".shd_{}.part", rand_hex()?)), keep: false };
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
    rename_replace(&part.path, path).map_err(|x| tf("eng.replace_failed", &[&x]))?;
    part.keep();
    let mut msg = t("eng.rekey_done").to_string();
    if let Some(w) = warn {
        msg += &format!(" · {w}");
    }
    Ok(msg)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
pub mod tests_support;
