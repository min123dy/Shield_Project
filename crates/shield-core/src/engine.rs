//! High-level operations: encrypt (with full restore verification before any shredding), decrypt,
//! password change (slot re-wrap) and full key replacement (re-encryption under a new DEK).
//! File format: see format.rs. Low-level crypto: crypto.rs.

use crate::archive;
use crate::compress::{self, Strength};
use crate::crypto::{encrypt_stream, read_header, stream_body, ChunkReader, Cred, Header};
use crate::entropy::rand_hex;
use crate::format::*;
use crate::i18n::{t, tf};
use crate::lock::{lock_container, Mode};
use crate::manifest::{compare, shred_listed, Digests, Manifest};
use crate::progress::*;
use crate::sectemp::SecTemp;
use crate::staging::Stage;
use crate::sysinfo::{self, rename_noreplace};
use crate::ui_fmt::human;
use crate::wipe::{exposure, trim_after_shred, wipe_free_space, Passes};
use std::collections::{BTreeSet, HashSet};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

pub use crate::format::DEFAULT_PIM;

/// Hard minimum password length (characters) for new credentials. At the default PIM or above a
/// short password is a warning the user may accept (3.0.0 §1, `password::check_new`). Below the
/// default PIM the KDF is cheaper per guess, so a longer password stays required (same idea as
/// VeraCrypt's rule for small PIMs); this compensates for a weaker KDF and is not relaxed.
pub fn min_password_len(pim: u32, has_keyfile: bool) -> usize {
    match (has_keyfile, pim >= DEFAULT_PIM) {
        (true, _) | (false, true) => 0,
        (false, false) => 20,
    }
}

/// `password::check_new` with the rules of a new container credential.
pub fn check_new_password(pw: &str, confirm_ok: Option<bool>, overflow: bool, pim: u32, has_keyfile: bool) -> crate::password::Check {
    let user = crate::password::user_name();
    let rules = crate::password::Rules { has_keyfile, min_len: min_password_len(pim, has_keyfile), user: &user };
    crate::password::check_new(pw, confirm_ok, overflow, rules)
}

pub struct Opts {
    pub shred_src: bool,
    /// Overwrite passes for the originals (3 or 7). TRIM runs by itself afterwards on flash.
    pub passes: Passes,
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
    pub fn new(path: PathBuf) -> Self {
        PartGuard { path, keep: false }
    }
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
    let part = PartGuard::new(outdir.join(format!(".shd_{}.part", rand_hex()?)));
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

fn check_paths(srcs: &[PathBuf], dst: &Path, keyfiles: &[PathBuf]) -> R<()> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(t("eng.out_exists").into());
    }
    for (i, s) in srcs.iter().enumerate() {
        if sysinfo::is_within(dst, s) {
            return Err(t("eng.out_inside").into());
        }
        if srcs.iter().enumerate().any(|(j, o)| i != j && sysinfo::is_within(s, o)) {
            return Err(tf("eng.src_overlap", &[&s.display()]));
        }
    }
    let mut all: Vec<&Path> = srcs.iter().map(PathBuf::as_path).collect();
    all.push(dst);
    crate::keyfile::check_overlap(keyfiles, &all)
}

/// Collision key of top-level names: Unicode NFC, case-folded (Windows and most Linux desktops
/// would otherwise show two items that look the same).
fn name_key(n: &str) -> String {
    n.nfc().collect::<String>().to_lowercase()
}

fn numbered(n: &str, is_dir: bool, i: u32) -> String {
    let p = Path::new(n);
    match (is_dir, p.file_stem(), p.extension()) {
        (false, Some(s), Some(x)) => format!("{} ({i}).{}", s.to_string_lossy(), x.to_string_lossy()),
        _ => format!("{n} ({i})"),
    }
}

/// Top-level entry names of a bundle: each item's own name, made unique ("a (2).txt") when two
/// selected items share a name. A drive root (no name) is only accepted alone.
pub fn top_names(srcs: &[PathBuf]) -> R<Vec<String>> {
    let mut used = HashSet::new();
    let mut out = Vec::with_capacity(srcs.len());
    for s in srcs {
        let n = s.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if n.is_empty() {
            if srcs.len() > 1 {
                return Err(tf("eng.root_in_bundle", &[&s.display()]));
            }
            out.push(n);
            continue;
        }
        let is_dir = fs::metadata(s).map(|m| m.is_dir()).unwrap_or(false);
        let mut cand = n.clone();
        let mut i = 2;
        while !used.insert(name_key(&cand)) {
            cand = numbered(&n, is_dir, i);
            i += 1;
        }
        out.push(cand);
    }
    Ok(out)
}

/// Fix list -> compress -> encrypt -> verify -> rename -> optional shred -> TRIM / free space.
pub fn do_encrypt(src: &Path, dst: &Path, c: &Cred, o: &Opts) -> R<String> {
    do_encrypt_many(&[src.to_path_buf()], dst, c, o)
}

/// Several files and folders into one container (a "bundle"). With one item this is exactly the
/// 2.x single-item format; with more, the meta is a folder named after the container and the
/// items are its top-level entries (decrypting recreates that folder).
pub fn do_encrypt_many(srcs: &[PathBuf], dst: &Path, c: &Cred, o: &Opts) -> R<String> {
    set_stage(ST_SCAN);
    if srcs.is_empty() {
        return Err(t("eng.nothing").into());
    }
    check_paths(srcs, dst, &o.keyfiles)?;
    if o.shred_src && srcs.iter().any(|s| fs::symlink_metadata(s).is_ok_and(|m| m.file_type().is_symlink())) {
        return Err(t("eng.link_shred").into());
    }
    let names = top_names(srcs)?;
    let mut m = Manifest::default();
    for (s, n) in srcs.iter().zip(&names) {
        Manifest::scan_named(s, "", n, &mut m)?;
    }
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
    let (name, flags) = if srcs.len() == 1 {
        let is_dir = fs::metadata(&srcs[0]).map_err(e)?.is_dir();
        (names[0].clone(), FLAG_ARCHIVE | if is_dir { FLAG_DIR } else { 0 })
    } else {
        let stem = dst.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        (safe_name(&stem).unwrap_or_else(|| "Shield".to_string()), FLAG_ARCHIVE | FLAG_DIR)
    };
    let outdir = parent_dir(dst);
    sysinfo::require_space(&outdir, m.total.saturating_mul(2).saturating_add(m.total / 8).saturating_add(64 << 20), t("eng.space_enc"))?;
    let plan = compress::plan(m.total, sysinfo::avail_mem(), sysinfo::cores(), o.strength);
    let mut meta = Meta::new(&name, flags);

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
    let src_refs: Vec<&Path> = srcs.iter().map(PathBuf::as_path).collect();
    let ex = exposure(&src_refs);
    set_stage(ST_SHRED); // from here on: no cancel
    progress_start(m.total.saturating_mul(o.passes.count() as u64));
    let rep = shred_listed(&m, o.passes, !ads.is_empty());
    msg += &format!(" · {}", rep.summary(o.passes));
    // the result file is saved either way, but a failed overwrite/delete is reported as a failure
    let mut failed = !rep.failed.is_empty();
    if !ads.zone_only.is_empty() {
        msg += &tf("eng.zone_only", &[&ads.zone_only.len()]);
    }
    msg += &ex.note();
    let parents: Vec<PathBuf> = srcs.iter().filter_map(|s| s.parent().map(Path::to_path_buf)).collect();
    if o.wipe_free_after {
        let mut done = HashSet::new();
        for p in &parents {
            if !done.insert(crate::wipe::volume_label(p)) {
                continue;
            }
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
    let prefs: Vec<&Path> = parents.iter().map(PathBuf::as_path).collect();
    msg += &trim_after_shred(&prefs);
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
    // B-7: the download mark goes on while everything is still in the private staging folder, so
    // nothing appears at the destination unmarked (security review 2026-11-08); the move below
    // is a rename on the same volume, which keeps it
    let motw_warn = match crate::ads::propagate(src, &items, o.strict_motw) {
        Ok(w) => w,
        Err(x) => {
            let msg = tf("eng.motw_strict", &[&outdir.display(), &x]);
            return Err(match stage.abort() {
                Some(w) => format!("{msg} · {w}"),
                None => msg,
            });
        }
    };
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
    let mut msg = tf("eng.dec_done", &[&dest.display(), &if renamed { t("eng.renamed") } else { "" }]);
    if let Some(w) = motw_warn {
        msg += &format!(" · {w}");
    }
    if let Some(w) = warn {
        msg += &format!(" · {w}");
    }
    Ok(msg)
}

pub use crate::rekey::{do_change_password, do_full_rekey};

#[cfg(test)]
#[path = "engine_tests.rs"]
pub mod tests_support;
