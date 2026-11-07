//! "Open in Shield": open a container without writing plaintext anywhere.
//!
//! A-4: opening authenticates the slots and the meta block, reads only the 7z headers through the
//! ChunkReader (each chunk authenticated on load), checks the listing against the authenticated
//! meta, and then drops the header (DEK), the KEK and the credentials (all zeroizing). `Opened`
//! keeps only the non-secret listing and meta. Every later operation (integrity check, extract,
//! add) takes the credentials again, takes the container lock FIRST, derives the key, works, and
//! zeroizes the key when it returns. Nothing is remembered between operations.
//!
//! Adding files rebuilds the whole container under a new DEK, verifies everything (old and new
//! entries, SHA3-512) and only then atomically replaces the original, under an exclusive lock held
//! through the rename. The replaced container's old data is then overwritten with the chosen
//! passes (3/7; its key area always 7) and deleted, and TRIM runs on flash storage.

use crate::archive::{self, EntryInfo};
use crate::compress::{self, Strength};
use crate::crypto::{read_header, stream_body, ChunkReader, Cred, Header};
use crate::engine::{move_out, parent_dir, seal_archive, set_comp, verify_container, DecOpts};
use crate::format::*;
use crate::i18n::{coded, t, tf};
use crate::lock::{lock_container, FileLock, Mode};
use crate::manifest::{shred_listed, Digests, Manifest};
use crate::progress::*;
use crate::sectemp::SecTemp;
use crate::staging::Stage;
use crate::sysinfo;
use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub const C_OPEN_BAD: &str = "E_OPEN_BAD";
pub const C_CHANGED: &str = "E_CHANGED";

/// Same text whatever failed before the meta authenticated (no oracle).
pub fn open_bad() -> String {
    coded(C_OPEN_BAD, "err.open_bad")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyCheck {
    NotChecked,
    Ok,
    Failed,
}

/// An opened container: listing and authenticated meta only. No key, no password, no key file
/// digest (see the module docs).
pub struct Opened {
    pub path: PathBuf,
    pub stamp: (u64, Option<SystemTime>),
    pub meta: Meta,
    pub file_len: u64,
    pub entries: Vec<EntryInfo>,
    pub total: u64,
    pub body: BodyCheck,
}

impl Opened {
    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.meta.padded_len)
    }
    pub fn padding(&self) -> u64 {
        self.meta.padded_len - self.meta.real_len
    }
}

fn stamp(p: &Path) -> R<(u64, Option<SystemTime>)> {
    let m = fs::metadata(p).map_err(e)?;
    Ok((m.len(), m.modified().ok()))
}

fn changed() -> String {
    coded(C_CHANGED, "err.changed_since_open")
}

fn header(f: &mut File, cred: &Cred) -> R<Header> {
    read_header(f, cred).map_err(|x| if crate::i18n::has_code(&x, C_BAD) { open_bad() } else { x })
}

/// Lock, then key: the credentials are only turned into a key once this process may use the file.
/// Also proves the container is still the one that was opened.
fn unlock_again(o: &Opened, cred: &Cred, mode: Mode) -> R<(FileLock, File, Header)> {
    let lock = lock_container(&o.path, mode)?;
    if stamp(&o.path)? != o.stamp {
        return Err(changed());
    }
    let mut f = File::open(&o.path).map_err(e)?;
    let h = header(&mut f, cred)?;
    if h.meta != o.meta || h.file_len != o.file_len {
        return Err(changed());
    }
    Ok((lock, f, h))
}

/// Unlocks, lists, checks the list against the meta, and forgets the key (A-4).
pub fn open(path: &Path, cred: Cred) -> R<Opened> {
    let _lock = lock_container(path, Mode::Shared)?;
    set_stage(ST_OPEN);
    let st = stamp(path)?;
    let mut f = File::open(path).map_err(e)?;
    let hdr = header(&mut f, &cred)?;
    drop(cred);
    let mut cr = ChunkReader::new(f, &hdr);
    let l = archive::inspect(&mut cr, hdr.meta.real_len).map_err(|x| tf("cont.inspect", &[&x]))?;
    archive::check_against_meta(&l, &hdr.meta)?;
    drop(cr);
    let o = Opened {
        path: path.to_path_buf(),
        stamp: st,
        meta: hdr.meta.clone(),
        file_len: hdr.file_len,
        entries: l.entries,
        total: l.total,
        body: BodyCheck::NotChecked,
    };
    drop(hdr); // DEK zeroized here
    Ok(o)
}

/// Authenticates every chunk of the body (no plaintext kept).
pub fn verify_body(o: &Opened, cred: Cred) -> R<String> {
    let (_lock, mut f, h) = unlock_again(o, &cred, Mode::Shared)?;
    drop(cred);
    set_stage(ST_CHECK);
    stream_body(&mut f, &h, &mut io::sink())?;
    Ok(tf("cont.body_ok", &[&o.chunk_count()]))
}

/// Output name of `entry` when extracting `selected` items viewed from folder `base` ("" = root).
/// Folders select everything below them. Names are made relative to `base`.
pub fn selection_map(entry: &str, base: &str, selected: &HashSet<String>) -> Option<String> {
    let hit = selected.iter().any(|s| entry == s || entry.starts_with(&format!("{s}/")));
    if !hit {
        return None;
    }
    if base.is_empty() {
        return Some(entry.to_string());
    }
    entry.strip_prefix(&format!("{base}/")).map(str::to_string)
}

/// Removes items this extraction already moved out (rollback, B-15). Returns warnings.
fn roll_back(moved: &[PathBuf]) -> String {
    let bad: Vec<String> = moved.iter().filter_map(|p| crate::wipe::shred_own_tree(p).err().map(|x| format!("{}: {x}", p.display()))).collect();
    if bad.is_empty() {
        tf("cont.rolled_back", &[&moved.len()])
    } else {
        tf("cont.rollback_failed", &[&bad.join(", ")])
    }
}

/// Extracts the selected entries (paths inside the archive) into `outdir`, viewed from `base`.
/// Each chunk read is authenticated; on any failure everything this call produced is removed.
pub fn extract_selected(o: &Opened, cred: Cred, selected: &HashSet<String>, base: &str, outdir: &Path, d: DecOpts) -> R<String> {
    let (_lock, f, h) = unlock_again(o, &cred, Mode::Shared)?;
    drop(cred);
    set_stage(ST_EXTRACT);
    let mut cr = ChunkReader::new(f, &h);
    // B-1: the 7z list is read again under the key that is used now, and must match the meta
    let l = archive::inspect(&mut cr, h.meta.real_len)?;
    archive::check_against_meta(&l, &h.meta)?;
    let total: u64 = l.entries.iter().filter(|en| !en.is_dir && selection_map(&en.name, base, selected).is_some()).map(|en| en.size).sum();
    sysinfo::require_space(outdir, total.saturating_add(16 << 20), t("cont.space_extract"))?;
    let stage = Stage::create(outdir)?;
    let r = archive::extract(&mut cr, &stage.path, total, &|n| selection_map(n, base, selected));
    drop(cr);
    drop(h);
    let n = match r {
        Ok(n) => n,
        Err(x) => return Err(stage.abort().map(|w| format!("{x} · {w}")).unwrap_or(x)),
    };
    let mut moved = Vec::new();
    let items: Vec<PathBuf> = fs::read_dir(&stage.path).map_err(e)?.flatten().map(|d| d.path()).collect();
    // B-7: marked inside the private staging folder, before anything appears at the destination
    // (security review 2026-11-08); moving out is a rename, which keeps the mark
    let motw_warn = match crate::ads::propagate(&o.path, &items, d.strict_motw) {
        Ok(w) => w,
        Err(x) => return Err(stage.abort().map(|w| format!("{x} · {w}")).unwrap_or(x)),
    };
    for it in items {
        let name = it.file_name().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
        let is_dir = it.is_dir();
        match move_out(&it, outdir, &name, is_dir) {
            Ok((d, _)) => moved.push(d),
            Err(x) => {
                let rb = roll_back(&moved);
                let w = stage.abort().map(|w| format!(" · {w}")).unwrap_or_default();
                return Err(format!("{x} · {rb}{w}"));
            }
        }
    }
    if let Err(x) = stage.finish() {
        return Err(format!("{x} · {}", roll_back(&moved)));
    }
    let mut msg = tf("cont.extracted", &[&n, &outdir.display()]);
    if let Some(w) = motw_warn {
        msg += &format!(" · {w}");
    }
    Ok(msg)
}

/// Entry names that already exist in the container for the items to add (case-insensitive).
pub fn conflicts(o: &Opened, adds: &[PathBuf], prefix: &str) -> Vec<String> {
    let have: HashSet<String> = o.entries.iter().map(|x| x.name.to_lowercase()).collect();
    adds.iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .map(|n| if prefix.is_empty() { n } else { format!("{prefix}/{n}") })
        .filter(|n| have.contains(&n.to_lowercase()))
        .collect()
}

pub struct AddOpts {
    pub overwrite: bool,
    pub shred_src: bool,
    /// Overwrite passes for the old container data and (with `shred_src`) the added originals.
    pub passes: crate::wipe::Passes,
    pub strength: Strength,
    /// Key file paths given for this operation (overlap check only).
    pub keyfiles: Vec<PathBuf>,
}

/// Adds files/folders under `prefix`. Old entries are copied through SecTemp (re-compressed with the
/// current policy), everything is re-encrypted under a new DEK/salt/prefix/padding, fully verified
/// (old + new entries, SHA3-512), and the original is replaced atomically. The exclusive lock is
/// taken before the key derivation and held through the rename. The listing is refreshed from
/// the new header, which is then dropped like every other key.
pub fn add_files(o: &mut Opened, cred: Cred, adds: &[PathBuf], prefix: &str, ao: &AddOpts) -> R<String> {
    rebuild(o, cred, adds, prefix, ao, &HashSet::new())
}

/// Removes the selected entries (folders with everything below them): the same verified rebuild
/// as `add_files`, with nothing added.
pub fn remove_entries(o: &mut Opened, cred: Cred, sel: &HashSet<String>, strength: Strength, passes: crate::wipe::Passes) -> R<String> {
    if sel.is_empty() {
        return Err(t("cont.nothing_selected").into());
    }
    let ao = AddOpts { overwrite: false, shred_src: false, passes, strength, keyfiles: vec![] };
    rebuild(o, cred, &[], "", &ao, sel)
}

fn rebuild(o: &mut Opened, cred: Cred, adds: &[PathBuf], prefix: &str, ao: &AddOpts, remove: &HashSet<String>) -> R<String> {
    set_stage(ST_SCAN);
    let mut targets: Vec<&Path> = adds.iter().map(PathBuf::as_path).collect();
    targets.push(&o.path);
    crate::keyfile::check_overlap(&ao.keyfiles, &targets)?;
    for a in adds {
        if sysinfo::is_within(&o.path, a) {
            return Err(t("cont.add_self").into());
        }
    }
    let clash = conflicts(o, adds, prefix);
    if !clash.is_empty() && !ao.overwrite {
        return Err(tf("cont.clash", &[&clash.join(", ")]));
    }
    let mut newm = Manifest::default();
    for a in adds {
        Manifest::scan(a, prefix, &mut newm)?;
    }
    let replaced: HashSet<String> = clash.iter().map(|c| c.to_lowercase()).collect();
    let is_replaced = |n: &str| {
        let l = n.to_lowercase();
        replaced.iter().any(|r| l == *r || l.starts_with(&format!("{r}/")))
    };
    let new_names: HashSet<String> =
        newm.files.iter().map(|f| f.rel.to_lowercase()).chain(newm.dirs.iter().map(|d| d.0.to_lowercase())).collect();
    // a new folder may share its name with an old folder (merge): old folder entries stay unless replaced
    let keep = |n: &str| !is_replaced(n) && !new_names.contains(&n.to_lowercase()) && selection_map(n, "", remove).is_none();
    let dir = parent_dir(&o.path);
    let keep_total: u64 = o.entries.iter().filter(|x| !x.is_dir && keep(&x.name)).map(|x| x.size).sum();
    sysinfo::require_space(&dir, (o.meta.real_len + newm.total).saturating_mul(3).saturating_add(64 << 20), t("cont.space_rebuild"))?;

    let (_lock, mut f, hdr) = unlock_again(o, &cred, Mode::Exclusive)?;
    // 1) the current archive into SecTemp A, every chunk authenticated first
    set_stage(ST_DECRYPT);
    let mut a = SecTemp::create(&dir).map_err(e)?;
    stream_body(&mut f, &hdr, &mut a)?;
    drop(f);
    io::Write::flush(&mut a).map_err(e)?;
    let mut meta = hdr.meta.clone();
    drop(hdr);

    // 2) new archive in SecTemp B: kept old entries streamed A -> B, then the added items
    set_stage(ST_REBUILD);
    let plan = compress::plan(keep_total + newm.total, sysinfo::avail_mem(), sysinfo::cores(), ao.strength);
    let main = compress::methods(&plan);
    let (mut want, mut want_dirs) = (Digests::new(), BTreeSet::new());
    let mut b = SecTemp::create(&dir).map_err(e)?;
    let mut stored = 0u64;
    {
        let mut z = sevenz_rust2::ArchiveWriter::new(&mut b).map_err(e)?;
        progress_start(keep_total.saturating_mul(2));
        archive::copy_entries(&mut a, &mut z, &keep, &main, &mut want, &mut want_dirs)?;
        archive::add_listed(&mut z, &mut newm, &main, &mut stored)?;
        z.finish().map_err(e)?;
    }
    let a_warn = a.destroy().err().map(|x| x.to_string());
    newm.expected(&mut want, &mut want_dirs)?;
    let total = keep_total + newm.total;
    meta.flags = FLAG_ARCHIVE | (meta.flags & FLAG_DIR);
    set_comp(&mut meta, &plan, stored);
    meta.file_count = want.len() as u64;
    meta.dir_count = want_dirs.len() as u64;
    meta.total_unpacked = total;
    let (h, part, warn) = seal_archive(b, &dir, &cred, meta)?;
    verify_container(&part.path, &h, &cred, &want, &want_dirs, total)?;
    drop(cred);
    if stamp(&o.path)? != o.stamp {
        return Err(changed());
    }
    set_stage(ST_REPLACE);
    let old_warn = crate::wipe::replace_and_shred(&part.path, &o.path, ao.passes)?;
    part.keep();

    // refresh the listing with the header we still hold, then drop it
    let fresh = File::open(&o.path).map_err(e)?;
    let mut cr = ChunkReader::new(fresh, &h);
    let l = archive::inspect(&mut cr, h.meta.real_len)?;
    drop(cr);
    o.stamp = stamp(&o.path)?;
    o.meta = h.meta.clone();
    o.file_len = h.file_len;
    o.entries = l.entries;
    o.total = l.total;
    o.body = BodyCheck::Ok; // just verified end to end
    drop(h);

    let mut msg = if remove.is_empty() {
        tf("cont.added", &[&newm.files.len(), &want.len()])
    } else {
        tf("cont.removed", &[&remove.len(), &want.len()])
    };
    msg += &tf("cont.old_shredded", &[&ao.passes.count()]);
    let mut failed = false;
    let mut touched: Vec<&Path> = vec![o.path.as_path()];
    if ao.shred_src {
        set_stage(ST_SHRED);
        progress_start(newm.total.saturating_mul(ao.passes.count() as u64));
        let rep = shred_listed(&newm, ao.passes, true);
        msg += &tf("cont.added_shred", &[&rep.summary(ao.passes)]);
        failed = !rep.failed.is_empty();
        touched.extend(adds.iter().map(PathBuf::as_path));
    }
    for w in [a_warn, warn, old_warn].into_iter().flatten() {
        msg += &format!(" · {w}");
    }
    msg += &crate::wipe::exposure(&touched).note();
    msg += &crate::wipe::trim_after_shred(&touched);
    // the container was replaced either way; a failed shred is still reported as a failure
    if failed {
        Err(msg)
    } else {
        Ok(msg)
    }
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod tests;
