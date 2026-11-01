//! "SHIELD에서 열기": open a container without writing plaintext anywhere.
//! Opening authenticates the slots and the meta block and reads only the 7z headers through the
//! ChunkReader (each chunk authenticated on load). The listing lives in zeroizing strings and is
//! dropped on close/idle. Selective extraction reuses the staging + limits path; adding files
//! rebuilds the whole container under a new DEK, verifies everything (old and new entries, SHA3-512)
//! and only then atomically replaces the original.

use crate::archive::{self, EntryInfo};
use crate::compress::{self, Strength};
use crate::crypto::{read_header, stream_body, ChunkReader, Cred, Header};
use crate::engine::{move_out, parent_dir, seal_archive, set_comp, verify_container};
use crate::format::*;
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

pub const OPEN_BAD: &str = "열 수 없습니다: 비밀번호/PIM/키 파일이 틀렸거나 Shield 2 파일이 아닙니다.";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyCheck {
    NotChecked,
    Ok,
    Failed,
}

pub struct Opened {
    pub path: PathBuf,
    pub stamp: (u64, Option<SystemTime>),
    pub hdr: Header,
    pub cred: Cred,
    pub keyfiles: Vec<PathBuf>,
    pub entries: Vec<EntryInfo>,
    pub total: u64,
    pub body: BodyCheck,
}

impl Opened {
    pub fn chunk_count(&self) -> u64 {
        self.hdr.n_chunks()
    }
    pub fn padding(&self) -> u64 {
        self.hdr.meta.padded_len - self.hdr.meta.real_len
    }
}

fn stamp(p: &Path) -> R<(u64, Option<SystemTime>)> {
    let m = fs::metadata(p).map_err(e)?;
    Ok((m.len(), m.modified().ok()))
}

/// Unlocks and lists. Any failure before the meta authenticated reads the same (no oracle).
pub fn open(path: &Path, cred: Cred, keyfiles: Vec<PathBuf>) -> R<Opened> {
    set_stage(ST_OPEN);
    let st = stamp(path)?;
    let mut f = File::open(path).map_err(e)?;
    let hdr = match read_header(&mut f, &cred) {
        Ok(h) => h,
        Err(x) if x == BAD => return Err(OPEN_BAD.into()),
        Err(x) => return Err(x),
    };
    let mut cr = ChunkReader::new(f, &hdr);
    let l = archive::inspect(&mut cr, hdr.meta.real_len).map_err(|x| format!("7z 헤더 검사 실패: {x}"))?;
    Ok(Opened { path: path.to_path_buf(), stamp: st, hdr, cred, keyfiles, entries: l.entries, total: l.total, body: BodyCheck::NotChecked })
}

/// Authenticates every chunk of the body (no plaintext kept).
pub fn verify_body(o: &Opened) -> R<String> {
    set_stage(ST_CHECK);
    let mut f = File::open(&o.path).map_err(e)?;
    if f.metadata().map_err(e)?.len() != o.hdr.file_len {
        return Err(SIZE_MISMATCH.into());
    }
    stream_body(&mut f, &o.hdr, &mut io::sink())?;
    Ok(format!("본문 전체 무결성 검사 통과 ({}개 청크 인증)", o.chunk_count()))
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

/// Extracts the selected entries (paths inside the archive) into `outdir`, viewed from `base`.
/// Each chunk read is authenticated; any failure removes the partial output.
pub fn extract_selected(o: &Opened, selected: &HashSet<String>, base: &str, outdir: &Path) -> R<String> {
    set_stage(ST_EXTRACT);
    let total: u64 = o
        .entries
        .iter()
        .filter(|en| !en.is_dir && selection_map(&en.name, base, selected).is_some())
        .map(|en| en.size)
        .sum();
    sysinfo::require_space(outdir, total.saturating_add(16 << 20), "추출 결과")?;
    let f = File::open(&o.path).map_err(e)?;
    if f.metadata().map_err(e)?.len() != o.hdr.file_len {
        return Err(SIZE_MISMATCH.into());
    }
    let mut cr = ChunkReader::new(f, &o.hdr);
    let stage = Stage::create(outdir)?;
    let r = archive::extract(&mut cr, &stage.path, total, &|n| selection_map(n, base, selected));
    let n = match r {
        Ok(n) => n,
        Err(x) => {
            return Err(match stage.abort() {
                Some(w) => format!("{x} · {w}"),
                None => x,
            })
        }
    };
    let mut moved = Vec::new();
    let items: Vec<PathBuf> = fs::read_dir(&stage.path).map_err(e)?.flatten().map(|d| d.path()).collect();
    for it in items {
        let name = it.file_name().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
        let is_dir = it.is_dir();
        match move_out(&it, outdir, &name, is_dir) {
            Ok((d, _)) => moved.push(d),
            Err(x) => {
                let w = stage.abort().map(|w| format!(" · {w}")).unwrap_or_default();
                return Err(format!("{x}{w}"));
            }
        }
    }
    stage.finish()?;
    Ok(format!("선택 항목 추출 완료: 파일 {n}개 → {}", outdir.display()))
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
    pub strength: Strength,
}

fn newm_has_file(new_names: &HashSet<String>, n: &str) -> bool {
    new_names.contains(&n.to_lowercase())
}

/// Adds files/folders under `prefix`. Old entries are copied through SecTemp (re-compressed with the
/// current policy), everything is re-encrypted under a new DEK/salt/prefix/padding, fully verified
/// (old + new entries, SHA3-512), and the original is replaced atomically only if it did not change
/// since it was opened. Returns the new state (listing refreshed without another KDF run).
pub fn add_files(o: &mut Opened, adds: &[PathBuf], prefix: &str, ao: &AddOpts) -> R<String> {
    set_stage(ST_SCAN);
    if stamp(&o.path)? != o.stamp {
        return Err("컨테이너가 연 뒤에 바뀌었습니다. 다시 열어 주세요.".into());
    }
    let mut targets: Vec<&Path> = adds.iter().map(PathBuf::as_path).collect();
    targets.push(&o.path);
    crate::keyfile::check_overlap(&o.keyfiles, &targets)?;
    for a in adds {
        if sysinfo::is_within(&o.path, a) {
            return Err("컨테이너 자신(또는 그것을 포함한 폴더)은 추가할 수 없습니다.".into());
        }
    }
    let clash = conflicts(o, adds, prefix);
    if !clash.is_empty() && !ao.overwrite {
        return Err(format!("같은 이름의 항목이 이미 있습니다: {}", clash.join(", ")));
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
    let new_names: HashSet<String> = newm.files.iter().map(|f| f.rel.to_lowercase()).chain(newm.dirs.iter().map(|d| d.0.to_lowercase())).collect();
    // a new folder may share its name with an old folder (merge): old folder entries stay unless replaced
    let keep = |n: &str| !is_replaced(n) && !newm_has_file(&new_names, n);
    let dir = parent_dir(&o.path);
    let keep_total: u64 = o.entries.iter().filter(|x| !x.is_dir && keep(&x.name)).map(|x| x.size).sum();
    sysinfo::require_space(&dir, (o.hdr.meta.real_len + newm.total).saturating_mul(3).saturating_add(64 << 20), "컨테이너 재구성")?;

    // 1) the current archive into SecTemp A, every chunk authenticated first
    set_stage(ST_DECRYPT);
    let mut f = File::open(&o.path).map_err(e)?;
    if f.metadata().map_err(e)?.len() != o.hdr.file_len {
        return Err(SIZE_MISMATCH.into());
    }
    let mut a = SecTemp::create(&dir).map_err(e)?;
    stream_body(&mut f, &o.hdr, &mut a)?;
    drop(f);
    io::Write::flush(&mut a).map_err(e)?;

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
    let mut meta = o.hdr.meta.clone();
    meta.flags = FLAG_ARCHIVE | (meta.flags & FLAG_DIR);
    set_comp(&mut meta, &plan, stored);
    meta.file_count = want.len() as u64;
    meta.dir_count = want_dirs.len() as u64;
    meta.total_unpacked = total;
    let (h, part, warn) = seal_archive(b, &dir, &o.cred, meta)?;
    verify_container(&part.path, &h, &o.cred, &want, &want_dirs, total)?;
    if stamp(&o.path)? != o.stamp {
        return Err("작업 중에 원본 컨테이너가 바뀌어 교체하지 않았습니다 (원본 유지).".into());
    }
    set_stage(ST_REPLACE);
    sysinfo::rename_replace(&part.path, &o.path).map_err(|x| format!("교체 실패 (원본 유지): {x}"))?;
    part.keep();

    // refresh state without another KDF run
    let fresh = File::open(&o.path).map_err(e)?;
    let mut cr = ChunkReader::new(fresh, &h);
    let l = archive::inspect(&mut cr, h.meta.real_len)?;
    o.stamp = stamp(&o.path)?;
    o.hdr = h;
    o.entries = l.entries;
    o.total = l.total;
    o.body = BodyCheck::Ok; // just verified end to end

    let mut msg = format!("파일 추가 완료: {}개 추가 · 전체 {}개 파일을 새 키로 재암호화하고 SHA3-512로 검증한 뒤 교체", newm.files.len(), want.len());
    if ao.shred_src {
        set_stage(ST_SHRED);
        progress_start(newm.total.saturating_mul(7));
        let rep = shred_listed(&newm, 7);
        msg += &format!(" · 추가한 {}", rep.summary(7));
    }
    for w in [a_warn, warn].into_iter().flatten() {
        msg += &format!(" · {w}");
    }
    Ok(msg)
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod tests;
