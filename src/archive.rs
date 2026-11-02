//! 7z packing/unpacking (sevenz-rust2) with progress, cancellation, strict entry checks and
//! decompression resource limits. Entries are non-solid (one stream per file), so single files can
//! be extracted without decoding the rest.

use crate::compress::{self, Plan};
use crate::format::Meta;
use crate::i18n::{t, tf};
use crate::manifest::{FileRec, HashingReader, Manifest};
use crate::progress::*;
use sevenz_rust2::{ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderMethod, Error as ZErr, NtTime, Password};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Decompression limits (decrypt, open and verify alike). Sizes come from format.rs so that
/// encryption refuses the same inputs up front.
pub const MAX_FILES: usize = crate::format::MAX_FILES as usize;
pub const MAX_DEPTH: usize = 64;
pub const MAX_PATH_CHARS: usize = 1024;
pub const MAX_COMPONENT_BYTES: usize = 255;
pub use crate::format::{MAX_ENTRY, MAX_TOTAL};
/// Unpacked / packed ratio limit.
pub const MAX_RATIO: u64 = 10_000;
/// The ratio limit applies from this unpacked total on (smaller inputs can't hurt and tiny
/// archives of zeros legitimately reach high ratios).
pub const RATIO_FROM: u64 = 64 << 20;

fn zerr(m: String) -> ZErr {
    ZErr::Other(Cow::Owned(m))
}

/// Maps a library error, keeping "cancelled" and our own messages readable.
fn from_z(x: ZErr) -> String {
    if cancelled() {
        return cancelled_msg();
    }
    match x {
        ZErr::Other(m) => m.into_owned(),
        o => tf("arc.7z_error", &[&o]),
    }
}

fn is_reserved(n: &str) -> bool {
    let base = n.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$")
        || (base.chars().count() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && base.chars().nth(3).is_some_and(|c| c.is_ascii_digit() || matches!(c, '\u{B9}' | '\u{B2}' | '\u{B3}')))
}

/// One path component that is safe to create on Windows (and elsewhere).
pub fn component_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_COMPONENT_BYTES
        && n != "."
        && n != ".."
        && !n.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        && !n.ends_with([' ', '.'])
        && !is_reserved(n)
}

/// Relative entry path whose every component is safe (no "..", drive, UNC, ADS, device names),
/// within the depth and length limits. '/' is the only separator: a '\' anywhere is refused, so
/// depth, duplicates and the created path all see the same components.
pub fn entry_ok(n: &str) -> bool {
    !n.is_empty()
        && !n.contains('\\')
        && n.chars().count() <= MAX_PATH_CHARS
        && n.split('/').count() <= MAX_DEPTH
        && n.split('/').all(component_ok)
}

/// Key used for duplicate detection: Windows file names are case-insensitive.
pub fn dup_key(n: &str) -> String {
    n.to_lowercase()
}

pub struct EntryInfo {
    pub name: zeroize::Zeroizing<String>,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

pub struct Listing {
    pub entries: Vec<EntryInfo>,
    pub total: u64,
    pub files: u64,
    pub dirs: u64,
}

/// The authenticated metadata promised these counts and this unpacked size; the 7z headers (which
/// only the chunk tags protect, not their meaning) must say exactly the same.
pub fn check_against_meta(l: &Listing, m: &Meta) -> R<()> {
    if l.total != m.total_unpacked || l.files != m.file_count || l.dirs != m.dir_count {
        return Err(tf(
            "arc.meta_mismatch",
            &[&l.files, &l.dirs, &crate::ui_fmt::human(l.total), &m.file_count, &m.dir_count, &crate::ui_fmt::human(m.total_unpacked)],
        ));
    }
    Ok(())
}

fn entry_is_link(f: &ArchiveEntry) -> bool {
    const REPARSE: u32 = 0x400;
    const UNIX_EXT: u32 = 0x8000;
    f.has_windows_attributes
        && (f.windows_attributes & REPARSE != 0
            || (f.windows_attributes & UNIX_EXT != 0 && (f.windows_attributes >> 16) & 0o170000 == 0o120000))
}

fn lzma2_dict(prop: u8) -> Option<u64> {
    match prop {
        0..=39 => Some((2 | (prop as u64 & 1)) << (prop / 2 + 11)),
        40 => Some(u32::MAX as u64),
        _ => None,
    }
}

/// True when `total` bytes unpacked from `packed` bytes is a suspicious ratio.
pub fn ratio_bad(total: u64, packed: u64) -> bool {
    total > RATIO_FROM && total / packed.max(1) > MAX_RATIO
}

/// Reads the 7z headers only and checks every entry and coder against the limits.
pub fn inspect<Rd: Read + Seek>(r: &mut Rd, packed_len: u64) -> R<Listing> {
    r.seek(SeekFrom::Start(0)).map_err(e)?;
    let rd = ArchiveReader::new(&mut *r, Password::empty()).map_err(|x| tf("arc.header", &[&from_z(x)]))?;
    let a = rd.archive();
    if a.files.len() > MAX_FILES {
        return Err(tf("arc.too_many", &[&a.files.len(), &MAX_FILES]));
    }
    let avail = crate::sysinfo::avail_mem();
    for b in &a.blocks {
        for c in &b.coders {
            let id = c.encoder_method_id();
            if id == EncoderMethod::ID_LZMA2 {
                let d = c.properties().first().and_then(|p| lzma2_dict(*p)).ok_or_else(|| t("arc.bad_lzma2").to_string())?;
                if d > crate::format::MAX_LZMA_DICT as u64 {
                    return Err(tf("arc.dict_too_big", &[&crate::ui_fmt::human(d)]));
                }
                if d > avail / 2 {
                    return Err(tf("arc.no_mem", &[&crate::ui_fmt::human(d)]));
                }
            } else if id != EncoderMethod::ID_ZSTD && id != EncoderMethod::ID_COPY {
                return Err(t("arc.method").into());
            }
        }
    }
    let mut seen = HashSet::new();
    let mut out = Listing { entries: Vec::with_capacity(a.files.len()), total: 0, files: 0, dirs: 0 };
    for f in &a.files {
        let n = f.name();
        if f.is_anti_item() || entry_is_link(f) {
            return Err(tf("arc.link", &[&n]));
        }
        if !entry_ok(n) {
            return Err(tf("arc.unsafe_path", &[&n]));
        }
        if !seen.insert(dup_key(n)) {
            return Err(tf("arc.dup", &[&n]));
        }
        if f.is_directory() {
            out.dirs += 1;
        } else {
            if f.size() > MAX_ENTRY {
                return Err(tf("arc.entry_big", &[&n]));
            }
            out.files += 1;
            out.total = out.total.checked_add(f.size()).filter(|t| *t <= MAX_TOTAL).ok_or_else(|| t("arc.total_big").to_string())?;
        }
        out.entries.push(EntryInfo {
            name: zeroize::Zeroizing::new(n.to_string()),
            is_dir: f.is_directory(),
            size: f.size(),
            mtime: f.has_last_modified_date.then(|| f.last_modified_date().into()),
        });
    }
    if ratio_bad(out.total, packed_len) {
        return Err(t("arc.bomb").into());
    }
    drop(rd);
    r.seek(SeekFrom::Start(0)).map_err(e)?;
    Ok(out)
}

fn entry_for(rel: &str, is_dir: bool, mtime: Option<SystemTime>) -> ArchiveEntry {
    let mut en = if is_dir { ArchiveEntry::new_directory(rel) } else { ArchiveEntry::new_file(rel) };
    if let Some(t) = mtime.and_then(|t| NtTime::try_from(t).ok()) {
        en.last_modified_date = t;
        en.has_last_modified_date = true;
    }
    en
}

/// Writes one listed file; its SHA3-512 is computed from exactly the bytes compressed.
fn push_file<W: Write + Seek>(z: &mut ArchiveWriter<W>, rec: &mut FileRec, main: &[sevenz_rust2::EncoderConfiguration]) -> R<bool> {
    let f = Manifest::open_checked(rec)?;
    let stored = compress::looks_compressed(&rec.path, rec.size);
    z.set_content_methods(if stored { compress::copy_methods() } else { main.to_vec() });
    let mut hr = HashingReader::new(BufReader::with_capacity(1 << 20, f));
    z.push_archive_entry(entry_for(&rec.rel, false, rec.mtime), Some(&mut hr)).map_err(from_z)?;
    if hr.n != rec.size {
        return Err(tf("arc.size_changed", &[&rec.path.display()]));
    }
    rec.hash = Some(hr.digest());
    Ok(stored)
}

/// Packs the listed folders/files (hashing every file) into `w`. Returns the number of entries
/// stored without compression.
pub fn pack<W: Write + Seek>(w: W, m: &mut Manifest, plan: &Plan) -> R<u64> {
    let mut z = ArchiveWriter::new(w).map_err(from_z)?;
    let main = compress::methods(plan);
    let mut stored = 0;
    add_listed(&mut z, m, &main, &mut stored)?;
    z.finish().map_err(e)?;
    Ok(stored)
}

pub fn add_listed<W: Write + Seek>(
    z: &mut ArchiveWriter<W>,
    m: &mut Manifest,
    main: &[sevenz_rust2::EncoderConfiguration],
    stored: &mut u64,
) -> R<()> {
    progress_start(m.total);
    for (d, p) in &m.dirs {
        check_cancel()?;
        let mt = fs::metadata(p).ok().and_then(|x| x.modified().ok());
        z.push_archive_entry::<&[u8]>(entry_for(d, true, mt), None).map_err(from_z)?;
    }
    for rec in m.files.iter_mut() {
        check_cancel()?;
        if push_file(z, rec, main)? {
            *stored += 1;
        }
    }
    z.set_content_methods(main.to_vec());
    Ok(())
}

/// Streams the kept entries of an existing archive straight into `z` (no plaintext on disk),
/// recording each file's size and SHA3-512 for the later restore comparison.
pub fn copy_entries<Rd: Read + Seek, W: Write + Seek>(
    r: &mut Rd,
    z: &mut ArchiveWriter<W>,
    keep: &dyn Fn(&str) -> bool,
    main: &[sevenz_rust2::EncoderConfiguration],
    files: &mut crate::manifest::Digests,
    dirs: &mut BTreeSet<String>,
) -> R<()> {
    z.set_content_methods(main.to_vec());
    for_each(r, |en, rdr| {
        let name = en.name();
        if !keep(name) {
            return Ok(true);
        }
        if !entry_ok(name) {
            return Err(tf("arc.unsafe_path", &[&name]));
        }
        let mt: Option<SystemTime> = en.has_last_modified_date.then(|| en.last_modified_date().into());
        if en.is_directory() {
            z.push_archive_entry::<&[u8]>(entry_for(name, true, mt), None).map_err(from_z)?;
            dirs.insert(name.to_string());
            return Ok(true);
        }
        let mut hr = HashingReader::new(Bounded { inner: rdr, left: en.size() });
        z.push_archive_entry(entry_for(name, false, mt), Some(&mut hr)).map_err(from_z)?;
        if hr.n != en.size() {
            return Err(tf("arc.unpack_size", &[&name]));
        }
        files.insert(name.to_string(), (hr.n, hr.digest()));
        Ok(true)
    })
}

/// Iterates entries with a reader for each; errors from `f` stop the walk and are returned as is.
pub fn for_each<Rd: Read + Seek>(r: &mut Rd, mut f: impl FnMut(&ArchiveEntry, &mut dyn Read) -> R<bool>) -> R<()> {
    r.seek(SeekFrom::Start(0)).map_err(e)?;
    let mut rd = ArchiveReader::new(&mut *r, Password::empty()).map_err(from_z)?;
    rd.set_thread_count(crate::sysinfo::cores().min(4));
    rd.for_each_entries(|en, rdr| f(en, rdr).map_err(zerr)).map_err(from_z)
}

/// Decompresses everything and returns the SHA3-512 of each file plus the folder set.
pub fn digests<Rd: Read + Seek>(r: &mut Rd) -> R<(crate::manifest::Digests, BTreeSet<String>)> {
    let mut files = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for_each(r, |en, rdr| {
        if en.is_directory() {
            dirs.insert(en.name().to_string());
            return Ok(true);
        }
        let mut hr = HashingReader::new(Bounded { inner: rdr, left: en.size() });
        io::copy(&mut hr, &mut io::sink()).map_err(|x| if cancelled() { cancelled_msg() } else { tf("arc.unpack_failed", &[&x]) })?;
        if hr.n != en.size() {
            return Err(tf("arc.unpack_size", &[&en.name()]));
        }
        files.insert(en.name().to_string(), (hr.n, hr.digest()));
        Ok(true)
    })?;
    Ok((files, dirs))
}

/// Creates every folder of `rel` below `dest`, refusing anything that is not a plain folder.
fn make_dirs(dest: &Path, rel: &str) -> R<PathBuf> {
    let mut p = dest.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err(tf("arc.path_clash", &[&rel])),
            Err(_) => fs::create_dir(&p).map_err(e)?,
        }
    }
    Ok(p)
}

/// Bounded copy: never yields more than the size declared in the header.
struct Bounded<'a> {
    inner: &'a mut dyn Read,
    left: u64,
}
impl Read for Bounded<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, cancelled_msg()));
        }
        let n = self.inner.read(b)?;
        if n as u64 > self.left {
            return Err(io::Error::new(io::ErrorKind::InvalidData, t("arc.bigger_than_declared")));
        }
        self.left -= n as u64;
        progress_add(n as u64);
        Ok(n)
    }
}

/// Extracts entries into `dest` (a fresh private staging folder). `map` gives the output relative
/// name of an entry (None = skip it). Files are created with `create_new` and never overwrite.
/// `limit` is the number of bytes the caller verified against the authenticated metadata; the
/// running total of written bytes may never exceed it.
pub fn extract<Rd: Read + Seek>(r: &mut Rd, dest: &Path, limit: u64, map: &dyn Fn(&str) -> Option<String>) -> R<u64> {
    progress_start(limit);
    let mut seen = HashSet::new();
    let mut count = 0u64;
    let mut written = 0u64;
    for_each(r, |en, rdr| {
        let Some(out) = map(en.name()) else { return Ok(true) };
        if !entry_ok(&out) || !seen.insert(dup_key(&out)) {
            return Err(tf("arc.unsafe_path", &[&out]));
        }
        if en.is_directory() {
            make_dirs(dest, &out)?;
            return Ok(true);
        }
        written = written.checked_add(en.size()).filter(|w| *w <= limit).ok_or_else(|| t("arc.over_declared_total").to_string())?;
        let (parent, file) = match out.rsplit_once('/') {
            Some((p, f)) => (make_dirs(dest, p)?, f),
            None => (dest.to_path_buf(), out.as_str()),
        };
        let path = parent.join(file);
        let fh = OpenOptions::new().write(true).create_new(true).open(&path).map_err(|x| format!("{out}: {x}"))?;
        let mut w = BufWriter::with_capacity(1 << 20, fh);
        let mut b = Bounded { inner: rdr, left: en.size() };
        let n = io::copy(&mut b, &mut w).map_err(|x| if cancelled() { cancelled_msg() } else { format!("{out}: {x}") })?;
        if n != en.size() {
            return Err(tf("arc.unpack_size", &[&out]));
        }
        let fh = w.into_inner().map_err(|x| e(x.into_error()))?;
        if en.has_last_modified_date {
            let _ = fh.set_modified(en.last_modified_date().into());
        }
        count += 1;
        Ok(true)
    })?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_names() {
        assert!(entry_ok("dir/file.txt") && entry_ok("a") && entry_ok("한글/파일.txt"));
        for bad in [
            "", "../x", "a/../b", "C:/x", "/abs", "a//b", "a/NUL", "con.txt", "x:ads", "a/b. ", "COM1", "LPT9.log",
            "COM\u{B9}", "\\\\server\\share", "a\\..\\b", "file.txt:stream", "a/aux",
        ] {
            assert!(!entry_ok(bad), "{bad}");
        }
        assert!(!entry_ok(&"x/".repeat(70)));
        assert!(!entry_ok(&"a".repeat(300)));
    }
    #[test]
    fn backslash_is_never_a_separator() {
        // 300 levels written with '\' used to pass the 64-level depth limit
        assert!(!entry_ok(&vec!["d"; 300].join("\\")));
        assert!(!entry_ok("a\\b"), "a\\b and a/b would otherwise be different entries");
        assert!(!entry_ok("dir/sub\\file"));
        assert!(entry_ok(&vec!["d"; MAX_DEPTH].join("/")));
        assert!(!entry_ok(&vec!["d"; MAX_DEPTH + 1].join("/")));
        assert_eq!(dup_key("Dir/A.TXT"), dup_key("dir/a.txt"));
    }
    #[test]
    fn ratio_limit_applies_below_one_gib() {
        assert!(ratio_bad(256 << 20, 1000), "256 MiB from 1000 bytes");
        assert!(!ratio_bad(256 << 20, 1 << 20));
        assert!(!ratio_bad(1 << 20, 10), "small totals are never refused");
    }
    #[test]
    fn listing_must_match_meta() {
        let l = Listing { entries: vec![], total: 256 << 20, files: 1, dirs: 0 };
        let mut m = Meta::new("x", crate::format::FLAG_ARCHIVE);
        m.file_count = 1;
        m.total_unpacked = 1; // the reported attack: 1 byte in the meta, 256 MiB in the 7z list
        assert!(check_against_meta(&l, &m).is_err());
        m.total_unpacked = 256 << 20;
        assert!(check_against_meta(&l, &m).is_ok());
        m.dir_count = 1;
        assert!(check_against_meta(&l, &m).is_err());
    }
    #[test]
    fn lzma2_dict_props() {
        assert_eq!(lzma2_dict(0), Some(4096));
        assert_eq!(lzma2_dict(1), Some(6144));
        assert_eq!(lzma2_dict(18), Some(2 << 20));
        assert_eq!(lzma2_dict(41), None);
    }
}
