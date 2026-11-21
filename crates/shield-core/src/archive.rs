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
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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

/// Key used for duplicate detection (3.1.0 final, review H: conservative). Two names count as the
/// same when they could be the same file somewhere or look the same: NFKC compatibility forms
/// ("ﬁ" / "fi", full-width letters), case (Windows, macOS), canonical composition (macOS stores
/// "e" + U+0301 as "é"), and invisible characters (spoofing characters, ZWJ/ZWNJ, variation
/// selectors). Such an archive is refused as a whole (`arc.dup`) instead of extracting one entry
/// over another or showing two entries that can't be told apart. Only used for comparison; names
/// are stored and extracted unchanged.
pub fn dup_key(n: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let visible: String = n.chars().filter(|c| !is_spoof_char(*c) && !is_variation_selector(*c) && !matches!(c, '\u{200C}' | '\u{200D}')).collect();
    let folded: String = visible.nfkc().collect::<String>().to_lowercase();
    folded.nfkc().collect()
}

/// Variation selectors (U+FE00..U+FE0F, U+E0100..U+E01EF): they change how the character BEFORE
/// them is drawn (emoji or text style, CJK variants) and are invisible on their own.
pub fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Characters that make a file name look like something else or hide part of it.
///
/// 3.1.0 #4: bidirectional embedding, override and isolate controls (U+202A..U+202E,
/// U+2066..U+2069), the LRM/RLM/ALM marks and the byte order mark. "a\u{202E}gpj.exe" shows as
/// "aexe.jpg".
/// 3.1.0 final (review H): every other invisible format character of Unicode category Cf (soft
/// hyphen, zero width space, word joiner, invisible operators, interlinear annotation, tags,
/// Arabic / Syriac / Kaithi / Egyptian format marks ...), private use characters (category Co: no
/// meaning, any font may draw anything) and noncharacters (U+FDD0..U+FDEF, U+xxFFFE/U+xxFFFF).
/// Not included on purpose: ZWJ (U+200D) and ZWNJ (U+200C), which emoji sequences, Persian and
/// Indic scripts need, and variation selectors after a visible character (`spoof_at` treats a
/// misplaced one as spoofing).
pub fn is_spoof_char(c: char) -> bool {
    let u = c as u32;
    matches!(c,
        // bidi controls and marks (3.1.0 #4)
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{FEFF}'
        // other Cf (Unicode 15.1)
        | '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
        | '\u{200B}' | '\u{2060}'..='\u{2064}' | '\u{206A}'..='\u{206F}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
        // private use (Co)
        | '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}'
        // noncharacters
        | '\u{FDD0}'..='\u{FDEF}'
    ) || (u & 0xFFFE) == 0xFFFE
}

/// `is_spoof_char`, plus a variation selector that has no visible character to modify: at the
/// start, after a separator or white space, or after another variation selector / spoofing
/// character.
fn spoof_at(prev: Option<char>, c: char) -> bool {
    is_spoof_char(c) || (is_variation_selector(c) && prev.is_none_or(|p| p == '/' || p.is_whitespace() || p.is_control() || is_variation_selector(p) || is_spoof_char(p)))
}

/// Indices (char positions) of the spoofing characters of `name`.
fn spoof_flags(name: &str) -> Vec<bool> {
    let mut prev = None;
    name.chars()
        .map(|c| {
            let s = spoof_at(prev, c);
            prev = Some(c);
            s
        })
        .collect()
}

/// True when `name` holds a spoofing character (`is_spoof_char` or a misplaced variation selector).
pub fn has_spoof(name: &str) -> bool {
    spoof_flags(name).into_iter().any(|x| x)
}

/// `name` with every spoofing character replaced by '_' (borrowed when there is none).
pub fn sanitize_component(name: &str) -> Cow<'_, str> {
    let f = spoof_flags(name);
    if f.iter().any(|x| *x) {
        Cow::Owned(name.chars().zip(f).map(|(c, s)| if s { '_' } else { c }).collect())
    } else {
        Cow::Borrowed(name)
    }
}

/// A name for display: each spoofing character shown as "<U+202E>". Comparisons and selection keep
/// using the real name; only what is drawn or printed changes.
pub fn display_name(name: &str) -> Cow<'_, str> {
    let f = spoof_flags(name);
    if f.iter().any(|x| *x) {
        let mut s = String::with_capacity(name.len() + 16);
        for (c, sp) in name.chars().zip(f) {
            if sp {
                s.push_str(&format!("<U+{:04X}>", c as u32));
            } else {
                s.push(c);
            }
        }
        Cow::Owned(s)
    } else {
        Cow::Borrowed(name)
    }
}

/// File types that Windows Explorer acts on by themselves (folder settings, shortcuts to network
/// locations, Explorer commands). They are extracted unchanged (the download mark is copied
/// already); the result only counts them so the user is warned.
pub fn is_risky_windows_name(name: &str) -> bool {
    let l = name.to_lowercase();
    l == "desktop.ini" || [".library-ms", ".searchconnector-ms", ".scf", ".url"].iter().any(|x| l.ends_with(x))
}

/// What an extraction did besides writing files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extracted {
    pub files: u64,
    /// Entries whose name had direction-control characters replaced by '_'.
    pub renamed: u64,
    /// Files of a type `is_risky_windows_name` names.
    pub risky: u64,
}

impl Extracted {
    /// " · N names ..." notes for the result message (empty when there is nothing to say).
    pub fn notes(&self) -> String {
        let mut s = String::new();
        if self.renamed > 0 {
            s += &format!(" · {}", tf("arc.spoof_renamed", &[&self.renamed]));
        }
        if self.risky > 0 {
            s += &format!(" · {}", tf("arc.risky_types", &[&self.risky]));
        }
        s
    }
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
    // (absolute offset, size) of every pack stream a zstd decoder reads (checked below)
    let mut zstd_streams = Vec::new();
    for (bi, b) in a.blocks.iter().enumerate() {
        if b.coders.iter().any(|c| c.encoder_method_id() == EncoderMethod::ID_ZSTD) {
            // Shield writes one coder per block; a zstd chain is not something it made
            let idx = a.stream_map.block_first_pack_stream_index().get(bi).copied();
            let range = idx.and_then(|i| Some((a.stream_map.pack_stream_offsets().get(i)?, a.pack_sizes().get(i)?)));
            match (b.coders.len(), range) {
                (1, Some((off, size))) => zstd_streams.push((sevenz_rust2::SIGNATURE_HEADER_SIZE.saturating_add(a.pack_pos()).saturating_add(*off), *size)),
                _ => return Err(t("arc.method").into()),
            }
        }
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
    for (off, size) in zstd_streams {
        zstd_frames_ok(r, off, size)?;
    }
    r.seek(SeekFrom::Start(0)).map_err(e)?;
    Ok(out)
}

/// Largest zstd window (decoder buffer) accepted (3.1.0 final, review H). Shield compresses with
/// levels 1..19 (window at most 8 MiB); the zstd decoder itself accepts up to 128 MiB per stream.
pub const MAX_ZSTD_WINDOW: u64 = 32 << 20;
/// Most zstd blocks walked in one pack stream (a 128 KiB block each: 64 GiB).
const MAX_ZSTD_BLOCKS: u64 = 1 << 19;

/// The window size a zstd frame header (starting at its magic number) asks for, or why it is
/// refused. `hdr` holds at least the first 14 bytes of the frame (fewer at the end of the stream).
/// Returns (window, header length).
pub fn zstd_frame_window(hdr: &[u8]) -> Result<(u64, usize), &'static str> {
    if hdr.len() < 5 || hdr[..4] != [0x28, 0xB5, 0x2F, 0xFD] {
        return Err("arc.zstd_frame");
    }
    let fhd = hdr[4];
    if fhd & 0x08 != 0 {
        return Err("arc.zstd_frame"); // reserved bit
    }
    if fhd & 0x03 != 0 {
        return Err("arc.zstd_dict"); // Shield never uses dictionaries
    }
    let single = fhd & 0x20 != 0;
    let fcs_len = match fhd >> 6 {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut pos = 5;
    let window = if single {
        0
    } else {
        let wd = *hdr.get(pos).ok_or("arc.zstd_frame")?;
        pos += 1;
        let log = 10 + u64::from(wd >> 3);
        if log > 41 {
            return Err("arc.zstd_frame");
        }
        let base = 1u64 << log;
        base + (base / 8) * u64::from(wd & 7)
    };
    let fcs_bytes = hdr.get(pos..pos + fcs_len).ok_or("arc.zstd_frame")?;
    pos += fcs_len;
    let mut fcs = 0u64;
    for (i, b) in fcs_bytes.iter().enumerate() {
        fcs |= u64::from(*b) << (8 * i);
    }
    if fcs_len == 2 {
        fcs += 256;
    }
    // a single segment frame is decoded into one buffer of its content size
    Ok((if single { fcs } else { window }, pos))
}

/// Walks every zstd frame of the pack stream at `off` (`size` bytes): each frame's window must be
/// within `MAX_ZSTD_WINDOW`, skippable frames are skipped, the blocks must fit the stream. Only
/// headers are read (3 bytes per block), never the compressed data.
fn zstd_frames_ok<Rd: Read + Seek>(r: &mut Rd, off: u64, size: u64) -> R<()> {
    let end = off.checked_add(size).ok_or_else(|| t("arc.zstd_frame").to_string())?;
    let bad = |k: &'static str| t(k).to_string();
    let mut pos = off;
    let mut blocks = 0u64;
    while pos < end {
        let mut hdr = [0u8; 14];
        r.seek(SeekFrom::Start(pos)).map_err(e)?;
        let n = read_up_to(r, &mut hdr[..(end - pos).min(14) as usize]).map_err(e)?;
        let h = &hdr[..n];
        // skippable frame: magic 0x184D2A50..5F, 4-byte length
        if h.len() >= 8 && h[1..4] == [0x2A, 0x4D, 0x18] && h[0] & 0xF0 == 0x50 {
            let len = u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]]));
            pos = pos.checked_add(8 + len).filter(|p| *p <= end).ok_or_else(|| bad("arc.zstd_frame"))?;
            continue;
        }
        let (window, hlen) = zstd_frame_window(h).map_err(bad)?;
        if window > MAX_ZSTD_WINDOW {
            return Err(tf("arc.zstd_window", &[&crate::ui_fmt::human(window), &crate::ui_fmt::human(MAX_ZSTD_WINDOW)]));
        }
        let checksum = h[4] & 0x04 != 0;
        pos += hlen as u64;
        loop {
            blocks += 1;
            if blocks > MAX_ZSTD_BLOCKS {
                return Err(bad("arc.zstd_frame"));
            }
            let mut bh = [0u8; 3];
            r.seek(SeekFrom::Start(pos)).map_err(e)?;
            if pos + 3 > end || read_up_to(r, &mut bh).map_err(e)? != 3 {
                return Err(bad("arc.zstd_frame"));
            }
            let v = u32::from(bh[0]) | u32::from(bh[1]) << 8 | u32::from(bh[2]) << 16;
            let (last, kind, bsize) = (v & 1 == 1, (v >> 1) & 3, u64::from(v >> 3));
            let data = match kind {
                0 | 2 => bsize,
                1 => 1,
                _ => return Err(bad("arc.zstd_frame")),
            };
            // a block is never larger than 128 KiB or the window
            if bsize > (128 << 10).min(window.max(1 << 10)) && kind != 1 {
                return Err(bad("arc.zstd_frame"));
            }
            pos = pos.checked_add(3 + data).filter(|p| *p <= end).ok_or_else(|| bad("arc.zstd_frame"))?;
            if last {
                break;
            }
        }
        if checksum {
            pos = pos.checked_add(4).filter(|p| *p <= end).ok_or_else(|| bad("arc.zstd_frame"))?;
        }
    }
    Ok(())
}

fn read_up_to<Rd: Read>(r: &mut Rd, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
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
///
/// 3.1.0 #4: every component of the output name has its direction-control characters replaced by
/// '_' (`sanitize_component`) and the result is checked again (`entry_ok`, duplicates). Two
/// entries that become the same name are an error, never silently renamed further.
pub fn extract<Rd: Read + Seek>(r: &mut Rd, dest: &Path, limit: u64, map: &dyn Fn(&str) -> Option<String>) -> R<Extracted> {
    progress_start(limit);
    let mut seen = HashSet::new();
    let mut done = Extracted::default();
    // cleaned name key -> the entry name it came from (for the collision message)
    let mut renamed: HashMap<String, String> = HashMap::new();
    let mut written = 0u64;
    for_each(r, |en, rdr| {
        let Some(orig) = map(en.name()) else { return Ok(true) };
        let out: String = orig.split('/').map(sanitize_component).collect::<Vec<_>>().join("/");
        let changed = out != orig;
        if !entry_ok(&out) {
            return Err(tf("arc.unsafe_path", &[&display_name(&orig)]));
        }
        let key = dup_key(&out);
        if !seen.insert(key.clone()) {
            let shown = if changed { Some(orig.as_str()) } else { renamed.get(&key).map(String::as_str) };
            return Err(match shown {
                Some(o) => tf("arc.spoof_clash", &[&display_name(o), &out]),
                None => tf("arc.unsafe_path", &[&out]),
            });
        }
        if changed {
            renamed.insert(key, orig.clone());
            done.renamed += 1;
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
        done.files += 1;
        if is_risky_windows_name(file) {
            done.risky += 1;
        }
        Ok(true)
    })?;
    Ok(done)
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

    /// One zstd frame: header with window descriptor `wd`, then raw blocks of `blocks` sizes.
    fn frame(wd: u8, blocks: &[usize], checksum: bool) -> Vec<u8> {
        let mut v = vec![0x28, 0xB5, 0x2F, 0xFD, if checksum { 0x04 } else { 0 }, wd];
        for (i, n) in blocks.iter().enumerate() {
            let last = u32::from(i + 1 == blocks.len());
            let h = last | ((*n as u32) << 3);
            v.extend_from_slice(&h.to_le_bytes()[..3]);
            v.extend(std::iter::repeat_n(0xAB, *n));
        }
        if checksum {
            v.extend_from_slice(&[1, 2, 3, 4]);
        }
        v
    }

    fn walk(data: &[u8]) -> R<()> {
        // 7 bytes of something else first: offsets are honoured
        let mut all = vec![9u8; 7];
        all.extend_from_slice(data);
        zstd_frames_ok(&mut std::io::Cursor::new(all), 7, data.len() as u64)
    }

    #[test]
    fn zstd_frames_are_walked_and_big_windows_refused() {
        let ok = frame(13 << 3, &[1000, 50], true);
        walk(&ok).unwrap();
        // two frames and a skippable frame in between
        let mut two = ok.clone();
        two.extend_from_slice(&[0x5E, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 7, 7, 7]);
        two.extend(frame(10 << 3, &[10], false));
        walk(&two).unwrap();
        // the second frame asks for 128 MiB: refused although the first is fine
        let mut big = ok.clone();
        big.extend(frame(17 << 3, &[10], false));
        let e = walk(&big).unwrap_err();
        assert!(e.contains("128"), "{e}");
        // cut off, garbage after the frame, a block past the end, reserved block type
        assert!(walk(&ok[..ok.len() - 2]).is_err());
        let mut junk = ok.clone();
        junk.extend_from_slice(&[0, 0, 0]);
        assert!(walk(&junk).is_err());
        let mut lie = frame(13 << 3, &[10], false);
        lie[6] = 0xF9; // block size far larger than the stream
        assert!(walk(&lie).is_err());
        let mut reserved = frame(13 << 3, &[10], false);
        reserved[6] |= 0b110;
        assert!(walk(&reserved).is_err());
    }

    #[test]
    fn archives_shield_writes_with_zstd_pass_the_frame_check() {
        use std::io::Cursor;
        let mut z = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        for level in [1, 19] {
            z.set_content_methods(vec![sevenz_rust2::encoder_options::ZstandardOptions::from_level(level).into()]);
            let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8 ^ (i / 7) as u8).collect();
            z.push_archive_entry(ArchiveEntry::new_file(&format!("f{level}.bin")), Some(Cursor::new(data))).unwrap();
        }
        let mut c = z.finish().unwrap();
        let n = c.get_ref().len() as u64;
        let l = inspect(&mut c, n).unwrap();
        assert_eq!(l.files, 2);
    }
}
