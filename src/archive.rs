//! 7z (LZMA2) packing/unpacking with progress, cancellation and path-safety checks.
//! Entries are named relative to the parent of the source, so a folder "Docs" becomes
//! "Docs", "Docs/a.txt", ... and a single file "a.txt" becomes "a.txt".

use crate::progress::*;
use sevenz_rust::{Password, SevenZArchiveEntry, SevenZReader, SevenZWriter};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Reader that reports progress and aborts on cancel.
struct Counted<Rd>(Rd);
impl<Rd: Read> Read for Counted<Rd> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, CANCELLED));
        }
        let n = self.0.read(b)?;
        progress_add(n as u64);
        Ok(n)
    }
}

/// Total bytes of regular files below `p` (symlinks/junctions below the top are not followed).
pub fn tree_size(p: &Path, top: bool) -> u64 {
    let m = if top { fs::metadata(p) } else { fs::symlink_metadata(p) };
    let Ok(m) = m else { return 0 };
    if m.file_type().is_symlink() {
        0
    } else if m.is_dir() {
        fs::read_dir(p)
            .map(|rd| rd.flatten().map(|d| tree_size(&d.path(), false)).sum())
            .unwrap_or(0)
    } else {
        m.len()
    }
}

/// Packs `src` into `w`. Returns the number of skipped links.
pub fn archive_into<W: Write + Seek>(src: &Path, w: W) -> R<u64> {
    let root = src.parent().filter(|_| src.file_name().is_some()).unwrap_or(src).to_path_buf();
    progress_start(tree_size(src, true));
    let mut z = SevenZWriter::new(w).map_err(e)?;
    let mut skipped = 0;
    walk(src, &root, true, &mut z, &mut skipped)?;
    z.finish().map_err(e)?;
    Ok(skipped)
}

fn walk<W: Write + Seek>(
    p: &Path,
    root: &Path,
    top: bool,
    z: &mut SevenZWriter<W>,
    skipped: &mut u64,
) -> R<()> {
    check_cancel()?;
    let m = if top { fs::metadata(p) } else { fs::symlink_metadata(p) }.map_err(e)?;
    if m.file_type().is_symlink() {
        *skipped += 1;
        return Ok(());
    }
    let name = p.strip_prefix(root).map_err(e)?.to_string_lossy().replace('\\', "/");
    let entry = SevenZArchiveEntry::from_path(p, name.clone());
    let cancel_map = |x: sevenz_rust::Error| if cancelled() { CANCELLED.to_string() } else { e(x) };
    if m.is_dir() {
        if !name.is_empty() {
            z.push_archive_entry::<&[u8]>(entry, None).map_err(cancel_map)?;
        }
        let mut kids: Vec<PathBuf> = fs::read_dir(p).map_err(e)?.flatten().map(|d| d.path()).collect();
        kids.sort();
        for k in kids {
            walk(&k, root, false, z, skipped)?;
        }
    } else if m.is_file() {
        let f = File::open(p).map_err(|x| format!("{}: {x}", p.display()))?;
        z.push_archive_entry(entry, Some(Counted(f))).map_err(cancel_map)?;
    } else {
        *skipped += 1;
    }
    Ok(())
}

fn is_reserved(n: &str) -> bool {
    let base = n.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'0'..=b'9'))
}

/// One path component that is safe to create on Windows (and elsewhere).
pub fn component_ok(n: &str) -> bool {
    !n.is_empty()
        && n != "."
        && n != ".."
        && !n.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        && !n.ends_with([' ', '.'])
        && !is_reserved(n)
}

/// Relative archive entry path whose every component is safe (no "..", drive, ADS, device names).
pub fn entry_ok(n: &str) -> bool {
    !n.is_empty() && n.split(['/', '\\']).all(component_ok)
}

/// Shield 1.0 packed folders with sevenz_rust::compress, which adds the folder itself as a
/// directory entry with an empty name. It stands for the extraction root and is skipped.
fn root_dir_entry(f: &SevenZArchiveEntry) -> bool {
    f.name().is_empty() && f.is_directory()
}

/// Rejects archives whose entries could escape the extraction folder; returns total unpacked size.
pub fn validate_archive<Rd: Read + Seek>(r: &mut Rd, len: u64) -> R<u64> {
    let rd = SevenZReader::new(&mut *r, len, Password::empty()).map_err(e)?;
    let mut total = 0u64;
    for f in &rd.archive().files {
        if root_dir_entry(f) {
            continue;
        }
        if !entry_ok(f.name()) {
            return Err(format!("보안 위반: 안전하지 않은 압축 항목 경로 ({})", f.name()));
        }
        if !f.is_directory() {
            total = total.saturating_add(f.size());
        }
    }
    drop(rd);
    r.seek(SeekFrom::Start(0)).map_err(e)?;
    Ok(total)
}

/// Extracts into `dest` (must be a fresh, empty folder). Never overwrites: files are created with
/// `create_new`, so an entry can't be redirected through something that already exists.
pub fn extract_from<Rd: Read + Seek>(r: &mut Rd, dest: &Path, total: u64) -> R<()> {
    progress_start(total);
    sevenz_rust::decompress_with_extract_fn(&mut *r, dest, |entry, reader, path| {
        let io_err = |x: io::Error| sevenz_rust::Error::io(x);
        if cancelled() {
            return Err(io_err(io::Error::new(io::ErrorKind::Interrupted, CANCELLED)));
        }
        if root_dir_entry(entry) {
            return Ok(true); // `dest` itself
        }
        if !entry_ok(entry.name()) {
            return Err(sevenz_rust::Error::other("unsafe entry"));
        }
        if entry.is_directory() {
            fs::create_dir_all(path).map_err(io_err)?;
            return Ok(true);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
        let f = OpenOptions::new().write(true).create_new(true).open(path).map_err(io_err)?;
        let mut w = BufWriter::with_capacity(1 << 20, f);
        io::copy(&mut Counted(reader), &mut w).map_err(io_err)?;
        let f = w.into_inner().map_err(|x| io_err(x.into_error()))?;
        if entry.has_last_modified_date {
            let _ = f.set_modified(entry.last_modified_date().into());
        }
        Ok(true)
    })
    .map_err(|x| if cancelled() { CANCELLED.to_string() } else { e(x) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_names() {
        assert!(entry_ok("dir/file.txt") && entry_ok("a"));
        for bad in ["", "../x", "a/../b", "C:/x", "/abs", "a//b", "a/NUL", "con.txt", "x:ads", "a/b. ", "COM1"] {
            assert!(!entry_ok(bad), "{bad}");
        }
    }
}
