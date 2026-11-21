//! Size-limited reading of files (3.1.0 review 3, CWE-789 / CWE-400).
//!
//! The limit is applied to the OPENED handle and while reading, never only to a path's metadata
//! before `std::fs::read`: a file that is huge, or that grows after it was checked, is never read
//! past `max + 1` bytes, and more than `max` is an error. Only regular files are read (on Linux
//! the file is opened with O_NONBLOCK, so a FIFO put where a file is expected does not hang the
//! open; it is then refused as "not a regular file").

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// "larger than the limit" (ErrorKind::FileTooLarge).
pub fn too_large(max: u64) -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, format!("larger than {max} bytes"))
}

/// Reads at most `max` bytes from `r`. Never reads more than `max + 1` bytes; reaching that is
/// an error (FileTooLarge).
#[allow(clippy::disallowed_methods)] // the one bounded use: `take` caps it at max + 1 bytes
pub fn read_limited(r: impl Read, max: u64) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.take(max.saturating_add(1)).read_to_end(&mut v)?;
    if v.len() as u64 > max {
        return Err(too_large(max));
    }
    Ok(v)
}

/// `f` (already open) is a regular file of at most `max` bytes; reads it within that limit.
pub fn read_open_limited(f: &File, max: u64) -> io::Result<Vec<u8>> {
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    if md.len() > max {
        return Err(too_large(max));
    }
    let mut v = read_limited(f, max)?;
    v.shrink_to_fit();
    Ok(v)
}

/// Opens `p` for reading (following links like `std::fs::read`) without blocking on a FIFO.
pub fn open_read(p: &Path) -> io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NONBLOCK);
    }
    o.open(p)
}

/// `std::fs::read` with a limit: opens `p`, checks the handle (regular file, at most `max`
/// bytes) and reads at most `max + 1` bytes.
pub fn read_file_limited(p: &Path, max: u64) -> io::Result<Vec<u8>> {
    read_open_limited(&open_read(p)?, max)
}

/// `read_file_limited` as UTF-8 text (invalid UTF-8 is InvalidData).
pub fn read_text_limited(p: &Path, max: u64) -> io::Result<String> {
    String::from_utf8(read_file_limited(p, max)?).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8 text"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("shield_bounded_{}_{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    #[test]
    fn limits_hold_at_the_edge() {
        let p = tmp("edge");
        std::fs::write(&p, vec![7u8; 100]).unwrap();
        assert_eq!(read_file_limited(&p, 100).unwrap().len(), 100, "exactly the limit is fine");
        assert_eq!(read_file_limited(&p, 99).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(read_file_limited(&p, 0).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(read_limited(&[1u8, 2, 3][..], 3).unwrap(), [1, 2, 3]);
        assert_eq!(read_limited(&[1u8, 2, 3][..], 2).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert!(read_file_limited(&std::env::temp_dir(), 100).is_err(), "a folder is not read");
        assert_eq!(read_text_limited(&p, 100).unwrap(), "\u{7}".repeat(100));
        std::fs::write(&p, [0xffu8, 0xfe]).unwrap();
        assert_eq!(read_text_limited(&p, 100).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_huge_file_is_refused_on_its_handle_without_reading_it() {
        // 1 GiB of length, written without data (sparse / not yet written): refused from the
        // handle's size; read_limited would stop after max + 1 bytes anyway
        let p = tmp("huge");
        let f = File::create(&p).unwrap();
        f.set_len(1 << 30).unwrap();
        drop(f);
        let t = std::time::Instant::now();
        assert_eq!(read_file_limited(&p, 64 * 1024).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        let big = File::open(&p).unwrap();
        assert_eq!(read_limited(&big, 64 * 1024).unwrap_err().kind(), io::ErrorKind::FileTooLarge, "stream: stops at max + 1");
        assert!(t.elapsed().as_secs() < 5, "nothing near 1 GiB was read");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn growth_after_the_check_is_cut_at_the_limit() {
        // the handle says 10 bytes; more arrive before the read: still at most max + 1 are read
        let p = tmp("grow");
        std::fs::write(&p, vec![1u8; 10]).unwrap();
        let f = File::open(&p).unwrap();
        assert!(f.metadata().unwrap().len() <= 16);
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(&[2u8; 100]).unwrap();
        assert_eq!(read_limited(&f, 16).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        let _ = std::fs::remove_file(p);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_does_not_hang() {
        let p = tmp("fifo");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_file_limited(&p, 1024).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_file(p);
    }
}
