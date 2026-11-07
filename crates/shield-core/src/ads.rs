//! Extra streams: NTFS alternate data streams on Windows, user extended attributes on Linux.
//!
//! * B-7 Mark of the Web: files extracted from a container that came from the internet must carry
//!   the container's download mark (Windows `Zone.Identifier`, Linux `user.xdg.origin.url` /
//!   `user.xdg.referrer.url`), or SmartScreen / Office Protected View would treat them as local,
//!   trusted files. This is the class of bug fixed in 7-Zip as CVE-2025-0411.
//! * B-9 Shredding: overwriting a file's main data does not touch its named streams; deleting the
//!   file then frees them unread-but-not-overwritten. Before shredding, streams are listed so the
//!   user can include them (overwritten here) or abort.
//!
//! The OS work is in `shield_platform`; this module only decides and reports.

use crate::i18n::tf;
use crate::progress::*;
use shield_platform::platform;
use std::path::{Path, PathBuf};

pub use shield_platform::Stream;

/// Named streams of `p` (the main data is not included).
pub fn list_streams(p: &Path) -> std::io::Result<Vec<Stream>> {
    shield_platform::fs::list_streams(p)
}

/// What the pre-shred check found.
#[derive(Default, Debug)]
pub struct AdsScan {
    /// Files with streams other than the download mark (real hidden data).
    pub data: Vec<(PathBuf, Vec<Stream>)>,
    /// Files whose only stream is the download mark (reduced warning).
    pub zone_only: Vec<PathBuf>,
    /// Files whose streams could not be listed.
    pub errors: Vec<String>,
}

impl AdsScan {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.zone_only.is_empty() && self.errors.is_empty()
    }
}

pub fn scan<'a>(files: impl Iterator<Item = &'a Path>) -> R<AdsScan> {
    let mut s = AdsScan::default();
    for p in files {
        check_cancel()?;
        match list_streams(p) {
            Ok(v) if v.is_empty() => {}
            Ok(v) if v.iter().all(|x| x.is_mark) => s.zone_only.push(p.to_path_buf()),
            Ok(v) => s.data.push((p.to_path_buf(), v)),
            Err(x) => s.errors.push(format!("{}: {x}", p.display())),
        }
    }
    Ok(s)
}

/// Overwrites every named stream of `p` with the shred patterns of `passes`, then removes /
/// empties it. Returns the count.
pub fn overwrite_streams(p: &Path, passes: crate::wipe::Passes) -> Result<u64, String> {
    let mut rng = crate::entropy::bulk_rng()?;
    let pats = passes.patterns();
    let mut fill = |b: &mut [u8], pass: usize| match pats.get(pass).copied().flatten() {
        Some(v) => b.fill(v),
        None => rand::RngCore::fill_bytes(&mut rng, b),
    };
    platform().strip_extra_streams(p, pats.len(), &mut fill).map_err(|x| tf("ads.overwrite_failed", &[&p.display(), &"*", &x]))
}

/// Propagates the container's download mark to everything extracted (`items`). Failures are a
/// warning, or an error in strict mode (Settings > Security).
pub fn propagate(container: &Path, items: &[PathBuf], strict: bool) -> R<Option<String>> {
    let rep = match platform().mark_of_the_web_propagate(container, items) {
        Ok(r) => r,
        Err(x) => {
            let msg = tf("ads.motw_failed", &[&items.len(), &x]);
            return if strict { Err(msg) } else { Ok(Some(msg)) };
        }
    };
    if !rep.had_mark || rep.failed.is_empty() {
        return Ok(None);
    }
    let msg = tf("ads.motw_failed", &[&rep.failed.len(), &rep.failed.first().cloned().unwrap_or_default()]);
    if strict {
        Err(msg)
    } else {
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_files_have_no_streams_and_no_mark_means_nothing_to_do() {
        let d = std::env::temp_dir().join(format!("shield_ads_{}", crate::entropy::rand_hex().unwrap()));
        std::fs::create_dir_all(&d).unwrap();
        let (c, out) = (d.join("box.shd"), d.join("out.txt"));
        std::fs::write(&c, b"x").unwrap();
        std::fs::write(&out, b"y").unwrap();
        assert!(scan([c.as_path(), out.as_path()].into_iter()).unwrap().is_empty());
        assert_eq!(propagate(&c, std::slice::from_ref(&out), true).unwrap(), None);
        assert_eq!(overwrite_streams(&out, crate::wipe::Passes::Three).unwrap(), 0);
        let _ = std::fs::remove_dir_all(d);
    }
}
