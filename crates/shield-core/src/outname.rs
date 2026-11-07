//! Default output names for new containers (GUI and console use the same rules).

use crate::settings::Naming;
use std::path::{Path, PathBuf};

/// Output next to `src`: "name.ext.shd" or "name.shd" (Settings), "(2)", "(3)"... when taken.
pub fn default_output(src: &Path, naming: Naming) -> Option<PathBuf> {
    let dir = src.parent()?;
    let full = src.file_name()?.to_string_lossy().into_owned();
    let base = match (naming, src.is_dir()) {
        (Naming::Replace, false) => src.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or(full),
        _ => full,
    };
    free_output(dir, &base)
}

/// The first "base.shd", "base (2).shd", ... in `dir` that does not exist (not even as a link).
pub fn free_output(dir: &Path, base: &str) -> Option<PathBuf> {
    (1..10_000u32)
        .map(|i| if i == 1 { dir.join(format!("{base}.shd")) } else { dir.join(format!("{base} ({i}).shd")) })
        .find(|p| std::fs::symlink_metadata(p).is_err())
}

/// One container for several items: next to the first item, named after its folder.
pub fn bundle_output(items: &[PathBuf]) -> Option<PathBuf> {
    let dir = items.first()?.parent()?;
    let base = dir.file_name().map(|n| n.to_string_lossy().into_owned()).filter(|n| !n.is_empty()).unwrap_or_else(|| "Shield".into());
    free_output(dir, &base)
}
