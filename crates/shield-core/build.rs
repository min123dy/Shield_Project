//! Build inputs (design 3.0 §3/§4/§7), from the environment (build.ps1 / build.sh set them):
//! * SHIELD_REPO_URL: `https://github.com/<owner>/<repo>` used for "Developer info" and updates.
//!   Anything else stops the build. Empty / unset: no link, no updates.
//! * SHIELD_PUBKEY_PATH: armored OpenPGP release key to embed. Default `keys/release_key.asc` of
//!   the workspace; missing: no key (signature checks then always fail closed).
//!
//! Nothing secret is read here and nothing is printed except the (public) values themselves.

use std::path::{Path, PathBuf};

fn valid_part(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn check_repo(url: &str) -> Result<(), String> {
    let rest = url.strip_prefix("https://github.com/").ok_or("must start with https://github.com/")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    match rest.split('/').collect::<Vec<_>>().as_slice() {
        [o, r] if valid_part(o) && valid_part(r) => Ok(()),
        _ => Err("expected https://github.com/<owner>/<repo>".into()),
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=SHIELD_REPO_URL");
    println!("cargo:rerun-if-env-changed=SHIELD_PUBKEY_PATH");
    let url = std::env::var("SHIELD_REPO_URL").unwrap_or_default();
    let url = url.trim();
    if !url.is_empty() {
        if let Err(e) = check_repo(url) {
            panic!("SHIELD_REPO_URL {url:?}: {e}");
        }
    }
    println!("cargo:rustc-env=SHIELD_REPO_URL={url}");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", manifest.join("../../keys").display());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // main release key (signs every release) and, since 3.1.0, an offline backup key that only
    // signs an emergency release after the main key was lost or leaked (docs/07)
    for (var, default, file) in [
        ("SHIELD_PUBKEY_PATH", "release_key.asc", "release_key.asc"),
        ("SHIELD_PUBKEY_BACKUP_PATH", "release_key_backup.asc", "release_key_backup.asc"),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let key = match std::env::var(var) {
            Ok(p) if !p.trim().is_empty() => Some(PathBuf::from(p.trim())),
            _ => Some(manifest.join("../../keys").join(default)).filter(|p| p.is_file()),
        };
        let bytes = match &key {
            Some(p) => {
                println!("cargo:rerun-if-changed={}", p.display());
                // build time, a key file chosen by the person building; a public key is a few KiB
                let md = std::fs::metadata(p).unwrap_or_else(|e| panic!("{var} {}: {e}", p.display()));
                assert!(md.len() <= 1 << 20, "{var} {}: larger than 1 MiB, not a public key", p.display());
                #[allow(clippy::disallowed_methods)]
                let b = std::fs::read(p).unwrap_or_else(|e| panic!("{var} {}: {e}", p.display()));
                check_public(&b, p);
                b
            }
            None => Vec::new(),
        };
        std::fs::write(out.join(file), bytes).unwrap();
    }
}

/// Only armored public keys are embedded; anything that looks like secret key material stops the build.
fn check_public(b: &[u8], p: &Path) {
    assert!(b.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"), "{}: not an armored OpenPGP public key", p.display());
    let s = String::from_utf8_lossy(b);
    assert!(!s.contains("PRIVATE KEY") && !s.contains("SECRET KEY"), "refusing to embed a private key ({})", p.display());
}
