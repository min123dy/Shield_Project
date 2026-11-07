//! Update check and installation (design 3.0 §3).
//!
//! * Off by default; "check" only asks GitHub for the latest release; installing always needs the
//!   user's confirmation. Offline or any network error: the caller stays silent.
//! * HTTPS only (`https_only`, redirects included), certificates validated by rustls against the
//!   Mozilla roots (webpki-roots). No cookies, no tokens, a fixed User-Agent without version or
//!   system details, no query parameters: nothing identifies the user or the installation.
//! * A release offers, per platform, the installer plus `<installer>.sig`, and a manifest
//!   `Shield_v<V>_release.txt` plus `.sig` that lists version and SHA-256 of every installer.
//!   Both signatures must be good signatures by the embedded release key. The version that counts
//!   is the one inside the signed manifest (a tag alone could re-label an old signed installer),
//!   it must equal the tag and be strictly newer than the running version: no downgrades, no
//!   reinstalls of the same version. Tags are parsed strictly (`vMAJOR.MINOR.PATCH`).
//! * Downloads go to a private folder (0700 / user profile), are size-limited and deleted on any
//!   failure. Verification happens before anything runs.
//! * `self_update` was considered and not used: it verifies zipsign/ed25519 signatures only (no
//!   OpenPGP) and replaces binaries, which does not fit MSI / deb installations.

use crate::sigverify::{Cert, Verified};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use shield_platform::sys::Installed;

pub const MAX_PACKAGE: u64 = 512 << 20;
const MAX_SMALL: u64 = 64 << 10;
const MAX_API: u64 = 1 << 20;
pub const USER_AGENT: &str = "Shield-Updater";
pub const MANIFEST_HEAD: &str = "Shield release manifest 1";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version(pub u32, pub u32, pub u32);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl Version {
    /// `MAJOR.MINOR.PATCH`, decimal, no sign, no leading zeros, at most 6 digits each.
    pub fn parse(s: &str) -> Option<Version> {
        let n = |p: &str| -> Option<u32> {
            let ok = !p.is_empty() && p.len() <= 6 && p.bytes().all(|c| c.is_ascii_digit()) && (p == "0" || !p.starts_with('0'));
            ok.then(|| p.parse().ok()).flatten()
        };
        let mut it = s.split('.');
        let v = Version(n(it.next()?)?, n(it.next()?)?, n(it.next()?)?);
        it.next().is_none().then_some(v)
    }
    /// `vMAJOR.MINOR.PATCH` exactly (no pre-release or build suffix).
    pub fn parse_tag(t: &str) -> Option<Version> {
        Version::parse(t.strip_prefix('v')?)
    }
    pub fn current() -> Version {
        Version::parse(crate::buildinfo::VERSION).expect("crate version is MAJOR.MINOR.PATCH")
    }
}

/// Installer file name for `kind` ("msi", "deb", "AppImage") on this CPU.
pub fn package_name(v: Version, kind: &str) -> Option<String> {
    let arch = std::env::consts::ARCH;
    Some(match (kind, arch) {
        ("msi", "x86_64") => format!("Shield_v{v}_x64.msi"),
        ("msi", "aarch64") => format!("Shield_v{v}_arm64.msi"),
        ("deb", "x86_64") => format!("shield_v{v}_amd64.deb"),
        ("deb", "aarch64") => format!("shield_v{v}_arm64.deb"),
        ("AppImage", "x86_64" | "aarch64") => format!("Shield_v{v}_{arch}.AppImage"),
        _ => return None,
    })
}

pub fn manifest_name(v: Version) -> String {
    format!("Shield_v{v}_release.txt")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub tag: String,
    /// Release page (https://github.com/<owner>/<repo>/releases/...), for "open in browser".
    pub page: String,
    /// installer, its signature, manifest, its signature (all four, or None: link only).
    pub files: Option<[Asset; 4]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    UpToDate(Version),
    Available(Box<Release>),
}

fn msg(key: &'static str) -> String {
    crate::i18n::t(key).to_string()
}
fn msgf(key: &'static str, x: impl std::fmt::Display) -> String {
    crate::i18n::tf(key, &[&x])
}

/// Interprets the GitHub "latest release" answer. `kind` is the installer kind of this
/// installation (None: no automatic install, only the link).
pub fn evaluate(json: &str, owner: &str, repo: &str, current: Version, kind: Option<&str>) -> Result<Check, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| msg("upd.bad_answer"))?;
    let tag = v["tag_name"].as_str().ok_or_else(|| msg("upd.bad_answer"))?;
    let Some(ver) = Version::parse_tag(tag) else { return Ok(Check::UpToDate(current)) };
    if v["draft"].as_bool() != Some(false) || v["prerelease"].as_bool() != Some(false) || ver <= current {
        return Ok(Check::UpToDate(current));
    }
    let base = format!("https://github.com/{owner}/{repo}/releases/");
    let page = v["html_url"].as_str().filter(|u| u.starts_with(&base) && !u.contains(['?', '#', '\\', ' ', '"'])).map(str::to_string).unwrap_or_else(|| format!("{base}tag/{tag}"));
    let dl = format!("{base}download/{tag}/");
    let assets = v["assets"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let find = |name: &str| -> Option<Asset> {
        let a = assets.iter().find(|a| a["name"].as_str() == Some(name))?;
        let url = a["browser_download_url"].as_str()?;
        // the download must come from this repository's release, under the expected name
        (url == format!("{dl}{name}")).then(|| Asset { name: name.to_string(), url: url.to_string(), size: a["size"].as_u64().unwrap_or(0) })
    };
    let files = kind.and_then(|k| package_name(ver, k)).and_then(|p| {
        let m = manifest_name(ver);
        Some([find(&p)?, find(&format!("{p}.sig"))?, find(&m)?, find(&format!("{m}.sig"))?])
    });
    Ok(Check::Available(Box::new(Release { version: ver, tag: tag.to_string(), page, files })))
}

/// Parses a signed manifest: returns its version and the SHA-256 listed for `file`.
pub fn parse_manifest(text: &str, file: &str) -> Result<(Version, [u8; 32]), String> {
    let bad = || msg("upd.bad_manifest");
    let mut lines = text.lines();
    if lines.next() != Some(MANIFEST_HEAD) {
        return Err(bad());
    }
    let ver = lines.next().and_then(|l| l.strip_prefix("version ")).and_then(Version::parse).ok_or_else(bad)?;
    let mut found = None;
    for l in lines.filter(|l| !l.is_empty()) {
        let mut p = l.split(' ');
        let (Some("sha256"), Some(h), Some(name), None) = (p.next(), p.next(), p.next(), p.next()) else { return Err(bad()) };
        if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad());
        }
        if name == file {
            if found.is_some() {
                return Err(bad());
            }
            let mut d = [0u8; 32];
            for (i, b) in d.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
            }
            found = Some(d);
        }
    }
    Ok((ver, found.ok_or_else(|| msgf("upd.not_in_manifest", file))?))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .user_agent(USER_AGENT)
        .max_redirects(5)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(20)))
        .build()
        .into()
}

/// Streams `url` into `out` (at most `max` bytes). `progress(done)`; `cancel()` stops.
fn fetch(url: &str, max: u64, out: &mut dyn Write, progress: &dyn Fn(u64), cancel: &dyn Fn() -> bool) -> Result<u64, String> {
    let mut r = agent().get(url).header("Accept", "application/octet-stream").call().map_err(|x| msgf("upd.offline", x))?;
    let mut body = r.body_mut().with_config().limit(max + 1).reader();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n = 0u64;
    loop {
        if cancel() {
            return Err(msg("upd.cancelled"));
        }
        let k = body.read(&mut buf).map_err(|x| msgf("upd.offline", x))?;
        if k == 0 {
            return Ok(n);
        }
        n += k as u64;
        if n > max {
            return Err(msgf("upd.too_big", crate::ui_fmt::human(max)));
        }
        out.write_all(&buf[..k]).map_err(|x| x.to_string())?;
        progress(n);
    }
}

fn fetch_small(url: &str) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    fetch(url, MAX_SMALL, &mut v, &|_| {}, &|| false)?;
    Ok(v)
}

/// Asks GitHub for the latest release of the embedded repository.
pub fn check() -> Result<Check, String> {
    let (o, r) = crate::buildinfo::repo().ok_or_else(|| msg("upd.no_repo"))?;
    let url = format!("https://api.github.com/repos/{o}/{r}/releases/latest");
    let mut resp = agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|x| msgf("upd.offline", x))?;
    let body = resp.body_mut().with_config().limit(MAX_API).read_to_string().map_err(|x| msgf("upd.offline", x))?;
    // portable copies (zip, console binary) are never replaced by an installer: link only
    let kind = if crate::settings::portable_dir().is_some() { None } else { shield_platform::sys::package_kind() };
    evaluate(&body, &o, &r, Version::current(), kind)
}

/// A downloaded and verified installer (in a private folder).
#[derive(Debug)]
pub struct Downloaded {
    pub dir: PathBuf,
    pub path: PathBuf,
    pub version: Version,
    pub signer: Verified,
}

/// Folder for update downloads (removed again by `cleanup`).
pub fn root() -> PathBuf {
    shield_platform::platform().temp_dir().join("shield-update")
}

/// Removes what earlier runs left (an MSI handed to msiexec is kept until the next start).
pub fn cleanup() {
    let _ = std::fs::remove_dir_all(root());
}

/// Checks a manifest, its signature, an installer and its signature, all already in hand.
pub fn verify_set(cert: &Cert, r: &Release, manifest: &[u8], manifest_sig: &[u8], pkg: &Path, pkg_sig: &[u8], pkg_sha: [u8; 32]) -> Result<Verified, String> {
    let [p, ..] = r.files.as_ref().ok_or_else(|| msg("upd.no_package"))?;
    cert.verify(manifest, manifest_sig).map_err(|x| msgf("upd.sig_failed", x))?;
    let text = std::str::from_utf8(manifest).map_err(|_| msg("upd.bad_manifest"))?;
    let (mver, want) = parse_manifest(text, &p.name)?;
    if mver != r.version || mver <= Version::current() {
        return Err(msgf("upd.version_mismatch", mver));
    }
    if !crate::password::ct_eq(&want, &pkg_sha) {
        return Err(msg("upd.hash_mismatch"));
    }
    let data = std::fs::read(pkg).map_err(|x| x.to_string())?;
    cert.verify(&data, pkg_sig).map_err(|x| msgf("upd.sig_failed", x))
}

/// Downloads and verifies `r` with the embedded key. Nothing is run; on any failure the files are
/// deleted.
pub fn download(r: &Release, progress: &dyn Fn(u64, u64), cancel: &dyn Fn() -> bool) -> Result<Downloaded, String> {
    let cert = crate::buildinfo::release_key().ok_or_else(|| msg("upd.no_key"))?;
    let [p, ps, m, ms] = r.files.as_ref().ok_or_else(|| msg("upd.no_package"))?;
    if p.size > MAX_PACKAGE {
        return Err(msgf("upd.too_big", crate::ui_fmt::human(MAX_PACKAGE)));
    }
    let base = root();
    // reused only when it is this user's private folder: in a folder somebody else controls the
    // verified package could be swapped before it is installed (security review 2026-11-08)
    crate::sysinfo::ensure_private_dir(&base).map_err(|x| x.to_string())?;
    let dir = base.join(format!("dl-{}", crate::entropy::rand_hex()?));
    crate::sysinfo::create_private_dir(&dir).map_err(|x| x.to_string())?;
    let path = dir.join(&p.name);
    let res = (|| {
        let (manifest, manifest_sig, pkg_sig) = (fetch_small(&m.url)?, fetch_small(&ms.url)?, fetch_small(&ps.url)?);
        // check the manifest before the large download
        cert.verify(&manifest, &manifest_sig).map_err(|x| msgf("upd.sig_failed", x))?;
        let mut f = crate::sysinfo::create_private_file(&path).map_err(|x| x.to_string())?;
        let mut h = Sha256::new();
        let mut w = HashWriter { f: &mut f, h: &mut h };
        let total = p.size;
        let n = fetch(&p.url, MAX_PACKAGE, &mut w, &|d| progress(d, total), cancel)?;
        if total != 0 && n != total {
            return Err(msg("upd.hash_mismatch"));
        }
        f.sync_all().map_err(|x| x.to_string())?;
        drop(f);
        let signer = verify_set(cert, r, &manifest, &manifest_sig, &path, &pkg_sig, h.finalize().into())?;
        Ok(Downloaded { dir: dir.clone(), path: path.clone(), version: r.version, signer })
    })();
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    res
}

struct HashWriter<'a> {
    f: &'a mut std::fs::File,
    h: &'a mut Sha256,
}
impl Write for HashWriter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.f.write(b)?;
        self.h.update(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

/// Installs a verified download. The caller has asked the user and dropped its own secrets
/// (keys, passwords, clipboard) first; this also clears the entropy pool.
pub fn install(d: Downloaded) -> Result<Installed, String> {
    crate::entropy::clear_pool();
    let r = shield_platform::sys::install_package(&d.path);
    if !matches!(r, Ok(Installed::ExitNow)) {
        let _ = std::fs::remove_dir_all(&d.dir);
    }
    r.map_err(|x| match x {
        shield_platform::PlatformError::Declined => msg("upd.declined"),
        x => msgf("upd.install_failed", x),
    })
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
