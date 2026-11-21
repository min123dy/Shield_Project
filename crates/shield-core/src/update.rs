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

/// Name of the v2 manifest (3.1.0 final, `manifest2`), published next to the v1 one.
pub fn manifest2_name(v: Version) -> String {
    format!("Shield_v{v}_release_v2.txt")
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
    /// installer, its signature, v2 manifest, its signature (all four, or None: link only; a
    /// release without a v2 manifest is offered as a link only).
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
        let m = manifest2_name(ver);
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

/// The four files of an update on disk: installer, its signature, manifest, its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateFiles {
    pub pkg: PathBuf,
    pub pkg_sig: PathBuf,
    pub manifest: PathBuf,
    pub manifest_sig: PathBuf,
}

impl UpdateFiles {
    pub fn all(&self) -> [&Path; 4] {
        [&self.pkg, &self.pkg_sig, &self.manifest, &self.manifest_sig]
    }
}

/// A downloaded and (unprivileged, for the dialog) verified installer in a private folder.
#[derive(Debug)]
pub struct Downloaded {
    pub dir: PathBuf,
    pub files: UpdateFiles,
    /// "msi", "deb" or "AppImage".
    pub kind: &'static str,
    pub version: Version,
    pub signer: Verified,
    /// SHA-256 the signed manifest lists for the installer.
    pub sha256: [u8; 32],
}

fn kind_of(name: &str) -> Option<&'static str> {
    ["msi", "deb", "AppImage"].into_iter().find(|k| name.ends_with(&format!(".{k}")))
}

/// Folder for update downloads (removed again by `cleanup`).
pub fn root() -> PathBuf {
    shield_platform::platform().temp_dir().join("shield-update")
}

/// Removes what earlier runs left (an MSI handed to msiexec is kept until the next start).
pub fn cleanup() {
    let _ = std::fs::remove_dir_all(root());
}

/// Every update signature (manifest and installer, unprivileged check and helper alike) is
/// checked with `Policy::Release`: binary signatures only, by a key still valid today
/// (3.1.0 review 2 #2).
fn verify_release(certs: &[Cert], data: &[u8], sig: &[u8]) -> Result<Verified, String> {
    crate::sigverify::verify_any_with(certs, data, sig, crate::sigverify::Policy::Release)
}

/// Checks a manifest, its signature, an installer and its signature, all already in hand.
/// Unprivileged check (for the "install?" dialog and to fail early). It is NOT what an
/// installation relies on: the files stay in a user-writable folder and could be swapped after
/// this check; the privileged helper copies and verifies them again (`verify_copies`, 3.1.0 #1).
#[allow(clippy::too_many_arguments)]
pub fn verify_set(cert: &Cert, r: &Release, manifest: &[u8], manifest_sig: &[u8], pkg: &Path, pkg_sig: &[u8], pkg_sha: [u8; 32], now: i64) -> Result<Verified, String> {
    verify_set_any(std::slice::from_ref(cert), r, manifest, manifest_sig, pkg, pkg_sig, pkg_sha, now)
}

/// Parses a v2 manifest whose signature `sig` already verified and applies the stateless checks
/// (`manifest2::check`): validity window at `now`, versions against `current`, signer not revoked.
pub fn checked_manifest2(manifest: &[u8], file: &str, sig: &Verified, current: Version, now: i64) -> Result<crate::manifest2::Manifest, String> {
    let text = std::str::from_utf8(manifest).map_err(|_| msg("upd.bad_manifest"))?;
    let m = crate::manifest2::parse(text, file)?;
    crate::manifest2::check(&m, now, current, &sig.fingerprint)?;
    Ok(m)
}

/// `verify_set` accepting a signature by any of `certs` (main and backup release key).
#[allow(clippy::too_many_arguments)]
pub fn verify_set_any(certs: &[Cert], r: &Release, manifest: &[u8], manifest_sig: &[u8], pkg: &Path, pkg_sig: &[u8], pkg_sha: [u8; 32], now: i64) -> Result<Verified, String> {
    let [p, ..] = r.files.as_ref().ok_or_else(|| msg("upd.no_package"))?;
    let ms = verify_release(certs, manifest, manifest_sig).map_err(|x| msgf("upd.sig_failed", x))?;
    let m = checked_manifest2(manifest, &p.name, &ms, Version::current(), now)?;
    if m.version != r.version {
        return Err(msgf("upd.version_mismatch", m.version));
    }
    let want = m.sha256;
    if !crate::password::ct_eq(&want, &pkg_sha) {
        return Err(msg("upd.hash_mismatch"));
    }
    let data = shield_platform::bounded::read_file_limited(pkg, MAX_PACKAGE).map_err(|x| x.to_string())?;
    verify_release(certs, &data, pkg_sig).map_err(|x| msgf("upd.sig_failed", x))
}

/// Downloads and verifies `r` with the embedded keys. Nothing is run; on any failure the files
/// are deleted. All four files stay in the private download folder for the privileged helper.
pub fn download(r: &Release, progress: &dyn Fn(u64, u64), cancel: &dyn Fn() -> bool) -> Result<Downloaded, String> {
    let certs = crate::buildinfo::release_keys();
    if certs.is_empty() {
        return Err(msg("upd.no_key"));
    }
    let [p, ps, m, ms] = r.files.as_ref().ok_or_else(|| msg("upd.no_package"))?;
    if p.size > MAX_PACKAGE {
        return Err(msgf("upd.too_big", crate::ui_fmt::human(MAX_PACKAGE)));
    }
    let kind = kind_of(&p.name).ok_or_else(|| msg("upd.no_package"))?;
    // the names come from the release and end up in paths: they must be plain file names
    if [p, ps, m, ms].iter().any(|a| crate::engine::safe_name(&a.name).is_none()) {
        return Err(msg("upd.bad_answer"));
    }
    let base = root();
    // reused only when it is this user's private folder: in a folder somebody else controls the
    // verified package could be swapped before it is installed (security review 2026-11-08)
    crate::sysinfo::ensure_private_dir(&base).map_err(|x| x.to_string())?;
    let dir = base.join(format!("dl-{}", crate::entropy::rand_hex()?));
    crate::sysinfo::create_private_dir(&dir).map_err(|x| x.to_string())?;
    let path = dir.join(&p.name);
    let files = UpdateFiles { pkg: path.clone(), pkg_sig: dir.join(&ps.name), manifest: dir.join(&m.name), manifest_sig: dir.join(&ms.name) };
    let res = (|| {
        let (manifest, manifest_sig, pkg_sig) = (fetch_small(&m.url)?, fetch_small(&ms.url)?, fetch_small(&ps.url)?);
        // check the manifest before the large download
        let ms = verify_release(certs, &manifest, &manifest_sig).map_err(|x| msgf("upd.sig_failed", x))?;
        let m2 = checked_manifest2(&manifest, &p.name, &ms, Version::current(), crate::manifest2::now())?;
        if m2.version != r.version {
            return Err(msgf("upd.version_mismatch", m2.version));
        }
        // rollback state (manifest2 module docs): refuse what is older than seen, then remember
        if let Ok(sp) = crate::manifest2::seen_path() {
            let seen = crate::manifest2::load_seen(&sp);
            seen.check(&m2, &ms.fingerprint)?;
            let _ = crate::manifest2::save_seen(&sp, &seen.merged(&m2));
        }
        for (p, b) in [(&files.manifest, &manifest), (&files.manifest_sig, &manifest_sig), (&files.pkg_sig, &pkg_sig)] {
            let mut f = crate::sysinfo::create_private_file(p).map_err(|x| x.to_string())?;
            f.write_all(b).and_then(|()| f.sync_all()).map_err(|x| x.to_string())?;
        }
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
        let sha256: [u8; 32] = h.finalize().into();
        let signer = verify_set_any(certs, r, &manifest, &manifest_sig, &path, &pkg_sig, sha256, crate::manifest2::now())?;
        Ok(Downloaded { dir: dir.clone(), files: files.clone(), kind, version: r.version, signer, sha256 })
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
///
/// msi / deb (3.1.0 #1): the privileged helper gets the four files, copies them where only it
/// can write, verifies the copies itself and installs the copy. Its answer tells "signature or
/// hash refused" (`upd.rejected`) apart from "the user declined the prompt" (`upd.declined`).
/// AppImage (no privileges): replaced in place, the copy re-checked against the manifest hash.
/// The download folder is removed in every case (the helper works on its own copies).
pub fn install(d: Downloaded) -> Result<Installed, String> {
    crate::entropy::clear_pool();
    let r = if d.kind == "AppImage" {
        let want = d.sha256;
        let check = move |p: &Path| sha256_file(p).is_ok_and(|h| crate::password::ct_eq(&h, &want));
        shield_platform::sys::install_package(&d.files.pkg, &check).map_err(|x| match x {
            shield_platform::PlatformError::Declined => msg("upd.declined"),
            x => msgf("upd.install_failed", x),
        })
    } else {
        match shield_platform::sys::run_update_helper(&d.files.all()) {
            Ok(code) => helper_outcome(code, d.kind),
            Err(shield_platform::PlatformError::Declined) => Err(msg("upd.declined")),
            Err(x) => Err(msgf("upd.install_failed", x)),
        }
    };
    let _ = std::fs::remove_dir_all(&d.dir);
    r
}

fn sha256_file(p: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut HashOnly(&mut h))?;
    Ok(h.finalize().into())
}

struct HashOnly<'a>(&'a mut Sha256);
impl Write for HashOnly<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Exit codes of the privileged helper (`helper_main`). Chosen apart from pkexec's 126/127 and
/// msiexec's codes; the helper itself never passes on another program's code.
pub mod helper_code {
    /// Verified; installed (deb) or the installer was started (msi).
    pub const OK: i32 = 0;
    pub const BAD_ARGS: i32 = 80;
    pub const NOT_PRIVILEGED: i32 = 81;
    /// Signature, hash, version or package name of the copies refused.
    pub const REJECTED: i32 = 82;
    pub const IO: i32 = 83;
    /// The package manager reported a failure.
    pub const INSTALL: i32 = 84;
}

/// Maps the helper's exit code (or pkexec's, which runs it) to the user's message.
pub fn helper_outcome(code: i32, kind: &str) -> Result<Installed, String> {
    match code {
        helper_code::OK if kind == "msi" => Ok(Installed::ExitNow),
        helper_code::OK => Ok(Installed::Done),
        helper_code::REJECTED => Err(msg("upd.rejected")),
        // pkexec: 126 = dialog dismissed / not authorized, 127 = authentication failed
        126 | 127 => Err(msg("upd.declined")),
        c => Err(msgf("upd.helper_failed", c)),
    }
}

/// Checks the helper's command line: exactly four absolute paths (installer, its signature,
/// manifest, its signature) of existing regular files - no links, junctions or other reparse
/// points - within the size limits (installer MAX_PACKAGE, the rest MAX_SMALL). Everything the
/// unprivileged caller passes is untrusted; this only rejects the obviously wrong early, the
/// real checks run on the copies.
/// 3.1.0 review 2 #1: each file must also belong to the user who started the helper
/// (`shield_platform::sys::update_input_owner_ok`; Linux: PKEXEC_UID), so the helper never reads
/// a file that user could not read. Every refusal of an existing path reads the same ("not a
/// usable update file"), whether the path is missing, someone else's, a folder or too large: the
/// root helper does not tell the caller what exists where it cannot look.
pub fn parse_helper_args(args: &[String]) -> Result<UpdateFiles, String> {
    let [p, ps, m, ms] = args else { return Err(format!("expected 4 paths, got {}", args.len())) };
    for (a, max) in [(p, MAX_PACKAGE), (ps, MAX_SMALL), (m, MAX_SMALL), (ms, MAX_SMALL)] {
        let path = Path::new(a);
        if !path.is_absolute() || a.contains('"') {
            return Err(format!("not an absolute path: {a}"));
        }
        let usable = std::fs::symlink_metadata(path).is_ok_and(|md| {
            !md.file_type().is_symlink() && !crate::sysinfo::is_reparse(&md) && md.is_file() && md.len() <= max && shield_platform::sys::update_input_owner_ok(&md)
        });
        if !usable {
            return Err(format!("not a usable update file: {a}"));
        }
    }
    Ok(UpdateFiles { pkg: p.into(), pkg_sig: ps.into(), manifest: m.into(), manifest_sig: ms.into() })
}

/// Reads `p` through one no-follow handle: a regular file (not a link or reparse point) of at
/// most `max` bytes, checked on the handle and while reading.
pub fn read_no_follow(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    read_checked(p, max, &|_| true)
}

/// `read_no_follow` that also requires `owner_ok` on the opened handle's metadata.
fn read_checked(p: &Path, max: u64, owner_ok: &dyn Fn(&std::fs::Metadata) -> bool) -> Result<Vec<u8>, String> {
    let f = crate::sysinfo::open_no_follow(p, false).map_err(|x| format!("{}: {x}", p.display()))?;
    let id = crate::sysinfo::file_id(&f).map_err(|x| x.to_string())?;
    let md = f.metadata().map_err(|x| x.to_string())?;
    if id.special || !md.is_file() || md.len() > max || !owner_ok(&md) {
        return Err(format!("{}: not a usable update file", p.display()));
    }
    shield_platform::bounded::read_limited(&f, max).map_err(|x| if x.kind() == std::io::ErrorKind::FileTooLarge { format!("{}: grew past the size limit", p.display()) } else { x.to_string() })
}

/// Name of the installer copy in the private folder (the platform installs only this name);
/// None: this kind is never installed with privileges.
pub fn copy_name(kind: &str) -> Option<&'static str> {
    match kind {
        "msi" => Some("package.msi"),
        "deb" => Some("package.deb"),
        _ => None,
    }
}

/// The privileged copies and the installer's original name (the key looked up in the manifest).
#[derive(Debug)]
pub struct UpdateCopies {
    pub files: UpdateFiles,
    pub pkg_name: String,
}

/// Step 1-2 of the helper: reads the four (untrusted) files without following links and writes
/// their bytes as NEW files into `dest`, a folder only the privileged side can write. From here on
/// only the copies are used; the originals are never opened again. The owner of each original is
/// checked again on the opened handle (3.1.0 review 2 #1), and the copies are readable by the
/// privileged side only until they are verified (Linux 0600; `install_from_private` opens the
/// verified package to apt).
pub fn copy_inputs(src: &UpdateFiles, dest: &Path, kind: &str) -> Result<UpdateCopies, String> {
    let pkg_file = copy_name(kind).ok_or_else(|| format!("no privileged installation for {kind}"))?;
    let pkg_name = src.pkg.file_name().and_then(|n| n.to_str()).ok_or("installer name")?.to_string();
    let files = UpdateFiles { pkg: dest.join(pkg_file), pkg_sig: dest.join("package.sig"), manifest: dest.join("manifest.txt"), manifest_sig: dest.join("manifest.sig") };
    for (from, to, max) in [(&src.pkg, &files.pkg, MAX_PACKAGE), (&src.pkg_sig, &files.pkg_sig, MAX_SMALL), (&src.manifest, &files.manifest, MAX_SMALL), (&src.manifest_sig, &files.manifest_sig, MAX_SMALL)] {
        let bytes = read_checked(from, max, &shield_platform::sys::update_input_owner_ok)?;
        let mut f = shield_platform::sys::create_update_file(to).map_err(|x| format!("{}: {x}", to.display()))?;
        f.write_all(&bytes).and_then(|()| f.sync_all()).map_err(|x| format!("{}: {x}", to.display()))?;
    }
    Ok(UpdateCopies { files, pkg_name })
}

/// Step 3 of the helper, on the copies only: manifest signature, installer name = this
/// platform's package name for the manifest's version, that version newer than `current` (the
/// helper's own build, never a value from the caller), installer SHA-256 as listed, installer
/// signature. `certs`: the helper's own embedded keys.
pub fn verify_copies(c: &UpdateCopies, certs: &[Cert], current: Version, kind: &str, now: i64) -> Result<Verified, String> {
    let f = &c.files;
    let manifest = read_no_follow(&f.manifest, MAX_SMALL)?;
    let ms = verify_release(certs, &manifest, &read_no_follow(&f.manifest_sig, MAX_SMALL)?).map_err(|x| msgf("upd.sig_failed", x))?;
    let m = checked_manifest2(&manifest, &c.pkg_name, &ms, current, now)?;
    let (mver, want) = (m.version, m.sha256);
    if package_name(mver, kind).as_deref() != Some(c.pkg_name.as_str()) {
        return Err(msgf("upd.not_in_manifest", &c.pkg_name));
    }
    let pkg = read_no_follow(&f.pkg, MAX_PACKAGE)?;
    let got: [u8; 32] = Sha256::digest(&pkg).into();
    if !crate::password::ct_eq(&got, &want) {
        return Err(msg("upd.hash_mismatch"));
    }
    verify_release(certs, &pkg, &read_no_follow(&f.pkg_sig, MAX_SMALL)?).map_err(|x| msgf("upd.sig_failed", x))
}

/// Entry point of the privileged helper (Windows: the installed `shield-gui.exe --install-update
/// ...`, started elevated; Linux: `pkexec /usr/bin/shield update-install ...`). Runs only
/// elevated / as root from pkexec. Copies, verifies the copies with its own keys and version, and
/// installs the copy (`verify_and_install_privileged`). Returns a `helper_code`.
pub fn helper_main(args: &[String]) -> i32 {
    if !shield_platform::sys::update_helper_allowed() {
        eprintln!("shield update helper: must run elevated / as root through pkexec");
        return helper_code::NOT_PRIVILEGED;
    }
    let files = match parse_helper_args(args) {
        Ok(f) => f,
        Err(x) => {
            eprintln!("shield update helper: {x}");
            return helper_code::BAD_ARGS;
        }
    };
    match verify_and_install_privileged(&files) {
        Ok(()) => helper_code::OK,
        Err((code, x)) => {
            eprintln!("shield update helper: {x}");
            code
        }
    }
}

/// 3.1.0 #1, called in the privileged process only: copy to the private folder -> verify the
/// copies -> install from the copy. The private folder is removed on failure (and after the
/// installation; on Windows by the second stage once msiexec is done).
pub fn verify_and_install_privileged(src: &UpdateFiles) -> Result<(), (i32, String)> {
    let kind = shield_platform::sys::package_kind().filter(|k| copy_name(k).is_some()).ok_or((helper_code::BAD_ARGS, "no privileged installation here".to_string()))?;
    let certs = crate::buildinfo::release_keys();
    if certs.is_empty() {
        return Err((helper_code::REJECTED, msg("upd.no_key")));
    }
    let name = crate::entropy::rand_hex().map_err(|x| (helper_code::IO, x))?;
    let dest = shield_platform::sys::update_private_dir(&name).map_err(|x| (helper_code::IO, x.to_string()))?;
    let res = (|| {
        let copies = copy_inputs(src, &dest, kind).map_err(|x| (helper_code::IO, x))?;
        let now = crate::manifest2::now();
        verify_copies(&copies, certs, Version::current(), kind, now).map_err(|x| (helper_code::REJECTED, x))?;

        // Re-apply the monotonic rollback floor in the elevated context. The per-user state is
        // useful for early rejection but is not trusted by this privilege boundary; this copy is
        // stored under ProgramData / /var/lib with a SYSTEM+Administrators / root-only ACL.
        let manifest_bytes = read_no_follow(&copies.files.manifest, MAX_SMALL).map_err(|x| (helper_code::REJECTED, x))?;
        let manifest_sig = read_no_follow(&copies.files.manifest_sig, MAX_SMALL).map_err(|x| (helper_code::REJECTED, x))?;
        let manifest_verified = verify_release(certs, &manifest_bytes, &manifest_sig).map_err(|x| (helper_code::REJECTED, msgf("upd.sig_failed", x)))?;
        let manifest_text = std::str::from_utf8(&manifest_bytes).map_err(|_| (helper_code::REJECTED, msg("upd.bad_manifest")))?;
        let m = crate::manifest2::parse(manifest_text, &copies.pkg_name).map_err(|x| (helper_code::REJECTED, x))?;
        crate::manifest2::check(&m, now, Version::current(), &manifest_verified.fingerprint).map_err(|x| (helper_code::REJECTED, x))?;
        let state_path = shield_platform::sys::update_state_path().map_err(|x| (helper_code::IO, x.to_string()))?;
        // Serialize the complete check -> persist -> install sequence. Without this lock, two
        // concurrent helpers could both read the same old floor and the slower one could replace
        // a newer floor with an older release_id.
        let _state_lock = crate::manifest2::lock_machine_seen(&state_path).map_err(|x| (helper_code::IO, x))?;
        let seen = crate::manifest2::load_machine_seen(&state_path).map_err(|x| (helper_code::IO, x))?;
        seen.check(&m, &manifest_verified.fingerprint).map_err(|x| (helper_code::REJECTED, x))?;
        crate::manifest2::save_machine_seen(&state_path, &seen.merged(&m)).map_err(|x| (helper_code::IO, x))?;

        match shield_platform::sys::install_from_private(&copies.files.pkg, &dest) {
            Ok(0) => Ok(()),
            Ok(c) => Err((helper_code::INSTALL, format!("package manager exit code {c}"))),
            Err(x) => Err((helper_code::IO, x.to_string())),
        }
    })();
    if res.is_err() {
        shield_platform::sys::remove_private_dir(&dest);
    }
    res
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
