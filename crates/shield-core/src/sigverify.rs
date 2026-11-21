//! OpenPGP detached signatures (design 3.0 §4): integrity check of Shield itself, `shield verify`,
//! and the release signatures of updates.
//!
//! rPGP (pure Rust) parses keys and signatures and performs every RFC 9580 check (issuer match,
//! signed-hash prefix, hash strength, text normalisation, key binding signatures). rPGP has no
//! brainpool arithmetic, so for ECDSA keys on brainpoolP256r1 / brainpoolP384r1 the final
//! "is this (r, s) valid for this digest" step is done by RustCrypto's `bp256` / `bp384` (`ecdsa`
//! `verify_prehash`). No signature code is written here: this file only connects the two.
//! brainpoolP512r1 has no maintained pure-Rust implementation yet and is refused explicitly.
//!
//! Policy on top: only binary-document (0x00) and text (0x01) signatures, no MD5 / SHA-1 /
//! RIPEMD-160, and the signing (sub)key must belong to the given certificate with valid bindings.
//! Updates use the stricter `Policy::Release` (3.1.0 review 2 #2): binary signatures only, and
//! the signing key must still be unexpired today, not only when the signature says it was made
//! (that time is chosen by whoever signs, so a leaked key that has since expired could otherwise
//! back-date a signature).

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{EcdsaPublicParams, Fingerprint, KeyDetails, KeyId, KeyVersion, PublicParams, SignatureBytes, Timestamp, VerifyingKey};
use std::io::{Cursor, Read, Seek, SeekFrom};

/// Largest signed file accepted (installers, archives). Files are read as a stream, not held in
/// memory (3.1.0 review 3).
pub const MAX_DATA: u64 = 2 << 30;
/// Largest detached signature file (read with this limit on the open handle, 3.1.0 review 3).
pub const MAX_SIG: u64 = 64 * 1024;
/// Largest certificate (public key) file read from disk (`shield verify --key`, 3.1.0 review 3).
pub const MAX_CERT: u64 = 1 << 20;

/// The signed document: bytes in memory or an open file, read from the start for each key that
/// is tried.
trait Doc: Read + Seek {}
impl<T: Read + Seek> Doc for T {}

/// `ds` is a good signature by `key` over the whole document (at most MAX_DATA bytes: a file that
/// grew past it after the size check is cut there, and its signature then fails).
fn sig_ok(ds: &DetachedSignature, key: &impl VerifyingKey, doc: &mut dyn Doc) -> bool {
    doc.seek(SeekFrom::Start(0)).is_ok() && ds.signature.verify(key, (&mut *doc).take(MAX_DATA + 1)).is_ok()
}

/// A certificate (public key with its subkeys), checked when parsed.
#[derive(Clone, Debug)]
pub struct Cert {
    key: SignedPublicKey,
}

/// What a good signature tells the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Primary key fingerprint (grouped hex).
    pub fingerprint: String,
    /// Fingerprint of the (sub)key that made the signature.
    pub signer: String,
    /// Signature creation time (Unix seconds) when present.
    pub created: Option<i64>,
    /// Which of the keys given to `verify_any` made it (0 = the main release key, 1 = backup).
    pub key_index: usize,
}

/// Which signatures count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `shield verify` and the self-check: binary or text signature; the key must not have
    /// expired before the signature was made.
    Any,
    /// Update files: binary (0x00) signatures only, and the key (primary and signing subkey) must
    /// also be unexpired now.
    Release,
}

/// Verifies with each certificate in turn (main release key first, then the backup key; 3.1.0
/// #3). The first good signature wins and records which key it was. When none verifies, the most
/// telling error is returned: one from a key that matched but was refused (expired, revoked, no
/// signing right) rather than plain "does not match".
pub fn verify_any(certs: &[Cert], data: &[u8], sig: &[u8]) -> Result<Verified, String> {
    verify_any_with(certs, data, sig, Policy::Any)
}

/// `verify_any` under `policy`.
pub fn verify_any_with(certs: &[Cert], data: &[u8], sig: &[u8], policy: Policy) -> Result<Verified, String> {
    verify_doc_any(certs, &mut Cursor::new(data), sig, policy)
}

fn verify_doc_any(certs: &[Cert], doc: &mut dyn Doc, sig: &[u8], policy: Policy) -> Result<Verified, String> {
    let mut best: Option<String> = None;
    for (i, c) in certs.iter().enumerate() {
        match c.verify_doc(doc, sig, policy) {
            Ok(v) => return Ok(Verified { key_index: i, ..v }),
            Err(x) if x != crate::i18n::t("sig.invalid") && best.as_ref().is_none_or(|b| b == crate::i18n::t("sig.invalid")) => best = Some(x),
            Err(x) => {
                best.get_or_insert(x);
            }
        }
    }
    Err(best.unwrap_or_else(|| crate::i18n::t("upd.no_key").to_string()))
}

/// `verify_any` over a file (at most MAX_DATA bytes, read as a stream) and its signature file
/// (at most MAX_SIG bytes).
pub fn verify_file_any(certs: &[Cert], file: &std::path::Path, sig_file: &std::path::Path) -> Result<Verified, String> {
    let (mut f, sig) = open_pair(file, sig_file)?;
    verify_doc_any(certs, &mut f, &sig, Policy::Any)
}

/// 3.1.0 review 3: the signature file is read with its limit on the open handle (3.1.0 first
/// read it whole and checked its size afterwards), and the signed file is opened and checked on
/// its handle (regular file, at most MAX_DATA) and then streamed instead of read into memory.
fn open_pair(file: &std::path::Path, sig_file: &std::path::Path) -> Result<(std::fs::File, Vec<u8>), String> {
    use shield_platform::bounded;
    let f = bounded::open_read(file).map_err(|x| err("sig.read", x))?;
    let md = f.metadata().map_err(|x| err("sig.read", x))?;
    if !md.is_file() {
        return Err(err("sig.read", "not a regular file"));
    }
    if md.len() > MAX_DATA {
        return Err(err("sig.too_big", crate::ui_fmt::human(MAX_DATA)));
    }
    let sig = bounded::read_file_limited(sig_file, MAX_SIG).map_err(|x| if x.kind() == std::io::ErrorKind::FileTooLarge { err("sig.bad_sig", "size") } else { err("sig.read", x) })?;
    Ok((f, sig))
}

/// Uppercase hex in groups of four ("8898 D3D9 ...").
pub fn group_fpr(f: &Fingerprint) -> String {
    let h: String = f.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
    h.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

/// rPGP's key with brainpool ECDSA verification added (everything else is delegated).
#[derive(Debug)]
struct Bp<'a, K>(&'a K);

impl<K: KeyDetails> KeyDetails for Bp<'_, K> {
    fn version(&self) -> KeyVersion {
        self.0.version()
    }
    fn legacy_key_id(&self) -> KeyId {
        self.0.legacy_key_id()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.0.algorithm()
    }
    fn created_at(&self) -> Timestamp {
        self.0.created_at()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.0.legacy_v3_expiration_days()
    }
    fn public_params(&self) -> &PublicParams {
        self.0.public_params()
    }
}

impl<K: pgp::ser::Serialize> pgp::ser::Serialize for Bp<'_, K> {
    fn to_writer<W: std::io::Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
        self.0.to_writer(w)
    }
    fn write_len(&self) -> usize {
        self.0.write_len()
    }
}

fn mpi_pad<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    let b = &b[b.iter().position(|x| *x != 0).unwrap_or(b.len())..];
    (b.len() <= N).then(|| {
        let mut o = [0u8; N];
        o[N - b.len()..].copy_from_slice(b);
        o
    })
}

/// (curve, SEC1 point) of a brainpool ECDSA key. rPGP keeps the MPI with its 2-byte bit length.
fn brainpool(p: &PublicParams) -> Option<(ECCCurve, &[u8])> {
    let PublicParams::ECDSA(EcdsaPublicParams::Unsupported { curve, opaque }) = p else { return None };
    let point = opaque.get(2..)?;
    matches!(curve, ECCCurve::BrainpoolP256r1 | ECCCurve::BrainpoolP384r1 | ECCCurve::BrainpoolP512r1).then(|| (curve.clone(), point))
}

fn bad() -> pgp::errors::Error {
    std::io::Error::other("brainpool signature invalid").into()
}

/// ECDSA prehash verification on one brainpool curve (`$c` = curve crate, `$n` = scalar bytes).
macro_rules! bp_verify {
    ($c:ident, $curve:ident, $n:literal, $point:expr, $digest:expr, $r:expr, $s:expr) => {{
        use ecdsa::signature::hazmat::PrehashVerifier;
        let vk = ecdsa::VerifyingKey::<$c::$curve>::from_sec1_bytes($point).map_err(|_| bad())?;
        let (Some(r), Some(s)) = (mpi_pad::<$n>($r), mpi_pad::<$n>($s)) else { return Err(bad()) };
        let sig = ecdsa::Signature::<$c::$curve>::from_scalars($c::FieldBytes::from(r), $c::FieldBytes::from(s)).map_err(|_| bad())?;
        vk.verify_prehash($digest, &sig).map_err(|_| bad())
    }};
}

impl<K: VerifyingKey> VerifyingKey for Bp<'_, K> {
    fn verify(&self, hash: HashAlgorithm, digest: &[u8], sig: &SignatureBytes) -> pgp::errors::Result<()> {
        let Some((curve, point)) = brainpool(self.0.public_params()) else {
            return self.0.verify(hash, digest, sig);
        };
        let SignatureBytes::Mpis(m) = sig else { return Err(std::io::Error::other("unexpected signature encoding").into()) };
        let [r, s] = m.as_slice() else { return Err(std::io::Error::other("unexpected signature encoding").into()) };
        match curve {
            ECCCurve::BrainpoolP256r1 => bp_verify!(bp256, BrainpoolP256r1, 32, point, digest, r.as_ref(), s.as_ref()),
            ECCCurve::BrainpoolP384r1 => bp_verify!(bp384, BrainpoolP384r1, 48, point, digest, r.as_ref(), s.as_ref()),
            _ => Err(std::io::Error::other("brainpoolP512r1 is not supported").into()),
        }
    }
}

/// A signing subkey counts only with a valid binding signature by the primary key that allows
/// signing, a valid back-signature by the subkey (RFC 9580 5.2.1), and no valid revocation.
/// Same checks as rPGP's `verify_bindings`, with the subkey wrapped so brainpool works. Returns
/// the newest such binding (its key expiration applies to the subkey, 3.1.0 #3).
fn subkey_bound<'s, P: VerifyingKey + pgp::ser::Serialize>(primary: &P, sub: &'s pgp::composed::SignedPublicSubKey) -> Result<&'s pgp::packet::Signature, String> {
    use pgp::packet::SignatureType;
    let sk = Bp(&sub.key);
    let mut bound: Option<&pgp::packet::Signature> = None;
    for sig in &sub.signatures {
        let valid = sig.verify_subkey_binding(primary, &sk).is_ok();
        match sig.typ() {
            Some(SignatureType::SubkeyRevocation) if valid => return Err(crate::i18n::t("sig.revoked").to_string()),
            Some(SignatureType::SubkeyBinding)
                if valid
                    && sig.key_flags().sign()
                    && sig.embedded_signature().is_some_and(|b| b.verify_primary_key_binding(&sk, primary).is_ok())
                    && bound.is_none_or(|b| secs(b.created()) < secs(sig.created())) =>
            {
                bound = Some(sig);
            }
            _ => {}
        }
    }
    bound.ok_or_else(|| err("sig.bad_key", "subkey binding"))
}

fn secs(t: Option<Timestamp>) -> i64 {
    t.map(|t| t.as_secs() as i64).unwrap_or(0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// A signature may be made at most this far "in the future" (clock differences).
pub const MAX_CLOCK_SKEW: i64 = 24 * 3600;

/// The newest self-signature on the primary key (direct-key or user-ID certification issued by
/// the primary itself). Its key flags and key expiration describe the primary key. Every one of
/// them was verified by `verify_bindings` when the certificate was parsed.
fn primary_self_sig(key: &SignedPublicKey) -> Option<&pgp::packet::Signature> {
    use pgp::packet::SignatureType as T;
    let (fp, id) = (key.primary_key.fingerprint(), key.primary_key.legacy_key_id());
    let own = |s: &&pgp::packet::Signature| s.issuer_fingerprint().contains(&&fp) || s.issuer_key_id().contains(&&id);
    key.details
        .direct_signatures
        .iter()
        .chain(key.details.users.iter().flat_map(|u| u.signatures.iter()))
        .filter(|s| matches!(s.typ(), Some(T::Key | T::CertGeneric | T::CertPersona | T::CertCasual | T::CertPositive)))
        .filter(own)
        .max_by_key(|s| secs(s.created()))
}

/// When a key made at `key_created` with this self/binding signature expires (None: never).
fn expires_at(key_created: i64, binding: Option<&pgp::packet::Signature>) -> Option<i64> {
    binding.and_then(|b| b.key_expiration_time()).map(|d| d.as_secs() as i64).filter(|d| *d > 0).map(|d| key_created + d)
}

/// The time rules rPGP's `verify` leaves to the caller (checked in its 0.21 source: it verifies
/// issuer, hash strength, hash prefix and the signature value, nothing about time; 3.1.0 #3):
/// a creation time is present, not before the signing key was made, at most a day in the
/// future; the signature has not expired; the signing key (and the primary) had not expired when
/// the signature was made. Errors carry [E_SIGTIME] and mention the system clock.
fn check_times(created: Option<i64>, sig_expiration: Option<i64>, signer_created: i64, key_expires: &[Option<i64>], now: i64) -> Result<(), String> {
    let created = created.ok_or_else(|| err("sig.bad_sig", "no creation time"))?;
    let coded = |key: &'static str| format!("{} [{SIGTIME}]", crate::i18n::t(key));
    if created < signer_created {
        return Err(coded("sig.before_key"));
    }
    if created > now + MAX_CLOCK_SKEW {
        return Err(coded("sig.future"));
    }
    if let Some(d) = sig_expiration.filter(|d| *d > 0) {
        if created + d <= now {
            return Err(coded("sig.expired"));
        }
    }
    if key_expires.iter().flatten().any(|e| *e <= created) {
        return Err(coded("sig.key_expired"));
    }
    Ok(())
}

/// `Policy::Release`: no key in `key_expires` may have expired by `now` either.
fn check_key_now(key_expires: &[Option<i64>], now: i64) -> Result<(), String> {
    if key_expires.iter().flatten().any(|e| *e <= now) {
        return Err(format!("{} [{SIGTIME}]", crate::i18n::t("sig.key_expired_now")));
    }
    Ok(())
}

/// Code of the time / expiry failures above (the system clock may be wrong).
pub const SIGTIME: &str = "E_SIGTIME";

fn err(key: &'static str, x: impl std::fmt::Display) -> String {
    crate::i18n::tf(key, &[&x])
}

impl Cert {
    /// Parses an armored (`.asc`) or binary certificate and checks its binding signatures.
    pub fn parse(bytes: &[u8]) -> Result<Cert, String> {
        let key = if bytes.trim_ascii_start().starts_with(b"-----BEGIN") {
            SignedPublicKey::from_armor_single(Cursor::new(bytes)).map(|k| k.0)
        } else {
            SignedPublicKey::from_bytes(Cursor::new(bytes))
        }
        .map_err(|x| err("sig.bad_key", x))?;
        key.details.verify_bindings(&Bp(&key.primary_key)).map_err(|x| err("sig.bad_key", x))?;
        // verify_bindings checked every revocation signature, so any left means "revoked"
        if !key.details.revocation_signatures.is_empty() {
            return Err(crate::i18n::t("sig.revoked").to_string());
        }
        Ok(Cert { key })
    }

    /// Reads a certificate file (at most MAX_CERT bytes, limit applied on the open handle).
    pub fn from_file(p: &std::path::Path) -> Result<Cert, String> {
        let b = shield_platform::bounded::read_file_limited(p, MAX_CERT).map_err(|x| err("sig.read", x))?;
        Cert::parse(&b)
    }

    pub fn fingerprint(&self) -> String {
        group_fpr(&self.key.primary_key.fingerprint())
    }

    /// Fingerprint without spaces (for comparisons with a pinned value).
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint().replace(' ', "")
    }

    /// Verifies a detached signature (armored or binary) over `data` (`Policy::Any`).
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<Verified, String> {
        self.verify_with(data, sig, Policy::Any)
    }

    /// Verifies a detached signature (armored or binary) over `data` under `policy`.
    pub fn verify_with(&self, data: &[u8], sig: &[u8], policy: Policy) -> Result<Verified, String> {
        self.verify_doc(&mut Cursor::new(data), sig, policy)
    }

    fn verify_doc(&self, doc: &mut dyn Doc, sig: &[u8], policy: Policy) -> Result<Verified, String> {
        let ds = if sig.trim_ascii_start().starts_with(b"-----BEGIN") {
            DetachedSignature::from_armor_single(Cursor::new(sig)).map(|s| s.0)
        } else {
            DetachedSignature::from_bytes(Cursor::new(sig))
        }
        .map_err(|x| err("sig.bad_sig", x))?;
        let s = &ds.signature;
        let cfg = s.config().ok_or_else(|| err("sig.bad_sig", "v3/unknown"))?;
        if matches!(cfg.hash_alg, HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160) {
            return Err(err("sig.weak_hash", format!("{:?}", cfg.hash_alg)));
        }
        let binary_only = policy == Policy::Release;
        if !matches!(s.typ(), Some(pgp::packet::SignatureType::Binary)) && (binary_only || !matches!(s.typ(), Some(pgp::packet::SignatureType::Text))) {
            return Err(err("sig.bad_sig", format!("{:?}", s.typ())));
        }
        self.verify_at(&ds, doc, now_secs(), policy)
    }

    fn verify_at(&self, ds: &DetachedSignature, doc: &mut dyn Doc, now: i64, policy: Policy) -> Result<Verified, String> {
        let strict = policy == Policy::Release;
        let s = &ds.signature;
        let created = s.created().map(|t| t.as_secs() as i64);
        let sig_exp = s.signature_expiration_time().map(|d| d.as_secs() as i64);
        let primary = Bp(&self.key.primary_key);
        let fpr = self.fingerprint();
        let p_created = self.key.primary_key.created_at().as_secs() as i64;
        let self_sig = primary_self_sig(&self.key);
        let p_expires = expires_at(p_created, self_sig);
        if sig_ok(ds, &primary, doc) {
            // signed by the primary directly: it must be allowed to sign (subkeys: subkey_bound)
            if !self_sig.is_some_and(|s| s.key_flags().sign()) {
                return Err(crate::i18n::t("sig.no_sign_flag").to_string());
            }
            check_times(created, sig_exp, p_created, &[p_expires], now)?;
            if strict {
                check_key_now(&[p_expires], now)?;
            }
            return Ok(Verified { fingerprint: fpr.clone(), signer: fpr, created, key_index: 0 });
        }
        for sub in &self.key.public_subkeys {
            let sk = Bp(&sub.key);
            if sig_ok(ds, &sk, doc) {
                let binding = subkey_bound(&primary, sub)?;
                let s_created = sub.key.created_at().as_secs() as i64;
                let exp = [p_expires, expires_at(s_created, Some(binding))];
                check_times(created, sig_exp, s_created, &exp, now)?;
                if strict {
                    check_key_now(&exp, now)?;
                }
                return Ok(Verified { fingerprint: fpr, signer: group_fpr(&sub.key.fingerprint()), created, key_index: 0 });
            }
        }
        Err(crate::i18n::t("sig.invalid").to_string())
    }

    /// Verifies `sig_file` (at most MAX_SIG bytes) over `file` (at most MAX_DATA bytes, streamed).
    pub fn verify_file(&self, file: &std::path::Path, sig_file: &std::path::Path) -> Result<Verified, String> {
        let (mut f, sig) = open_pair(file, sig_file)?;
        self.verify_doc(&mut f, &sig, Policy::Any)
    }

    /// Describes the key's structure for optional operational-hardening diagnostics. These
    /// properties are recommendations, not prerequisites for building or verifying releases.
    /// Only cryptographically valid key bindings are included.
    pub fn shape(&self) -> KeyShape {
        let primary = Bp(&self.key.primary_key);
        let p_created = self.key.primary_key.created_at().as_secs() as i64;
        let self_sig = primary_self_sig(&self.key);
        let signing_subkeys = self
            .key
            .public_subkeys
            .iter()
            .filter_map(|sub| subkey_bound(&primary, sub).ok().map(|b| expires_at(sub.key.created_at().as_secs() as i64, Some(b))))
            .collect();
        KeyShape {
            primary_signs: self_sig.is_some_and(|s| s.key_flags().sign()),
            primary_expires: expires_at(p_created, self_sig),
            signing_subkeys,
            user_ids: self.key.details.users.iter().map(|u| String::from_utf8_lossy(u.id.id()).into_owned()).collect(),
        }
    }
}

/// See [`Cert::shape`]. Times are Unix seconds; None: never expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyShape {
    /// The primary key itself may sign (the model wants it to certify only, kept offline).
    pub primary_signs: bool,
    pub primary_expires: Option<i64>,
    /// Valid, unrevoked subkeys allowed to sign: when each expires.
    pub signing_subkeys: Vec<Option<i64>>,
    pub user_ids: Vec<String>,
}

/// Mail domains of personal accounts: a release key's user ID should name the project instead.
const PERSONAL_MAIL: &[&str] = &[
    "gmail.com", "googlemail.com", "naver.com", "daum.net", "hanmail.net", "kakao.com", "nate.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.co.kr", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.de", "gmx.net", "mail.ru", "qq.com",
];

impl KeyShape {
    /// Optional hardening recommendations from docs/07 (empty: all recommendations are met), at `now`.
    /// Rules: a signing subkey that expires (within `max_life` seconds from `now`, not yet
    /// expired); the primary key does not sign itself; every user ID names Shield and none uses
    /// a personal mail domain.
    pub fn release_problems(&self, now: i64, max_life: i64) -> Vec<String> {
        let mut v = Vec::new();
        let subs: Vec<i64> = self.signing_subkeys.iter().flatten().copied().collect();
        if self.signing_subkeys.is_empty() {
            v.push("no signing subkey ([S]): CI must hold only a signing subkey, the primary stays offline".to_string());
        } else if subs.len() != self.signing_subkeys.len() {
            v.push("a signing subkey never expires: give it an expiry of 1-2 years".to_string());
        }
        if subs.iter().any(|e| *e <= now) {
            v.push("a signing subkey has expired".to_string());
        }
        if subs.iter().any(|e| *e > now + max_life) {
            v.push(format!("a signing subkey is valid for more than {} days", max_life / 86_400));
        }
        if self.primary_signs {
            v.push("the primary key may sign: it should only certify ([C]) and stay offline".to_string());
        }
        if self.user_ids.is_empty() {
            v.push("no user ID".to_string());
        }
        for u in &self.user_ids {
            let l = u.to_ascii_lowercase();
            if !l.contains("shield") {
                v.push(format!("user ID does not name the project: {u}"));
            }
            let domain = l.rsplit_once('@').map(|(_, d)| d.trim_end_matches('>').to_string());
            if domain.is_some_and(|d| PERSONAL_MAIL.contains(&d.as_str())) {
                v.push(format!("user ID uses a personal mail address: {u}"));
            }
        }
        v
    }
}

#[cfg(test)]
#[path = "sigverify_tests.rs"]
mod tests;
