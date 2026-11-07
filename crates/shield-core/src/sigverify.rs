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

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{EcdsaPublicParams, Fingerprint, KeyDetails, KeyId, KeyVersion, PublicParams, SignatureBytes, Timestamp, VerifyingKey};
use std::io::Cursor;

/// Accepted size of signed data held in memory (installers, archives).
pub const MAX_DATA: u64 = 2 << 30;

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
/// Same checks as rPGP's `verify_bindings`, with the subkey wrapped so brainpool works.
fn subkey_bound<P: VerifyingKey + pgp::ser::Serialize>(primary: &P, sub: &pgp::composed::SignedPublicSubKey) -> Result<(), String> {
    use pgp::packet::SignatureType;
    let sk = Bp(&sub.key);
    let mut bound = false;
    for sig in &sub.signatures {
        let valid = sig.verify_subkey_binding(primary, &sk).is_ok();
        match sig.typ() {
            Some(SignatureType::SubkeyRevocation) if valid => return Err(crate::i18n::t("sig.revoked").to_string()),
            Some(SignatureType::SubkeyBinding) if valid && sig.key_flags().sign() => {
                bound |= sig.embedded_signature().is_some_and(|b| b.verify_primary_key_binding(&sk, primary).is_ok());
            }
            _ => {}
        }
    }
    if bound { Ok(()) } else { Err(err("sig.bad_key", "subkey binding")) }
}

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

    pub fn fingerprint(&self) -> String {
        group_fpr(&self.key.primary_key.fingerprint())
    }

    /// Fingerprint without spaces (for comparisons with a pinned value).
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint().replace(' ', "")
    }

    /// Verifies a detached signature (armored or binary) over `data`.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<Verified, String> {
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
        if !matches!(s.typ(), Some(pgp::packet::SignatureType::Binary) | Some(pgp::packet::SignatureType::Text)) {
            return Err(err("sig.bad_sig", format!("{:?}", s.typ())));
        }
        let created = cfg.created().map(|t| t.as_secs() as i64);
        let primary = Bp(&self.key.primary_key);
        let fpr = self.fingerprint();
        if ds.verify(&primary, data).is_ok() {
            return Ok(Verified { fingerprint: fpr.clone(), signer: fpr, created });
        }
        for sub in &self.key.public_subkeys {
            let sk = Bp(&sub.key);
            if ds.verify(&sk, data).is_ok() {
                subkey_bound(&primary, sub)?;
                return Ok(Verified { fingerprint: fpr, signer: group_fpr(&sub.key.fingerprint()), created });
            }
        }
        Err(crate::i18n::t("sig.invalid").to_string())
    }

    /// Reads `file` (at most MAX_DATA bytes) and `sig_file` and verifies.
    pub fn verify_file(&self, file: &std::path::Path, sig_file: &std::path::Path) -> Result<Verified, String> {
        let n = std::fs::metadata(file).map_err(|x| err("sig.read", x))?.len();
        if n > MAX_DATA {
            return Err(err("sig.too_big", crate::ui_fmt::human(MAX_DATA)));
        }
        let data = std::fs::read(file).map_err(|x| err("sig.read", x))?;
        let sig = std::fs::read(sig_file).map_err(|x| err("sig.read", x))?;
        if sig.len() > 64 * 1024 {
            return Err(err("sig.bad_sig", "size"));
        }
        self.verify(&data, &sig)
    }
}

#[cfg(test)]
#[path = "sigverify_tests.rs"]
mod tests;
