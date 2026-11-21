use super::*;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp").join(name)).unwrap()
}

fn cert(name: &str) -> Cert {
    Cert::parse(&fx(name)).unwrap()
}

/// The release key the repository ships (`keys/release_key.asc`), read from there: test fixtures
/// hold only test keys (3.1.0 final, review C).
fn repo_release_key() -> Cert {
    Cert::from_file(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../keys/release_key.asc")).unwrap()
}

/// The bundled release key is a valid OpenPGP public key. Its fingerprint is intentionally not
/// pinned in source so a project can rotate or replace the trust anchor without editing tests.
/// Users should still compare published fingerprints out of band before trusting a release.
#[test]
fn bundled_release_key_has_a_well_formed_fingerprint() {
    let c = repo_release_key();
    let fpr = c.fingerprint_hex();
    assert_eq!(fpr.len(), 40);
    assert!(fpr.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase()), "{fpr}");
}

#[test]
fn brainpool_and_ed25519_signatures_verify() {
    let data = fx("data.txt");
    for (key, sig) in [
        ("bp256.asc", "data.bp256.sig"),
        ("bp384.asc", "data.bp384.asc"),
        ("ed25519.asc", "data.ed25519.sig"),
        ("ed25519.asc", "data.ed25519.text.sig"),
    ] {
        let c = cert(key);
        let v = c.verify(&data, &fx(sig)).unwrap_or_else(|e| panic!("{sig}: {e}"));
        assert_eq!(v.fingerprint, c.fingerprint());
        assert!(v.created.is_some());
    }
}

#[test]
fn subkey_signature_names_the_subkey() {
    let c = cert("bp384.asc");
    let v = c.verify(&fx("data.txt"), &fx("data.bp384sub.sig")).unwrap();
    assert_ne!(v.signer, v.fingerprint);
    assert_eq!(v.fingerprint, c.fingerprint());
}

#[test]
fn tampered_data_or_wrong_key_fails() {
    let mut data = fx("data.txt");
    for (key, sig) in [("bp256.asc", "data.bp256.sig"), ("bp384.asc", "data.bp384.asc"), ("ed25519.asc", "data.ed25519.sig")] {
        let c = cert(key);
        data[3] ^= 1;
        assert!(c.verify(&data, &fx(sig)).is_err(), "{sig} tampered");
        data[3] ^= 1;
    }
    // right data, other key
    assert!(cert("bp256.asc").verify(&data, &fx("data.bp384.asc")).is_err());
    assert!(cert("test_release_key.asc").verify(&data, &fx("data.ed25519.sig")).is_err());
    // a binary-signature byte flipped
    let mut sig = fx("data.bp256.sig");
    let n = sig.len();
    sig[n - 5] ^= 0x40;
    assert!(cert("bp256.asc").verify(&data, &sig).is_err());
}

#[test]
fn garbage_inputs_are_errors_not_panics() {
    assert!(Cert::parse(b"").is_err());
    assert!(Cert::parse(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n").is_err());
    let c = cert("bp256.asc");
    assert!(c.verify(b"x", b"").is_err());
    assert!(c.verify(b"x", &[0xFF; 300]).is_err());
    // the signature passed as key and vice versa
    assert!(Cert::parse(&fx("data.bp256.sig")).is_err());
    assert!(c.verify(b"x", &fx("bp256.asc")).is_err());
}

#[test]
fn verify_file_limits() {
    let d = std::env::temp_dir().join(format!("shield_sig_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("data.txt"), fx("data.txt")).unwrap();
    std::fs::write(d.join("data.sig"), fx("data.bp256.sig")).unwrap();
    std::fs::write(d.join("big.sig"), vec![0u8; 70 * 1024]).unwrap();
    let c = cert("bp256.asc");
    c.verify_file(&d.join("data.txt"), &d.join("data.sig")).unwrap();
    assert!(c.verify_file(&d.join("data.txt"), &d.join("big.sig")).is_err());
    assert!(c.verify_file(&d.join("missing"), &d.join("data.sig")).is_err());
    let _ = std::fs::remove_dir_all(d);
}

/// The 2.1.0 release in `dist/` (when present in the source tree) is signed by the release key.
#[test]
fn released_v2_archive_verifies_when_present() {
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dist");
    let (f, s) = (dist.join("Shield_Project_v2.1.0.zip"), dist.join("Shield_Project_v2.1.0.zip.sig"));
    if !f.exists() || !s.exists() {
        return;
    }
    let key = repo_release_key();
    let v = key.verify_file(&f, &s).unwrap();
    // Compare with the key bundled by this checkout; do not pin a particular project key here.
    assert_eq!(v.fingerprint, key.fingerprint());
}

#[test]
fn revoked_key_is_refused() {
    let e = Cert::parse(&fx("bp256_revoked.asc")).unwrap_err();
    assert_eq!(e, crate::i18n::t("sig.revoked"));
}

// ---- 3.1.0 #3: time rules, signing right of the primary, backup key ----
// The k1..k4 fixtures were made with GnuPG 2.4.9 and --faked-system-time in a throwaway keyring
// (only public keys and signatures were kept; no secret key is in the repository):
//   k1_expired.asc   key made 2020-01-01, expiry later set to 2020-01-02; data.k1.sig made 2020-01-11
//   k2.asc           key made 2020-01-01, no expiry; data.k2.sig (2020-02-01, plain),
//                    .sigexp (expires after 1 day), .sigexp_ok (expires 2090), .future (2090),
//                    .early (2019, before the key existed; --ignore-time-conflict)
//   k3_expiring.asc  key made 2020-01-01, expires 2090-01-01; data.k3.sig 2020-02-01
//   k4.asc           certify-only primary + signing subkey; data.k4sub.sig by the subkey
//   k4_subrevoked    the same key after the subkey was revoked (2020-03-01)

fn has_time_code(e: &str) -> bool {
    crate::i18n::has_code(e, SIGTIME)
}

#[test]
fn plain_and_far_expiring_signatures_still_verify() {
    // signatures made the 3.0.0 way (no expiry on key or signature) keep working, and so do keys
    // and signatures whose expiry lies in the future
    let data = fx("data.txt");
    for (key, sig) in [("k2.asc", "data.k2.sig"), ("k2.asc", "data.k2.sigexp_ok.sig"), ("k3_expiring.asc", "data.k3.sig"), ("k4.asc", "data.k4sub.sig")] {
        cert(key).verify(&data, &fx(sig)).unwrap_or_else(|e| panic!("{sig}: {e}"));
    }
    // and the existing 3.0.0 fixtures (brainpool, ed25519, subkey) still pass
    brainpool_and_ed25519_signatures_verify();
    subkey_signature_names_the_subkey();
}

#[test]
fn expired_future_and_early_signatures_are_refused_with_a_clock_hint() {
    let data = fx("data.txt");
    for (key, sig, msg) in [
        ("k1_expired.asc", "data.k1.sig", "sig.key_expired"),
        ("k2.asc", "data.k2.sigexp.sig", "sig.expired"),
        ("k2.asc", "data.k2.future.sig", "sig.future"),
        ("k2.asc", "data.k2.early.sig", "sig.before_key"),
    ] {
        let e = cert(key).verify(&data, &fx(sig)).unwrap_err();
        assert!(has_time_code(&e) && e.starts_with(crate::i18n::t(msg)), "{sig}: {e}");
        assert_ne!(e, crate::i18n::t("sig.invalid"), "told apart from a wrong signature");
    }
    // a wrong signature is still "invalid", without the clock code
    let mut bad = data.clone();
    bad[0] ^= 1;
    let e = cert("k2.asc").verify(&bad, &fx("data.k2.sig")).unwrap_err();
    assert!(!has_time_code(&e), "{e}");
}

#[test]
fn time_rules_table() {
    let (key, now) = (1_000_000i64, 2_000_000i64);
    let ok = |created: Option<i64>, sig_exp: Option<i64>, kexp: &[Option<i64>]| check_times(created, sig_exp, key, kexp, now).is_ok();
    assert!(ok(Some(1_500_000), None, &[None]));
    assert!(!ok(None, None, &[None]), "no creation time");
    assert!(!ok(Some(key - 1), None, &[None]), "before the key");
    assert!(ok(Some(now + MAX_CLOCK_SKEW), None, &[None]), "up to a day ahead");
    assert!(!ok(Some(now + MAX_CLOCK_SKEW + 1), None, &[None]), "more than a day ahead");
    assert!(!ok(Some(1_500_000), Some(10), &[None]), "signature expired");
    assert!(ok(Some(1_500_000), Some(0), &[None]), "0 = never expires");
    assert!(ok(Some(1_500_000), Some(600_000), &[None]), "expires after now");
    assert!(!ok(Some(1_500_000), None, &[Some(1_400_000)]), "key expired before signing");
    assert!(ok(Some(1_500_000), None, &[Some(1_600_000)]), "key expired after signing is fine");
    assert!(!ok(Some(1_500_000), None, &[None, Some(1_500_000)]), "subkey expiry counts too");
}

#[test]
fn revoked_signing_subkey_is_refused() {
    let data = fx("data.txt");
    cert("k4.asc").verify(&data, &fx("data.k4sub.sig")).unwrap();
    let e = cert("k4_subrevoked.asc").verify(&data, &fx("data.k4sub.sig")).unwrap_err();
    assert_eq!(e, crate::i18n::t("sig.revoked"));
}

#[test]
fn primary_without_sign_flag_is_refused() {
    // GnuPG refuses to make such a signature, so it is built here with rPGP: a certify-only
    // primary key signs data directly. The key and signature exist only in this test.
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::ser::Serialize;
    use pgp::types::Password;
    let mut rng = rand::thread_rng();
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(false)
        .primary_user_id("Shield Test no-sign <nosign@invalid>".into())
        .build()
        .unwrap();
    let sk = params.generate(&mut rng).unwrap();
    let public = sk.to_public_key().to_armored_bytes(Default::default()).unwrap();
    let c = Cert::parse(&public).unwrap();
    let data = b"signed by a primary key without the sign flag";
    let mut cfg = SignatureConfig::from_key(&mut rng, &sk.primary_key, SignatureType::Binary).unwrap();
    cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(sk.primary_key.fingerprint())).unwrap(),
    ];
    let sig = cfg.sign(&sk.primary_key, &Password::empty(), &data[..]).unwrap();
    let ds = DetachedSignature::new(sig).to_bytes().unwrap();
    let e = c.verify(data, &ds).unwrap_err();
    assert_eq!(e, crate::i18n::t("sig.no_sign_flag"));
}

#[test]
fn backup_key_signature_is_accepted_and_named() {
    // main key first, backup second: a signature by the backup verifies and says so
    let data = fx("data.txt");
    let keys = [cert("test_release_key.asc"), cert("ed25519.asc")];
    let v = verify_any(&keys, &data, &fx("data.ed25519.sig")).unwrap();
    assert_eq!((v.key_index, v.fingerprint.clone()), (1, cert("ed25519.asc").fingerprint()));
    // a signature by the first key reports index 0
    let keys = [cert("ed25519.asc"), cert("bp256.asc")];
    assert_eq!(verify_any(&keys, &data, &fx("data.ed25519.sig")).unwrap().key_index, 0);
    // neither key: refused; a known-but-refused key wins over "does not match"
    assert_eq!(verify_any(&[cert("bp256.asc")], &data, &fx("data.ed25519.sig")).unwrap_err(), crate::i18n::t("sig.invalid"));
    let e = verify_any(&[cert("bp256.asc"), cert("k2.asc")], &data, &fx("data.k2.future.sig")).unwrap_err();
    assert!(has_time_code(&e), "{e}");
    assert!(verify_any(&[], &data, &fx("data.ed25519.sig")).is_err());
}

// ---- 3.1.0 review 2 #2: stricter policy for update files ----
// k5_expired_later.asc: ed25519, made 2020-01-01, expires 2021-01-01 (GnuPG 2.4, --faked-system-time,
// throwaway keyring; only the public key and the signature were kept). data.k5.sig: 2020-06-01,
// binary. data.ed25519.text.sig (3.0.0 fixture) is a text-mode (0x01) signature.

#[test]
fn release_policy_refuses_keys_that_have_expired_since_signing() {
    let data = fx("data.txt");
    let k5 = cert("k5_expired_later.asc");
    // `shield verify` keeps the 3.1.0 rule: the key was valid when the signature was made
    k5.verify(&data, &fx("data.k5.sig")).unwrap();
    // an update is not accepted: the (back-datable) signature time alone is not enough
    let e = k5.verify_with(&data, &fx("data.k5.sig"), Policy::Release).unwrap_err();
    assert!(e.starts_with(crate::i18n::t("sig.key_expired_now")) && has_time_code(&e), "{e}");
    let e = verify_any_with(&[cert("k2.asc"), k5], &data, &fx("data.k5.sig"), Policy::Release).unwrap_err();
    assert!(e.starts_with(crate::i18n::t("sig.key_expired_now")), "the telling error wins: {e}");
    // keys without an expiry, or expiring in 2090, still pass
    for (key, sig) in [("k2.asc", "data.k2.sig"), ("k3_expiring.asc", "data.k3.sig"), ("k4.asc", "data.k4sub.sig"), ("bp256.asc", "data.bp256.sig")] {
        cert(key).verify_with(&data, &fx(sig), Policy::Release).unwrap_or_else(|e| panic!("{sig}: {e}"));
    }
}

#[test]
fn release_policy_takes_binary_signatures_only() {
    let data = fx("data.txt");
    let ed = cert("ed25519.asc");
    ed.verify(&data, &fx("data.ed25519.text.sig")).expect("text signatures stay valid for shield verify");
    let e = ed.verify_with(&data, &fx("data.ed25519.text.sig"), Policy::Release).unwrap_err();
    assert!(e.contains("Text"), "{e}");
    ed.verify_with(&data, &fx("data.ed25519.sig"), Policy::Release).unwrap();
}

#[test]
fn key_expiry_now_rule_table() {
    let now = 2_000_000i64;
    assert!(check_key_now(&[None], now).is_ok());
    assert!(check_key_now(&[None, Some(now + 1)], now).is_ok());
    assert!(check_key_now(&[Some(now)], now).is_err(), "expires at now = expired");
    assert!(check_key_now(&[None, Some(now - 1)], now).is_err(), "subkey expiry counts");
    assert!(check_key_now(&[Some(now - 1), None], now).is_err(), "primary expiry counts");
}

// ---- 3.1.0 review 3: limits applied before reading; signed files streamed ----

#[test]
fn an_oversized_signature_or_key_file_is_refused_without_reading_it() {
    let d = std::env::temp_dir().join(format!("shield_sig3_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("data.txt"), fx("data.txt")).unwrap();
    // 256 MiB of length without data: refused from the handle's size, nothing near it is read
    let big = d.join("huge.sig");
    std::fs::File::create(&big).unwrap().set_len(256 << 20).unwrap();
    let t = std::time::Instant::now();
    let e = cert("bp256.asc").verify_file(&d.join("data.txt"), &big).unwrap_err();
    assert!(e.contains("size"), "{e}");
    let e = verify_file_any(&[cert("bp256.asc")], &d.join("data.txt"), &big).unwrap_err();
    assert!(e.contains("size"), "{e}");
    // exactly MAX_SIG is still read (and then is no signature); MAX_SIG + 1 is refused as too large
    let edge = d.join("edge.sig");
    std::fs::write(&edge, vec![0u8; MAX_SIG as usize]).unwrap();
    assert!(!cert("bp256.asc").verify_file(&d.join("data.txt"), &edge).unwrap_err().contains("size"));
    std::fs::write(&edge, vec![0u8; MAX_SIG as usize + 1]).unwrap();
    assert!(cert("bp256.asc").verify_file(&d.join("data.txt"), &edge).unwrap_err().contains("size"));
    // a key file past MAX_CERT
    let key = d.join("huge.asc");
    std::fs::File::create(&key).unwrap().set_len(512 << 20).unwrap();
    assert!(Cert::from_file(&key).is_err());
    assert_eq!(Cert::from_file(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/k2.asc")).unwrap().fingerprint(), cert("k2.asc").fingerprint());
    // a folder is not a signed file
    assert!(cert("bp256.asc").verify_file(&d, &d.join("data.txt")).is_err());
    assert!(t.elapsed().as_secs() < 10, "nothing large was read");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn streamed_files_give_the_same_results_as_bytes_in_memory() {
    let d = std::env::temp_dir().join(format!("shield_sig4_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    let data = d.join("data.txt");
    std::fs::write(&data, fx("data.txt")).unwrap();
    // primary key, subkeys (the document is read again from the start for each key tried), text
    // signature, expired key, wrong key
    for (key, sig, good) in [
        ("bp256.asc", "data.bp256.sig", true),
        ("bp384.asc", "data.bp384sub.sig", true),
        ("k4.asc", "data.k4sub.sig", true),
        ("ed25519.asc", "data.ed25519.text.sig", true),
        ("k1_expired.asc", "data.k1.sig", false),
        ("k2.asc", "data.bp256.sig", false),
    ] {
        let s = d.join("s.sig");
        std::fs::write(&s, fx(sig)).unwrap();
        let mem = cert(key).verify(&fx("data.txt"), &fx(sig));
        let file = cert(key).verify_file(&data, &s);
        assert_eq!(mem, file, "{key} {sig}");
        assert_eq!(file.is_ok(), good, "{key} {sig}: {file:?}");
        // and through the several-keys entry point, the good key second
        let any = verify_file_any(&[cert("k2.asc"), cert(key)], &data, &s);
        assert_eq!(any.is_ok(), good, "{key} {sig}: {any:?}");
    }
    // changed content after the signature: refused
    std::fs::write(&data, b"other content").unwrap();
    std::fs::write(d.join("s.sig"), fx("data.bp256.sig")).unwrap();
    assert!(cert("bp256.asc").verify_file(&data, &d.join("s.sig")).is_err());
    let _ = std::fs::remove_dir_all(d);
}

/// 3.1.0 final (review C): the key shape the release gate checks. `release_model.asc` (test only)
/// is built like docs/07 asks: certify-only primary, ed25519 signing subkey valid two years.
#[test]
fn release_key_shape_rules() {
    let m = cert("release_model.asc").shape();
    assert!(!m.primary_signs, "{m:?}");
    assert_eq!(m.primary_expires, None);
    assert_eq!(m.signing_subkeys, vec![Some(1_857_394_112)], "{m:?}");
    let made = 1_794_322_112;
    let three_years = 3 * 366 * 86_400;
    assert_eq!(m.release_problems(made + 86_400, three_years), Vec::<String>::new());
    // expired subkey, or one valid for too long
    assert!(m.release_problems(1_857_394_112, three_years).iter().any(|p| p.contains("expired")));
    assert!(m.release_problems(made, 86_400).iter().any(|p| p.contains("more than")));
    // the old single-key form (primary signs, no subkey, no expiry) fails
    let old = cert("test_release_key.asc").shape();
    let p = old.release_problems(made, three_years);
    assert!(p.iter().any(|x| x.contains("no signing subkey")) && p.iter().any(|x| x.contains("primary key may sign")), "{p:?}");
    // a subkey that signs but never expires
    let k4 = cert("k4.asc").shape();
    assert!(k4.release_problems(made, three_years).iter().any(|x| x.contains("never expires")), "{k4:?}");
    // a revoked signing subkey does not count
    assert!(cert("k4_subrevoked.asc").shape().signing_subkeys.is_empty());
    // user IDs: the project, not a personal account
    let mut u = m.clone();
    u.user_ids = vec!["Someone <someone@gmail.com>".into()];
    let p = u.release_problems(made + 86_400, three_years);
    assert!(p.iter().any(|x| x.contains("personal mail")) && p.iter().any(|x| x.contains("does not name the project")), "{p:?}");
    u.user_ids = vec!["Shield releases <release@shield-project.example>".into()];
    assert!(u.release_problems(made + 86_400, three_years).is_empty());
}
