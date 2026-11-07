use super::*;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp").join(name)).unwrap()
}

fn cert(name: &str) -> Cert {
    Cert::parse(&fx(name)).unwrap()
}

#[test]
fn release_key_fingerprint() {
    let c = cert("release_key.asc");
    assert_eq!(c.fingerprint_hex(), "8898D3D917432C7D6F77B42209617B5442C8AB6D");
    assert_eq!(c.fingerprint(), "8898 D3D9 1743 2C7D 6F77 B422 0961 7B54 42C8 AB6D");
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
    assert!(cert("release_key.asc").verify(&data, &fx("data.ed25519.sig")).is_err());
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
    let v = cert("release_key.asc").verify_file(&f, &s).unwrap();
    assert_eq!(v.fingerprint.replace(' ', ""), "8898D3D917432C7D6F77B42209617B5442C8AB6D");
}

#[test]
fn revoked_key_is_refused() {
    let e = Cert::parse(&fx("bp256_revoked.asc")).unwrap_err();
    assert_eq!(e, crate::i18n::t("sig.revoked"));
}
