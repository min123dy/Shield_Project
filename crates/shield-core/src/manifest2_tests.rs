use super::*;

const H: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const FPR: &str = "B6792BD8AC6DC91352B3EA8B2BA9AE9BB2DA2DDA";
const OTHER: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const ISS: i64 = 1_790_000_000;

fn text(version: &str, id: u64, min: &str, revoked: &[&str]) -> String {
    let mut s = format!("{HEAD}\nversion {version}\nrelease_id {id}\nissued_at {ISS}\nexpires_at {}\nmin_allowed_version {min}\n", ISS + 365 * 86400);
    for r in revoked {
        s.push_str(&format!("revoked_key {r}\n"));
    }
    s.push_str(&format!("sha256 {H} a.msi\nsha256 {} b.deb\n", "22".repeat(32)));
    s
}

fn m(version: &str, id: u64, min: &str, revoked: &[&str]) -> Manifest {
    parse(&text(version, id, min, revoked), "a.msi").unwrap()
}

#[test]
fn parses_the_documented_format() {
    let x = m("3.1.1", 7, "3.1.0", &[OTHER]);
    assert_eq!((x.version, x.release_id, x.issued_at, x.min_allowed), (Version(3, 1, 1), 7, ISS, Version(3, 1, 0)));
    assert_eq!(x.expires_at, ISS + 365 * 86400);
    assert_eq!(x.revoked, vec![OTHER.to_string()]);
    assert_eq!(x.sha256, [0x11; 32]);
    assert_eq!(parse(&text("3.1.1", 7, "3.1.0", &[]), "b.deb").unwrap().sha256, [0x22; 32]);
    assert!(parse(&text("3.1.1", 7, "3.1.0", &[]), "c.msi").is_err(), "not listed");
}

#[test]
fn anything_else_is_refused() {
    let good = text("3.1.1", 7, "3.1.0", &[OTHER]);
    let bad = [
        good.replace(HEAD, "Shield release manifest 1"),
        good.replace('\n', "\r\n"),
        good.trim_end().to_string(),                                          // no final LF
        good.replace("release_id 7\n", ""),                                   // missing field
        good.replace("release_id 7", "release_id 07"),                        // leading zero
        good.replace("release_id 7", "release_id -7"),
        good.replace("release_id 7", "release_id 99999999999999999999"),
        good.replace("version 3.1.1", "version v3.1.1"),
        good.replace("issued_at", "issued"),
        good.replace(&format!("revoked_key {OTHER}"), &format!("revoked_key {}", OTHER.to_lowercase())),
        good.replace(&format!("revoked_key {OTHER}"), "revoked_key 0123"),
        good.replace(&format!("revoked_key {OTHER}\n"), &format!("revoked_key {OTHER}\nrevoked_key {OTHER}\n")),
        format!("{good}revoked_key {FPR}\n"),                                 // after the hashes
        format!("{good}sha256 {} a.msi\n", "33".repeat(32)),                  // one name, two hashes
        good.replace(&format!("sha256 {H} a.msi"), &format!("sha256 {} a.msi", "AB".repeat(32))), // upper-case hex
        good.replace(&format!("sha256 {H} a.msi"), &format!("sha256 {H} a.msi extra")),
        format!("{good}comment\n"),
        format!("{good}\n"),                                                  // empty line
    ];
    for b in bad {
        assert!(parse(&b, "a.msi").is_err(), "{b:?}");
    }
    let many: Vec<String> = (0..=MAX_REVOKED).map(|i| format!("{i:040X}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(parse(&text("3.1.1", 7, "3.1.0", &many), "a.msi").is_err(), "too many revoked keys");
}

#[test]
fn freshness_versions_and_revocation() {
    let x = m("3.1.1", 7, "3.1.1", &[OTHER]);
    let cur = Version(3, 1, 0);
    check(&x, ISS + 10, cur, FPR).unwrap();
    check(&x, ISS - MAX_CLOCK_SKEW, cur, FPR).unwrap();
    assert_eq!(check(&x, ISS - MAX_CLOCK_SKEW - 1, cur, FPR).unwrap_err(), crate::i18n::tf("upd.m_future", &[&when(ISS)]));
    assert!(check(&x, x.expires_at - 1, cur, FPR).is_ok());
    assert_eq!(check(&x, x.expires_at, cur, FPR).unwrap_err(), crate::i18n::tf("upd.m_expired", &[&when(x.expires_at)]));
    // not newer than the running version
    assert!(check(&x, ISS, Version(3, 1, 1), FPR).is_err());
    // the minimum above the version itself is nonsense
    assert!(check(&m("3.1.1", 7, "3.2.0", &[]), ISS, cur, FPR).is_err());
    // validity window: backwards, or longer than MAX_VALIDITY
    let mut y = x.clone();
    y.expires_at = y.issued_at;
    assert!(check(&y, ISS, cur, FPR).is_err());
    y.expires_at = y.issued_at + MAX_VALIDITY + 1;
    assert!(check(&y, ISS, cur, FPR).is_err());
    // the signer is in the manifest's own revocation list (spaces in the fingerprint don't matter)
    let spaced = "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567";
    assert_eq!(check(&x, ISS, cur, spaced).unwrap_err(), crate::i18n::t("upd.m_revoked"));
}

#[test]
fn rollback_state_only_grows_and_blocks_older_manifests() {
    let s0 = Seen::default();
    let a = m("3.1.2", 200, "3.1.2", &[OTHER]);
    s0.check(&a, FPR).unwrap();
    let s1 = s0.merged(&a);
    assert_eq!((s1.release_id, s1.min_allowed), (200, Some(Version(3, 1, 2))));
    // an older but still valid manifest (3.1.1 was replaced because it was broken): refused
    assert_eq!(s1.check(&m("3.1.1", 100, "3.1.1", &[]), FPR).unwrap_err(), crate::i18n::t("upd.m_rollback"));
    // a lower release id alone is enough
    assert!(s1.check(&m("3.1.3", 199, "3.1.3", &[]), FPR).is_err());
    // a key revoked once stays revoked, even in a manifest that no longer lists it
    assert_eq!(s1.check(&m("3.1.3", 300, "3.1.3", &[]), OTHER).unwrap_err(), crate::i18n::t("upd.m_revoked"));
    s1.check(&m("3.1.3", 300, "3.1.3", &[]), FPR).unwrap();
    // merging something older never lowers anything
    let s2 = s1.merged(&m("3.0.9", 5, "3.0.9", &[]));
    assert_eq!(s2, s1);
    // text round trip; damaged lines are dropped, never invented
    assert_eq!(Seen::parse(&s1.to_text()), s1);
    let d = Seen::parse("release_id x\nmin_allowed_version 3.1\nrevoked_key 12\nrelease_id 5\nother 1\n");
    assert_eq!(d, Seen { release_id: 5, min_allowed: None, revoked: vec![] });
}

#[test]
fn rollback_state_is_saved_and_loaded() {
    let d = std::env::temp_dir().join(format!("shield_seen_{}", crate::entropy::rand_hex().unwrap()));
    let p = d.join("update_seen.txt");
    assert_eq!(load_seen(&p), Seen::default(), "missing file: empty state");
    let s = Seen::default().merged(&m("3.1.2", 200, "3.1.2", &[OTHER]));
    save_seen(&p, &s).unwrap();
    assert_eq!(load_seen(&p), s);
    // huge file: not read (empty state, like a deleted one)
    std::fs::File::create(&p).unwrap().set_len(1 << 20).unwrap();
    assert_eq!(load_seen(&p), Seen::default());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn fingerprints_are_normalised() {
    assert_eq!(norm_fpr("8898 d3d9 1743 2C7D 6F77 B422 0961 7B54 42C8 AB6D").as_deref(), Some("8898D3D917432C7D6F77B42209617B5442C8AB6D"));
    assert_eq!(norm_fpr("8898"), None);
    assert_eq!(norm_fpr(&"G".repeat(40)), None);
}

#[test]
fn strict_seen_state_rejects_corruption_and_noncanonical_records() {
    let good = Seen { release_id: 42, min_allowed: Some(Version(3, 1, 2)), revoked: vec!["0123456789ABCDEF0123456789ABCDEF01234567".into()] };
    let text = good.to_text();
    assert_eq!(Seen::parse_strict(&text).unwrap(), good);
    assert!(Seen::parse_strict("release_id 42\nunknown x\n").is_err());
    assert!(Seen::parse_strict("release_id 042\n").is_err());
    assert!(Seen::parse_strict("release_id 42").is_err());
    assert!(Seen::parse_strict("release_id 42\nrelease_id 43\n").is_err());
}

#[test]
fn protected_machine_seen_state_round_trips_and_fails_closed() {
    let dir = std::env::temp_dir().join(format!("shield_seen_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("update_seen.txt");
    assert_eq!(load_machine_seen(&path).unwrap(), Seen::default());
    let expected = Seen { release_id: 123, min_allowed: Some(Version(3, 2, 0)), revoked: vec![OTHER.into()] };
    save_machine_seen(&path, &expected).unwrap();
    assert_eq!(load_machine_seen(&path).unwrap(), expected);
    std::fs::write(&path, b"release_id 123\ncorrupt row\n").unwrap();
    assert!(load_machine_seen(&path).is_err(), "a damaged privileged rollback floor must not reset to empty");
    let _ = std::fs::remove_dir_all(dir);
}
