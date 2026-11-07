use super::*;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update").join(name)).unwrap()
}

const V: Version = Version(3, 0, 0);

fn api(tag: &str, assets: &[&str], draft: bool, pre: bool) -> String {
    let list: Vec<String> = assets
        .iter()
        .map(|n| format!(r#"{{"name":"{n}","size":21,"browser_download_url":"https://github.com/raven/shield/releases/download/{tag}/{n}"}}"#))
        .collect();
    format!(
        r#"{{"tag_name":"{tag}","draft":{draft},"prerelease":{pre},"html_url":"https://github.com/raven/shield/releases/tag/{tag}","assets":[{}]}}"#,
        list.join(",")
    )
}

fn release_999() -> Release {
    let a = |n: &str| Asset { name: n.into(), url: String::new(), size: 21 };
    Release { version: Version(9, 9, 9), tag: "v9.9.9".into(), page: String::new(), files: Some([a("Shield_v9.9.9_x64.msi"), a("x.sig"), a("m"), a("m.sig")]) }
}

const NAMES: [&str; 4] = ["Shield_v3.0.1_x64.msi", "Shield_v3.0.1_x64.msi.sig", "Shield_v3.0.1_release.txt", "Shield_v3.0.1_release.txt.sig"];

#[test]
fn versions_and_tags_are_strict() {
    assert_eq!(Version::parse_tag("v3.0.1"), Some(Version(3, 0, 1)));
    assert_eq!(Version::parse_tag("v10.20.30"), Some(Version(10, 20, 30)));
    for bad in ["3.0.1", "v3.0", "v3.0.1.2", "v3.0.1-rc1", "v3.0.1+b", "v03.0.1", "v3.00.1", "v-3.0.1", "v3. 0.1", "v", "", "v1234567.0.0", "V3.0.1", "v\u{ff13}.0.1"] {
        assert_eq!(Version::parse_tag(bad), None, "{bad}");
    }
    assert!(Version(3, 0, 10) > Version(3, 0, 9) && Version(3, 1, 0) > Version(3, 0, 99));
    assert_eq!(Version::current().to_string(), crate::buildinfo::VERSION);
}

#[test]
fn newer_release_with_all_files_is_offered() {
    let c = evaluate(&api("v3.0.1", &NAMES, false, false), "raven", "shield", V, Some("msi")).unwrap();
    let Check::Available(r) = c else { panic!() };
    assert_eq!(r.version, Version(3, 0, 1));
    if std::env::consts::ARCH == "x86_64" {
        let f = r.files.unwrap();
        assert_eq!(f[0].name, "Shield_v3.0.1_x64.msi");
        assert!(f[0].url.starts_with("https://github.com/raven/shield/releases/download/v3.0.1/"));
    }
    // without an installable kind: only the link
    let Check::Available(r) = evaluate(&api("v3.0.1", &NAMES, false, false), "raven", "shield", V, None).unwrap() else { panic!() };
    assert!(r.files.is_none() && r.page.ends_with("/tag/v3.0.1"));
}

#[test]
fn same_older_draft_prerelease_and_odd_tags_are_not_offered() {
    for (tag, draft, pre) in [("v3.0.0", false, false), ("v2.9.9", false, false), ("v3.0.1-beta", false, false), ("latest", false, false), ("v9.0.0", true, false), ("v9.0.0", false, true)] {
        let j = api(tag, &[], draft, pre);
        assert_eq!(evaluate(&j, "raven", "shield", V, Some("msi")).unwrap(), Check::UpToDate(V), "{tag}");
    }
    assert!(evaluate("not json", "raven", "shield", V, None).is_err());
}

#[test]
fn assets_from_elsewhere_are_ignored() {
    let j = api("v3.0.1", &NAMES, false, false)
        .replacen("https://github.com/raven/shield/releases/download/v3.0.1/Shield_v3.0.1_x64.msi\"", "https://evil.example/Shield_v3.0.1_x64.msi\"", 1);
    let Check::Available(r) = evaluate(&j, "raven", "shield", V, Some("msi")).unwrap() else { panic!() };
    assert!(r.files.is_none(), "a download URL outside the repository's release is refused");
    let j = api("v3.0.1", &[], false, false).replace("https://github.com/raven/shield/releases/tag/v3.0.1", "https://evil.example/x");
    let Check::Available(r) = evaluate(&j, "raven", "shield", V, Some("msi")).unwrap() else { panic!() };
    assert!(r.page.starts_with("https://github.com/raven/shield/releases/"), "page link stays on the repository");
}

#[test]
fn manifest_parsing_is_strict() {
    let m = String::from_utf8(fx("manifest_999.txt")).unwrap();
    let (v, h) = parse_manifest(&m, "Shield_v9.9.9_x64.msi").unwrap();
    assert_eq!(v, Version(9, 9, 9));
    assert_eq!(h, <[u8; 32]>::from(Sha256::digest(fx("pkg.bin"))));
    assert!(parse_manifest(&m, "other.msi").is_err());
    for bad in [
        "Shield release manifest 2\nversion 9.9.9\n",
        "Shield release manifest 1\nversion v9.9.9\n",
        "Shield release manifest 1\nversion 9.9.9\nsha256 00 x\n",
        "Shield release manifest 1\nversion 9.9.9\nsha1 0000000000000000000000000000000000000000 x\n",
    ] {
        assert!(parse_manifest(bad, "x").is_err(), "{bad}");
    }
    let dup = format!("{m}sha256 {} Shield_v9.9.9_x64.msi\n", "0".repeat(64));
    assert!(parse_manifest(&dup, "Shield_v9.9.9_x64.msi").is_err(), "duplicate entry");
}

#[test]
fn verified_set_passes_and_every_tampering_fails() {
    let cert = Cert::parse(&fx("key.asc")).unwrap();
    let d = std::env::temp_dir().join(format!("shield_upd_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    let pkg = d.join("pkg.bin");
    std::fs::write(&pkg, fx("pkg.bin")).unwrap();
    let sha: [u8; 32] = Sha256::digest(fx("pkg.bin")).into();
    let r = release_999();
    let (m, ms, ps) = (fx("manifest_999.txt"), fx("manifest_999.txt.sig"), fx("pkg.bin.sig"));
    verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha).unwrap();
    // manifest changed
    let mut m2 = m.clone();
    m2[40] ^= 1;
    assert!(verify_set(&cert, &r, &m2, &ms, &pkg, &ps, sha).is_err());
    // installer changed (hash first, then signature)
    let mut sha2 = sha;
    sha2[0] ^= 1;
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha2).is_err());
    std::fs::write(&pkg, b"fake installer 9.9.8\n").unwrap();
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha).is_err(), "package signature");
    std::fs::write(&pkg, fx("pkg.bin")).unwrap();
    // installer signature swapped for the manifest's
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ms, sha).is_err());
    // replay: an older signed manifest under a newer tag
    let e = verify_set(&cert, &r, &fx("manifest_200.txt"), &fx("manifest_200.txt.sig"), &pkg, &ps, sha).unwrap_err();
    assert!(e.contains("2.0.0"), "{e}");
    // another key
    let other = Cert::parse(&std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/bp256.asc")).unwrap()).unwrap();
    assert!(verify_set(&other, &r, &m, &ms, &pkg, &ps, sha).is_err());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn package_names_follow_the_artifact_scheme() {
    let v = Version(3, 0, 0);
    if std::env::consts::ARCH == "x86_64" {
        assert_eq!(package_name(v, "msi").unwrap(), "Shield_v3.0.0_x64.msi");
        assert_eq!(package_name(v, "deb").unwrap(), "shield_v3.0.0_amd64.deb");
        assert_eq!(package_name(v, "AppImage").unwrap(), "Shield_v3.0.0_x86_64.AppImage");
    }
    assert_eq!(package_name(v, "exe"), None);
    assert_eq!(manifest_name(v), "Shield_v3.0.0_release.txt");
}
