use super::*;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update").join(name)).unwrap()
}

const V: Version = Version(3, 0, 0);
/// A time inside the validity window of the v2 fixtures (issued 1790000000, 365 days).
const NOW: i64 = 1_790_000_000 + 3600;

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

const NAMES: [&str; 4] = ["Shield_v3.0.1_x64.msi", "Shield_v3.0.1_x64.msi.sig", "Shield_v3.0.1_release_v2.txt", "Shield_v3.0.1_release_v2.txt.sig"];

/// 3.1.0 final (review B): a release with only the v1 manifest (what 3.0.0 reads) is a link.
#[test]
fn a_release_without_the_v2_manifest_is_only_a_link() {
    let v1 = ["Shield_v3.0.1_x64.msi", "Shield_v3.0.1_x64.msi.sig", "Shield_v3.0.1_release.txt", "Shield_v3.0.1_release.txt.sig"];
    let Check::Available(r) = evaluate(&api("v3.0.1", &v1, false, false), "raven", "shield", V, Some("msi")).unwrap() else { panic!() };
    assert!(r.files.is_none());
    assert_eq!(manifest2_name(Version(3, 1, 0)), "Shield_v3.1.0_release_v2.txt");
    assert_ne!(manifest2_name(Version(3, 1, 0)), manifest_name(Version(3, 1, 0)));
}

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
    let (m, ms, ps) = (fx("manifest2_999.txt"), fx("manifest2_999.txt.sig"), fx("pkg.bin.sig"));
    verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha, NOW).unwrap();
    // manifest changed
    let mut m2 = m.clone();
    m2[40] ^= 1;
    assert!(verify_set(&cert, &r, &m2, &ms, &pkg, &ps, sha, NOW).is_err());
    // installer changed (hash first, then signature)
    let mut sha2 = sha;
    sha2[0] ^= 1;
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha2, NOW).is_err());
    std::fs::write(&pkg, b"fake installer 9.9.8\n").unwrap();
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha, NOW).is_err(), "package signature");
    std::fs::write(&pkg, fx("pkg.bin")).unwrap();
    // installer signature swapped for the manifest's
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ms, sha, NOW).is_err());
    // replay: an older signed manifest under a newer tag
    let e = verify_set(&cert, &r, &fx("manifest2_200.txt"), &fx("manifest2_200.txt.sig"), &pkg, &ps, sha, NOW).unwrap_err();
    assert!(e.contains("2.0.0"), "{e}");
    // 3.1.0 final (review B): expired, dated in the future, signer revoked by the manifest itself
    let exp = 1_790_000_000 + 365 * 86400;
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha, exp).unwrap_err().contains(&crate::ui_fmt::date(Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(exp as u64)))));
    verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha, 1_790_000_000 - 23 * 3600).unwrap();
    assert!(verify_set(&cert, &r, &m, &ms, &pkg, &ps, sha, 1_790_000_000 - 25 * 3600).is_err(), "more than a day ahead of the clock");
    let e = verify_set(&cert, &r, &fx("manifest2_selfrevoked.txt"), &fx("manifest2_selfrevoked.txt.sig"), &pkg, &ps, sha, NOW).unwrap_err();
    assert_eq!(e, crate::i18n::t("upd.m_revoked"));
    // the v1 manifest (for 3.0.0 clients) is not accepted by this client
    assert!(verify_set(&cert, &r, &fx("manifest_999.txt"), &ms, &pkg, &ps, sha, NOW).is_err());
    // another key
    let other = Cert::parse(&std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/bp256.asc")).unwrap()).unwrap();
    assert!(verify_set(&other, &r, &m, &ms, &pkg, &ps, sha, NOW).is_err());
    let _ = std::fs::remove_dir_all(d);
}

// ---- 3.1.0 #1: privileged helper (copy, then verify the copy) ----

fn tdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_upd_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The 9.9.9 fixture set as the unprivileged side leaves it: four files in one folder.
fn fixture_set(d: &Path) -> UpdateFiles {
    let f = UpdateFiles {
        pkg: d.join("Shield_v9.9.9_x64.msi"),
        pkg_sig: d.join("Shield_v9.9.9_x64.msi.sig"),
        manifest: d.join("Shield_v9.9.9_release_v2.txt"),
        manifest_sig: d.join("Shield_v9.9.9_release_v2.txt.sig"),
    };
    for (p, n) in [(&f.pkg, "pkg.bin"), (&f.pkg_sig, "pkg.bin.sig"), (&f.manifest, "manifest2_999.txt"), (&f.manifest_sig, "manifest2_999.txt.sig")] {
        std::fs::write(p, fx(n)).unwrap();
    }
    f
}

fn args_of(f: &UpdateFiles) -> Vec<String> {
    f.all().iter().map(|p| p.to_string_lossy().into_owned()).collect()
}

#[test]
fn helper_arguments_are_checked() {
    let d = tdir();
    let f = fixture_set(&d);
    assert_eq!(parse_helper_args(&args_of(&f)).unwrap(), f);
    let a = args_of(&f);
    // wrong count
    assert!(parse_helper_args(&a[..3]).is_err());
    assert!(parse_helper_args(&[a.clone(), vec![a[0].clone()]].concat()).is_err());
    assert!(parse_helper_args(&[]).is_err());
    // relative path
    let mut rel = a.clone();
    rel[1] = "Shield_v9.9.9_x64.msi.sig".into();
    assert!(parse_helper_args(&rel).is_err());
    // missing file
    let mut missing = a.clone();
    missing[2] = d.join("nope.txt").to_string_lossy().into_owned();
    assert!(parse_helper_args(&missing).is_err());
    // a folder is not a file
    let mut folder = a.clone();
    folder[0] = d.to_string_lossy().into_owned();
    assert!(parse_helper_args(&folder).is_err());
    // over the size limit (signature files: MAX_SMALL)
    let big = d.join("big.sig");
    std::fs::write(&big, vec![0u8; MAX_SMALL as usize + 1]).unwrap();
    let mut over = a.clone();
    over[3] = big.to_string_lossy().into_owned();
    assert!(parse_helper_args(&over).is_err());
    assert!(read_no_follow(&big, MAX_SMALL).is_err());
    // a link (symlink; on Windows only where the account may create one)
    let link = d.join("link.sig");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&f.pkg_sig, &link).is_ok();
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&f.pkg_sig, &link).is_ok();
    if made {
        let mut l = a.clone();
        l[1] = link.to_string_lossy().into_owned();
        assert!(parse_helper_args(&l).is_err(), "link accepted");
        assert!(read_no_follow(&link, MAX_SMALL).is_err(), "link followed");
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn copies_are_verified_and_later_changes_to_the_originals_do_not_matter() {
    if std::env::consts::ARCH != "x86_64" {
        return; // the fixture manifest lists the x64 installer name
    }
    let cert = Cert::parse(&fx("key.asc")).unwrap();
    let (src, dest) = (tdir(), tdir());
    let f = fixture_set(&src);
    let c = copy_inputs(&f, &dest, "msi").unwrap();
    assert_eq!(c.files.pkg, dest.join("package.msi"));
    assert_eq!(c.pkg_name, "Shield_v9.9.9_x64.msi");
    // the originals are swapped AFTER the copy: what gets installed is still the verified copy
    std::fs::write(&f.pkg, b"evil installer").unwrap();
    std::fs::write(&f.manifest, b"evil manifest").unwrap();
    verify_copies(&c, std::slice::from_ref(&cert), V, "msi", NOW).unwrap();
    assert_eq!(std::fs::read(&c.files.pkg).unwrap(), fx("pkg.bin"), "the copy is what will be installed");
    // the helper's own version decides, not the caller: no downgrade, no reinstall
    assert!(verify_copies(&c, std::slice::from_ref(&cert), Version(9, 9, 9), "msi", NOW).is_err());
    // the installer name must be this platform's package name for the signed version
    assert!(verify_copies(&c, std::slice::from_ref(&cert), V, "deb", NOW).is_err());
    // another key
    let other = Cert::parse(&std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/bp256.asc")).unwrap()).unwrap();
    assert!(verify_copies(&c, &[other], V, "msi", NOW).is_err());
    let _ = std::fs::remove_dir_all(&dest);

    // the originals were changed BEFORE the copy: the copy is not correctly signed -> refused
    let dest2 = tdir();
    let f2 = fixture_set(&src);
    std::fs::write(&f2.pkg, b"fake installer 9.9.8\n").unwrap();
    let c2 = copy_inputs(&f2, &dest2, "msi").unwrap();
    assert!(verify_copies(&c2, std::slice::from_ref(&cert), V, "msi", NOW).is_err());
    // a manifest whose signature does not match
    let dest3 = tdir();
    let f3 = fixture_set(&src);
    // the helper checks the validity window too (its own clock)
    assert!(verify_copies(&c, std::slice::from_ref(&cert), V, "msi", 1_790_000_000 + 400 * 86400).is_err(), "expired");
    let mut m = fx("manifest2_999.txt");
    m[40] ^= 1;
    std::fs::write(&f3.manifest, m).unwrap();
    let c3 = copy_inputs(&f3, &dest3, "msi").unwrap();
    assert!(verify_copies(&c3, &[cert], V, "msi", NOW).is_err());
    // the copy target must be new: copying twice into the same folder fails
    assert!(copy_inputs(&f3, &dest3, "msi").is_err());
    // only msi / deb are installed with privileges
    assert!(copy_inputs(&f3, &tdir(), "AppImage").is_err());
    for d in [src, dest2, dest3] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn helper_refuses_to_run_unprivileged_and_reports_outcomes() {
    // a test run is neither elevated nor started by pkexec
    if !shield_platform::sys::update_helper_allowed() {
        let d = tdir();
        let f = fixture_set(&d);
        assert_eq!(helper_main(&args_of(&f)), helper_code::NOT_PRIVILEGED);
        assert!(f.pkg.is_file(), "nothing touched");
        let _ = std::fs::remove_dir_all(d);
    }
    assert_eq!(helper_outcome(helper_code::OK, "msi"), Ok(Installed::ExitNow));
    assert_eq!(helper_outcome(helper_code::OK, "deb"), Ok(Installed::Done));
    assert_eq!(helper_outcome(helper_code::REJECTED, "msi").unwrap_err(), crate::i18n::t("upd.rejected"));
    for c in [126, 127] {
        assert_eq!(helper_outcome(c, "deb").unwrap_err(), crate::i18n::t("upd.declined"));
    }
    assert_ne!(crate::i18n::t("upd.rejected"), crate::i18n::t("upd.declined"), "refused and declined read differently");
    assert!(helper_outcome(helper_code::INSTALL, "deb").unwrap_err().contains(&helper_code::INSTALL.to_string()));
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

// ---- 3.1.0 review 2 #1 / #2 ----

#[test]
fn helper_refusals_do_not_tell_what_exists() {
    let d = tdir();
    let f = fixture_set(&d);
    let a = args_of(&f);
    let big = d.join("big.sig");
    std::fs::write(&big, vec![0u8; MAX_SMALL as usize + 1]).unwrap();
    let mut msgs = Vec::new();
    for p in [d.join("nope.sig"), d.clone(), big] {
        let mut x = a.clone();
        x[1] = p.to_string_lossy().into_owned();
        let e = parse_helper_args(&x).unwrap_err();
        msgs.push(e.replace(&x[1], "<path>"));
    }
    assert!(msgs.iter().all(|m| m == "not a usable update file: <path>"), "{msgs:?}");
    // and the copy step reads with the owner rule (Linux: PKEXEC_UID; see shield-platform tests)
    let src = include_str!("update.rs");
    assert!(src.contains("read_checked(from, max, &shield_platform::sys::update_input_owner_ok)"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn every_update_signature_uses_the_release_policy() {
    let src = include_str!("update.rs");
    let code = &src[..src.find("#[cfg(test)]").unwrap()];
    // 6: manifest + installer, dialog check, helper copies (2) and the helper's rollback-floor re-check
    assert_eq!(code.matches("verify_release(certs, ").count(), 6, "manifest + installer, dialog check, helper and its rollback re-check");
    assert!(!code.contains("sigverify::verify_any(") && !code.contains(".verify(&"), "no update signature checked with the general policy");
}
