//! 3.1.0 #15 / 0-2, 0-3: what a 3.0.0 installation reads must not change.
//!
//! * The update manifest: a 3.0.0 client parses 3.1.0's manifest with its own `parse_manifest`.
//!   The 3.0.0 text of that function is kept in tests/fixtures/compat_3_0_0 (copied from the 3.0.0
//!   source); the current one must still contain it verbatim, so "the 3.0.0 parser" and the parser
//!   these tests run are the same code.
//! * Settings: the MAC covers `Settings::protected_text`; its 3.0.0 text is kept the same way, and
//!   SCHEMA stays 2. Together with `settings_auth_tests::a_3_0_0_mac_without_lock_on_focus_loss_
//!   still_opens` a 3.0.0 settings file loads without the "changed outside Shield" warning.
//! * Containers: `cross_os_tests` opens the fixtures 3.0.x wrote on Windows and Linux; FORMAT
//!   VERSION stays 2.
use std::path::Path;

fn fixture(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat_3_0_0").join(name);
    std::fs::read_to_string(&p).unwrap().replace('\r', "")
}

fn source(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap().replace('\r', "")
}

/// A 3.1.0 manifest as the release workflow writes it (header, version, sorted "sha256" lines, LF).
fn manifest_3_1_0() -> String {
    let mut s = String::from("Shield release manifest 1\nversion 3.1.0\n");
    for (i, name) in ["Shield_Project_v3_1_0.zip", "Shield_v3.1.0_aarch64.AppImage", "Shield_v3.1.0_x64.msi", "Shield_v3.1.0_x64_portable.exe",
        "Shield_v3.1.0_x86_64.AppImage", "shield-console_v3.1.0_linux_arm64", "shield-console_v3.1.0_linux_x64",
        "shield-console_v3.1.0_windows_x64.exe", "shield_v3.1.0_amd64.deb", "shield_v3.1.0_arm64.deb"]
        .iter()
        .enumerate()
    {
        s.push_str(&format!("sha256 {} {name}\n", format!("{:02x}", i + 1).repeat(32)));
    }
    s
}

#[test]
fn the_3_0_0_manifest_parser_is_unchanged_and_reads_3_1_0_manifests() {
    let old = fixture("update_parse_manifest.rs.txt");
    assert!(old.starts_with("pub fn parse_manifest(") && old.trim_end().ends_with('}'));
    assert!(source("src/update.rs").contains(old.trim_end()), "update::parse_manifest differs from 3.0.0's");
    assert_eq!(crate::update::MANIFEST_HEAD, "Shield release manifest 1");
    let m = manifest_3_1_0();
    let v = crate::update::Version(3, 1, 0);
    for (i, kind) in ["msi", "deb", "AppImage"].iter().enumerate() {
        let Some(name) = crate::update::package_name(v, kind) else { continue };
        let (ver, hash) = crate::update::parse_manifest(&m, &name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(ver, v);
        assert!(m.contains(&format!("sha256 {} {name}", hex(&hash))), "{i}: {name}");
    }
    assert_eq!(crate::update::manifest_name(v), "Shield_v3.1.0_release.txt");
    // what a 3.0.0 client refuses still makes 3.1.0's merge step fail (one name, two hashes)
    let dup = format!("{m}sha256 {} Shield_v3.1.0_x64.msi\n", "ab".repeat(32));
    assert!(crate::update::parse_manifest(&dup, "Shield_v3.1.0_x64.msi").is_err());
}

#[test]
fn the_settings_mac_input_is_the_one_3_0_0_wrote() {
    let old = fixture("settings_protected_text.rs.txt");
    assert!(old.trim_start().starts_with("pub fn protected_text("));
    assert!(source("src/settings.rs").contains(old.trim_end()), "Settings::protected_text differs from 3.0.0's");
    assert_eq!(crate::settings::SCHEMA, 2);
    assert_eq!(crate::format::FORMAT_VERSION, 2);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
