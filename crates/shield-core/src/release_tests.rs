//! Release checks on repository files (3.0.0 §5 / §8): the Windows installer keeps its identity
//! and upgrade rules, and version / labels agree everywhere.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// 2.1.0 (dist_old_v2.1.0/Shield.msi), the 3.0.0 betas and 3.0.0: one product family.
const UPGRADE_CODE: &str = "6B1E5C0A-3D7F-4C52-9A1B-0F8E2D4C7A91";

#[test]
fn installer_replaces_every_earlier_version_in_any_language() {
    let w = read("installer/windows/installer.wxs");
    assert_eq!(w.matches("UpgradeCode=").count(), 1);
    assert!(w.contains(&format!("UpgradeCode=\"{UPGRADE_CODE}\"")), "the UpgradeCode must never change");
    let mu = w.lines().find(|l| l.contains("<MajorUpgrade")).expect("MajorUpgrade");
    for need in ["IgnoreLanguage=\"yes\"", "AllowSameVersionUpgrades=\"yes\"", "DowngradeErrorMessage=", "Schedule=\"afterInstallValidate\""] {
        assert!(mu.contains(need), "MajorUpgrade needs {need}");
    }
    assert!(w.contains("Scope=\"perMachine\""), "2.1.0 was per machine; another scope is not upgraded");
}

#[test]
fn installer_components_are_stable_and_single() {
    let w = read("installer/windows/installer.wxs");
    // components with a fixed GUID (values WiX derived in 3.0.0; ConsoleExe = 2.1.0's AppExe)
    for (id, g) in [
        ("GuiExe", "2149D7DF-3449-5EC9-9F05-D5D77B0E8A13"),
        ("ConsoleExe", "50338B79-36DE-5605-9117-ED7A4F0FD500"),
        ("ConsolePath", "9C3A41E2-7B5D-4E08-8F16-2D7C5B0A9E31"),
        ("ShellEncrypt", "B14657AC-1287-5D56-8858-EEB0FA8885E1"),
        ("ShellDecrypt", "D36A412F-9CF9-5678-9480-CADEDC89AB90"),
        ("ShellOpen", "FAD7429D-1362-5A6A-BA62-507E092764CC"),
    ] {
        let line = w.lines().find(|l| l.contains(&format!("<Component Id=\"{id}\""))).unwrap_or_else(|| panic!("{id}"));
        assert!(line.contains(&format!("Guid=\"{g}\"")), "{id} GUID changed: {line}");
    }
    let guids: Vec<&str> = w.match_indices("Guid=\"").map(|(i, _)| &w[i + 6..i + 42]).collect();
    let mut u = guids.clone();
    u.sort_unstable();
    u.dedup();
    assert_eq!(u.len(), guids.len(), "a GUID is used twice");
    // exactly one PATH entry, appended, removed on uninstall
    assert_eq!(w.matches("<Environment ").count(), 1);
    let env = w.lines().find(|l| l.contains("<Environment ")).unwrap();
    for need in ["Name=\"PATH\"", "Part=\"last\"", "Permanent=\"no\"", "System=\"yes\""] {
        assert!(env.contains(need), "PATH entry needs {need}");
    }
    // each Explorer verb registered once
    for k in ["*\\shell\\Shield.Encrypt", "Directory\\shell\\Shield.Encrypt", ".shd\\shell\\Shield.Decrypt", ".shd\\shell\\Shield.Open"] {
        assert_eq!(w.matches(&format!("{k}\"")).count(), 1, "{k}");
    }
}

#[test]
fn msi_version_mapping_for_pre_releases() {
    // build.ps1 turns X.0.0-<tag>.N into (X-1).99.N and refuses other pre-release forms
    let b = read("build.ps1");
    assert!(b.contains(r"'^(\d+)\.(\d+)\.(\d+)-[0-9A-Za-z]+\.(\d+)$'"), "pre-release pattern");
    assert!(b.contains("$msiVersion = \"$([int]$Matches[1] - 1).99.$([int]$Matches[4])\""), "mapping");
    assert!(b.contains("-d \"Version=$msiVersion\""), "the MSI is built with the mapped version");
    // the mapping keeps the order Windows Installer sees: 2.1.0 < 2.99.1 < 2.99.2 < 3.0.0
    let v = |s: &str| s.split('.').map(|x| x.parse::<u32>().unwrap()).collect::<Vec<_>>();
    assert!(v("2.1.0") < v("2.99.1") && v("2.99.1") < v("2.99.2") && v("2.99.2") < v("3.0.0"));
    assert!(b.starts_with('\u{feff}'), "build.ps1 needs its UTF-8 BOM (Windows PowerShell 5.1 reads Korean text otherwise as ANSI)");
}

#[test]
fn ui_state_never_holds_secrets_or_picked_paths() {
    // 3.0.0 §3: passwords, key files, key file paths and picked targets are never remembered
    let s = crate::settings::Settings::default();
    let text = s.to_toml();
    for k in crate::settings::UI_KEYS {
        assert!(text.contains(&format!("{k} =")), "{k} is written");
        for bad in ["pw", "pass_", "password", "keyfile", "key_", "_key", "path", "file", "target", "pim", "ack"] {
            assert!(!k.contains(bad), "{k} looks like something that must not be stored ({bad})");
        }
    }
    let auth = crate::settings_auth::Auth { salt: [7; 16], verifier: [9; 32], mac: [1; 64] };
    assert_eq!(format!("{auth:?}"), "Auth { .. }");
}

#[test]
fn one_version_and_no_pre_release_labels() {
    // 3.0.0 §8: the release says what it is everywhere
    let v = crate::buildinfo::VERSION;
    assert!(!v.contains('-'), "{v} is a pre-release version");
    let cargo = read("Cargo.toml");
    assert!(cargo.contains(&format!("version = \"{v}\"")), "workspace version");
    for (f, want) in [("docs/06_3.0.0_수정_기록.txt", format!("SHIELD {v}")), ("docs/en/06_changes_3.0.0.txt", v.to_string()), ("docs/04_설치_안내.txt", v.to_string()), ("docs/en/04_install_notes.txt", v.to_string())] {
        assert!(read(f).lines().next().unwrap_or("").contains(&want) || read(f).contains(&want), "{f} names {want}");
    }
    // nothing the program shows calls itself a beta / preview
    for l in [crate::i18n::Lang::Ko, crate::i18n::Lang::En] {
        for t in crate::i18n::tables(l) {
            for (k, s) in t.iter() {
                let low = s.to_lowercase();
                for bad in ["beta", "베타", "preview", "미리 보기", "시험판", "release candidate"] {
                    assert!(!low.contains(bad), "{l:?} {k}: {s}");
                }
            }
        }
    }
    for f in ["installer/windows/installer.ko-KR.wxl", "installer/windows/installer.en-US.wxl", "installer/linux/shield.desktop", "README.md", "README.txt"] {
        let low = read(f).to_lowercase();
        assert!(!low.contains("beta") && !low.contains("베타"), "{f} has a beta label");
    }
}

#[test]
fn windows_programs_load_dlls_from_system32_only() {
    // security review 2026-11-08: a DLL with a system name next to the portable / console exe
    // used to be loaded before main; vcruntime140.dll was one of them
    for f in ["crates/shield-gui/build.rs", "crates/shield-cli/build.rs"] {
        assert!(read(f).contains("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800"), "{f}: System32-only DLL search");
    }
    let c = read(".cargo/config.toml");
    assert!(c.contains("target_env = \"msvc\"") && c.contains("target-feature=+crt-static"), "static C runtime");
    for f in ["build.ps1", ".github/workflows/release.yml"] {
        assert!(!read(f).contains("RUSTFLAGS"), "{f}: a RUSTFLAGS variable would replace .cargo/config.toml");
    }
}
