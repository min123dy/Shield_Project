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
fn the_msi_creates_the_update_folder_with_the_helper_dacl() {
    // 3.1.0 review 2 #3: same SYSTEM + Administrators protected DACL as the helper's ADMIN_DACL
    let w = read("installer/windows/installer.wxs");
    let helper = read("crates/shield-platform/src/windows/install.rs");
    assert!(helper.contains(r#"ADMIN_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";"#));
    assert!(w.contains(r#"<PermissionEx Sddl="O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" />"#));
    assert!(w.contains(r#"<StandardDirectory Id="CommonAppDataFolder">"#) && w.contains(r#"<Directory Id="SHIELDDATAFOLDER" Name="Shield" />"#));
    assert!(w.contains(r#"<ComponentRef Id="UpdateDataFolder" />"#));
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
        // 3.1.0 #14: replaces ShellOpen {FAD7429D-...} (new key path, so a new component; docs 06)
        ("ShellOpenAny", "4FFE6B85-5A92-46BC-AB60-BA9877B1BB95"),
        // 3.1.0 review 2 #3: %ProgramData%\Shield, created by the MSI
        ("UpdateDataFolder", "975C4053-E64B-4359-B32A-261CA43C1CAE"),
        // 3.1.0 final: secure delete verb
        ("ShellWipe", "C81AF9CF-4EC3-4E3E-B743-306BC6D54FDA"),
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
    for k in ["*\\shell\\Shield.Encrypt", "Directory\\shell\\Shield.Encrypt", ".shd\\shell\\Shield.Decrypt", "*\\shell\\Shield.Open", "*\\shell\\Shield.Wipe", "Directory\\shell\\Shield.Wipe"] {
        assert_eq!(w.matches(&format!("{k}\"")).count(), 1, "{k}");
    }
    // the old component GUID is not reused for anything else
    assert!(!w.contains("Guid=\"FAD7429D-1362-5A6A-BA62-507E092764CC\""), "ShellOpen's GUID must not come back");
}

/// 3.1.0 #14: "Open in SHIELD" on every file, single selection, classic menu only; the .shd
/// type keeps its decrypt verb; no .shd-only open verb; no Windows 11 new-menu registration.
#[test]
fn open_in_shield_is_offered_on_every_file() {
    let w = read("installer/windows/installer.wxs");
    let start = w.find("<Component Id=\"ShellOpenAny\"").unwrap();
    let comp = &w[start..start + w[start..].find("</Component>").unwrap()];
    assert!(comp.contains("Root=\"HKLM\" Key=\"Software\\Classes\\*\\shell\\Shield.Open\""), "{comp}");
    assert!(comp.contains("Name=\"MultiSelectModel\" Value=\"Single\""), "{comp}");
    assert!(comp.contains("--open \"%1\""), "{comp}");
    assert!(!w.contains("Key=\"SystemFileAssociations\\.shd\\shell\\Shield.Open\""), "the .shd-only open verb is gone");
    assert!(w.contains("SystemFileAssociations\\.shd\\shell\\Shield.Decrypt"), "decrypt on .shd stays");
    assert!(w.contains("<ComponentRef Id=\"ShellOpenAny\" />") && !w.contains("<ComponentRef Id=\"ShellOpen\" />"));
    for bad in ["IExplorerCommand", "SparsePackage", "AppxManifest", "ExplorerCommandHandler"] {
        assert!(!w.contains(bad), "no Windows 11 new-menu registration ({bad})");
    }
    // portable registration writes the same
    let s = read("crates/shield-platform/src/windows/shell.rs");
    assert!(s.contains(r#"r"Software\Classes\*\shell\Shield.Open""#));
    assert!(s.contains(r#"["Player", "Player", "Player", "Single", "Player", "Player"]"#));
    assert!(s.contains(r#"OLD_KEYS: [&str; 1] = [r"Software\Classes\SystemFileAssociations\.shd\shell\Shield.Open"]"#));
    // Linux: every file manager integration offers it for one file, any type
    let nemo = read("installer/linux/filemanagers/shield-open.nemo_action");
    assert!(nemo.contains("Exec=shield-gui --open %F") && nemo.contains("Selection=s") && nemo.contains("Extensions=any;"));
    let dolphin = read("installer/linux/filemanagers/shield-open-dolphin.desktop");
    assert!(dolphin.contains("X-KDE-MaxNumberOfUrls=1") && dolphin.contains("Exec=shield-gui --open %f") && dolphin.contains("all/allfiles"));
    let thunar = read("installer/linux/filemanagers/thunar-uca.xml");
    assert!(thunar.contains("shield-open-3") && thunar.contains("shield-gui --open %f"));
    let naut = read("installer/linux/filemanagers/nautilus-open.sh");
    assert!(naut.contains("shield-gui --open -- \"$1\""));
    let build = read("build.sh");
    for f in ["shield-open.nemo_action", "shield-open-dolphin.desktop", "nautilus-open.sh"] {
        assert!(build.contains(f), "build.sh installs {f}");
    }
    // the .shd type: its own desktop entry still opens containers by default
    assert!(read("installer/linux/shield-open.desktop").contains("MimeType=application/x-shield-container;"));
}

/// 3.1.0 final (review F): the three Nautilus scripts turn the selection into absolute paths the
/// same way (one block, byte for byte), pass items after `--`, and build.sh runs their test
/// (installer/linux/tests/nautilus_scripts_test.sh: spaces, quotes, newlines, file://, search views).
#[test]
fn nautilus_scripts_share_the_absolute_path_block() {
    let block = |f: &str| {
        let t = read(&format!("installer/linux/filemanagers/{f}")).replace('\r', "");
        let a = t.find("# Selection as absolute paths").unwrap_or_else(|| panic!("{f}: selection block"));
        let b = t.rfind("\nexec shield-gui ").unwrap_or_else(|| panic!("{f}: exec"));
        assert!(t[b..].contains(" -- \""), "{f}: items after --");
        for l in t.lines().filter(|l| !l.trim_start().starts_with('#')) {
            let subst = l.replace("$((", "");
            assert!(!l.contains("eval") && !subst.contains("$(") && !l.contains('`'), "{f}: nothing from a name is evaluated: {l}");
        }
        t[a..b].to_string()
    };
    let e = block("nautilus-encrypt.sh");
    assert!(e.contains("NAUTILUS_SCRIPT_SELECTED_FILE_PATHS") && e.contains("a=$PWD/$a"));
    assert_eq!(e, block("nautilus-wipe.sh"));
    assert_eq!(e, block("nautilus-open.sh"));
    assert!(read("build.sh").contains("sh installer/linux/tests/nautilus_scripts_test.sh"));
}

/// 3.1.0 final: "secure delete" is offered on files and folders on both OSes, always quoted, and
/// only opens the window (`--wipe`); no menu entry deletes anything by itself.
#[test]
fn secure_delete_verb_is_registered_everywhere_and_only_opens_the_window() {
    let w = read("installer/windows/installer.wxs");
    let start = w.find("<Component Id=\"ShellWipe\"").unwrap();
    let comp = &w[start..start + w[start..].find("</Component>").unwrap()];
    assert_eq!(comp.matches("--wipe \"%1\"").count(), 2, "{comp}");
    assert_eq!(comp.matches("Value='\"[INSTALLFOLDER]shield-gui.exe\" --wipe").count(), 2, "exe path quoted");
    assert!(w.contains("<ComponentRef Id=\"ShellWipe\" />"));
    for l in ["installer/windows/installer.en-US.wxl", "installer/windows/installer.ko-KR.wxl"] {
        assert!(read(l).contains("<String Id=\"VerbWipe\""), "{l}");
    }
    assert!(read("installer/windows/installer.ko-KR.wxl").contains("SHIELD로 완전삭제"));
    let s = read("crates/shield-platform/src/windows/shell.rs");
    assert!(s.contains(r#"r"Software\Classes\*\shell\Shield.Wipe""#) && s.contains(r#"r"Software\Classes\Directory\shell\Shield.Wipe""#));
    assert!(s.contains(r#"format!("\"{e}\" {a} \"%1\"")"#), "portable registration quotes the program and the item");
    for f in ["shield-wipe.nemo_action", "shield-wipe-dolphin.desktop", "nautilus-wipe.sh"] {
        let t = read(&format!("installer/linux/filemanagers/{f}"));
        assert!(t.contains("--wipe"), "{f}");
        for bad in ["--yes", "--i-understand", "--confirm-token", "shield wipe"] {
            assert!(!t.contains(bad), "{f} must only open the window ({bad})");
        }
        assert!(read("build.sh").contains(f), "build.sh installs {f}");
    }
    let t = read("installer/linux/filemanagers/thunar-uca.xml");
    assert!(t.contains("<unique-id>shield-wipe-3</unique-id>") && t.contains("shield-gui --wipe %F"));
    assert!(read("installer/linux/filemanagers/integrate.sh").contains("nautilus-wipe.sh"));
    let l = read("crates/shield-platform/src/linux/shell.rs");
    assert!(l.contains("\\\"{e}\\\" --wipe %F") && l.contains("SHIELD로 완전삭제"));
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
fn debian_control_directory_permissions_are_explicit() {
    let script = read("build.sh");
    assert!(script.contains("install -d -m 0755 \"$d/DEBIAN\""), "DEBIAN must not inherit a permissive umask");
    assert!(script.contains("chmod 0755 \"$d/DEBIAN\""), "dpkg-deb requires a valid control directory mode");
    assert!(script.contains("chmod 0644 \"$d/DEBIAN/control\""), "the control file must have predictable permissions");
}

#[test]
fn workspace_license_is_unified_on_apache_2() {
    let workspace = read("Cargo.toml");
    assert!(workspace.contains("license = \"Apache-2.0\""));
    assert!(!workspace.contains("GPL-3.0-or-later"));
    for crate_name in ["shield-core", "shield-platform", "shield-gui", "shield-cli"] {
        let manifest = read(&format!("crates/{crate_name}/Cargo.toml"));
        assert!(manifest.contains("license.workspace = true"), "{crate_name} must inherit the workspace license");
    }
    let license = read("LICENSE");
    assert!(license.contains("Apache License") && license.contains("Version 2.0"));
    assert!(read("deny.toml").contains("\"Apache-2.0\""));
}

#[test]
fn one_version_and_no_pre_release_labels() {
    // 3.0.0 §8: the release says what it is everywhere
    let v = crate::buildinfo::VERSION;
    assert!(!v.contains('-'), "{v} is a pre-release version");
    let cargo = read("Cargo.toml");
    assert!(cargo.contains(&format!("version = \"{v}\"")), "workspace version");
    // 3.1.0: the change log of this release names it (the 3.0.0 log stays as the 3.0 record)
    for (f, want) in [(format!("docs/06_{v}_수정_기록.txt"), format!("SHIELD {v}")), (format!("docs/en/06_changes_{v}.txt"), v.to_string()), ("docs/04_설치_안내.txt".to_string(), v.to_string()), ("docs/en/04_install_notes.txt".to_string(), v.to_string())] {
        assert!(read(&f).lines().next().unwrap_or("").contains(&want) || read(&f).contains(&want), "{f} names {want}");
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
    // RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS both replace the rustflags of .cargo/config.toml
    // (3.1.0 final: the path remapping first used CARGO_ENCODED_RUSTFLAGS and silently dropped
    // crt-static; the Linux test run caught it)
    for f in ["build.ps1", "build.sh", ".github/workflows/release.yml"] {
        assert!(!read(f).contains("RUSTFLAGS"), "{f}: a RUSTFLAGS variable would replace .cargo/config.toml");
    }
}

/// The jobs of release.yml: (name, text of the job).
fn workflow_jobs() -> Vec<(String, String)> {
    let w = read(".github/workflows/release.yml");
    let body = &w[w.find("\njobs:\n").expect("jobs:") + 7..];
    let mut jobs: Vec<(String, String)> = vec![];
    for line in body.lines() {
        let top = line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') && !line.trim_start().starts_with('#');
        if top {
            jobs.push((line.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some(j) = jobs.last_mut() {
            j.1.push_str(line);
            j.1.push('\n');
        }
    }
    jobs
}

/// 3.1.0 #2: building and signing are separate; secrets only where signing happens.
#[test]
fn release_workflow_keeps_secrets_out_of_builds() {
    let jobs = workflow_jobs();
    let names: Vec<&str> = jobs.iter().map(|j| j.0.as_str()).collect();
    for want in ["audit", "build-windows", "build-linux", "sign-binaries", "package-windows", "package-linux", "sign-release", "publish"] {
        assert!(names.contains(&want), "job {want} missing: {names:?}");
    }
    for (name, text) in &jobs {
        let signing = text.contains("environment: release-signing");
        assert_eq!(signing, name.starts_with("sign-"), "{name}: only the sign-* jobs use the signing environment");
        if signing {
            // tag pushes only; no cargo, no package installs, no third-party actions
            assert!(text.contains("if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"), "{name}: tags only");
            for bad in ["cargo ", "apt-get", "pip ", "npm ", "curl ", "wget "] {
                assert!(!text.contains(bad), "{name} runs {bad}");
            }
            for u in text.lines().filter_map(|l| l.trim().strip_prefix("- uses: ")) {
                assert!(["actions/checkout@", "actions/download-artifact@", "actions/upload-artifact@"].iter().any(|a| u.starts_with(a)), "{name}: {u}");
            }
            // the passphrase only on file descriptor 0
            assert!(text.contains("--passphrase-fd 0") && !text.contains("passphrase-file"), "{name}");
        } else {
            assert!(!text.contains("secrets."), "{name} must not see secrets");
            assert!(!text.contains("--sign ") && !text.contains("-Sign "), "{name} must not sign");
        }
    }
    let w = read(".github/workflows/release.yml");
    // every action pinned to a full commit SHA (or explicitly marked as not yet pinned)
    for u in w.lines().filter_map(|l| l.trim().strip_prefix("- uses: ")) {
        let at = u.split_once('@').map(|x| x.1).unwrap_or("");
        let sha = at.split_whitespace().next().unwrap_or("");
        assert!((sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())) || u.contains("TODO-PIN"), "not pinned: {u}");
    }
    assert!(!w.contains("passphrase-file") && !w.contains("> \"$h/pp\""), "no passphrase file");
    assert!(w.contains("cargo audit --deny warnings") && w.contains("cargo deny --locked check advisories bans sources licenses"));
    assert!(read(".github/dependabot.yml").contains("package-ecosystem: github-actions"));
    assert!(read("deny.toml").contains("[advisories]"));
}

/// 3.1.0 #2: every cargo build / test / run in the build scripts and CI uses the lock file.
#[test]
fn every_cargo_build_is_locked() {
    for f in ["build.ps1", "build.sh", ".github/workflows/release.yml"] {
        for (i, l) in read(f).lines().enumerate() {
            let code = l.split(" #").next().unwrap_or(l).trim_start();
            if code.starts_with('#') {
                continue;
            }
            for c in ["cargo test", "cargo build", "cargo run", "cargo zigbuild", "cargo install"] {
                if code.contains(c) && !code.contains("cargo test`") {
                    assert!(code.contains("--locked"), "{f}:{}: {l}", i + 1);
                }
            }
        }
    }
    // the stages exist in both scripts
    let (ps, sh) = (read("build.ps1"), read("build.sh"));
    assert!(ps.contains("[ValidateSet('all', 'build', 'package', 'manifest')][string]$Stage"));
    assert!(sh.contains("case \"$stage\" in all|build|package|manifest)"));
    // 3.1.0 #9-C: Windows release builds are MSVC only
    assert!(ps.contains("'^host: x86_64-pc-windows-msvc$'"));
}

/// 3.1.0 final (review G): pinned runners and toolchain, no `${{ ... }}` expression expanded
/// inside `run:` scripts (values go through `env:`), clippy in CI, build attestations checked before signing.
#[test]
fn release_workflow_is_pinned_and_checks_provenance_before_signing() {
    let w = read(".github/workflows/release.yml").replace('\r', "");
    for l in w.lines().filter(|l| l.trim_start().starts_with("runs-on:")) {
        assert!(!l.contains("-latest"), "unpinned runner image: {l}");
    }
    // inside run: blocks, untrusted values only through env:
    let mut in_run = false;
    let mut run_indent = 0;
    for l in w.lines() {
        let indent = l.len() - l.trim_start().len();
        if in_run && !l.trim().is_empty() && indent <= run_indent {
            in_run = false;
        }
        let t = l.trim_start();
        if let Some(rest) = t.strip_prefix("run: ").or_else(|| t.strip_prefix("- run: ")) {
            in_run = rest.trim() == "|";
            run_indent = indent;
            // no expression at all, not even trusted ones (github.repository, matrix.*): values
            // reach scripts only through env: / the runner's GITHUB_* variables
            assert!(!rest.contains("${{"), "expanded inside a script: {l}");
        } else if in_run {
            assert!(!l.contains("${{"), "expanded inside a script: {l}");
        }
    }
    let tc = read("rust-toolchain.toml");
    assert!(tc.lines().any(|l| l.trim().starts_with("channel = \"1.") && l.matches('.').count() == 2), "exact toolchain version: {tc}");
    assert!(tc.contains("clippy"));
    let jobs = workflow_jobs();
    let job = |n: &str| jobs.iter().find(|j| j.0 == n).map(|j| j.1.clone()).unwrap_or_else(|| panic!("job {n}"));
    for b in ["build-windows", "build-linux"] {
        assert!(job(b).contains("cargo clippy --workspace --release --locked --all-targets -- -D warnings"), "{b}: clippy (each OS has code the other can't check)");
    }
    for b in ["build-windows", "build-linux"] {
        assert!(job(b).contains("actions/attest-build-provenance@"), "{b}");
        assert!(job(b).contains("id-token: write") && job(b).contains("attestations: write"), "{b}");
    }
    let sb = job("sign-binaries");
    let (check, sign) = (sb.find("gh attestation verify").expect("attestation check"), sb.find("--detach-sign").unwrap());
    let secret = sb.find("secrets.").unwrap();
    assert!(check < secret && check < sign, "the attestation check runs before any secret is loaded");
    assert!(sb.contains("--signer-workflow \"$GITHUB_REPOSITORY/.github/workflows/release.yml\""));
    assert!(job("package-linux").contains("sha256sum -c -") && job("package-linux").contains("URL: ${{ vars.APPIMAGETOOL_URL }}"));
}

/// 3.1.0 final (review B): every release also carries the v2 manifest, built from the same hash
/// lines as v1 (CI and both build scripts), and signed with the rest.
#[test]
fn v2_manifest_is_written_and_signed_everywhere() {
    let w = read(".github/workflows/release.yml").replace('\r', "");
    let sr = workflow_jobs().into_iter().find(|j| j.0 == "sign-release").unwrap().1;
    for t in [&sr, &read("build.sh"), &read("build.ps1")] {
        assert!(t.contains("Shield release manifest 2"), "{t:.80}");
        for f in ["release_id", "issued_at", "expires_at", "min_allowed_version", "revoked_key", "keys/revoked_keys.txt".replace('/', if t.contains("$distDir") { "\\" } else { "/" }).as_str()] {
            assert!(t.contains(f), "{f}");
        }
        assert!(t.contains("365 * 86400"), "validity: 365 days");
        assert!(t.contains("_release_v2.txt"));
    }
    // CI: the v2 hash lines equal v1's; per-platform v2 files from the package jobs are not copied
    assert!(sr.contains("[ \"$(grep '^sha256 ' \"out/Shield_v${v}_release_v2.txt\")\" = \"$(tail -n +3 \"out/Shield_v${v}_release.txt\")\" ]"));
    assert!(w.contains("Shield_v*_release_v2.txt*|"));
    // CI signs everything in out/ (v2 included); the scripts sign it explicitly
    assert!(sr.contains("for f in out/*; do"));
    assert!(read("build.sh").contains("\"$manifest\" \"$manifest2\"; do sign_file"));
    assert!(read("build.ps1").contains("@($manifest, $manifest2)"));
    // the 365 days fit what the client accepts
    const { assert!(365 * 86400 <= crate::manifest2::MAX_VALIDITY) };
    assert_eq!(crate::update::manifest2_name(crate::update::Version(3, 1, 0)), "Shield_v3.1.0_release_v2.txt");
    // the revocation list exists and holds only comments or fingerprints
    for l in read("keys/revoked_keys.txt").lines() {
        assert!(l.is_empty() || l.starts_with('#') || crate::manifest2::norm_fpr(l).as_deref() == Some(l), "{l}");
    }
}

/// 3.1.0 final (review I): every advisory exception has a review date, is listed in deny.toml
/// too, and CI fails once the date has passed.
#[test]
fn advisory_exceptions_have_review_dates() {
    let (a, d) = (read(".cargo/audit.toml"), read("deny.toml"));
    let ids: Vec<&str> = a.lines().filter_map(|l| l.trim().strip_prefix('"')).filter_map(|l| l.split('"').next()).filter(|i| i.starts_with("RUSTSEC-")).collect();
    assert!(!ids.is_empty());
    for id in ids {
        let line = a.lines().find(|l| l.contains(&format!("\"{id}\""))).unwrap();
        let date = line.split("review-by ").nth(1).unwrap_or_else(|| panic!("{id}: no review-by date"));
        let b = date.trim().as_bytes();
        assert!(b.len() == 10 && b[4] == b'-' && b[7] == b'-', "{id}: {date}");
        assert!(d.contains(&format!("\"{id}\"")), "{id} missing in deny.toml");
    }
    assert!(read(".github/workflows/release.yml").contains("review date $d has passed"));
}

/// Every armored file under `dir` (recursive).
fn asc_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            asc_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "asc") {
            out.push(p);
        }
    }
}

/// 3.1.0 final (review C): test fixtures hold only test keys. No fixture is (or contains) the
/// bundled release key or backup key, none has a private key, and test key user IDs use the
/// reserved `.invalid` domain, so no personal address is copied into the test tree.
#[test]
fn test_fixtures_never_hold_a_release_key_or_personal_data() {
    use crate::sigverify::Cert;
    let real: Vec<String> = ["keys/release_key.asc", "keys/release_key_backup.asc"]
        .iter()
        .map(|k| root().join(k))
        .filter(|p| p.is_file())
        .map(|p| Cert::from_file(&p).unwrap().fingerprint_hex())
        .collect();
    assert!(!real.is_empty(), "keys/release_key.asc is missing");
    let mut files = Vec::new();
    asc_files(&root().join("crates/shield-core/tests/fixtures"), &mut files);
    assert!(files.len() >= 10, "{files:?}");
    for f in files {
        #[allow(clippy::disallowed_methods)]
        let text = std::fs::read_to_string(&f).unwrap();
        assert!(!text.contains("PRIVATE KEY"), "{}: private key in the test tree", f.display());
        if !text.contains("PUBLIC KEY BLOCK") {
            continue; // an armored signature
        }
        let c = Cert::from_file(&f);
        if let Ok(c) = &c {
            assert!(!real.contains(&c.fingerprint_hex()), "{}: a copy of a release key", f.display());
        }
        for real_fpr in &real {
            assert!(!text.contains(real_fpr.as_str()), "{}", f.display());
        }
        use pgp::composed::{Deserializable, SignedPublicKey};
        let (k, _) = SignedPublicKey::from_armor_single(std::io::Cursor::new(text.as_bytes())).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let uids: Vec<String> = k.details.users.iter().map(|u| String::from_utf8_lossy(u.id.id()).into_owned()).collect();
        assert!(!uids.is_empty(), "{}: no user ID found", f.display());
        for u in uids {
            assert!(u.ends_with(".invalid>") || u.ends_with("@invalid>"), "{}: user ID {u:?} is not a test address", f.display());
        }
    }
}

/// 3.1.0 #2 / 0-2: what 3.0.0 clients rely on is unchanged: the manifest header and line format,
/// the asset names.
#[test]
fn release_manifest_and_asset_names_are_unchanged() {
    let sh = read("build.sh");
    let ps = read("build.ps1");
    let w = read(".github/workflows/release.yml");
    for t in [&sh, &ps, &w] {
        assert!(t.contains("Shield release manifest 1"));
    }
    assert!(w.contains("grep -E '^sha256 [0-9a-f]{64} [^[:space:]]+$'"));
    assert!(ps.contains("\"Shield_v${version}_x64.msi\"") && ps.contains("Shield_v${version}_x64_portable.exe"));
    assert!(sh.contains("shield_v${version}_${deb_arch}.deb") && sh.contains("Shield_v${version}_${native}.AppImage"));
    assert_eq!(crate::update::package_name(crate::update::Version(3, 1, 0), "msi").as_deref(), Some("Shield_v3.1.0_x64.msi"));
}

/// 3.1.0 (found while running the stages): under `set -e` an EXIT trap whose last command is a
/// false `[ ... ] && ...` turns the script's exit status into 1, so every unsigned build.sh run
/// "failed". The trap function has to end with `return 0`.
#[test]
fn build_sh_exit_trap_cannot_fail_the_build() {
    let sh = read("build.sh").replace('\r', "");
    let i = sh.find("\ncleanup() {").expect("cleanup()");
    let body = &sh[i..i + sh[i..].find("\n}\n").expect("end of cleanup()")];
    assert!(body.trim_end().ends_with("return 0"), "{body}");
    assert!(sh.contains("\ntrap cleanup EXIT\n"));
}

/// 3.1.0 review 3 (CWE-789 / CWE-400): product code reads files only through
/// shield_platform::bounded (limit on the open handle and on the read). The few whole reads
/// left are listed here with the reason; a new one fails this test.
#[test]
fn no_unbounded_file_reads_in_product_code() {
    const ALLOWED: &[(&str, &str, &str)] = &[
        ("shield-platform/src/bounded.rs", "r.take(max.saturating_add(1)).read_to_end", "the limited reader itself"),
        ("shield-platform/src/linux/entropy.rs", "f.take(256 * 1024).read_to_end", "limited by take"),
        ("shield-core/src/update.rs", ".limit(MAX_API).read_to_string()", "HTTP body with a limit"),
        ("shield-platform/src/linux/storage.rs", "fs::read_to_string(\"/proc/self/mountinfo\")", "kernel pseudo-file"),
        ("shield-platform/src/linux/storage.rs", "fs::read_to_string(p).ok().map(|s| s.trim()", "read_trim: /sys attributes only"),
        ("shield-platform/src/linux/sys.rs", "fs::read_to_string(\"/proc/meminfo\")", "kernel pseudo-file"),
        ("shield-platform/src/linux/sys.rs", "fs::read_to_string(format!(\"/proc/{pid}/stat\"))", "kernel pseudo-file"),
        ("shield-platform/src/linux/sys.rs", "io::Read::read_to_string(child.stdout.as_mut()?", "output of an exited system program (pipe buffer)"),
    ];
    let mut found = Vec::new();
    let mut stack = vec![root().join("crates")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if p.is_dir() {
                if name != "target" && name != "tests" {
                    stack.push(p);
                }
                continue;
            }
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" || name == "build.rs" {
                continue;
            }
            let rel = p.strip_prefix(root().join("crates")).unwrap().to_string_lossy().replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap();
            for l in code.lines() {
                let hit = ["fs::read(", "fs::read_to_string(", "read_to_end(", "read_to_string("].iter().any(|k| l.contains(k));
                if hit && !l.trim_start().starts_with("//") && !ALLOWED.iter().any(|(f, s, _)| rel == *f && l.contains(s)) {
                    found.push(format!("{rel}: {}", l.trim()));
                }
            }
        }
    }
    assert!(found.is_empty(), "unbounded reads (use shield_platform::bounded):\n{}", found.join("\n"));
}

/// The bundled public key must be parseable, but key topology (subkeys, expiry, user ID,
/// optional backup key) is an operational hardening recommendation, not a build or release gate.
#[test]
fn bundled_release_key_is_usable_without_optional_key_shape_requirements() {
    let cert = crate::sigverify::Cert::from_file(&root().join("keys/release_key.asc")).expect("usable public key");
    assert_eq!(cert.fingerprint_hex().len(), 40);
}

/// Release builds must not require a special key topology or a backup key merely to compile.
#[test]
fn release_workflow_has_no_release_key_shape_gate() {
    let workflow = read(".github/workflows/release.yml");
    assert!(!workflow.contains("release_tests::release_key_gate"), "the release workflow must not block on optional key-shape policy");
    assert!(!workflow.contains("Release key gate (tags only"), "remove the tag-only key gate step");
    assert!(workflow.contains("run: |\n          gh release create"), "release notes containing a colon must be in a YAML block scalar");
    for script in ["build.ps1", "build.sh"] {
        let body = read(script);
        assert!(!body.contains("release_tests::release_key_gate"), "{script} must not run a mandatory key-shape check");
    }
}

/// 3.1.0 final 2-2: no setting weakens the secure delete confirmation ("don't ask again", "skip
/// the code" ...). Every stored key is listed here; a new key that mentions wiping, confirming,
/// codes or skipping makes this fail until it is looked at.
#[test]
fn no_setting_skips_the_secure_delete_confirmation() {
    let text = crate::settings::Settings::default().to_toml();
    let keys: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_once(" = ").map(|(k, _)| k.trim())).collect();
    assert!(keys.len() > 20, "{keys:?}");
    // known keys that mention these words: the manager's delete question and the disk tab;
    // wipe_needs_settings_pw adds a step (settings password) on top of the three and is on
    // by default; off gives back the three steps, never fewer (it is not part of `Confirmation`)
    let known = ["confirm_delete", "ui_wipe_free_after", "ui_disk_trim_after_wipe", "wipe_needs_settings_pw"];
    assert!(crate::settings::Settings::default().wipe_needs_pw, "the settings password step is on by default");
    for k in keys {
        let l = k.to_ascii_lowercase();
        if ["wipe", "secure", "sd_", "confirm", "captcha", "code", "skip", "ask", "never", "always"].iter().any(|w| l.contains(w)) {
            assert!(known.contains(&k), "new setting {k}: secure delete has no option that skips or weakens its confirmation (docs/10 2-2)");
        }
    }
    // the confirmation itself has no switch: Confirmation::new takes only the plan
    let src = read("crates/shield-core/src/secure_delete.rs");
    assert!(src.contains("pub fn new(plan: Plan) -> Confirmation"));
}

/// 3.1.0 final (4-7): the build scripts (and so CI, which runs them) remap local absolute source
/// paths, so no account name or folder of the build computer ends up in the programs.
/// 3.1.0 final: `sudo ./build.sh` found no cargo (sudo's PATH and HOME) and left target/ owned by
/// root. build.sh refuses sudo before the first question, says what to do about files a sudo run
/// left behind, and finds rustup's cargo in ~/.cargo/bin.
#[test]
fn build_sh_refuses_sudo_and_finds_rustup_cargo() {
    let sh = read("build.sh");
    let guard = sh.find("[ -n \"${SUDO_USER:-}\" ]").expect("sudo guard");
    let first_question = sh.find("read -r -p").expect("a question");
    assert!(guard < first_question, "refused before anything is asked");
    assert!(sh.contains("is not writable (left by a sudo run?)") && sh.contains("sudo chown -R"));
    assert!(sh.contains("/bin/cargo\" ]; then") && sh.contains("export PATH=\"${CARGO_HOME:-$HOME/.cargo}/bin:$PATH\""));
    assert!(sh.contains("cargo not found"));
}

#[test]
fn builds_remap_local_paths_out_of_the_programs() {
    // The flags live in a generated cargo config file (target.'cfg(any(unix, windows))'), which
    // cargo joins with the crt-static flags of .cargo/config.toml; a flags variable would replace
    // them (windows_programs_load_dlls_from_system32_only).
    let ps = read("build.ps1");
    for r in ["--remap-path-prefix=$homeDir=~", "--remap-path-prefix=$cargoHome=/cargo", "--remap-path-prefix=$rustupHome=/rustup", "--remap-path-prefix=$root=/shield", "[target.'cfg(any(unix, windows))']"] {
        assert!(ps.contains(r), "build.ps1: {r}");
    }
    let sh = read("build.sh");
    for r in ["--remap-path-prefix=$HOME=~", "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo", "--remap-path-prefix=$ROOT=/shield", "[target.'cfg(any(unix, windows))']"] {
        assert!(sh.contains(r), "build.sh: {r}");
    }
    // every cargo build / test / run of the scripts uses the file, and it is written first
    for (t, name, cfg, written) in [(&ps, "build.ps1", "--config $remapConfig", "WriteAllText($remapConfig"), (&sh, "build.sh", "--config \"$remap_config\"", "> \"$remap_config\"")] {
        let calls: Vec<&str> = t.lines().map(str::trim_start).filter(|l| ["cargo build", "cargo test", "cargo run", "cargo zigbuild"].iter().any(|c| l.trim_start_matches("& ").trim_start_matches("then ").trim_start_matches("else ").starts_with(c))).collect();
        assert!(calls.len() >= 3, "{name}: {calls:?}");
        for c in &calls {
            assert!(c.contains(cfg), "{name}: without the remap config: {c}");
        }
        assert!(t.find(written).unwrap() < t.find(calls[0]).unwrap(), "{name}: written before the first cargo call");
    }
}
