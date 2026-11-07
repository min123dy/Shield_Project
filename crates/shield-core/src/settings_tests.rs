use super::*;

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_set_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(FILE)
}

#[test]
fn defaults_match_the_spec() {
    let d = Settings::default();
    assert!(d.capture_protect && d.mouse_entropy && d.lock_on_minimize && d.confirm_delete);
    assert_eq!(d.auto_lock_min, 5);
    assert!(!d.recent_files, "recent files are off by default");
    assert!(!d.allow_arg_secrets && d.update == UpdateMode::Off, "3.0: secrets on the command line and updates off");
    assert_eq!(d.shred_passes, crate::wipe::Passes::Seven);
    assert_eq!(d.ui_scale, 100);
}

#[test]
fn round_trip_every_field() {
    let s = Settings {
        lang: LangPref::En,
        theme: ThemePref::Dark,
        ui_scale: 130,
        date_fmt: DateFmt::Us,
        date_seconds: true,
        start_screen: StartScreen::Manager,
        capture_protect: false,
        mouse_entropy: false,
        auto_lock_min: 30,
        lock_on_focus_loss: true,
        strict_motw: true,
        strength: crate::compress::Strength::Max,
        default_pim: 20,
        keyfile_kib: 64,
        naming: Naming::Replace,
        show_hidden: true,
        start_folder: StartFolder::Documents,
        sort: SortBy::Date,
        allow_arg_secrets: true,
        entropy_disabled: vec!["perfdata".into(), "timers".into()],
        update: UpdateMode::Check,
        shred_passes: crate::wipe::Passes::Three,
        ..Default::default()
    };
    let p = tmp();
    let mut s = s;
    let u = crate::settings_auth::set_password(&mut s, b"round trip pw", None).unwrap();
    s.save_to_with(&p, Some(&u)).unwrap();
    let back = Settings::load_from(&p);
    s.auth.as_mut().unwrap().mac = back.auth.as_ref().unwrap().mac;
    assert_eq!(back, s);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains(&format!("schema = {SCHEMA}")));
}

#[test]
fn corrupt_file_keeps_capture_protection_on() {
    let p = tmp();
    std::fs::write(&p, [0xFFu8, 0xFE, 0x00, 0x13, 0x37]).unwrap();
    assert!(Settings::load_from(&p).capture_protect, "binary garbage");
    std::fs::write(&p, "capture_protect = maybe\nui_scale = 999\nauto_lock_minutes = 7\n").unwrap();
    let s = Settings::load_from(&p);
    assert!(s.capture_protect, "bad value");
    assert_eq!((s.ui_scale, s.auto_lock_min), (100, 5), "out-of-range values keep their defaults");
    assert!(Settings::load_from(&p.with_file_name("missing.toml")).capture_protect, "missing file");
}

#[test]
fn nothing_sensitive_is_written() {
    let p = tmp();
    Settings::default().save_to(&p).unwrap();
    let text = std::fs::read_to_string(&p).unwrap().to_lowercase();
    for word in ["password", "keyfile_path", "container", "recent_list", ":\\", "/users/"] {
        assert!(!text.contains(word), "{word} in {text}");
    }
}

#[test]
fn category_reset_touches_only_that_category() {
    let mut s = Settings { theme: ThemePref::Dark, auto_lock_min: 30, show_hidden: true, ..Default::default() };
    s.reset(Category::Security);
    assert_eq!(s.auto_lock_min, 5);
    assert_eq!(s.theme, ThemePref::Dark);
    assert!(s.show_hidden);
    s.reset(Category::General);
    s.reset(Category::Explorer);
    assert_eq!(s, Settings::default());
}

#[test]
fn atomic_save_leaves_no_temp_files() {
    let p = tmp();
    for i in 0..5 {
        let s = Settings { ui_scale: SCALES[i % SCALES.len()], ..Default::default() };
        s.save_to(&p).unwrap();
    }
    let dir = p.parent().unwrap();
    let left: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).collect();
    assert!(left.is_empty());
}

// ------------------------------------------------------------------ 3.0.0 §3 / §4

#[test]
fn ui_prefs_survive_a_restart() {
    let p = tmp();
    let base = Settings::load_from(&p);
    let mut s = base.clone();
    s.ui.choose_dest = true;
    s.ui.full_rekey = true;
    s.ui.win_enc = Some(crate::ui_prefs::WinPos { x: 120, y: 80 });
    s.strength = crate::compress::Strength::Max;
    let saved = s.save_merged(&base, &p, None).unwrap();
    assert_eq!(saved, s);
    let back = Settings::load_from(&p);
    assert_eq!(back.ui, s.ui);
    assert_eq!(back.strength, crate::compress::Strength::Max);
    assert!(back.load_issues.is_empty(), "{:?}", back.load_issues);
}

#[test]
fn damaged_rows_get_defaults_and_are_reported() {
    let p = tmp();
    std::fs::write(&p, "schema = 2\nui_choose_dest = perhaps\nui_win_enc = \"-32000,-32000\"\nui_scale = 999\nshow_hidden = true\nui_from_a_newer_version = 1\nfuture_key = 3\n").unwrap();
    let s = Settings::load_from(&p);
    assert!(s.show_hidden, "good rows are kept");
    assert_eq!((s.ui.choose_dest, s.ui.win_enc, s.ui_scale), (false, None, 100));
    let mut issues = s.load_issues.clone();
    issues.sort();
    assert_eq!(issues, vec!["ui_choose_dest", "ui_scale", "ui_win_enc"], "unknown rows of a newer version are not damage");
    std::fs::write(&p, [0xFFu8, 0xFE, 0x00]).unwrap();
    assert_eq!(Settings::load_from(&p).load_issues, vec![FILE.to_string()]);
    assert!(Settings::load_from(&p.with_file_name("missing.toml")).load_issues.is_empty(), "a missing file is not damage");
}

#[test]
fn a_version_1_file_still_loads() {
    let p = tmp();
    std::fs::write(&p, "schema = 1\nlang = \"en\"\nshow_hidden = true\n").unwrap();
    let s = Settings::load_from(&p);
    assert_eq!((s.lang, s.show_hidden), (LangPref::En, true));
    assert_eq!(s.ui, crate::ui_prefs::UiPrefs::default());
    assert!(s.load_issues.is_empty());
}

#[test]
fn two_instances_do_not_undo_each_other() {
    let p = tmp();
    let start = Settings::load_from(&p);
    // A changes one option, B (started at the same time, so the same base) another one
    let mut a = start.clone();
    a.ui.choose_dest = true;
    let a_saved = a.save_merged(&start, &p, None).unwrap();
    let mut b = start.clone();
    b.show_hidden = true;
    let b_saved = b.save_merged(&start, &p, None).unwrap();
    let disk = Settings::load_from(&p);
    assert!(disk.ui.choose_dest && disk.show_hidden, "both changes are in the file");
    assert!(b_saved.ui.choose_dest, "B picked up A's change");
    // the last change of the same option wins
    let mut a2 = a_saved.clone();
    a2.ui.choose_dest = false;
    a2.save_merged(&a_saved, &p, None).unwrap();
    assert!(!Settings::load_from(&p).ui.choose_dest);
    let _ = b_saved;
}

#[test]
fn switched_off_by_the_environment_keeps_the_file_value() {
    let p = tmp();
    let start = Settings::load_from(&p);
    assert!(start.capture_protect);
    let mut s = start.clone();
    s.suppress(EnvKey::CaptureProtect, "not available here");
    s.suppress(EnvKey::RememberWindowPos, "Wayland");
    assert!(!s.capture_protect && !s.ui.remember_window_pos, "shown and used as off");
    assert_eq!(s.off_reason(EnvKey::CaptureProtect), Some("not available here"));
    let mut base = start.clone();
    base.suppress(EnvKey::CaptureProtect, "not available here");
    base.suppress(EnvKey::RememberWindowPos, "Wayland");
    // another option is saved: the switched-off ones are not written as off
    s.show_hidden = true;
    let saved = s.save_merged(&base, &p, None).unwrap();
    let disk = Settings::load_from(&p);
    assert!(disk.capture_protect && disk.ui.remember_window_pos && disk.show_hidden, "file keeps the user's values");
    assert!(!saved.capture_protect && saved.off_reason(EnvKey::CaptureProtect).is_some(), "still off in this run");
    // an off feature can't be switched off by the environment (nothing to keep)
    let mut off = Settings { capture_protect: false, ..Default::default() };
    off.suppress(EnvKey::CaptureProtect, "x");
    assert!(off.env_off.is_empty());
    // the user switches it off by hand: that is saved
    let mut u = saved.clone();
    u.unsuppress(EnvKey::RememberWindowPos);
    u.ui.remember_window_pos = false;
    let mut ubase = saved.clone();
    ubase.unsuppress(EnvKey::RememberWindowPos);
    ubase.ui.remember_window_pos = true;
    u.save_merged(&ubase, &p, None).unwrap();
    assert!(!Settings::load_from(&p).ui.remember_window_pos);
    // the update mode keeps "check" in the file when no repository is built in
    let mut up = Settings { update: UpdateMode::Check, ..Default::default() };
    up.suppress(EnvKey::Update, "no repository");
    assert_eq!(up.update, UpdateMode::Off);
    assert!(up.to_toml().contains("update = \"check\""));
}
