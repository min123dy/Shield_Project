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
        ..Default::default()
    };
    let p = tmp();
    s.save_to(&p).unwrap();
    assert_eq!(Settings::load_from(&p), s);
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
