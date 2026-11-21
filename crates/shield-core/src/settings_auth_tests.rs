use super::*;
use crate::i18n::has_code;
use crate::settings::UpdateMode;

fn file() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_auth_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("settings.toml")
}

#[test]
fn unprotected_changes_save_freely_but_protected_ones_need_a_password() {
    let p = file();
    let mut s = Settings { ui_scale: 120, ..Default::default() };
    s.save_to(&p).unwrap();
    assert_eq!(Settings::load_from(&p).ui_scale, 120);
    s.allow_arg_secrets = true;
    let e = s.save_to(&p).unwrap_err();
    assert!(has_code(&e, C_NEED_PW), "first protected change must set a password: {e}");
    let u = set_password(&mut s, b"settings secret 1", None).unwrap();
    s.save_to_with(&p, Some(&u)).unwrap();
    let back = Settings::load_from(&p);
    assert!(back.allow_arg_secrets && back.auth.is_some() && !back.tampered);
    assert!(!std::fs::read_to_string(&p).unwrap().contains("settings secret"), "no plaintext password");
    // without the password: theme may change, protected values may not
    let mut t = back.clone();
    t.ui_scale = 90;
    t.save_to(&p).unwrap();
    t.update = UpdateMode::Auto;
    assert!(has_code(&t.save_to(&p).unwrap_err(), C_NEED_PW));
    // going back to the safe defaults needs no password (and keeps the password entry)
    t.reset_protected();
    t.save_to(&p).unwrap();
    let back = Settings::load_from(&p);
    assert!(!back.allow_arg_secrets && back.auth.is_some() && !back.tampered);
    // dropping the password entry without the password is refused
    let mut t = back.clone();
    t.auth = None;
    assert!(has_code(&t.save_to(&p).unwrap_err(), C_NEED_PW));
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn edits_outside_shield_reset_the_protected_values() {
    let p = file();
    let mut s = Settings::default();
    let u = set_password(&mut s, b"settings secret 2", None).unwrap();
    s.shred_passes = crate::wipe::Passes::Three;
    s.save_to_with(&p, Some(&u)).unwrap();
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, text.replace("allow_arg_secrets = false", "allow_arg_secrets = true")).unwrap();
    let t = Settings::load_from(&p);
    assert!(t.tampered && !t.allow_arg_secrets && t.auth.is_none());
    assert_eq!(t.shred_passes, crate::wipe::Passes::Seven, "protected values back to defaults");
    // removing the password lines while the key file exists is noticed too
    s.save_to_with(&p, Some(&u)).unwrap();
    let text = std::fs::read_to_string(&p).unwrap();
    let stripped: String = text.lines().filter(|l| !l.starts_with("auth_")).map(|l| format!("{l}\n")).collect();
    std::fs::write(&p, stripped).unwrap();
    assert!(Settings::load_from(&p).tampered);
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn wrong_password_is_refused_and_delays_the_next_try() {
    let mut s = Settings::default();
    let _ = set_password(&mut s, b"right password", None).unwrap();
    assert!(has_code(&unlock(&s, b"wrong password").err().unwrap(), C_WRONG_PW));
    assert!(retry_delay() >= Duration::from_secs(1));
    let u = unlock(&s, b"right password").unwrap();
    assert_eq!(retry_delay(), Duration::ZERO);
    // replacing needs the current unlock
    assert!(set_password(&mut s.clone(), b"another one", None).is_err());
    let mut s2 = s.clone();
    set_password(&mut s2, b"another one", Some(&u)).unwrap();
    // 3.0.0 §1: a short password is a warning confirmed in the window, only empty is refused here
    assert!(set_password(&mut s.clone(), b"", Some(&u)).is_err(), "empty");
    assert!(set_password(&mut s.clone(), b"short", Some(&u)).is_ok(), "short, after the warning");
    clear_password(&mut s, &u).unwrap();
    assert!(s.auth.is_none());
}

#[test]
fn reset_by_deleting_the_file_forgets_the_password() {
    let p = file();
    let mut s = Settings::default();
    let u = set_password(&mut s, b"settings secret 3", None).unwrap();
    s.save_to_with(&p, Some(&u)).unwrap();
    assert!(key_path(&p).exists());
    forget_key(&p);
    std::fs::remove_file(&p).unwrap();
    let d = Settings::load_from(&p);
    assert!(d.auth.is_none() && !d.tampered, "a clean reset is not reported as tampering");
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

/// A file with a password whose protected values were set with it (not the defaults).
fn protected_file() -> (PathBuf, String) {
    let p = file();
    let mut s = Settings::default();
    let u = set_password(&mut s, b"owner settings password", None).unwrap();
    (s.allow_arg_secrets, s.capture_protect, s.lock_on_focus_loss, s.shred_passes) = (false, true, true, crate::wipe::Passes::Seven);
    s.save_to_with(&p, Some(&u)).unwrap();
    let text = std::fs::read_to_string(&p).unwrap();
    (p, text)
}

#[test]
fn deleting_the_password_entry_and_key_file_gives_only_the_defaults() {
    // security review 2026-11-08: dropping the auth_* lines and settings.key used to be taken as
    // "no password ever set" and the values written into the file were used
    let (p, text) = protected_file();
    let edited: String = text
        .lines()
        .filter(|l| !l.starts_with("auth_"))
        .map(|l| match l {
            "allow_arg_secrets = false" => "allow_arg_secrets = true",
            "capture_protect = true" => "capture_protect = false",
            "update = \"off\"" => "update = \"auto\"",
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(edited.lines().count(), text.lines().count(), "auth lines were there");
    std::fs::write(&p, edited).unwrap();
    std::fs::remove_file(key_path(&p)).unwrap();
    let a = Settings::load_from(&p);
    assert!(a.tampered, "reported");
    assert!(a.auth.is_none());
    assert!(a.protected_is_default(), "only the defaults are used");
    assert!(!a.allow_arg_secrets && a.capture_protect && a.update == UpdateMode::Off);
    // deleting only the key file, or only the auth lines, is caught by the MAC rule as before
    let (p2, text2) = protected_file();
    std::fs::remove_file(key_path(&p2)).unwrap();
    assert!(Settings::load_from(&p2).tampered);
    let (p3, text3) = protected_file();
    std::fs::write(&p3, text3.lines().filter(|l| !l.starts_with("auth_")).collect::<Vec<_>>().join("\n")).unwrap();
    assert!(Settings::load_from(&p3).tampered);
    let _ = text2;
    for f in [p, p2, p3] {
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }
}

#[test]
fn lock_on_focus_loss_is_protected() {
    let (p, text) = protected_file();
    assert!(Settings::load_from(&p).lock_on_focus_loss);
    std::fs::write(&p, text.replace("lock_on_focus_loss = true", "lock_on_focus_loss = false")).unwrap();
    let a = Settings::load_from(&p);
    assert!(a.tampered, "an edit is noticed");
    // and without the password it can't be switched on
    let mut s = Settings::default();
    let q = file();
    s.save_to(&q).unwrap();
    s.lock_on_focus_loss = true;
    assert!(has_code(&s.save_to(&q).unwrap_err(), C_NEED_PW));
    for f in [p, q] {
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }
}

#[test]
fn a_3_0_0_mac_without_lock_on_focus_loss_still_opens() {
    let (p, text) = protected_file();
    let s = Settings::load_from(&p);
    let key = read_key(&p).unwrap();
    let old = hex(&mac_of_v1(&key, &s));
    let new = hex(&s.auth.as_ref().unwrap().mac);
    assert_ne!(old, new);
    std::fs::write(&p, text.replace(&new, &old)).unwrap();
    let back = Settings::load_from(&p);
    assert!(!back.tampered && back.auth.is_some(), "the MAC 3.0.0 wrote is accepted");
    std::fs::write(&p, text.replace(&new, &old).replace("allow_arg_secrets = false", "allow_arg_secrets = true")).unwrap();
    assert!(Settings::load_from(&p).tampered, "but still covers the other values");
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn removing_the_password_returns_the_defaults_without_a_warning() {
    let (p, _) = protected_file();
    let mut s = Settings::load_from(&p);
    assert!(!s.protected_is_default());
    let u = unlock(&s, b"owner settings password").unwrap();
    clear_password(&mut s, &u).unwrap();
    assert!(s.protected_is_default());
    s.save_to_with(&p, Some(&u)).unwrap();
    let back = Settings::load_from(&p);
    assert!(!back.tampered && back.auth.is_none() && !key_path(&p).exists());
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn a_2_x_file_goes_to_the_defaults_quietly() {
    // 2.x had no settings password: its protected values are not used by 3.0 (migration)
    let p = file();
    std::fs::write(&p, "schema = 1\nlang = \"en\"\nallow_arg_secrets = true\nshred_passes = 3\n").unwrap();
    let s = Settings::load_from(&p);
    assert!(!s.tampered && s.protected_is_default() && s.lang == crate::settings::LangPref::En);
    // the same values in a 3.0 file without a password were written by someone else
    std::fs::write(&p, "schema = 2\nlang = \"en\"\nallow_arg_secrets = true\n").unwrap();
    let s = Settings::load_from(&p);
    assert!(s.tampered && s.protected_is_default());
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

// ---- 3.1.0 review 3: settings.key and the settings file are read with a limit ----

#[test]
fn oversized_key_and_settings_files_are_not_read() {
    let p = file();
    let s = Settings { ui_scale: 120, ..Default::default() };
    s.save_to(&p).unwrap();
    let kp = key_path(&p);
    if kp.exists() {
        assert!(std::fs::metadata(&kp).unwrap().len() <= MAX_KEY_FILE, "a real key file fits the limit");
    }
    // a huge settings.key (length without data) is "no usable key", found quickly
    let _ = std::fs::remove_file(&kp);
    std::fs::File::create(&kp).unwrap().set_len(512 << 20).unwrap();
    let t = std::time::Instant::now();
    assert!(read_key(&p).is_none());
    // exactly at the limit is read (and is no valid key), one more byte is refused
    std::fs::write(&kp, vec![0u8; MAX_KEY_FILE as usize]).unwrap();
    assert!(read_key(&p).is_none());
    // a huge settings file loads as "damaged" (defaults + load issue), it is not read
    let _ = std::fs::remove_file(&kp);
    std::fs::File::create(&p).unwrap().set_len(512 << 20).unwrap();
    let back = Settings::load_from(&p);
    assert!(!back.load_issues.is_empty() && back.ui_scale != 120, "{:?}", back.load_issues);
    assert!(t.elapsed().as_secs() < 10, "nothing large was read");
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn the_secure_delete_password_switch_is_protected() {
    let (p, _) = protected_file();
    let s = Settings::load_from(&p);
    assert!(s.wipe_needs_pw && s.mac_text() == s.protected_text(), "on by default: the 3.0.0 MAC text is unchanged");
    // switching it off is a protected change: refused without the password, also through
    // "reset" (on is the default, so a reset can only switch it on)
    let mut off = s.clone();
    off.wipe_needs_pw = false;
    assert!(has_code(&off.save_to(&p).unwrap_err(), C_NEED_PW));
    let mut reset = off.clone();
    reset.reset(crate::settings::Category::Security);
    assert!(reset.wipe_needs_pw);
    let u = unlock(&s, b"owner settings password").unwrap();
    off.save_to_with(&p, Some(&u)).unwrap();
    let back = Settings::load_from(&p);
    assert!(!back.tampered && !back.wipe_needs_pw, "saved with the password");
    // "reset security" (every protected value to its default) needs no password: it switches it on
    let mut on = back.clone();
    on.reset(crate::settings::Category::Security);
    on.save_to(&p).unwrap();
    assert!(Settings::load_from(&p).wipe_needs_pw);
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn switching_secure_delete_off_by_editing_the_file_is_noticed() {
    let (p, text) = protected_file();
    assert!(text.contains("wipe_needs_settings_pw = true"));
    std::fs::write(&p, text.replace("wipe_needs_settings_pw = true", "wipe_needs_settings_pw = false")).unwrap();
    let t = Settings::load_from(&p);
    assert!(t.tampered && t.wipe_needs_pw, "v2 MAC");
    // nor with the 3.0.0 (v1) MAC, which never covered this value: a line 3.0.0 never wrote
    // must not slip past it
    std::fs::write(&p, &text).unwrap();
    let s = Settings::load_from(&p);
    let key = read_key(&p).unwrap();
    let (old, new) = (hex(&mac_of_v1(&key, &s)), hex(&s.auth.as_ref().unwrap().mac));
    let v1 = text.replace(&new, &old);
    std::fs::write(&p, &v1).unwrap();
    assert!(!Settings::load_from(&p).tampered, "the 3.0.0 MAC itself is accepted");
    std::fs::write(&p, v1.replace("wipe_needs_settings_pw = true", "wipe_needs_settings_pw = false")).unwrap();
    let t = Settings::load_from(&p);
    assert!(t.tampered && t.wipe_needs_pw, "v1 MAC");
    // a 3.0.0 file has no such line at all: it opens, and the switch is on
    std::fs::write(&p, v1.lines().filter(|l| !l.starts_with("wipe_needs_settings_pw")).map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    let t = Settings::load_from(&p);
    assert!(!t.tampered && t.wipe_needs_pw && t.auth.is_some());
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}
