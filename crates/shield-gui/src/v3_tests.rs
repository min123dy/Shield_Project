//! GUI behaviour added in 3.0: multi-item encryption, shred confirmations, settings categories.

use crate::enc_app::{bundle_output, EncApp, Pending, ShredAction, Tab};
use crate::settings::{Category, Settings};
use crate::Start;
use eframe::egui;
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_gv3_{}", crate::entropy::rand_hex().unwrap())).join("Reports");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn draw(a: &mut EncApp, frames: usize) {
    let ctx = egui::Context::default();
    crate::theme::apply(&ctx, &a.sh.set);
    for _ in 0..frames {
        let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1040.0, 700.0))), ..Default::default() };
        let _ = ctx.run(input, |ctx| crate::enc_views::frame(a, ctx));
    }
}

#[test]
fn explorer_multi_selection_asks_separately_or_bundled() {
    let d = tmpdir();
    let (f1, f2) = (d.join("a.txt"), d.join("b.txt"));
    std::fs::write(&f1, b"1").unwrap();
    std::fs::write(&f2, b"2").unwrap();
    let a = EncApp::new(Settings::default(), Start::Encrypt(vec![f1.clone(), f2.clone(), f1.clone()]));
    assert_eq!(a.items, vec![f1.clone(), f2.clone()], "duplicates are dropped");
    assert_eq!(a.pending, Some(Pending::Multi(2)));
    assert_eq!(a.tab, Tab::Encrypt);
    // one container named after the folder, next to the items
    assert_eq!(bundle_output(&a.items).unwrap(), d.join("Reports.shd"));
    std::fs::write(d.join("Reports.shd"), b"taken").unwrap();
    assert_eq!(bundle_output(&a.items).unwrap(), d.join("Reports (2).shd"));
    let _ = std::fs::remove_dir_all(d.parent().unwrap());
}

#[test]
fn a_container_goes_to_decryption_and_other_items_to_the_list() {
    let d = tmpdir();
    let shd = d.join("x.shd");
    std::fs::write(&shd, b"not really").unwrap();
    let mut a = EncApp::new(Settings::default(), Start::Default);
    a.select(shd.clone());
    assert_eq!((a.tab, a.selected.clone()), (Tab::Decrypt, Some(shd)));
    a.tab = Tab::Encrypt;
    a.select(d.clone());
    assert_eq!(a.items, vec![d.clone()]);
    assert!(a.pending.is_none(), "a single item needs no question");
    let _ = std::fs::remove_dir_all(d.parent().unwrap());
}

#[test]
fn every_tab_and_settings_category_draws() {
    let mut a = EncApp::new(Settings::default(), Start::Default);
    for tab in [Tab::Encrypt, Tab::Decrypt, Tab::Rekey, Tab::Disk, Tab::Algo, Tab::Help] {
        a.tab = tab;
        draw(&mut a, 2);
    }
    a.tab = Tab::Settings;
    for c in [Category::General, Category::Security, Category::Encryption, Category::Explorer, Category::Update] {
        a.sh.set_cat = c;
        draw(&mut a, 2);
    }
    // the shred confirmation and the multi question render too
    a.pending = Some(Pending::Shred(ShredAction::Encrypt, vec!["line".into()]));
    draw(&mut a, 1);
    a.pending = Some(Pending::Multi(3));
    draw(&mut a, 1);
}

#[test]
fn shred_confirmation_lists_storage_limits() {
    let d = tmpdir();
    let f = d.join("a.txt");
    std::fs::write(&f, b"1").unwrap();
    let mut a = EncApp::new(Settings::default(), Start::Encrypt(vec![f]));
    a.sh.set.shred_default = true;
    a.shred_ack = true;
    a.pw.push_str("correct horse battery staple 1");
    a.pw2.push_str("correct horse battery staple 1");
    a.request_encrypt();
    let Some(Pending::Shred(ShredAction::Encrypt, lines)) = &a.pending else { panic!("{:?}", a.pending) };
    assert_eq!(lines.last().map(String::as_str), Some(crate::i18n::t("dlg.shred_body")));
    let _ = std::fs::remove_dir_all(d.parent().unwrap());
}

#[test]
fn short_password_is_a_warning_and_low_pim_still_blocks() {
    // 3.0.0 §1: the same checker as the settings password; a short password asks, never blocks
    let d = tmpdir();
    let f = d.join("a.txt");
    std::fs::write(&f, b"1").unwrap();
    let mut a = EncApp::new(Settings::default(), Start::Encrypt(vec![f]));
    a.pw.push_str("Zk#9vQ!x");
    a.pw2.push_str("Zk#9vQ!x");
    assert!(a.encrypt_problems().is_empty(), "{:?}", a.encrypt_problems());
    a.request_encrypt();
    let Some(Pending::WeakEncrypt(r)) = &a.pending else { panic!("{:?}", a.pending) };
    assert!(r.contains(&crate::i18n::tf("pw.r_short", &[&8usize])), "{r:?}");
    // below the default PIM the longer minimum compensates for the cheaper KDF: still a block
    a.pending = None;
    a.custom_pim = true;
    a.pim = 0;
    assert!(!a.encrypt_problems().is_empty());
    // the mismatch is a block
    a.custom_pim = false;
    a.pw2.push_str("x");
    assert!(a.encrypt_problems().contains(&crate::i18n::t("pw.b_confirm").to_string()));
    let _ = std::fs::remove_dir_all(d.parent().unwrap());
}
