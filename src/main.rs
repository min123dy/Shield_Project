#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Shield 2.1 - one executable, two windows (like 7-Zip's compressor dialog and file manager):
//!   shield.exe                       encryption window
//!   shield.exe --encrypt <path>      encryption window, target selected
//!   shield.exe --decrypt <file.shd>  encryption window, decryption tab
//!   shield.exe --manager [<path>]    file manager window
//!   shield.exe --open <file.shd>     file manager window, container unlock screen

mod ads;
mod archive;
mod capture;
mod compress;
mod container;
mod crypto;
mod enc_app;
mod enc_views;
mod engine;
mod entropy;
mod format;
#[cfg(test)]
mod fuzz_tests;
#[cfg(test)]
mod glyphs;
mod harden;
mod help;
mod i18n;
mod icon;
mod job;
mod keyfile;
mod lang;
mod lock;
mod manifest;
mod mgr_app;
mod mgr_views;
mod password;
mod progress;
mod sectemp;
mod settings;
mod settings_view;
mod shell;
mod staging;
mod sysinfo;
mod theme;
mod ui;
mod ui_fmt;
mod ui_table;
mod wipe;

use eframe::egui;
use std::path::PathBuf;

enum Start {
    Enc(Option<(enc_app::Tab, PathBuf)>),
    Mgr(Option<PathBuf>),
}

fn parse_args(args: &[String], start: settings::StartScreen) -> Start {
    let path = args.get(1).map(PathBuf::from);
    match args.first().map(String::as_str) {
        None if start == settings::StartScreen::Manager => Start::Mgr(None),
        Some("--encrypt") => Start::Enc(path.map(|p| (enc_app::Tab::Encrypt, p))),
        Some("--decrypt") => Start::Enc(path.map(|p| (enc_app::Tab::Decrypt, p))),
        Some("--manager") | Some("--open") => Start::Mgr(path),
        // a .shd given without a flag (e.g. "open with") goes to the file manager
        Some(p) if !p.starts_with("--") && sysinfo::is_shd(std::path::Path::new(p)) => Start::Mgr(Some(PathBuf::from(p))),
        _ => Start::Enc(None),
    }
}

fn main() {
    harden::harden_process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Elevated TRIM helper started by wipe::trim_volume through UAC: must exit before any
    // window is created (without this the helper opens a second Shield window and never trims).
    #[cfg(windows)]
    if args.first().map(String::as_str) == Some(wipe::RETRIM_ARG) {
        std::process::exit(wipe::retrim_main(args.get(1).filter(|_| args.len() == 2).map(String::as_str)));
    }
    // E-5: settings are read once, here; changes are saved atomically and applied live
    let set = settings::Settings::load();
    i18n::set_lang(set.effective_lang());
    ui_fmt::set_date_style(set.date_fmt, set.date_seconds);
    entropy::set_mouse_enabled(set.mouse_entropy);
    let start = parse_args(&args, set.start_screen);
    let title = match &start {
        Start::Enc(_) => "Shield",
        Start::Mgr(_) => i18n::t("m.window_title"),
    };
    let icon = egui::IconData { rgba: icon::shield_rgba(64), width: 64, height: 64 };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id(title)
            .with_icon(icon)
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([800.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    let _ = eframe::run_native(
        title,
        opts,
        Box::new(move |cc| {
            theme::load_fonts(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, &set);
            match start {
                Start::Enc(s) => Box::new(enc_app::EncApp::new(set, s)) as Box<dyn eframe::App>,
                Start::Mgr(p) => Box::new(mgr_app::MgrApp::new(set, p)),
            }
        }),
    );
    entropy::clear_pool();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn argument_dispatch() {
        let s = |v: &[&str]| parse_args(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>(), settings::StartScreen::Encrypt);
        assert!(matches!(s(&[]), Start::Enc(None)));
        assert!(matches!(s(&["--encrypt", "a.txt"]), Start::Enc(Some((enc_app::Tab::Encrypt, _)))));
        assert!(matches!(s(&["--decrypt", "a.shd"]), Start::Enc(Some((enc_app::Tab::Decrypt, _)))));
        assert!(matches!(s(&["--open", "a.shd"]), Start::Mgr(Some(_))));
        assert!(matches!(s(&["--manager"]), Start::Mgr(None)));
        assert!(matches!(s(&["--bogus"]), Start::Enc(None)));
        let m = parse_args(&[], settings::StartScreen::Manager);
        assert!(matches!(m, Start::Mgr(None)), "start screen from Settings");
    }
}
