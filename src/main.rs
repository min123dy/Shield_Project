#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Shield 2.0 — one executable, two windows (like 7-Zip's compressor dialog and file manager):
//!   shield.exe                       encryption window
//!   shield.exe --encrypt <path>      encryption window, target selected
//!   shield.exe --decrypt <file.shd>  encryption window, decryption tab
//!   shield.exe --manager [<path>]    file manager window
//!   shield.exe --open <file.shd>     file manager window, container unlock screen

mod archive;
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
mod harden;
mod help;
mod icon;
mod job;
mod keyfile;
mod manifest;
mod mgr_app;
mod mgr_views;
mod password;
mod progress;
mod sectemp;
mod staging;
mod sysinfo;
mod ui;
mod ui_fmt;
mod wipe;

use eframe::egui;
use std::path::PathBuf;

enum Start {
    Enc(Option<(enc_app::Tab, PathBuf)>),
    Mgr(Option<PathBuf>),
}

fn parse_args(args: &[String]) -> Start {
    let path = args.get(1).map(PathBuf::from);
    match args.first().map(String::as_str) {
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
    let start = parse_args(&args);
    let (title, size) = match &start {
        Start::Enc(_) => ("Shield", [1000.0, 760.0]),
        Start::Mgr(_) => ("Shield 파일 관리자", [1080.0, 700.0]),
    };
    let icon = egui::IconData { rgba: icon::shield_rgba(64), width: 64, height: 64 };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id(title)
            .with_icon(icon)
            .with_inner_size(size)
            .with_min_inner_size([820.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    let _ = eframe::run_native(
        title,
        opts,
        Box::new(move |cc| {
            ui::load_korean_font(&cc.egui_ctx);
            ui::style(&cc.egui_ctx);
            match start {
                Start::Enc(s) => Box::new(enc_app::EncApp::new(s)) as Box<dyn eframe::App>,
                Start::Mgr(p) => Box::new(mgr_app::MgrApp::new(p)),
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
        let s = |v: &[&str]| parse_args(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert!(matches!(s(&[]), Start::Enc(None)));
        assert!(matches!(s(&["--encrypt", "a.txt"]), Start::Enc(Some((enc_app::Tab::Encrypt, _)))));
        assert!(matches!(s(&["--decrypt", "a.shd"]), Start::Enc(Some((enc_app::Tab::Decrypt, _)))));
        assert!(matches!(s(&["--open", "a.shd"]), Start::Mgr(Some(_))));
        assert!(matches!(s(&["--manager"]), Start::Mgr(None)));
        assert!(matches!(s(&["--bogus"]), Start::Enc(None)));
    }
}
