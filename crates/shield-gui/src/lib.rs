//! Shield GUI - one library, two windows (like 7-Zip's compressor dialog and file manager): the
//! encryption window and the container file manager. Started by `shield-gui` (windowed
//! launcher, Explorer / file manager verbs) and by `shield gui ...` (console binary).
// tests read the files they made themselves; product code reads through `bounded` (clippy.toml)
#![cfg_attr(test, allow(clippy::disallowed_methods))]

// The engine lives in shield-core; re-exported so `crate::engine::...` paths keep working.
pub use shield_core::{
    ads, archive, buildinfo, compress, container, crypto, engine, entropy, format, harden, help, i18n, job, keyfile, lang, lock, manifest, outname, password, progress, sectemp, secure_delete,
    settings, settings_auth, sigverify, spool, staging, sysinfo, ui_fmt, ui_prefs, update, wipe,
};

mod capture;
mod dialogs;
mod enc_app;
mod enc_jobs;
mod enc_views;
#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod glyphs;
pub mod icon;
mod mgr_app;
mod mgr_ops;
mod mgr_views;
mod settings_pw;
mod settings_view;
mod shell;
mod theme;
mod ui;
mod ui_table;
mod update_ui;
mod window;
mod wipe_view;

use eframe::egui;
use std::path::PathBuf;

/// Which window opens, with what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// The start screen chosen in Settings.
    Default,
    /// Encryption window with these items (several: the user is asked "separately or bundled").
    /// `dropped`: items of a file manager selection that could not be used (shown, review F).
    Encrypt { items: Vec<PathBuf>, dropped: usize },
    Decrypt(Option<PathBuf>),
    /// File manager; with a .shd it opens the unlock screen.
    Explorer(Option<PathBuf>),
    /// "Open in SHIELD" (3.1.0 #14): the unlock screen for this file, whatever its name. Not a
    /// regular file: the file manager with one message.
    Open(PathBuf),
    Settings,
    /// "Secure delete with SHIELD" (3.1.0 final): the secure delete tab with these items; nothing
    /// is deleted before the scan and the three confirmations. `dropped`: items of the file manager
    /// selection that could not be used (shown).
    Wipe { items: Vec<PathBuf>, dropped: usize },
}

/// File manager / command line items made absolute (`spool::normalize_arg`, relative to the
/// current folder); the second value counts what could not be used.
pub fn absolute_items(items: &[PathBuf]) -> (Vec<PathBuf>, usize) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut out = Vec::new();
    let mut dropped = 0;
    for p in items {
        // a name that is not UTF-8 can't be a URI: joined as it is
        let a = match p.to_str() {
            Some(s) => spool::normalize_arg(s, &cwd),
            None => std::path::absolute(cwd.join(p)).ok(),
        };
        match a {
            Some(a) if !out.contains(&a) => out.push(a),
            Some(_) => {}
            None => dropped += 1,
        }
    }
    (out, dropped)
}

/// Legacy / launcher flags (`shield-gui --encrypt-multi <items...>` etc.).
pub fn parse_args(args: &[String]) -> Start {
    // `--` (Nautilus script): everything after it is an item, also names starting with -
    let rest = args.get(1..).unwrap_or_default();
    let rest = if rest.first().map(String::as_str) == Some("--") { &rest[1..] } else { rest };
    let paths: Vec<PathBuf> = rest.iter().map(PathBuf::from).collect();
    let first = paths.first().cloned();
    match args.first().map(String::as_str) {
        None => Start::Default,
        Some("--encrypt") | Some("--encrypt-multi") => Start::Encrypt { items: paths, dropped: 0 },
        Some("--decrypt") => Start::Decrypt(first),
        Some("--open") if first.is_some() => Start::Open(first.unwrap_or_default()),
        Some("--manager") | Some("--open") | Some("--explorer") => Start::Explorer(first),
        Some("--settings") => Start::Settings,
        Some("--wipe") => Start::Wipe { items: paths, dropped: 0 },
        // a .shd given without a flag (e.g. "open with") goes to the file manager
        Some(p) if !p.starts_with("--") && args.len() == 1 && std::path::Path::new(p).extension().is_some_and(|x| x.eq_ignore_ascii_case("shd")) => Start::Explorer(Some(PathBuf::from(p))),
        Some(p) if !p.starts_with("--") => Start::Encrypt { items: args.iter().map(PathBuf::from).collect(), dropped: 0 },
        _ => Start::Default,
    }
}

/// Opens the window and runs until it is closed. Returns the process exit code.
pub fn run(start: Start) -> i32 {
    // before any thread and before the window: the display scale the OS is configured for
    // (Linux X11: never winit's guess from the monitor size; see shield_platform::display)
    let scale_note = shield_platform::display::prepare_scale();
    let _ = window::SCALE_NOTE.set(scale_note);
    harden::harden_process();
    // E-5: settings are read once, here; changes are saved atomically and applied live
    let set = settings::Settings::load();
    i18n::set_lang(set.effective_lang());
    ui_fmt::set_date_style(set.date_fmt, set.date_seconds);
    entropy::set_gui(true);
    set.apply_entropy();
    entropy::set_mouse_enabled(set.mouse_entropy);
    entropy::start_background();
    update::cleanup();
    let start = match start {
        Start::Default => match set.start_screen {
            settings::StartScreen::Manager => Start::Explorer(None),
            settings::StartScreen::Decrypt => Start::Decrypt(None),
            settings::StartScreen::Encrypt => Start::Encrypt { items: Vec::new(), dropped: 0 },
        },
        s => s,
    };
    let title = match &start {
        Start::Explorer(_) | Start::Open(_) => i18n::t("m.window_title"),
        _ => "Shield",
    };
    let icon = egui::IconData { rgba: icon::shield_rgba(64), width: 64, height: 64 };
    let kind = if matches!(start, Start::Explorer(_) | Start::Open(_)) { window::WinKind::Manager } else { window::WinKind::Encrypt };
    let monitors = shield_platform::display::monitors();
    let target = window::target_position(&set, kind, monitors.as_deref());
    let opts = eframe::NativeOptions {
        viewport: window::viewport(title, icon, target, monitors.as_deref()),
        // no (usable) remembered position: the centre of the screen
        centered: target.is_none(),
        ..Default::default()
    };
    let r = eframe::run_native(
        title,
        opts,
        Box::new(move |cc| {
            theme::load_fonts(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, &set);
            let tracker = window::Tracker::new(kind, target);
            match start {
                Start::Explorer(p) => {
                    let mut a = mgr_app::MgrApp::new(set, p);
                    a.sh.tracker = tracker;
                    Box::new(a) as Box<dyn eframe::App>
                }
                Start::Open(p) => {
                    let mut a = mgr_app::MgrApp::new_open(set, p);
                    a.sh.tracker = tracker;
                    Box::new(a) as Box<dyn eframe::App>
                }
                s => {
                    let mut a = enc_app::EncApp::new(set, s);
                    a.sh.tracker = tracker;
                    Box::new(a)
                }
            }
        }),
    );
    entropy::clear_pool();
    i32::from(r.is_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &[&str]) -> Start {
        parse_args(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>())
    }
    #[test]
    fn argument_dispatch() {
        assert_eq!(s(&[]), Start::Default);
        assert_eq!(s(&["--encrypt", "a.txt"]), Start::Encrypt { items: vec!["a.txt".into()], dropped: 0 });
        assert_eq!(s(&["--encrypt-multi", "a", "b"]), Start::Encrypt { items: vec!["a".into(), "b".into()], dropped: 0 });
        assert_eq!(s(&["--decrypt", "a.shd"]), Start::Decrypt(Some("a.shd".into())));
        assert_eq!(s(&["--open", "a.shd"]), Start::Open("a.shd".into()));
        // 3.1.0 #14: any name, no extension assumed; without a path it is the file manager
        assert_eq!(s(&["--open", "photo.jpg"]), Start::Open("photo.jpg".into()));
        assert_eq!(s(&["--open", "noext"]), Start::Open("noext".into()));
        assert_eq!(s(&["--open"]), Start::Explorer(None));
        assert_eq!(s(&["--manager", "a.shd"]), Start::Explorer(Some("a.shd".into())));
        assert_eq!(s(&["--manager"]), Start::Explorer(None));
        assert_eq!(s(&["--settings"]), Start::Settings);
        assert_eq!(s(&["x.shd"]), Start::Explorer(Some("x.shd".into())));
        assert_eq!(s(&["--bogus"]), Start::Default);
        // 3.1.0 final: secure delete only opens the tab; `--` keeps names starting with -
        assert_eq!(s(&["--wipe", "a", "b"]), Start::Wipe { items: vec!["a".into(), "b".into()], dropped: 0 });
        assert_eq!(s(&["--wipe", "--", "-x", "--yes"]), Start::Wipe { items: vec!["-x".into(), "--yes".into()], dropped: 0 });
        assert_eq!(s(&["--wipe"]), Start::Wipe { items: vec![], dropped: 0 });
    }

    #[test]
    fn launcher_items_become_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let (v, n) = absolute_items(&["rel.txt".into(), "rel.txt".into(), "".into()]);
        assert_eq!(v, vec![cwd.join("rel.txt")], "made absolute, duplicates once");
        assert_eq!(n, 1, "the empty name is counted as dropped");
    }
}
#[cfg(test)]
mod v3_tests;
