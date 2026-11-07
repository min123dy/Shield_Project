//! Shield GUI - one library, two windows (like 7-Zip's compressor dialog and file manager): the
//! encryption window and the container file manager. Started by `shield-gui` (windowed
//! launcher, Explorer / file manager verbs) and by `shield gui ...` (console binary).

// The engine lives in shield-core; re-exported so `crate::engine::...` paths keep working.
pub use shield_core::{
    ads, archive, buildinfo, compress, container, crypto, engine, entropy, format, harden, help, i18n, job, keyfile, lang, lock, manifest, outname, password, progress, sectemp, settings,
    settings_auth, sigverify, spool, staging, sysinfo, ui_fmt, ui_prefs, update, wipe,
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

use eframe::egui;
use std::path::PathBuf;

/// Which window opens, with what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// The start screen chosen in Settings.
    Default,
    /// Encryption window with these items (several: the user is asked "separately or bundled").
    Encrypt(Vec<PathBuf>),
    Decrypt(Option<PathBuf>),
    /// File manager; with a .shd it opens the unlock screen.
    Explorer(Option<PathBuf>),
    Settings,
}

/// Legacy / launcher flags (`shield-gui --encrypt-multi <items...>` etc.).
pub fn parse_args(args: &[String]) -> Start {
    let paths: Vec<PathBuf> = args.iter().skip(1).map(PathBuf::from).collect();
    let first = paths.first().cloned();
    match args.first().map(String::as_str) {
        None => Start::Default,
        Some("--encrypt") | Some("--encrypt-multi") => Start::Encrypt(paths),
        Some("--decrypt") => Start::Decrypt(first),
        Some("--manager") | Some("--open") | Some("--explorer") => Start::Explorer(first),
        Some("--settings") => Start::Settings,
        // a .shd given without a flag (e.g. "open with") goes to the file manager
        Some(p) if !p.starts_with("--") && args.len() == 1 && std::path::Path::new(p).extension().is_some_and(|x| x.eq_ignore_ascii_case("shd")) => Start::Explorer(Some(PathBuf::from(p))),
        Some(p) if !p.starts_with("--") => Start::Encrypt(args.iter().map(PathBuf::from).collect()),
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
            settings::StartScreen::Encrypt => Start::Encrypt(Vec::new()),
        },
        s => s,
    };
    let title = match &start {
        Start::Explorer(_) => i18n::t("m.window_title"),
        _ => "Shield",
    };
    let icon = egui::IconData { rgba: icon::shield_rgba(64), width: 64, height: 64 };
    let kind = if matches!(start, Start::Explorer(_)) { window::WinKind::Manager } else { window::WinKind::Encrypt };
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
        assert_eq!(s(&["--encrypt", "a.txt"]), Start::Encrypt(vec!["a.txt".into()]));
        assert_eq!(s(&["--encrypt-multi", "a", "b"]), Start::Encrypt(vec!["a".into(), "b".into()]));
        assert_eq!(s(&["--decrypt", "a.shd"]), Start::Decrypt(Some("a.shd".into())));
        assert_eq!(s(&["--open", "a.shd"]), Start::Explorer(Some("a.shd".into())));
        assert_eq!(s(&["--manager"]), Start::Explorer(None));
        assert_eq!(s(&["--settings"]), Start::Settings);
        assert_eq!(s(&["x.shd"]), Start::Explorer(Some("x.shd".into())));
        assert_eq!(s(&["--bogus"]), Start::Default);
    }
}
#[cfg(test)]
mod v3_tests;
