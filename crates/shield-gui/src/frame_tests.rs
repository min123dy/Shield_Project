//! Real frames of both windows on a headless egui context (3.0.0 hang fix).
//!
//! The 3.0.0 release build never showed its window: the first frame blocked on egui's context
//! lock (`ctx.input` holds it for writing; `ctx.zoom_factor()` inside the closure waited for it
//! again). eframe only shows the window after the first frame, so nothing appeared and the
//! process sat at 0 % CPU. These tests run every tab of both windows for several frames on their
//! own thread with a time limit, so a blocked UI thread fails the test instead of hanging it.

use crate::enc_app::{EncApp, Tab};
use crate::mgr_app::{MTab, MgrApp};
use crate::settings::{Category, Settings};
use crate::ui_prefs::WinPos;
use crate::window::{Tracker, WinKind};
use crate::Start;
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

/// Runs `f` on its own thread and fails when it does not finish in time.
fn within<T: Send + 'static>(what: &str, secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name(what.into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .unwrap();
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(RecvTimeoutError::Timeout) => panic!("{what}: a frame did not finish within {secs} s - the UI thread is blocked (deadlock)"),
        Err(RecvTimeoutError::Disconnected) => panic!("{what}: the frame thread panicked (see the output above)"),
    }
}

fn temp_settings() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_frames_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("settings.toml")
}

/// Input as egui-winit gives it: window rect in points, scale, state of the window.
struct Win {
    frame: u32,
    pos: egui::Pos2,
    ppp: f32,
    minimized: bool,
    close: bool,
}

impl Win {
    fn new() -> Self {
        Win { frame: 0, pos: egui::pos2(100.0, 80.0), ppp: 1.0, minimized: false, close: false }
    }
    fn input(&mut self) -> egui::RawInput {
        self.frame += 1;
        let size = egui::vec2(crate::window::DEFAULT_SIZE[0], crate::window::DEFAULT_SIZE[1]);
        let mut r = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)), time: Some(f64::from(self.frame) / 60.0), ..Default::default() };
        let vp = r.viewports.entry(egui::ViewportId::ROOT).or_default();
        vp.native_pixels_per_point = Some(self.ppp);
        vp.outer_rect = Some(egui::Rect::from_min_size(self.pos, size));
        vp.inner_rect = vp.outer_rect;
        vp.minimized = Some(self.minimized);
        vp.focused = Some(true);
        if self.close {
            vp.events.push(egui::ViewportEvent::Close);
        }
        r
    }
}

/// The window system as on Windows and X11: positions are reported and accepted. Without this the
/// tests would depend on the machine (a headless Linux build has no DISPLAY, a desktop may run
/// Wayland) - `position_supported` is the platform's answer, tested in shield-platform.
fn positions() -> Result<(), &'static str> {
    Ok(())
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::load_fonts(&ctx);
    crate::theme::apply(&ctx, &Settings::default());
    ctx
}

#[test]
fn encryption_window_draws_every_tab_without_blocking() {
    let file = temp_settings();
    let f2 = file.clone();
    let saved = within("encryption window", 120, move || {
        let ctx = context();
        let mut a = EncApp::new(Settings::default(), Start::Default);
        a.sh.settings_file = f2.clone();
        a.sh.tracker = Tracker::new(WinKind::Encrypt, None).with_support(positions);
        let mut w = Win::new();
        for tab in [Tab::Encrypt, Tab::Decrypt, Tab::Rekey, Tab::Disk, Tab::Settings, Tab::Algo, Tab::Help] {
            a.tab = tab;
            for _ in 0..3 {
                let out = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
                assert!(!out.shapes.is_empty(), "{tab:?} drew nothing");
            }
        }
        for cat in [Category::General, Category::Security, Category::Encryption, Category::Explorer, Category::Update] {
            a.tab = Tab::Settings;
            a.sh.set_cat = cat;
            let _ = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
        }
        // window position: followed while visible, never while minimized, written on close
        assert_eq!(a.sh.set.ui.win_enc, Some(WinPos { x: 100, y: 80 }));
        w.minimized = true;
        w.pos = egui::pos2(-32000.0, -32000.0);
        let _ = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
        assert_eq!(a.sh.set.ui.win_enc, Some(WinPos { x: 100, y: 80 }), "minimized position ignored");
        w.minimized = false;
        w.pos = egui::pos2(300.0, 200.0);
        w.ppp = 1.5;
        w.close = true;
        let _ = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
        Settings::load_from(&f2).ui.win_enc
    });
    assert_eq!(saved, Some(WinPos { x: 450, y: 300 }), "physical pixels = points x scale, saved when the window closes");
    let _ = std::fs::remove_dir_all(file.parent().unwrap());
}

#[test]
fn every_start_screen_opens() {
    for start in [Start::Default, Start::Encrypt(vec![]), Start::Decrypt(None), Start::Settings] {
        let file = temp_settings();
        let label = format!("{start:?}");
        within(&label, 60, move || {
            let ctx = context();
            let mut a = EncApp::new(Settings::default(), start);
            a.sh.settings_file = file;
            let mut w = Win::new();
            for _ in 0..3 {
                let _ = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
            }
        });
    }
}

#[test]
fn file_manager_draws_every_tab_without_blocking() {
    let file = temp_settings();
    within("file manager", 120, move || {
        let ctx = context();
        let mut a = MgrApp::new(Settings::default(), None);
        a.sh.settings_file = file;
        a.sh.tracker = Tracker::new(WinKind::Manager, Some(WinPos { x: 100, y: 80 })).with_support(positions);
        let mut w = Win::new();
        for tab in [MTab::Files, MTab::Info, MTab::Settings, MTab::Help] {
            a.tab = tab;
            for _ in 0..3 {
                let out = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
                assert!(!out.shapes.is_empty(), "{tab:?} drew nothing");
            }
        }
        assert_eq!(a.sh.set.ui.win_mgr, Some(WinPos { x: 100, y: 80 }), "restored position confirmed and kept");
    });
}

#[test]
fn a_window_that_reports_no_position_still_runs() {
    // Wayland and some X11 window managers give no outer rect: the option switches off, the
    // window keeps drawing
    let file = temp_settings();
    within("no position", 60, move || {
        let ctx = context();
        let mut a = EncApp::new(Settings::default(), Start::Default);
        a.sh.settings_file = file;
        a.sh.tracker = Tracker::new(WinKind::Encrypt, None).with_support(positions);
        for i in 0..15u32 {
            let mut r = egui::RawInput { time: Some(f64::from(i) / 60.0), ..Default::default() };
            r.viewports.entry(egui::ViewportId::ROOT).or_default().native_pixels_per_point = Some(1.0);
            let _ = ctx.run(r, |ctx| a.ui_frame(ctx));
        }
        assert!(a.sh.set.off_reason(crate::settings::EnvKey::RememberWindowPos).is_some());
        assert!(!a.sh.set.ui.remember_window_pos, "shown and used as off");
        assert!(a.sh.set.file_view().ui.remember_window_pos, "the file keeps the user's choice");
        // the user switches it on again and the window now reports a position: tried again
        a.sh.set.ui.remember_window_pos = true;
        let mut w = Win::new();
        let _ = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
        assert_eq!(a.sh.set.off_reason(crate::settings::EnvKey::RememberWindowPos), None);
        assert_eq!(a.sh.set.ui.win_enc, Some(WinPos { x: 100, y: 80 }));
    });
}

#[test]
fn a_window_system_without_positions_switches_the_option_off() {
    // Wayland, or Linux without a display: off with the reason from the start, nothing saved,
    // the window keeps drawing, the file keeps the user's choice
    let file = temp_settings();
    within("positions unsupported", 60, move || {
        let ctx = context();
        let mut a = EncApp::new(Settings::default(), Start::Default);
        a.sh.settings_file = file;
        a.sh.tracker = Tracker::new(WinKind::Encrypt, None).with_support(|| Err("Wayland"));
        let mut w = Win::new();
        for _ in 0..3 {
            let out = ctx.run(w.input(), |ctx| a.ui_frame(ctx));
            assert!(!out.shapes.is_empty());
        }
        let why = a.sh.set.off_reason(crate::settings::EnvKey::RememberWindowPos).expect("switched off with a reason");
        assert!(why.contains("Wayland"), "{why}");
        assert!(!a.sh.set.ui.remember_window_pos, "shown and used as off");
        assert!(a.sh.set.file_view().ui.remember_window_pos, "the file keeps the user's choice");
        assert_eq!(a.sh.set.ui.win_enc, None, "no position saved");
    });
}

/// egui calls that run their closure while holding the context lock (egui 0.27: `input` takes it
/// for writing, the readers for reading; parking_lot's lock is not re-entrant).
const LOCKING: [&str; 16] = [
    ".input(", ".input_mut(", ".memory(", ".memory_mut(", ".data(", ".data_mut(", ".options(", ".options_mut(", ".style_mut(", ".fonts(", ".output(", ".output_mut(", ".graphics(", ".graphics_mut(", ".tessellation_options(", ".tessellation_options_mut(",
];

/// The closure passed at `open` (index of its '('), up to the matching ')'.
fn call_body(s: &str, open: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open..open + i];
                }
            }
            _ => {}
        }
    }
    &s[open..]
}

/// Lines where a locking closure calls back into the context (`ctx.` / `.ctx()` / `ui.`).
fn nested_locks(src: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    for pat in LOCKING {
        for (at, _) in src.match_indices(pat) {
            let open = at + pat.len() - 1;
            let body = call_body(src, open);
            // only closures: `.input(|i| ...)`, `.memory_mut(move |m| ...)`
            let head = body[1..].trim_start();
            if !(head.starts_with('|') || head.starts_with("move |")) {
                continue;
            }
            let inner = &body[1 + body[1..].find('|').unwrap() + 1..];
            let inner = &inner[inner.find('|').map_or(0, |p| p + 1)..];
            if inner.contains("ctx.") || inner.contains(".ctx()") || inner.contains("ui.") {
                hits.push(src[..at].matches('\n').count() + 1);
            }
        }
    }
    hits
}

#[test]
fn the_scan_finds_the_3_0_0_bug() {
    let bad = "let x = ctx.input(|i| {\n    i.viewport().native_pixels_per_point.unwrap_or(1.0) * ctx.zoom_factor()\n});";
    assert_eq!(nested_locks(bad), vec![1]);
    assert_eq!(nested_locks("ui.input(|i| i.key_pressed(egui::Key::Enter) && ui.is_enabled())"), vec![1]);
    assert_eq!(nested_locks("ctx.memory_mut(move |m| m.request_focus(ctx.viewport_id()))"), vec![1]);
    assert!(nested_locks("let z = ctx.zoom_factor();\nlet r = ctx.input(|i| i.viewport().outer_rect);").is_empty());
    assert!(nested_locks("ui.input(|i| i.modifiers.command)").is_empty());
}

#[test]
fn no_egui_call_blocks_on_its_own_lock() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") && p.file_name().is_some_and(|n| n != "frame_tests.rs") {
            let src = std::fs::read_to_string(&p).unwrap();
            for l in nested_locks(&src) {
                bad.push(format!("{}:{l}", p.file_name().unwrap().to_string_lossy()));
            }
        }
    }
    assert!(bad.is_empty(), "these closures hold egui's context lock and call the context again (deadlock, the window never shows): {bad:?}");
}
