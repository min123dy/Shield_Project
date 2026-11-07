//! Updates in the GUI (3.0 §3): check (manual, or at start-up when enabled), a "new version"
//! button, download + verification in a worker thread, and an explicit confirmation before the
//! installer runs. Offline / network errors are silent for automatic checks.

use crate::i18n::{t, tf};
use crate::settings::UpdateMode;
use crate::update::{self, Check, Downloaded, Release};
use crate::ui::{confirm_modal, hint, warn};
use eframe::egui;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

enum Msg {
    Checked(Result<Check, String>),
    Fetched(Result<Downloaded, String>),
}

#[derive(Default)]
pub struct Updater {
    rx: Option<mpsc::Receiver<Msg>>,
    pub available: Option<Box<Release>>,
    pub ready: Option<Downloaded>,
    pub note: String,
    started: bool,
    manual: bool,
    ask_download: bool,
    ask_install: bool,
    /// Set when the user confirmed the installation; the window wipes its secrets, then calls
    /// `install`.
    pub install_requested: bool,
    progress: Arc<(AtomicU64, AtomicU64)>,
    cancel: Arc<AtomicBool>,
}

impl Updater {
    pub fn busy(&self) -> bool {
        self.rx.is_some()
    }

    fn check(&mut self, manual: bool) {
        if self.busy() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.manual = manual;
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Checked(update::check()));
        });
    }

    fn download(&mut self) {
        let Some(r) = self.available.clone() else { return };
        if self.busy() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.cancel.store(false, Ordering::Relaxed);
        let (p, c) = (self.progress.clone(), self.cancel.clone());
        std::thread::spawn(move || {
            let res = update::download(
                &r,
                &|done, total| {
                    p.0.store(done, Ordering::Relaxed);
                    p.1.store(total, Ordering::Relaxed);
                },
                &|| c.load(Ordering::Relaxed),
            );
            let _ = tx.send(Msg::Fetched(res));
        });
    }

    /// Once per frame: start-up check, results of the worker.
    pub fn poll(&mut self, ctx: &egui::Context, mode: UpdateMode) {
        if !self.started {
            self.started = true;
            if mode != UpdateMode::Off && crate::buildinfo::repo().is_some() {
                self.check(false);
            }
        }
        let Some(rx) = &self.rx else { return };
        ctx.request_repaint_after(std::time::Duration::from_millis(200));
        let Ok(m) = rx.try_recv() else { return };
        self.rx = None;
        match m {
            Msg::Checked(Ok(Check::UpToDate(v))) => self.note = if self.manual { tf("upd.up_to_date", &[&v]) } else { String::new() },
            Msg::Checked(Ok(Check::Available(r))) => {
                self.note = tf("upd.available", &[&r.version]);
                let auto = mode == UpdateMode::Auto && r.files.is_some();
                self.available = Some(r);
                if auto {
                    self.download();
                }
            }
            // offline and other failures are only shown when the user asked
            Msg::Checked(Err(e)) => self.note = if self.manual { e } else { String::new() },
            Msg::Fetched(Ok(d)) => {
                self.note = tf("upd.verified", &[&d.version, &d.signer.fingerprint]);
                self.ready = Some(d);
                self.ask_install = true;
            }
            Msg::Fetched(Err(e)) => self.note = e,
        }
    }

    /// "New version" button for the top bar (only when one is known).
    pub fn badge(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.available {
            let label = tf("upd.badge", &[&r.version]);
            if ui.button(egui::RichText::new(label).color(crate::theme::pal().accent)).clicked() {
                if self.ready.is_some() {
                    self.ask_install = true;
                } else {
                    self.ask_download = true;
                }
            }
        }
    }

    /// Download / install questions (Cancel is the default).
    pub fn dialogs(&mut self, ctx: &egui::Context) {
        if self.ask_download {
            let Some(r) = &self.available else { return self.ask_download = false };
            let mut lines = vec![tf("upd.ask_download", &[&r.version, &update::Version::current()])];
            if r.files.is_none() {
                lines.push(t("upd.no_package").into());
            }
            lines.push(r.page.clone());
            let label = if r.files.is_some() { t("upd.download") } else { t("upd.open_page") };
            if let Some(yes) = confirm_modal(ctx, "upd_dl", t("upd.title"), &lines, label) {
                self.ask_download = false;
                if yes && r.files.is_some() {
                    self.download();
                } else if yes {
                    let _ = shield_platform::platform().open_url(&r.page);
                }
            }
        }
        if self.ask_install {
            let Some(d) = &self.ready else { return self.ask_install = false };
            let lines = vec![tf("upd.ask_install", &[&d.version]), tf("upd.signed_by", &[&d.signer.fingerprint]), t("upd.install_note").into()];
            if let Some(yes) = confirm_modal(ctx, "upd_inst", t("upd.title"), &lines, t("upd.install")) {
                self.ask_install = false;
                self.install_requested = yes;
            }
        }
    }

    /// Runs the verified installer. The caller wiped its secrets. Returns true when the window
    /// should close now (Windows Installer replaces the program files).
    pub fn install(&mut self) -> bool {
        self.install_requested = false;
        let Some(d) = self.ready.take() else { return false };
        match update::install(d) {
            Ok(update::Installed::ExitNow) => true,
            Ok(update::Installed::Done) => {
                self.note = t("upd.installed").into();
                self.available = None;
                false
            }
            Err(e) => {
                self.note = e;
                false
            }
        }
    }

    /// Settings > Updates.
    pub fn settings(&mut self, ui: &mut egui::Ui, locked: bool, mode: &mut UpdateMode) {
        // without a built-in repository there is nothing to check: shown as off (3.0.0 §4)
        let available = crate::buildinfo::repo_url().is_some();
        ui.add_enabled_ui(!locked && available, |ui| {
            ui.horizontal(|ui| {
                ui.label(t("upd.mode"));
                ui.radio_value(mode, UpdateMode::Off, t("upd.mode_off"));
                ui.radio_value(mode, UpdateMode::Check, t("upd.mode_check"));
                ui.radio_value(mode, UpdateMode::Auto, t("upd.mode_auto"));
            });
        });
        hint(ui, t("upd.mode_hint"));
        let repo = crate::buildinfo::repo_url();
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(repo.is_some() && !self.busy(), egui::Button::new(t("upd.check_now"))).clicked() {
                self.check(true);
            }
            if self.busy() {
                ui.spinner();
                let (d, n) = (self.progress.0.load(Ordering::Relaxed), self.progress.1.load(Ordering::Relaxed));
                if n > 0 {
                    ui.label(format!("{} / {}", crate::ui_fmt::human(d), crate::ui_fmt::human(n)));
                    if ui.button(t("ui.cancel")).clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                }
            }
            if self.available.is_some() {
                self.badge(ui);
            }
        });
        if !self.note.is_empty() {
            hint(ui, &self.note);
        }
        if repo.is_none() {
            warn(ui, t("upd.no_repo"));
        }
    }
}

/// Developer info (opens the GitHub page of this build), release key and integrity check.
pub fn about(ui: &mut egui::Ui, note: &mut String) {
    let repo = crate::buildinfo::repo_url();
    ui.horizontal_wrapped(|ui| {
        let b = ui.add_enabled(repo.is_some(), egui::Button::new(t("upd.dev_info")));
        if let Some(u) = &repo {
            b.clone().on_hover_text(u.as_str());
        }
        if b.clicked() {
            if let Some(u) = repo.filter(|u| u.starts_with("https://github.com/")) {
                if let Err(e) = shield_platform::platform().open_url(&u) {
                    *note = e.to_string();
                }
            }
        }
        if ui.button(t("upd.self_check")).clicked() {
            *note = match crate::buildinfo::self_check() {
                crate::buildinfo::SelfCheck::Verified(v) => tf("upd.self_ok", &[&v.fingerprint]),
                crate::buildinfo::SelfCheck::NoSignature => t("upd.self_nosig").into(),
                crate::buildinfo::SelfCheck::NoKey => t("upd.no_key").into(),
                crate::buildinfo::SelfCheck::Invalid(e) => tf("upd.self_bad", &[&e]),
            };
        }
    });
    match crate::buildinfo::fingerprint() {
        Some(f) => {
            ui.label(egui::RichText::new(tf("upd.fingerprint", &[&f])).monospace());
            hint(ui, t("upd.fingerprint_hint"));
        }
        None => warn(ui, t("upd.no_key")),
    }
    if !note.is_empty() {
        hint(ui, note.as_str());
    }
}
