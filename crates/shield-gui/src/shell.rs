//! State and per-frame chores shared by both windows: settings (applied live), status line,
//! capture protection, auto-lock (idle / minimize / focus loss), clipboard clearing, dropped files
//! and leftover staging folders.

use crate::capture::Applied;
use crate::i18n::{t, tf};
use crate::settings::{Category, EnvKey, Settings};
use crate::ui::Leftovers;
use eframe::egui;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// Last call of every frame. Links never go through egui: egui-winit would hand them to the
/// `webbrowser` crate (RUSTSEC-2026-0257: argument injection through `BROWSER` on Unix; no
/// fixed version for egui 0.27). Shield opens its few https links itself
/// (`Platform::open_url`: checked URL, xdg-open / ShellExecute without a shell).
pub fn end_frame(ctx: &egui::Context) {
    ctx.output_mut(|o| o.open_url = None);
}

/// Pause before remembered UI state is written (window moves, tab options).
const SAVE_DELAY: Duration = Duration::from_millis(800);

pub struct Shell {
    pub set: Settings,
    pub status: String,
    pub ok: bool,
    pub leftovers: Leftovers,
    pub last_act: Instant,
    pub capture: Option<Result<Applied, String>>,
    pub set_cat: Category,
    pub updater: crate::update_ui::Updater,
    /// The settings password was entered (protected settings may change) until the next lock.
    pub unlocked: Option<crate::settings_auth::Unlocked>,
    pub auth: crate::settings_pw::AuthUi,
    pub about_note: String,
    /// 3.0.0 §4: the user accepted, for this window, that some protections are not in effect.
    degraded_ack: bool,
    /// The job (window-specific number) waiting for that answer.
    gate_wait: Option<u8>,
    /// Window position tracking (3.0.0 §2-B).
    pub tracker: crate::window::Tracker,
    applied: Option<Settings>,
    /// What this process last read from or wrote to the settings file (the merge base, §3).
    saved: Settings,
    /// A change of remembered UI state only (window position, tab options) waits this long for
    /// more changes before it is written (debounce).
    dirty_since: Option<Instant>,
    /// The file view whose save failed (not retried every frame).
    save_failed: Option<Settings>,
    /// Where settings are saved (`settings::settings_path`; tests use a temporary folder).
    pub settings_file: PathBuf,
    theme_check: Instant,
    was_minimized: bool,
    was_focused: bool,
}

/// Why the window locked (secrets wiped, container closed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockReason {
    Idle,
    Minimized,
    FocusLost,
}

#[derive(Default)]
pub struct FrameEvents {
    pub lock: Option<LockReason>,
    /// The user confirmed an update: wipe secrets, then `Shell::install_update`.
    pub install: bool,
    pub dropped: Vec<PathBuf>,
    pub close_requested: bool,
}

impl Shell {
    pub fn new(set: Settings) -> Self {
        let issues = set.load_issues.clone();
        let mut sh = Shell {
            saved: set.clone(),
            dirty_since: None,
            save_failed: None,
            settings_file: crate::settings::settings_path(),
            degraded_ack: false,
            gate_wait: None,
            tracker: crate::window::Tracker::new(crate::window::WinKind::Encrypt, None),
            set,
            status: String::new(),
            ok: true,
            leftovers: Leftovers::check(),
            last_act: Instant::now(),
            capture: None,
            set_cat: Category::General,
            updater: Default::default(),
            unlocked: None,
            auth: Default::default(),
            about_note: String::new(),
            applied: None,
            theme_check: Instant::now(),
            was_minimized: false,
            was_focused: true,
        };
        if !issues.is_empty() {
            sh.msg(false, tf("set.load_issues", &[&issues.join(", ")]));
        }
        sh
    }

    pub fn msg(&mut self, ok: bool, m: impl Into<String>) {
        self.ok = ok;
        self.status = m.into();
    }

    pub fn apply_msg(&mut self, m: Option<(bool, String)>) {
        if let Some((ok, s)) = m {
            self.msg(ok, s);
        }
    }

    /// Applies changed settings to this process right away (all windows of it).
    fn apply_settings(&mut self, ctx: &egui::Context) {
        let changed = self.applied.as_ref() != Some(&self.set);
        let follow_system = self.set.theme == crate::settings::ThemePref::System && self.theme_check.elapsed() > Duration::from_secs(3);
        if !changed && !follow_system {
            return;
        }
        self.theme_check = Instant::now();
        crate::theme::apply(ctx, &self.set);
        if !changed {
            return;
        }
        crate::i18n::set_lang(self.set.effective_lang());
        crate::ui_fmt::set_date_style(self.set.date_fmt, self.set.date_seconds);
        self.set.apply_entropy();
        crate::entropy::set_mouse_enabled(self.set.mouse_entropy);
        let first = self.applied.is_none();
        let prev = self.applied.clone();
        // capture protection: tried at start-up and whenever the user switches it (3.0.0 §4: a
        // failure switches it off with the reason; the file keeps the user's choice)
        if prev.as_ref().map(|a| a.capture_protect) != Some(self.set.capture_protect) {
            if !first {
                self.set.unsuppress(EnvKey::CaptureProtect);
            }
            let r = crate::capture::apply(self.set.capture_protect);
            match &r {
                Err(x) => {
                    self.set.suppress(EnvKey::CaptureProtect, x.clone());
                    if !first || crate::capture::supported() {
                        self.msg(false, tf("cap.status_failed", &[x]));
                    }
                }
                Ok(Applied::Monitor) => self.msg(true, t("cap.status_monitor")),
                Ok(_) => {}
            }
            self.capture = Some(r);
        }
        // remembering the window position: the user switching it on tries again. Only on -> the
        // tracker's own switch-off (on -> off, after `applied` was taken) must keep its reason, or
        // the next frame took it for the user's choice and the file lost the user's value
        if prev.as_ref().is_some_and(|a| !a.ui.remember_window_pos && self.set.ui.remember_window_pos) {
            self.set.unsuppress(EnvKey::RememberWindowPos);
        }
        // update checks need the release repository built in
        if crate::buildinfo::repo_url().is_none() {
            self.set.suppress(EnvKey::Update, t("upd.no_repo"));
        }
        crate::capture::dark_title_bar(crate::theme::is_dark());
        self.applied = Some(self.set.clone());
    }

    /// Writes changed settings (3.0.0 §3): at once for settings, after a short pause for UI
    /// state (window position, tab options), and always when the window closes.
    fn save_if_needed(&mut self, ctx: &egui::Context, now: bool) {
        let mine = self.set.file_view();
        if mine == self.saved.file_view() || self.save_failed.as_ref() == Some(&mine) {
            self.dirty_since = None;
            return;
        }
        let ui_only = {
            let mut a = mine.clone();
            a.ui = self.saved.ui.clone();
            a == self.saved.file_view()
        };
        if ui_only && !now {
            let since = *self.dirty_since.get_or_insert_with(Instant::now);
            if since.elapsed() < SAVE_DELAY {
                ctx.request_repaint_after(SAVE_DELAY);
                return;
            }
        }
        self.dirty_since = None;
        match self.set.save_merged(&self.saved, &self.settings_file, self.unlocked.as_ref()) {
            Ok(m) => {
                self.set = m.clone();
                self.saved = m;
                self.save_failed = None;
            }
            Err(x) => {
                // a protected value changed without the settings password: undo that part
                if crate::i18n::has_code(&x, crate::settings_auth::C_NEED_PW) {
                    let base = self.saved.clone();
                    self.set.copy_protected_from(&base);
                    self.set.apply_entropy();
                    crate::entropy::set_mouse_enabled(self.set.mouse_entropy);
                } else {
                    self.save_failed = Some(self.set.file_view());
                }
                self.msg(false, x);
            }
        }
    }

    /// Before a job that handles secrets: true = go ahead. When protections failed
    /// (`harden::degraded`) and this window has not confirmed it yet, the job waits for
    /// `gate_dialog` instead.
    pub fn gate(&mut self, job: u8) -> bool {
        if self.degraded_ack || crate::harden::degraded().is_empty() {
            return true;
        }
        self.gate_wait = Some(job);
        false
    }

    /// The question for `gate`; returns the job to start once the user continued.
    pub fn gate_dialog(&mut self, ctx: &egui::Context) -> Option<u8> {
        let job = self.gate_wait?;
        let mut lines = crate::harden::degraded();
        lines.push(t("harden.degraded_body").into());
        let yes = crate::dialogs::confirm_modal(ctx, "degraded", t("harden.degraded_title"), &lines, t("harden.continue"))?;
        self.gate_wait = None;
        if yes {
            self.degraded_ack = true;
            Some(job)
        } else {
            self.msg(true, t("dlg.cancelled"));
            None
        }
    }

    /// Call once per frame before drawing.
    pub fn frame(&mut self, ctx: &egui::Context, has_secrets: bool) -> FrameEvents {
        self.apply_settings(ctx);
        self.tracker.frame(ctx, &mut self.set);
        let mut ev = FrameEvents::default();
        let (active, minimized, focused) = ctx.input(|i| {
            for e in &i.events {
                match e {
                    egui::Event::PointerMoved(p) => crate::entropy::mix_mouse(p.x, p.y, i.time),
                    // time differences of key / button events inside this window only
                    egui::Event::Key { .. } | egui::Event::PointerButton { .. } => crate::entropy::mix_input_timing(),
                    _ => {}
                }
            }
            ev.dropped = i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect();
            ev.close_requested = i.viewport().close_requested();
            let vp = i.viewport();
            (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO, vp.minimized.unwrap_or(false), vp.focused.unwrap_or(true))
        });
        if active {
            self.last_act = Instant::now();
        }
        let idle = Duration::from_secs(self.set.auto_lock_min as u64 * 60);
        if has_secrets && self.last_act.elapsed() > idle {
            ev.lock = Some(LockReason::Idle);
            self.last_act = Instant::now();
        }
        if minimized && !self.was_minimized && self.set.lock_on_minimize {
            ev.lock = Some(LockReason::Minimized);
        }
        if !focused && self.was_focused && self.set.lock_on_focus_loss {
            ev.lock = Some(LockReason::FocusLost);
        }
        self.was_minimized = minimized;
        self.was_focused = focused;
        if ev.lock.is_some() {
            crate::entropy::clear_pool();
            self.unlocked = None;
            self.auth.clear();
        }
        self.updater.poll(ctx, self.set.update);
        self.updater.dialogs(ctx);
        self.auth.poll(&mut self.set, &mut self.unlocked, &mut self.status, &mut self.ok);
        if self.updater.install_requested {
            ev.install = true;
        }
        self.save_if_needed(ctx, ev.close_requested);
        ctx.request_repaint_after(Duration::from_secs(5));
        ev
    }

    /// Runs the verified installer after the window wiped its secrets. Closes the window when
    /// the installer needs the program files.
    pub fn install_update(&mut self, ctx: &egui::Context) {
        self.unlocked = None;
        self.auth.clear();
        crate::sysinfo::clear_clipboard();
        if self.updater.install() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let n = self.updater.note.clone();
        self.msg(true, n);
    }

    pub fn lock_message(&mut self, r: LockReason) {
        let m = match r {
            LockReason::Idle => tf("shell.locked_idle", &[&self.set.auto_lock_min]),
            LockReason::Minimized => t("shell.locked_min").to_string(),
            LockReason::FocusLost => t("shell.locked_focus").to_string(),
        };
        self.msg(true, m);
    }

    /// Settings > Security > clear clipboard: empties it right after a password was pasted.
    /// Linux has no clipboard API outside a toolkit (`sysinfo::clear_clipboard` is false there):
    /// the window then overwrites the clipboard through egui with a single space.
    pub fn clipboard_after_paste(&self, ctx: &egui::Context, bufs: &mut [&mut crate::harden::SecretBuf]) {
        if !self.set.clipboard_clear {
            return;
        }
        for b in bufs.iter_mut() {
            if b.pasted {
                if !crate::sysinfo::clear_clipboard() {
                    ctx.output_mut(|o| o.copied_text = " ".into());
                }
                b.pasted = false;
            }
        }
    }
}

#[cfg(test)]
mod link_tests {
    #[test]
    fn links_never_reach_the_webbrowser_crate() {
        let ctx = eframe::egui::Context::default();
        let out = ctx.run(Default::default(), |ctx| {
            ctx.open_url(eframe::egui::OpenUrl::new_tab("https://example.invalid/x"));
            super::end_frame(ctx);
        });
        assert!(out.platform_output.open_url.is_none());
    }
}
