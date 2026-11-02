//! State and per-frame chores shared by both windows: settings (applied live), status line,
//! capture protection, auto-lock (idle / minimize / focus loss), clipboard clearing, dropped files
//! and leftover staging folders.

use crate::capture::Applied;
use crate::i18n::{t, tf};
use crate::settings::{Category, Settings};
use crate::ui::Leftovers;
use eframe::egui;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

pub struct Shell {
    pub set: Settings,
    pub status: String,
    pub ok: bool,
    pub leftovers: Leftovers,
    pub last_act: Instant,
    pub capture: Option<Result<Applied, String>>,
    pub set_cat: Category,
    applied: Option<Settings>,
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
    pub dropped: Vec<PathBuf>,
    pub close_requested: bool,
}

impl Shell {
    pub fn new(set: Settings) -> Self {
        Shell {
            set,
            status: String::new(),
            ok: true,
            leftovers: Leftovers::check(),
            last_act: Instant::now(),
            capture: None,
            set_cat: Category::General,
            applied: None,
            theme_check: Instant::now(),
            was_minimized: false,
            was_focused: true,
        }
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
        crate::entropy::set_mouse_enabled(self.set.mouse_entropy);
        let cap_changed = self.applied.as_ref().map(|a| a.capture_protect) != Some(self.set.capture_protect);
        if cap_changed {
            let r = crate::capture::apply(self.set.capture_protect);
            if let Err(x) = &r {
                self.msg(false, tf("cap.status_failed", &[x]));
            } else if r == Ok(Applied::Monitor) {
                self.msg(true, t("cap.status_monitor"));
            }
            self.capture = Some(r);
        }
        crate::capture::dark_title_bar(crate::theme::is_dark());
        if self.applied.is_some() {
            if let Err(x) = self.set.save() {
                self.msg(false, x);
            }
        }
        self.applied = Some(self.set.clone());
    }

    /// Call once per frame before drawing.
    pub fn frame(&mut self, ctx: &egui::Context, has_secrets: bool) -> FrameEvents {
        self.apply_settings(ctx);
        let mut ev = FrameEvents::default();
        let (active, minimized, focused) = ctx.input(|i| {
            for e in &i.events {
                if let egui::Event::PointerMoved(p) = e {
                    crate::entropy::mix_mouse(p.x, p.y, i.time);
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
        }
        ctx.request_repaint_after(Duration::from_secs(5));
        ev
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
    pub fn clipboard_after_paste(&self, bufs: &mut [&mut crate::harden::SecretBuf]) {
        if !self.set.clipboard_clear {
            return;
        }
        for b in bufs.iter_mut() {
            if b.pasted && crate::sysinfo::clear_clipboard() {
                b.pasted = false;
            }
        }
    }
}
