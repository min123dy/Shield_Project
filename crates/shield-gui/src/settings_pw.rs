//! Settings password in the GUI (3.0 §8). Argon2id runs in a worker thread so the window stays
//! responsive (and the retry delay after a wrong password does not freeze it).

use crate::harden::SecretBuf;
use crate::i18n::t;
use crate::settings::Settings;
use crate::settings_auth::{self, Unlocked};
use crate::ui::{hint, password_report, secret_field, strength_bar, warn};
use eframe::egui;
use std::sync::mpsc;

/// A usable but weak new password waiting for "use it anyway" (B-10, same as for encryption).
struct Weak {
    reasons: Vec<String>,
    /// true: replaces the current password (needs the unlock), false: first password.
    change: bool,
}

enum Done {
    Unlocked(Result<Unlocked, String>),
    /// New password set: its salt / verifier, and the unlock to save with.
    Set(Result<(Option<settings_auth::Auth>, Unlocked), String>),
}

#[derive(Default)]
pub struct AuthUi {
    pub pw: SecretBuf,
    pub new1: SecretBuf,
    pub new2: SecretBuf,
    rx: Option<mpsc::Receiver<Done>>,
    /// The create / change button was pressed: reasons are shown even for empty fields.
    tried: bool,
    /// The unlock button was pressed with an empty field.
    unlock_tried: bool,
    weak: Option<Weak>,
}

impl AuthUi {
    pub fn clear(&mut self) {
        self.pw.clear();
        self.new1.clear();
        self.new2.clear();
        self.tried = false;
        self.unlock_tried = false;
        self.weak = None;
    }

    pub fn busy(&self) -> bool {
        self.rx.is_some()
    }

    fn run(&mut self, f: impl FnOnce() -> Done + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
    }

    /// Results of the worker (called every frame by the shell).
    pub fn poll(&mut self, set: &mut Settings, unlocked: &mut Option<Unlocked>, status: &mut String, ok: &mut bool) {
        let Some(rx) = &self.rx else { return };
        let Ok(d) = rx.try_recv() else { return };
        self.rx = None;
        let r = match d {
            Done::Unlocked(Ok(u)) => {
                *unlocked = Some(u);
                Ok(t("set.pw_unlocked").to_string())
            }
            Done::Set(Ok((auth, u))) => {
                set.auth = auth;
                let r = set.save_unlocked(&u).map(|_| t("set.pw_saved").to_string());
                *unlocked = Some(u);
                r
            }
            Done::Unlocked(Err(e)) | Done::Set(Err(e)) => Err(e),
        };
        (*ok, *status) = match r {
            Ok(m) => (true, m),
            Err(e) => (false, e),
        };
    }

    /// The password section at the top of Settings > Security.
    pub fn view(&mut self, ui: &mut egui::Ui, set: &mut Settings, unlocked: &mut Option<Unlocked>, allow_reveal: bool) {
        if set.tampered {
            warn(ui, t("set.tampered"));
        }
        if self.busy() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(t("set.pw_working"));
            });
            return;
        }
        if let Some(w) = &self.weak {
            // the fields stay hidden so the password can't change behind the confirmation
            let change = w.change;
            match crate::ui::confirm_modal(ui.ctx(), "setpw_weak", t("dlg.weak_title"), &w.reasons, t("dlg.weak_use")) {
                Some(true) => {
                    self.weak = None;
                    let cur = if change { unlocked.take() } else { None };
                    self.set_new(set, cur);
                }
                Some(false) => self.weak = None,
                None => {}
            }
            return;
        }
        match (&set.auth, unlocked.is_some()) {
            (None, _) => {
                hint(ui, t("set.pw_create_hint"));
                self.new_fields(ui, allow_reveal);
                if ui.button(t("set.pw_create")).clicked() {
                    self.try_new(set, unlocked, false);
                }
            }
            (Some(_), false) => {
                hint(ui, t("set.pw_locked_hint"));
                secret_field(ui, "setpw", &mut self.pw, t("set.pw_enter"), allow_reveal);
                let wait = settings_auth::retry_delay();
                if !wait.is_zero() {
                    hint(ui, crate::i18n::tf("set.pw_wait", &[&wait.as_secs()]));
                }
                // never disabled (3.0.0 §1): an empty field gives its reason instead
                if self.unlock_tried && self.pw.is_empty() {
                    password_report(ui, &crate::password::Check { blocks: vec![t("pw.b_empty").into()], warnings: vec![] });
                }
                if ui.button(t("set.pw_unlock")).clicked() {
                    if self.pw.is_empty() {
                        self.unlock_tried = true;
                        return;
                    }
                    self.unlock_tried = false;
                    let s = set.clone();
                    let pw = self.pw.normalized();
                    self.pw.clear();
                    self.run(move || Done::Unlocked(settings_auth::unlock(&s, &pw)));
                }
            }
            (Some(_), true) => {
                ui.horizontal_wrapped(|ui| {
                    ui.label(t("set.pw_is_unlocked"));
                    if ui.button(t("set.pw_lock")).clicked() {
                        *unlocked = None;
                        self.clear();
                    }
                });
                ui.collapsing(t("set.pw_change"), |ui| {
                    self.new_fields(ui, allow_reveal);
                    ui.horizontal(|ui| {
                        if ui.button(t("set.pw_change")).clicked() {
                            self.try_new(set, unlocked, true);
                        }
                        if ui.button(t("set.pw_remove")).on_hover_text(t("set.pw_remove_hint")).clicked() {
                            if let Some(u) = unlocked.as_ref() {
                                if settings_auth::clear_password(set, u).is_ok() {
                                    // saved by the shell with the unlock (protected text changed)
                                    let _ = set.save_unlocked(u);
                                }
                            }
                            *unlocked = None;
                        }
                    });
                });
            }
        }
    }

    fn new_fields(&mut self, ui: &mut egui::Ui, allow_reveal: bool) {
        secret_field(ui, "setpw1", &mut self.new1, t("set.pw_new"), allow_reveal);
        secret_field(ui, "setpw2", &mut self.new2, t("set.pw_new2"), allow_reveal);
        strength_bar(ui, &self.new1);
        // live while typing (and after a click on empty fields): blocks, then the warnings
        if self.tried || !self.new1.is_empty() || !self.new2.is_empty() {
            password_report(ui, &self.check());
        }
    }

    /// The one password check (`password::check_new`, the same as for encryption). Blocks: empty,
    /// confirmation differs, too long. Everything else is a warning confirmed in a dialog.
    fn check(&self) -> crate::password::Check {
        let user = crate::password::user_name();
        let rules = crate::password::Rules { has_keyfile: false, min_len: 0, user: &user };
        crate::password::check_new(self.new1.as_str(), Some(self.new1.ct_eq(&self.new2)), self.new1.overflow, rules)
    }

    /// Why the new password can't be used (empty = usable).
    fn new_problems(&self) -> Vec<String> {
        self.check().blocks
    }

    /// The create / change button: refuse with the reasons shown, confirm a weak password, or set it.
    fn try_new(&mut self, set: &Settings, unlocked: &mut Option<Unlocked>, change: bool) {
        self.tried = true;
        if !self.new_problems().is_empty() {
            return;
        }
        let reasons = self.check().warnings;
        if reasons.is_empty() {
            let cur = if change { unlocked.take() } else { None };
            self.set_new(set, cur);
        } else {
            self.weak = Some(Weak { reasons, change });
        }
    }

    fn set_new(&mut self, set: &Settings, current: Option<Unlocked>) {
        let mut s = set.clone();
        let pw = self.new1.normalized();
        self.clear();
        self.run(move || Done::Set(settings_auth::set_password(&mut s, &pw, current.as_ref()).map(|u| (s.auth.clone(), u))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ui_with(a: &str, b: &str) -> AuthUi {
        let mut u = AuthUi::default();
        u.new1.push_str(a);
        u.new2.push_str(b);
        u
    }

    #[test]
    fn unusable_passwords_give_reasons_and_start_nothing() {
        let set = Settings::default();
        // blocked: empty, confirmation differs (too long: tested in password.rs); "short" alone
        // is only a warning now
        for (a, b, n) in [("", "", 1), ("long enough 1", "long enough 2", 1), ("", "abd", 2)] {
            let mut u = ui_with(a, b);
            u.try_new(&set, &mut None, false);
            assert_eq!(u.new_problems().len(), n, "{a:?}");
            assert!(u.tried && u.weak.is_none() && !u.busy(), "{a:?} must not be set");
        }
    }

    #[test]
    fn weak_but_usable_password_asks_first() {
        let set = Settings::default();
        for pw in ["password1", "12345678", "abcdefgh1", "short", "Zk#9vQ!x"] {
            let mut u = ui_with(pw, pw);
            u.try_new(&set, &mut None, false);
            assert!(u.new_problems().is_empty(), "{pw:?} is allowed");
            let w = u.weak.as_ref().unwrap_or_else(|| panic!("{pw:?} needs the confirmation"));
            assert!(!w.reasons.is_empty() && !w.change);
            assert!(!u.busy(), "nothing derived before the confirmation");
        }
    }
}
