//! "Secure delete" tab of the encryption window (3.1.0 final; design: docs/10).
//!
//! The list is only a selection: pressing the button scans it on a worker thread
//! (`secure_delete::scan`), and the plan that comes back is shown in three modal steps (warning,
//! limits with an acknowledgement, typed code) driven by `secure_delete::Confirmation`. Only a
//! finished confirmation yields the `ConfirmedWipePlan` the delete job takes. Cancel is the
//! default everywhere; changing the list, locking the window or failing the code three times
//! throws the confirmation away. There is no "don't ask again" and no way to skip a step.
//! When the settings ask for it (Settings > Security > Secure delete, with a settings password
//! set), one more modal asks for the settings password after the code; it is checked on a worker
//! thread (`secure_delete::permit`, Argon2id) and only its permit lets the delete job start.
//! Three wrong passwords, a lock or a changed list throw everything away.

use crate::enc_app::EncApp;
use crate::i18n::{t, tf};
use crate::job::Job;
use crate::progress::{ST_SCAN, ST_TRIM, ST_WIPE};
use crate::secure_delete::{self as sd, Answer, Confirmation, Plan, Report, Step};
use crate::theme::pal;
use crate::ui::{hint, section, warn};
use crate::ui_fmt::path_shown;
use crate::wipe::Passes;
use crate::harden::SecretBuf;
use eframe::egui::{self, vec2, RichText};
use std::{path::PathBuf, sync::mpsc, time::Instant};

/// The settings password step: the confirmed plan waits here for its permit.
pub struct PwStep {
    confirmed: sd::ConfirmedWipePlan,
    pub buf: SecretBuf,
    fails: u32,
    check: Option<mpsc::Receiver<Result<sd::WipePermit, String>>>,
    note: Option<String>,
    /// The empty field was submitted (its reason is shown instead of a disabled button).
    tried_empty: bool,
}

/// State of the tab. Nothing of it is saved (no paths, no codes).
pub struct WipeTab {
    pub items: Vec<PathBuf>,
    pub passes: Passes,
    pub scan: Option<Job<Plan>>,
    pub run: Option<Job<Report>>,
    pub confirm: Option<Confirmation>,
    pub limits_ack: bool,
    pub typed: String,
    /// Message inside the code dialog (wrong code, too early).
    pub note: Option<String>,
    /// Lines of the last result that did not fully work.
    pub problems: Vec<String>,
    /// Items of a file manager selection that could not be used (relative, gone, too many).
    pub dropped: usize,
    /// The settings password step (after the code), when the settings ask for it.
    pub pw: Option<PwStep>,
}

impl WipeTab {
    pub fn new(passes: Passes) -> WipeTab {
        WipeTab { items: vec![], passes, scan: None, run: None, confirm: None, limits_ack: false, typed: String::new(), note: None, problems: vec![], dropped: 0, pw: None }
    }

    pub fn busy(&self) -> bool {
        self.scan.is_some() || self.run.is_some() || self.pw.as_ref().is_some_and(|p| p.check.is_some())
    }

    /// A confirmation (or its settings password step) is open.
    pub fn confirming(&self) -> bool {
        self.confirm.is_some() || self.pw.is_some()
    }

    /// Throws away a running confirmation (list changed, window locked, cancelled).
    pub fn reset_confirm(&mut self) {
        if let Some(c) = &mut self.confirm {
            c.cancel();
        }
        self.confirm = None;
        // the confirmed plan and the typed settings password go too (SecretBuf wipes on drop)
        self.pw = None;
        self.limits_ack = false;
        self.typed.clear();
        self.note = None;
    }

    pub fn add(&mut self, p: PathBuf) {
        if !self.items.contains(&p) && self.items.len() < sd::MAX_ITEMS {
            self.items.push(p);
            self.reset_confirm();
        }
    }
}

impl EncApp {
    pub fn wipe_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.wipe.items.is_empty() {
            v.push(t("sd.pick").into());
        }
        v
    }

    /// The button: scan the list (nothing is changed on disk).
    pub fn start_wipe_scan(&mut self) {
        if !self.wipe_problems().is_empty() || self.wipe.busy() {
            return;
        }
        self.wipe.reset_confirm();
        self.wipe.problems.clear();
        let (items, passes) = (self.wipe.items.clone(), self.wipe.passes);
        self.wipe.scan = Some(Job::spawn(t("sd.job_scan"), vec![ST_SCAN], move || sd::scan(&items, passes)));
        self.sh.msg(true, "");
    }

    /// Called every frame: results of the scan and of the delete job.
    pub fn poll_wipe(&mut self) {
        if let Some(r) = self.wipe.scan.as_ref().and_then(Job::poll) {
            self.wipe.scan = None;
            match r {
                Ok(plan) if plan.same_selection(&self.wipe.items) => {
                    self.wipe.confirm = Some(Confirmation::new(plan));
                    self.sh.msg(true, t("sd.confirm_hint"));
                }
                Ok(_) => self.sh.msg(false, t("sd.list_changed")),
                Err(m) => self.sh.msg(false, m),
            }
        }
        if let Some(job) = &self.wipe.run {
            if let Some(r) = job.poll() {
                let secs = job.secs();
                self.wipe.run = None;
                crate::entropy::clear_pool();
                match r {
                    Ok(rep) => {
                        // what was removed leaves the list; the rest stays so it can be looked at
                        let gone: Vec<PathBuf> = rep.results.iter().filter(|x| x.outcome == sd::Outcome::Done).map(|x| x.path.clone()).collect();
                        self.wipe.items.retain(|p| {
                            let real = std::fs::canonicalize(p).ok();
                            !(gone.contains(p) || real.is_some_and(|r| gone.contains(&r)) || std::fs::symlink_metadata(p).is_err())
                        });
                        self.wipe.problems = rep.problem_lines(50);
                        self.sh.msg(rep.all_ok(), rep.summary() + &secs);
                    }
                    Err(m) => self.sh.msg(false, m),
                }
            }
        }
    }

    fn start_wipe_run(&mut self, c: sd::ConfirmedWipePlan, p: sd::WipePermit) {
        self.wipe.reset_confirm();
        self.wipe.run = Some(Job::spawn(t("sd.job_run"), vec![ST_WIPE, ST_TRIM], move || Ok(sd::execute(c, p))));
        self.sh.msg(true, "");
    }

    /// After the code: straight to the delete job, or first the settings password step.
    fn after_code(&mut self, c: sd::ConfirmedWipePlan) {
        if sd::settings_password_needed(&self.sh.set) {
            self.wipe.reset_confirm();
            self.wipe.pw = Some(PwStep { confirmed: c, buf: SecretBuf::new(), fails: 0, check: None, note: None, tried_empty: false });
            return;
        }
        match sd::permit(&self.sh.set, None) {
            Ok(p) => self.start_wipe_run(c, p),
            Err(m) => {
                self.wipe.reset_confirm();
                self.sh.msg(false, m);
            }
        }
    }

    /// The settings password step (modal, after the code step).
    fn wipe_pw_dialog(&mut self, ctx: &egui::Context) {
        let items_same = self.wipe.pw.as_ref().is_some_and(|st| st.confirmed.plan().same_selection(&self.wipe.items));
        if !items_same {
            // a list changed meanwhile never reaches the delete job
            self.wipe.reset_confirm();
            return self.sh.msg(false, t("sd.list_changed"));
        }
        let Some(st) = self.wipe.pw.as_mut() else { return };
        // result of the check running on the worker
        let mut done = None;
        if let Some(rx) = &st.check {
            match rx.try_recv() {
                Ok(r) => done = Some(r),
                Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
                Err(mpsc::TryRecvError::Disconnected) => done = Some(Err(t("sd.cancelled").to_string())),
            }
        }
        match done {
            Some(Ok(permit)) => {
                let st = self.wipe.pw.take().expect("present");
                return self.start_wipe_run(st.confirmed, permit);
            }
            Some(Err(e)) if crate::i18n::has_code(&e, crate::settings_auth::C_WRONG_PW) => {
                st.check = None;
                st.fails += 1;
                if st.fails >= sd::MAX_FAILS {
                    self.wipe.reset_confirm();
                    return self.sh.msg(false, tf("sd.pw_aborted", &[&sd::MAX_FAILS]));
                }
                st.note = Some(tf("sd.pw_wrong", &[&(sd::MAX_FAILS - st.fails)]));
            }
            Some(Err(e)) => {
                self.wipe.reset_confirm();
                return self.sh.msg(false, e);
            }
            None => {}
        }
        let allow_reveal = self.sh.set.allow_reveal;
        let checking = st.check.is_some();
        let (mut cancel, mut submit) = (false, false);
        egui::Window::new(RichText::new(t("sd.pw_title")).color(pal().err).strong())
            .id(egui::Id::new("wipe_settings_pw"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_max_width(520.0);
                ui.label(RichText::new(t("sd.pw_desc")).strong());
                ui.label(st.confirmed.plan().summary_line());
                if checking {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(t("sd.pw_checking"));
                    });
                } else {
                    crate::ui::secret_field(ui, "wipe_set_pw", &mut st.buf, t("sd.pw_field"), allow_reveal);
                    let wait = crate::settings_auth::retry_delay();
                    if !wait.is_zero() {
                        hint(ui, tf("set.pw_wait", &[&wait.as_secs()]));
                    }
                    if st.tried_empty && st.buf.is_empty() {
                        warn(ui, t("pw.b_empty"));
                    }
                    if let Some(n) = &st.note {
                        warn(ui, n.clone());
                    }
                    if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let b = ui.add(egui::Button::new(RichText::new(t("ui.cancel")).strong()).min_size(vec2(110.0, 28.0)));
                    if b.clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        cancel = true;
                    }
                    if ui.add_enabled(!checking, egui::Button::new(RichText::new(t("sd.pw_go")).color(pal().err))).clicked() {
                        submit = true;
                    }
                });
            });
        if cancel {
            // also while checking: the receiver goes, a permit sent later is dropped unused
            self.wipe.reset_confirm();
            return self.sh.msg(true, t("sd.cancelled"));
        }
        if submit && !checking {
            if st.buf.is_empty() {
                st.tried_empty = true;
                return;
            }
            st.tried_empty = false;
            st.note = None;
            let pw = st.buf.normalized();
            st.buf.clear();
            let set = self.sh.set.clone();
            let (tx, rx) = mpsc::channel();
            st.check = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(sd::permit(&set, Some(&pw)));
            });
        }
    }

    /// The three confirmation steps (modal). Called after the frame's panels.
    pub fn wipe_dialogs(&mut self, ctx: &egui::Context) {
        if self.wipe.pw.is_some() {
            return self.wipe_pw_dialog(ctx);
        }
        let Some(c) = &self.wipe.confirm else { return };
        // a list changed after the scan never reaches the code step
        if !c.plan().same_selection(&self.wipe.items) {
            self.wipe.reset_confirm();
            return self.sh.msg(false, t("sd.list_changed"));
        }
        let now = Instant::now();
        let step = c.step();
        let title = tf("sd.step_title", &[&c.step_no(), &c.steps_total()]);
        let mut cancel = false;
        let mut next = false;
        let mut submit = false;
        let w = &mut self.wipe;
        let c = w.confirm.as_ref().expect("checked above");
        let plan = c.plan();
        egui::Window::new(RichText::new(title).color(pal().err).strong())
            .id(egui::Id::new("wipe_confirm"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_max_width(560.0);
                match step {
                    Step::Warning => {
                        ui.label(RichText::new(t("sd.w_irreversible")).color(pal().err).strong().size(16.0));
                        ui.label(plan.summary_line());
                        if plan.is_big() {
                            ui.label(RichText::new(t("sd.w_big")).color(pal().err).strong());
                        }
                        egui::ScrollArea::vertical().id_source("wipe_targets").max_height(220.0).show(ui, |ui| {
                            for l in plan.target_lines() {
                                ui.add(egui::Label::new(RichText::new(l).monospace()).wrap(true));
                            }
                        });
                        hint(ui, t("sd.w_real_paths"));
                    }
                    Step::Limits => {
                        ui.label(RichText::new(t("sd.l_title")).color(pal().warn).strong());
                        egui::ScrollArea::vertical().id_source("wipe_limits").max_height(260.0).show(ui, |ui| {
                            for l in plan.limit_lines() {
                                ui.label(format!("\u{2022} {l}"));
                            }
                        });
                        ui.checkbox(&mut w.limits_ack, RichText::new(t("sd.l_ack")).strong());
                    }
                    Step::Code => {
                        ui.label(RichText::new(t("sd.c_title")).color(pal().err).strong());
                        hint(ui, t("sd.c_hint"));
                        if let Some(code) = c.code() {
                            // drawn, not selectable: it is to be read and typed, not copied
                            let spaced: String = code.chars().flat_map(|ch| [ch, ' ']).collect();
                            ui.add(egui::Label::new(RichText::new(spaced.trim_end()).monospace().size(26.0).strong()).selectable(false));
                        }
                        // the code is typed: pasted text never reaches the field
                        ui.input_mut(|i| i.events.retain(|e| !matches!(e, egui::Event::Paste(_))));
                        let field = ui.add(egui::TextEdit::singleline(&mut w.typed).char_limit(sd::CODE_LEN + 6).font(egui::TextStyle::Monospace).desired_width(180.0).hint_text(t("sd.c_field")));
                        let left = c.wait_left(now);
                        if !left.is_zero() {
                            hint(ui, tf("sd.c_wait", &[&(left.as_secs() + 1)]));
                            ctx.request_repaint_after(std::time::Duration::from_millis(200));
                        }
                        hint(ui, tf("sd.c_tries", &[&c.tries_left()]));
                        if let Some(n) = &w.note {
                            warn(ui, n.clone());
                        }
                        if left.is_zero() && field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            submit = true;
                        }
                    }
                    Step::Done | Step::Aborted => {}
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let b = ui.add(egui::Button::new(RichText::new(t("ui.cancel")).strong()).min_size(vec2(110.0, 28.0)));
                    if step != Step::Code && !ui.memory(|m| m.focused().is_some()) {
                        b.request_focus();
                    }
                    if b.clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        cancel = true;
                    }
                    let (label, enabled) = match step {
                        Step::Warning => (t("sd.w_go"), true),
                        Step::Limits => (t("sd.l_go"), w.limits_ack),
                        _ => (t("sd.c_go"), c.wait_left(now).is_zero() && !w.typed.trim().is_empty()),
                    };
                    if ui.add_enabled(enabled, egui::Button::new(RichText::new(label).color(pal().err))).clicked() {
                        if step == Step::Code {
                            submit = true;
                        } else {
                            next = true;
                        }
                    }
                });
            });
        if cancel {
            self.wipe.reset_confirm();
            return self.sh.msg(true, t("sd.cancelled"));
        }
        let w = &mut self.wipe;
        let Some(c) = w.confirm.as_mut() else { return };
        let r = if next {
            match step {
                Step::Warning => c.accept_warning(now),
                _ => c.accept_limits(w.limits_ack, now),
            }
            .map(|_| None)
        } else if submit {
            let typed = std::mem::take(&mut w.typed);
            c.submit(&typed, now).map(Some)
        } else {
            return;
        };
        match r {
            Err(m) => {
                self.wipe.reset_confirm();
                self.sh.msg(false, m);
            }
            Ok(None) => {}
            Ok(Some(Answer::Accepted)) => {
                let c = self.wipe.confirm.take().expect("present");
                match c.finish() {
                    Ok(confirmed) => self.after_code(confirmed),
                    Err(_) => self.wipe.reset_confirm(),
                }
            }
            Ok(Some(Answer::Wrong(n))) => self.wipe.note = Some(tf("sd.c_wrong", &[&n])),
            Ok(Some(Answer::TooEarly)) => self.wipe.note = Some(t("sd.c_early").into()),
            Ok(Some(Answer::Aborted)) => {
                self.wipe.reset_confirm();
                self.sh.msg(false, tf("sd.c_aborted", &[&sd::MAX_FAILS]));
            }
            Ok(Some(Answer::NotNow)) => {}
        }
    }
}

/// The tab itself: list, passes, notes. The button is in the bottom bar.
pub fn view(a: &mut EncApp, ui: &mut egui::Ui) {
    ui.heading(t("sd.title"));
    ui.label(RichText::new(t("sd.desc")).color(pal().err));
    hint(ui, t("sd.desc2"));
    if a.sh.set.wipe_needs_pw && a.sh.set.auth.is_some() {
        hint(ui, t("sd.pw_needed_hint"));
    }
    let w = &mut a.wipe;
    if w.dropped > 0 {
        warn(ui, tf("sd.dropped", &[&w.dropped]));
    }
    section(ui, t("sd.s_items"), |ui| {
        let mut remove = None;
        if w.items.is_empty() {
            hint(ui, t("v.nothing_selected"));
        }
        egui::ScrollArea::vertical().id_source("wipe_items").max_height(200.0).show(ui, |ui| {
            for (i, p) in w.items.iter().enumerate() {
                let kind = match std::fs::symlink_metadata(p) {
                    Ok(m) if m.file_type().is_symlink() => t("sd.k_link").to_string(),
                    Ok(m) if m.is_dir() => t("v.folder").to_string(),
                    Ok(m) => crate::ui_fmt::human(m.len()),
                    Err(_) => t("v.not_found").to_string(),
                };
                ui.horizontal(|ui| {
                    if ui.small_button("\u{00D7}").on_hover_text(t("multi.remove")).clicked() {
                        remove = Some(i);
                    }
                    let shown = path_shown(p);
                    let width = (ui.available_width() - 90.0).max(60.0);
                    crate::ui_table::clipped_label(ui, &shown, width).on_hover_text(shown.clone());
                    hint(ui, kind);
                });
            }
        });
        if let Some(i) = remove {
            w.items.remove(i);
            w.reset_confirm();
        }
        let mut add = Vec::new();
        ui.horizontal_wrapped(|ui| {
            if ui.button(t("multi.add_files")).clicked() {
                add.extend(rfd::FileDialog::new().set_title(t("multi.add_files")).pick_files().unwrap_or_default());
            }
            if ui.button(t("v.pick_folder")).clicked() {
                add.extend(rfd::FileDialog::new().set_title(t("v.pick_folder")).pick_folder());
            }
            if !w.items.is_empty() && ui.button(t("multi.clear")).clicked() {
                w.items.clear();
                w.reset_confirm();
            }
        });
        for p in add {
            w.add(p);
        }
    });
    section(ui, t("sd.s_passes"), |ui| {
        crate::dialogs::passes_picker(ui, &mut w.passes);
        hint(ui, t("sd.passes_hint"));
    });
    if !w.problems.is_empty() {
        section(ui, t("sd.s_result"), |ui| {
            egui::ScrollArea::vertical().id_source("wipe_problems").max_height(160.0).show(ui, |ui| {
                for l in &w.problems {
                    ui.add(egui::Label::new(RichText::new(l).color(pal().warn)).wrap(true));
                }
            });
        });
    }
}
