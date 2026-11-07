//! Shared widgets and the progress/status bar used by both windows. Colors come from `theme::pal()`,
//! text from `i18n`; only glyphs listed in `glyphs::ALLOWED` are used.

use crate::harden::SecretBuf;
use crate::i18n::{t, tf};
use crate::job::Job;
use crate::progress::*;
use crate::theme::pal;
use eframe::egui::{self, vec2, RichText};
pub use crate::ui_fmt::{date, human};
pub use crate::dialogs::*;
use std::{
    path::PathBuf,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60) } else { format!("{}:{:02}", s / 60, s % 60) }
}

/// A titled group box. Returns the rectangle it occupies.
pub fn section(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) -> egui::Rect {
    let r = egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(10.0)).rounding(6.0).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(title).strong().size(15.5));
        ui.add_space(2.0);
        add(ui);
    });
    ui.add_space(4.0);
    r.response.rect
}

/// Collapsible "advanced options" block (A-5): closed by default.
pub fn advanced(ui: &mut egui::Ui, id: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(t("ui.advanced")).id_source(id).default_open(false).show(ui, add);
}

pub fn hint(ui: &mut egui::Ui, s: impl Into<String>) {
    ui.label(RichText::new(s.into()).small().weak());
}

pub fn warn(ui: &mut egui::Ui, s: impl Into<String>) {
    ui.label(RichText::new(format!("\u{203B} {}", s.into())).small().color(pal().warn));
}

/// Tab strip; returns true when the selection changed.
pub fn tabs<T: PartialEq + Copy>(ui: &mut egui::Ui, cur: &mut T, items: &[(T, &str)]) -> bool {
    let before = *cur;
    for (m, s) in items {
        ui.selectable_value(cur, *m, RichText::new(*s).size(15.0));
    }
    *cur != before
}

/// Password field that never hands the secret to egui's TextEdit (which keeps undo copies and
/// re-allocates). Key events go straight into a fixed locked buffer; dots are drawn unless the
/// user pressed "Show" (only offered when Settings allow it). Limitation: egui owns the event
/// strings (Event::Text/Paste) and frees them without zeroizing; a shown password is also laid
/// out as text by egui. The clipboard can be emptied after a paste.
pub fn secret_field(ui: &mut egui::Ui, id: &str, buf: &mut SecretBuf, placeholder: &str, allow_reveal: bool) {
    let eid = egui::Id::new(id);
    let reveal_id = eid.with("reveal");
    let mut reveal = allow_reveal && ui.data(|d| d.get_temp::<bool>(reveal_id)).unwrap_or(false);
    ui.horizontal(|ui| {
        let size = vec2((ui.available_width() - if allow_reveal { 70.0 } else { 0.0 }).clamp(120.0, 400.0), 28.0);
        let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let resp = ui.interact(rect, eid, egui::Sense::click());
        ui.memory_mut(|m| m.interested_in_focus(eid));
        if resp.clicked() {
            ui.memory_mut(|m| m.request_focus(eid));
        }
        let focused = ui.memory(|m| m.has_focus(eid));
        if focused {
            ui.input(|i| {
                for ev in &i.events {
                    match ev {
                        egui::Event::Text(s) => buf.push_str(s),
                        egui::Event::Paste(s) => {
                            buf.push_str(s);
                            buf.pasted = true;
                        }
                        egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => buf.pop(),
                        _ => {}
                    }
                }
            });
        }
        let v = ui.visuals();
        let col = if focused { pal().accent } else { v.widgets.inactive.bg_stroke.color };
        ui.painter().rect(rect, 4.0, v.extreme_bg_color, egui::Stroke::new(if focused { 2.0_f32 } else { 1.0_f32 }, col));
        let (text, color) = if buf.is_empty() && !focused {
            (placeholder.to_string(), v.weak_text_color())
        } else {
            let mut d = if reveal { buf.as_str().to_string() } else { "\u{25CF}".repeat(buf.char_count().min(40)) };
            if focused {
                d.push('|');
            }
            (d, v.text_color())
        };
        ui.painter().with_clip_rect(rect.shrink(2.0)).text(rect.left_center() + vec2(8.0, 0.0), egui::Align2::LEFT_CENTER, text, egui::FontId::proportional(13.5), color);
        resp.on_hover_text(t("ui.secret_hover"));
        if allow_reveal && ui.selectable_label(reveal, t("ui.show")).on_hover_text(t("ui.show_hover")).clicked() {
            reveal = !reveal;
        }
    });
    ui.data_mut(|d| d.insert_temp(reveal_id, reveal));
    if buf.overflow {
        ui.label(RichText::new(tf("ui.pw_too_long", &[&crate::harden::SECRET_CAP])).small().color(pal().err));
    }
    if buf.pasted {
        ui.horizontal(|ui| {
            warn(ui, t("ui.pasted"));
            if ui.small_button(t("ui.clear_clipboard")).clicked() {
                // Linux: no clipboard API outside the toolkit, overwrite it through egui
                if !crate::sysinfo::clear_clipboard() {
                    ui.ctx().output_mut(|o| o.copied_text = " ".into());
                }
                buf.pasted = false;
            }
        });
    }
}

/// Rough strength guess. Never claims more than an estimate. The reasons are listed by
/// `password_report` (one list for the field, the dialog and the console).
pub fn strength_bar(ui: &mut egui::Ui, b: &SecretBuf) {
    if b.is_empty() {
        return;
    }
    let a = crate::password::assess(b.as_str());
    let c = match a.level {
        0 | 1 => pal().err,
        2 => pal().warn,
        _ => pal().ok,
    };
    let f = (a.bits / 110.0).clamp(0.05, 1.0) as f32;
    ui.horizontal(|ui| {
        ui.add(egui::ProgressBar::new(f).desired_width(140.0).desired_height(8.0).fill(c));
        ui.label(RichText::new(tf("ui.strength", &[&a.label, &crate::password::length(b.as_str())])).color(c).small());
    });
}

pub fn match_label(ui: &mut egui::Ui, a: &SecretBuf, b: &SecretBuf) {
    if b.is_empty() {
        return;
    }
    if a.ct_eq(b) {
        ui.label(RichText::new(t("ui.match")).color(pal().ok));
    } else {
        ui.label(RichText::new(t("ui.no_match")).color(pal().err));
    }
}

pub fn pim_picker(ui: &mut egui::Ui, custom: &mut bool, pim: &mut u32, decrypting: bool, default_pim: u32) {
    use crate::format::{DEFAULT_PIM, MAX_PIM};
    ui.horizontal_wrapped(|ui| {
        ui.label("PIM");
        ui.radio_value(custom, false, tf("ui.pim_default", &[&default_pim]));
        ui.radio_value(custom, true, t("ui.pim_custom"));
        if *custom {
            ui.add(egui::DragValue::new(pim).clamp_range(0..=MAX_PIM).speed(0.2));
        }
    });
    let eff = if *custom { *pim } else { default_pim };
    if decrypting {
        hint(ui, t("ui.pim_dec_hint"));
    } else if eff < DEFAULT_PIM {
        warn(ui, t("ui.pim_weak"));
    } else if *custom {
        hint(ui, t("ui.pim_hint"));
    }
}

/// Key file list with add/remove (+ generate with an adjustable size). Generation never waits for
/// mouse input (A-3). Returns a status message.
pub fn keyfile_list(ui: &mut egui::Ui, list: &mut Vec<PathBuf>, gen_kib: Option<&mut u32>) -> Option<(bool, String)> {
    let mut msg = None;
    let mut rm: Option<usize> = None;
    if list.is_empty() {
        hint(ui, t("ui.kf_none"));
    }
    for (i, p) in list.iter().enumerate() {
        ui.horizontal(|ui| {
            if ui.small_button("\u{00D7}").on_hover_text(t("ui.kf_remove")).clicked() {
                rm = Some(i);
            }
            let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            crate::ui_table::clipped_label(ui, &n, ui.available_width()).on_hover_text(p.display().to_string());
        });
    }
    if let Some(i) = rm {
        list.remove(i);
    }
    ui.horizontal_wrapped(|ui| {
        if ui.button(t("ui.kf_add")).clicked() {
            if let Some(v) = rfd::FileDialog::new().set_title(t("ui.kf_pick")).pick_files() {
                for p in v {
                    if !list.contains(&p) {
                        list.push(p);
                    }
                }
            }
        }
        if let Some(kib) = gen_kib {
            ui.label(t("ui.kf_size"));
            ui.add(egui::DragValue::new(kib).clamp_range(1..=crate::keyfile::KF_MAX_KIB).suffix(" KiB").speed(1.0));
            if ui.button(t("ui.kf_generate")).clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title(t("ui.kf_save")).set_file_name("my.key").save_file() {
                    msg = Some(match crate::keyfile::generate_keyfile(&p, *kib) {
                        Ok(()) => {
                            let m = tf("ui.kf_created", &[&kib, &p.display()]);
                            list.push(p);
                            (true, m)
                        }
                        Err(x) => (false, tf("ui.kf_failed", &[&x])),
                    });
                }
            }
        }
    });
    if !list.is_empty() {
        hint(ui, t("ui.kf_all_needed"));
    }
    msg
}

/// List of what is still missing, then the primary button. The button is never disabled (3.0.0
/// §1): a click while something is missing starts nothing and lists every reason (in the error
/// colour) instead of only the first three. Returns true only for a click with nothing missing.
pub fn action_button(ui: &mut egui::Ui, problems: &[String], label: &str) -> bool {
    let tried_id = egui::Id::new("action_button_tried").with(label);
    let tried = !problems.is_empty() && ui.data(|d| d.get_temp::<bool>(tried_id)).unwrap_or(false);
    let (n, c) = if tried { (problems.len(), pal().err) } else { (3, pal().warn) };
    for p in problems.iter().take(n) {
        ui.label(RichText::new(format!("\u{2022} {p}")).small().color(c));
    }
    let ok = problems.is_empty();
    let b = egui::Button::new(RichText::new(label).size(16.0).strong().color(pal().on_accent))
        .fill(if ok { pal().accent } else { pal().disabled })
        .min_size(vec2(220.0, 36.0))
        .rounding(6.0);
    let clicked = ui.add(b).clicked();
    ui.data_mut(|d| d.insert_temp(tried_id, if ok { false } else { tried || clicked }));
    clicked && ok
}

/// Live findings for a new password (3.0.0 §1): blocks in the error colour, then the reasons a
/// "use it anyway" confirmation will list. The same `password::check_new` result decides the
/// button, so what is shown and what happens never differ.
pub fn password_report(ui: &mut egui::Ui, c: &crate::password::Check) {
    for b in &c.blocks {
        ui.label(RichText::new(format!("\u{00D7} {b}")).small().color(pal().err));
    }
    for w in &c.warnings {
        warn(ui, w);
    }
}

/// How much mouse entropy has been collected (A-3). Informational only: nothing waits for it.
/// `compact` is the one-line form used on the Encrypt and Rekey screens.
pub fn mouse_meter(ui: &mut egui::Ui, compact: bool) {
    use crate::entropy::{credited_bits, mouse_enabled, DISPLAY_BITS, SAMPLES};
    if !mouse_enabled() {
        hint(ui, t("ui.mouse_off"));
        return;
    }
    let f = credited_bits().min(DISPLAY_BITS) as f32 / DISPLAY_BITS as f32;
    let done = credited_bits() >= DISPLAY_BITS; // 100%: the bar turns green
    let samples = SAMPLES.load(Ordering::Relaxed);
    ui.horizontal(|ui| {
        if compact {
            ui.label(t("ui.mouse"));
        }
        let fill = if done { pal().ok } else { pal().accent };
        let bar = egui::ProgressBar::new(f).desired_height(if compact { 14.0 } else { 8.0 }).fill(fill);
        let bar = if compact { bar.text(format!("{:.0}%", f * 100.0)) } else { bar.desired_width(260.0) };
        ui.add(bar).on_hover_text(tf("set.mouse_count", &[&samples]));
    });
    // Keep the sample count and a short movement instruction on separate lines.
    // The instruction remains visible even after the meter reaches 100%.
    let count = tf("set.mouse_count", &[&samples]);
    hint(ui, count);
    if compact {
        hint(ui, t("ui.mouse_hint"));
    }
}

/// Memory-protection warnings (shown when a lock failed).
pub fn memory_warnings(ui: &mut egui::Ui) {
    if crate::harden::LOCK_FAILED.load(Ordering::Relaxed) {
        warn(ui, t("ui.lock_failed"));
    }
    if crate::harden::KDF_LOCK_FAILED.load(Ordering::Relaxed) {
        warn(ui, t("ui.kdf_lock_failed"));
    }
}

pub fn progress_view<T>(ui: &mut egui::Ui, job: &mut Job<T>) {
    let st = STAGE.load(Ordering::Relaxed);
    if job.stage_t0.0 != st {
        job.stage_t0 = (st, Instant::now());
    }
    let cur = job.stages.iter().position(|&s| s == st);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(job.title).strong());
        for (i, &s) in job.stages.iter().enumerate() {
            let label = format!("{} {}", i + 1, stage_short(s));
            let r = match cur {
                Some(c) if i < c => RichText::new(format!("\u{25CF} {label}")).color(pal().ok),
                Some(c) if i == c => RichText::new(format!("\u{25B6} {label}")).color(pal().accent).strong(),
                _ => RichText::new(label).weak(),
            };
            ui.label(r);
            if i + 1 < job.stages.len() {
                ui.label(RichText::new("\u{203A}").weak());
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(tf("ui.elapsed", &[&clock(job.started.elapsed())]));
        });
    });
    let (done, tot) = (PROG_DONE.load(Ordering::Relaxed), PROG_TOTAL.load(Ordering::Relaxed));
    let bar = if KDF_BUSY.load(Ordering::Relaxed) {
        egui::ProgressBar::new(0.0).animate(true).text(t("ui.kdf_busy"))
    } else if tot > 0 {
        let f = (done as f64 / tot as f64).min(1.0);
        let el = job.stage_t0.1.elapsed().as_secs_f64();
        let speed = if el > 0.5 { done as f64 / el } else { 0.0 };
        let mut s = format!("{:.0}% \u{00B7} {} / {}", f * 100.0, human(done.min(tot)), human(tot));
        if speed > 0.0 {
            s += &format!(" \u{00B7} {}/s", human(speed as u64));
            if f > 0.02 && f < 1.0 {
                s += &tf("ui.eta", &[&clock(Duration::from_secs_f64((tot - done.min(tot)) as f64 / speed))]);
            }
        }
        egui::ProgressBar::new(f as f32).text(s)
    } else {
        egui::ProgressBar::new(0.0).animate(true).text(format!("{} \u{2026}", stage_label(st)))
    };
    ui.horizontal(|ui| {
        ui.add(bar.desired_width((ui.available_width() - 110.0).max(100.0)).fill(pal().bar));
        let can = stage_cancellable(st) && !cancelled();
        let label = if cancelled() { t("ui.cancelling") } else { t("ui.cancel") };
        let b = ui.add_enabled(can, egui::Button::new(label).min_size(vec2(96.0, 24.0)));
        if b.on_disabled_hover_text(t("ui.not_cancellable")).clicked() {
            CANCEL.store(true, Ordering::Relaxed);
        }
    });
    ui.label(RichText::new(stage_label(st)).small());
}

/// Bottom status line (last result or a hint). Long results are cut to one line; the full text is
/// in the tooltip. Returns true when the user pressed "Retry" on a busy-container error.
pub fn status_line(ui: &mut egui::Ui, ok: bool, status: &str, idle_hint: &str) -> bool {
    if status.is_empty() {
        hint(ui, idle_hint);
        return false;
    }
    let (icon, c) = if ok { ("\u{25CF}", pal().ok) } else { ("\u{00D7}", pal().err) };
    let mut retry = false;
    ui.horizontal(|ui| {
        if !ok && crate::lock::is_busy(status) && ui.button(t("ui.retry")).clicked() {
            retry = true;
        }
        let w = ui.available_width();
        crate::ui_table::clipped_rich(ui, &format!("{icon} {status}"), w, c).on_hover_text(status);
    });
    retry
}

/// Renders a usage text (help tab).
pub fn usage_view(ui: &mut egui::Ui, title: &str, sections: crate::help::Sections) {
    ui.heading(title);
    ui.add_space(4.0);
    for (h, lines) in sections {
        section(ui, h, |ui| {
            for l in *lines {
                ui.label(*l);
            }
        });
    }
}

/// Plaintext staging folders left by a killed run, or a damaged journal (B-3). Returns a status.
pub struct Leftovers {
    pub found: Vec<crate::staging::Entry>,
    pub journal_error: Option<String>,
    pub dismissed: bool,
}

impl Leftovers {
    pub fn check() -> Self {
        match crate::staging::leftovers() {
            Ok(found) => Leftovers { found, journal_error: None, dismissed: false },
            Err(x) => Leftovers { found: Vec::new(), journal_error: Some(x), dismissed: false },
        }
    }
}

pub fn leftover_banner(ui: &mut egui::Ui, l: &mut Leftovers) -> Option<(bool, String)> {
    if l.dismissed || (l.found.is_empty() && l.journal_error.is_none()) {
        return None;
    }
    let mut out = None;
    egui::Frame::none().fill(pal().warn_bg).inner_margin(8.0).rounding(4.0).show(ui, |ui| {
        if let Some(x) = &l.journal_error {
            ui.label(RichText::new(tf("ui.journal_bad", &[x])).color(pal().warn).strong());
            ui.horizontal(|ui| {
                if ui.button(t("ui.journal_scan")).on_hover_text(t("ui.journal_scan_hover")).clicked() {
                    let dir = rfd::FileDialog::new().set_title(t("ui.journal_scan_pick")).pick_folder();
                    match crate::staging::reset_journal(dir.as_deref()) {
                        Ok(found) => {
                            out = Some((true, tf("ui.journal_reset", &[&found.len()])));
                            *l = Leftovers { found, journal_error: None, dismissed: false };
                        }
                        Err(x) => out = Some((false, x)),
                    }
                }
                if ui.button(t("ui.later")).clicked() {
                    l.dismissed = true;
                }
            });
            return;
        }
        ui.label(RichText::new(tf("ui.leftovers", &[&l.found.len()])).color(pal().warn).strong());
        for en in l.found.iter().take(4) {
            ui.label(RichText::new(en.path().display().to_string()).small());
        }
        ui.horizontal(|ui| {
            if ui.button(t("ui.leftovers_remove")).clicked() {
                let (n, bad) = crate::staging::remove_leftovers(&l.found);
                out = Some(if bad.is_empty() { (true, tf("ui.leftovers_done", &[&n])) } else { (false, tf("ui.leftovers_partial", &[&n, &bad.join(" / ")])) });
                *l = Leftovers::check();
            }
            if ui.button(t("ui.later")).clicked() {
                l.dismissed = true;
            }
        });
    });
    out
}
