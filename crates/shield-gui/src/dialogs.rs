//! Modal dialogs: confirmation (Cancel is the default), two-way choice, the shredding
//! confirmation with the pass count (3.0 §2).

use crate::i18n::t;
use crate::theme::pal;
use crate::ui::hint;
use eframe::egui::{self, vec2, RichText};

/// Modal confirmation with Cancel as the default (focused, Enter/Esc) button. Returns Some(true)
/// on confirm, Some(false) on cancel, None while open.
pub fn confirm_modal(ctx: &egui::Context, id: &str, title: &str, lines: &[String], confirm: &str) -> Option<bool> {
    let mut out = None;
    egui::Window::new(title).id(egui::Id::new(id)).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0)).show(ctx, |ui| {
        ui.set_max_width(460.0);
        for l in lines {
            ui.label(format!("\u{2022} {l}"));
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let cancel = ui.add(egui::Button::new(RichText::new(t("ui.cancel")).strong()).min_size(vec2(110.0, 28.0)));
            if !ui.memory(|m| m.focused().is_some()) {
                cancel.request_focus();
            }
            if cancel.clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                out = Some(false);
            }
            if ui.add(egui::Button::new(RichText::new(confirm).color(pal().err))).clicked() {
                out = Some(true);
            }
        });
    });
    out
}

/// Two-way choice without a cancel (e.g. "bundled" / "separately"). Some(true) = first button.
pub fn choice_modal(ctx: &egui::Context, id: &str, title: &str, lines: &[String], first: &str, second: &str) -> Option<bool> {
    let mut out = None;
    egui::Window::new(title).id(egui::Id::new(id)).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0)).show(ctx, |ui| {
        ui.set_max_width(460.0);
        for l in lines {
            ui.label(l);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new(first).strong()).min_size(vec2(150.0, 28.0))).clicked() {
                out = Some(true);
            }
            if ui.add(egui::Button::new(second).min_size(vec2(150.0, 28.0))).clicked() {
                out = Some(false);
            }
        });
    });
    out
}

/// 3 or 7 overwrite passes (3.0 §2). Key material is always overwritten 7 times regardless.
pub fn passes_picker(ui: &mut egui::Ui, p: &mut crate::wipe::Passes) {
    use crate::wipe::Passes;
    ui.horizontal_wrapped(|ui| {
        ui.label(t("v.passes"));
        ui.radio_value(p, Passes::Three, t("v.passes3"));
        ui.radio_value(p, Passes::Seven, t("v.passes7"));
    });
}

/// Confirmation before overwriting / deleting: what may survive, and (when `passes` is given)
/// the pass count for this job. Cancel is the default.
pub fn shred_modal(ctx: &egui::Context, title: &str, lines: &[String], passes: Option<&mut crate::wipe::Passes>, confirm: &str) -> Option<bool> {
    let mut out = None;
    egui::Window::new(title).id(egui::Id::new("shred")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0)).show(ctx, |ui| {
        ui.set_max_width(500.0);
        for l in lines {
            ui.label(format!("\u{2022} {l}"));
        }
        if let Some(p) = passes {
            ui.add_space(4.0);
            passes_picker(ui, p);
            hint(ui, t("v.passes_hint"));
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let cancel = ui.add(egui::Button::new(RichText::new(t("ui.cancel")).strong()).min_size(vec2(110.0, 28.0)));
            if !ui.memory(|m| m.focused().is_some()) {
                cancel.request_focus();
            }
            if cancel.clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                out = Some(false);
            }
            if ui.add(egui::Button::new(RichText::new(confirm).color(pal().err))).clicked() {
                out = Some(true);
            }
        });
    });
    out
}
