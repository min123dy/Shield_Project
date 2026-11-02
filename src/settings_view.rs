//! Settings tab (E-2): categories on the left, options on the right. Every change is applied at
//! once and saved atomically (shell.rs). Values that are part of the format are shown read-only.

use crate::compress::Strength;
use crate::i18n::{t, tf};
use crate::settings::*;
use crate::shell::Shell;
use crate::ui::{hint, mouse_meter, section, warn};
use eframe::egui::{self, RichText};

fn combo<T: PartialEq + Copy>(ui: &mut egui::Ui, id: &str, label: &str, cur: &mut T, items: &[(T, &str)]) {
    ui.horizontal(|ui| {
        ui.label(label);
        let sel = items.iter().find(|(v, _)| v == cur).map(|(_, s)| *s).unwrap_or("");
        egui::ComboBox::from_id_source(id).selected_text(sel).show_ui(ui, |ui| {
            for (v, s) in items {
                ui.selectable_value(cur, *v, *s);
            }
        });
    });
}

pub fn view(ui: &mut egui::Ui, sh: &mut Shell) {
    ui.heading(t("set.title"));
    hint(ui, tf("set.where", &[&settings_path().display()]));
    ui.add_space(4.0);
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(150.0);
            for (c, s) in [(Category::General, t("set.cat_general")), (Category::Security, t("set.cat_security")), (Category::Encryption, t("set.cat_encryption")), (Category::Explorer, t("set.cat_explorer"))] {
                ui.selectable_value(&mut sh.set_cat, c, RichText::new(s).size(15.0));
            }
            ui.add_space(12.0);
            if ui.button(t("set.reset_cat")).clicked() {
                let c = sh.set_cat;
                sh.set.reset(c);
            }
            if ui.button(t("set.reset_all")).clicked() {
                sh.set = Settings::default();
            }
            if ui.button(t("set.delete_file")).on_hover_text(t("set.delete_file_hover")).clicked() {
                match delete_file() {
                    Ok(()) => sh.msg(true, t("set.deleted")),
                    Err(x) => sh.msg(false, x),
                }
            }
        });
        ui.separator();
        ui.vertical(|ui| match sh.set_cat {
            Category::General => general(ui, &mut sh.set),
            Category::Security => security(ui, sh),
            Category::Encryption => encryption(ui, &mut sh.set),
            Category::Explorer => explorer(ui, &mut sh.set),
        });
    });
}

fn general(ui: &mut egui::Ui, s: &mut Settings) {
    section(ui, t("set.cat_general"), |ui| {
        combo(ui, "lang", t("set.lang"), &mut s.lang, &[(LangPref::System, t("set.lang_system")), (LangPref::Ko, "\u{D55C}\u{AD6D}\u{C5B4}"), (LangPref::En, "English")]);
        combo(ui, "theme", t("set.theme"), &mut s.theme, &[(ThemePref::System, t("set.theme_system")), (ThemePref::Light, t("set.theme_light")), (ThemePref::Dark, t("set.theme_dark"))]);
        let scales: Vec<(u32, String)> = SCALES.iter().map(|v| (*v, format!("{v}%"))).collect();
        let items: Vec<(u32, &str)> = scales.iter().map(|(v, s)| (*v, s.as_str())).collect();
        combo(ui, "scale", t("set.scale"), &mut s.ui_scale, &items);
        combo(ui, "datefmt", t("set.date_format"), &mut s.date_fmt, &[(DateFmt::Iso, "YYYY-MM-DD"), (DateFmt::Dots, "YYYY.MM.DD"), (DateFmt::Us, "MM/DD/YYYY")]);
        ui.checkbox(&mut s.date_seconds, t("set.date_seconds"));
        combo(ui, "start", t("set.start_screen"), &mut s.start_screen, &[(StartScreen::Encrypt, t("tab.encrypt")), (StartScreen::Decrypt, t("tab.decrypt")), (StartScreen::Manager, t("tab.manager"))]);
        hint(ui, t("set.start_hint"));
    });
}

fn security(ui: &mut egui::Ui, sh: &mut Shell) {
    let s = &mut sh.set;
    section(ui, t("set.capture"), |ui| {
        ui.checkbox(&mut s.capture_protect, t("set.capture_on"));
        let state = match &sh.capture {
            Some(Ok(crate::capture::Applied::Excluded)) => t("set.capture_excluded").to_string(),
            Some(Ok(crate::capture::Applied::Monitor)) => t("set.capture_monitor").to_string(),
            Some(Ok(crate::capture::Applied::Off)) => t("set.capture_off").to_string(),
            Some(Err(x)) => tf("set.capture_error", &[x]),
            None => String::new(),
        };
        hint(ui, state);
        warn(ui, t("set.capture_limits"));
    });
    section(ui, t("set.mouse"), |ui| {
        ui.checkbox(&mut s.mouse_entropy, t("set.mouse_on"));
        hint(ui, t("set.mouse_desc"));
        if s.mouse_entropy {
            mouse_meter(ui, false);
        }
    });
    section(ui, t("set.lock"), |ui| {
        let mins: Vec<(u32, String)> = LOCK_MINUTES.iter().map(|m| (*m, tf("set.minutes", &[m]))).collect();
        let items: Vec<(u32, &str)> = mins.iter().map(|(v, s)| (*v, s.as_str())).collect();
        combo(ui, "autolock", t("set.auto_lock"), &mut s.auto_lock_min, &items);
        ui.checkbox(&mut s.lock_on_minimize, t("set.lock_min"));
        ui.checkbox(&mut s.lock_on_focus_loss, t("set.lock_focus"));
        hint(ui, t("set.lock_hint"));
    });
    section(ui, t("set.input"), |ui| {
        ui.checkbox(&mut s.allow_reveal, t("set.reveal"));
        ui.checkbox(&mut s.clipboard_clear, t("set.clipboard"));
        let mut always = true;
        ui.add_enabled(false, egui::Checkbox::new(&mut always, t("set.weak_confirm")));
        ui.checkbox(&mut s.recent_files, t("set.recent"));
        hint(ui, t("set.recent_hint"));
        ui.checkbox(&mut s.strict_motw, t("set.strict_motw"));
        hint(ui, t("set.motw_hint"));
    });
}

fn encryption(ui: &mut egui::Ui, s: &mut Settings) {
    section(ui, t("set.cat_encryption"), |ui| {
        let labels: Vec<(Strength, &str)> = Strength::ALL.iter().map(|x| (*x, x.label())).collect();
        combo(ui, "strength", t("set.strength"), &mut s.strength, &labels);
        ui.horizontal(|ui| {
            ui.label(t("set.default_pim"));
            ui.add(egui::DragValue::new(&mut s.default_pim).clamp_range(0..=crate::format::MAX_PIM));
        });
        if s.default_pim < crate::format::DEFAULT_PIM {
            warn(ui, t("ui.pim_weak"));
        }
        ui.horizontal(|ui| {
            ui.label(t("set.kf_size"));
            ui.add(egui::DragValue::new(&mut s.keyfile_kib).clamp_range(1..=crate::keyfile::KF_MAX_KIB).suffix(" KiB"));
        });
        ui.checkbox(&mut s.shred_default, t("set.shred_default"));
        hint(ui, t("set.shred_default_hint"));
        combo(ui, "naming", t("set.naming"), &mut s.naming, &[(Naming::Append, "report.pdf.shd"), (Naming::Replace, "report.shd")]);
    });
    section(ui, t("set.fixed"), |ui| {
        egui::Grid::new("fixed").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            for (k, v) in [
                (t("set.fixed_aead"), "XChaCha20-Poly1305"),
                (t("set.fixed_kdf"), "Argon2id 256 MiB, 4 lanes, t = 3 + PIM"),
                (t("set.fixed_hash"), "SHA3-512 / SHAKE256"),
                (t("set.fixed_comp"), "7z (LZMA2 / Zstandard)"),
                (t("set.fixed_shred"), "7 passes (HDD), 1 (SSD)"),
            ] {
                ui.label(RichText::new(k).weak());
                ui.label(v);
                ui.end_row();
            }
        });
        hint(ui, t("set.fixed_hint"));
    });
}

fn explorer(ui: &mut egui::Ui, s: &mut Settings) {
    section(ui, t("set.cat_explorer"), |ui| {
        ui.checkbox(&mut s.show_hidden, t("set.hidden"));
        combo(ui, "startdir", t("set.start_folder"), &mut s.start_folder, &[(StartFolder::Drives, t("set.sf_drives")), (StartFolder::Home, t("set.sf_home")), (StartFolder::Documents, t("set.sf_docs"))]);
        combo(ui, "sort", t("set.sort"), &mut s.sort, &[(SortBy::Name, t("col.name")), (SortBy::Size, t("col.size")), (SortBy::Date, t("col.date")), (SortBy::Kind, t("col.kind"))]);
        ui.checkbox(&mut s.confirm_delete, t("set.confirm_delete"));
    });
}
