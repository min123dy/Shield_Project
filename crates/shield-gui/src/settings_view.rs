//! Settings tab (E-2): categories on the left, options on the right. Every change is applied at
//! once and saved atomically (shell.rs). Values that are part of the format are shown read-only.
//! Security-relevant values (3.0 §8) can only be changed after the settings password was entered;
//! their widgets are disabled until then.

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
            for (c, s) in [
                (Category::General, t("set.cat_general")),
                (Category::Security, t("set.cat_security")),
                (Category::Encryption, t("set.cat_encryption")),
                (Category::Explorer, t("set.cat_explorer")),
                (Category::Update, t("set.cat_update")),
            ] {
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
        let locked = sh.unlocked.is_none();
        ui.vertical(|ui| match sh.set_cat {
            Category::General => general(ui, &mut sh.set),
            Category::Security => security(ui, sh),
            Category::Encryption => encryption(ui, &mut sh.set, locked),
            Category::Explorer => explorer(ui, sh),
            Category::Update => {
                section(ui, t("set.cat_update"), |ui| sh.updater.settings(ui, locked, &mut sh.set.update));
                section(ui, t("upd.about"), |ui| crate::update_ui::about(ui, &mut sh.about_note));
            }
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
        ui.checkbox(&mut s.ui.remember_window_pos, t("set.remember_pos"));
        match s.off_reason(EnvKey::RememberWindowPos) {
            Some(why) => env_off_note(ui, t("set.remember_pos"), why),
            None => hint(ui, t("set.remember_pos_hint")),
        }
    });
}

/// "Not available here, switched off (reason: ...)" under a switched-off option (3.0.0 §4).
pub fn env_off_note(ui: &mut egui::Ui, what: &str, why: &str) {
    ui.label(RichText::new(tf("set.env_off", &[&what, &why])).small().color(crate::theme::pal().err));
}

fn security(ui: &mut egui::Ui, sh: &mut Shell) {
    let allow = sh.set.allow_reveal;
    section(ui, t("set.pw_title"), |ui| sh.auth.view(ui, &mut sh.set, &mut sh.unlocked, allow));
    let locked = sh.unlocked.is_none();
    let s = &mut sh.set;
    if locked {
        hint(ui, t("set.protected_hint"));
    }
    section(ui, t("set.capture"), |ui| {
        // 3.0.0 §4: one value. When it could not be applied it is off here and in use, with the
        // reason; switching it on tries again (the file keeps the user's choice meanwhile)
        ui.add_enabled_ui(!locked, |ui| ui.checkbox(&mut s.capture_protect, t("set.capture_on")));
        if let Some(why) = s.off_reason(EnvKey::CaptureProtect) {
            env_off_note(ui, t("set.capture"), why);
        } else {
            let state = match &sh.capture {
                Some(Ok(crate::capture::Applied::Excluded)) => t("set.capture_excluded").to_string(),
                Some(Ok(crate::capture::Applied::Monitor)) => t("set.capture_monitor").to_string(),
                Some(Ok(crate::capture::Applied::Off)) => t("set.capture_off").to_string(),
                Some(Err(x)) => tf("set.capture_error", &[x]),
                None => String::new(),
            };
            hint(ui, state);
        }
        warn(ui, t("set.capture_limits"));
    });
    section(ui, t("set.mouse"), |ui| {
        ui.add_enabled_ui(!locked, |ui| ui.checkbox(&mut s.mouse_entropy, t("set.mouse_on")));
        hint(ui, t("set.mouse_desc"));
        if s.mouse_entropy {
            mouse_meter(ui, false);
        }
    });
    section(ui, t("ent.title"), |ui| entropy_sources(ui, s, locked));
    section(ui, t("set.cli"), |ui| {
        ui.add_enabled_ui(!locked, |ui| ui.checkbox(&mut s.allow_arg_secrets, t("set.arg_secrets")));
        warn(ui, t("set.arg_secrets_warn"));
    });
    ui.add_enabled_ui(!locked, |ui| security_protected(ui, s));
}

/// Entropy sources (3.0 §1): switches and Normal / Weak status only, never values.
fn entropy_sources(ui: &mut egui::Ui, s: &mut Settings, locked: bool) {
    use crate::entropy::SourceStatus as St;
    use shield_platform::Source;
    hint(ui, t("ent.hint"));
    egui::Grid::new("entropy").num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
        for (src, st) in crate::entropy::status() {
            if src == Source::Mouse || st == St::Unavailable {
                continue;
            }
            let mut on = src == Source::OsCsprng || !s.entropy_disabled.iter().any(|c| c == src.code());
            let fixed = src == Source::OsCsprng;
            let r = ui.add_enabled(!locked && !fixed, egui::Checkbox::new(&mut on, crate::i18n::t(source_key(src))));
            if r.changed() && !fixed {
                s.entropy_disabled.retain(|c| c != src.code());
                if !on {
                    s.entropy_disabled.push(src.code().to_string());
                }
            }
            let (label, c) = match st {
                St::Normal => (t("ent.normal"), crate::theme::pal().ok),
                St::Weak => (t("ent.weak"), crate::theme::pal().warn),
                St::Waiting => (t("ent.waiting"), crate::theme::pal().disabled),
                _ => (t("ent.off"), crate::theme::pal().disabled),
            };
            ui.label(RichText::new(label).color(c));
            ui.end_row();
        }
    });
}

pub fn source_key(s: shield_platform::Source) -> &'static str {
    use shield_platform::Source::*;
    match s {
        OsCsprng => "ent.os",
        OsAux => "ent.os_aux",
        HwRng => "ent.hwrng",
        Timers => "ent.timers",
        CpuJitter => "ent.cpu_jitter",
        Memory => "ent.memory",
        Process => "ent.process",
        Ids => "ent.ids",
        SystemTimes => "ent.system_times",
        Disk => "ent.disk",
        Network => "ent.network",
        Processes => "ent.processes",
        PerfData => "ent.perfdata",
        ProcFs => "ent.procfs",
        Sensors => "ent.sensors",
        WindowState => "ent.window_state",
        InputTiming => "ent.input_timing",
        Mouse => "ent.mouse",
    }
}

fn security_protected(ui: &mut egui::Ui, s: &mut Settings) {
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

fn encryption(ui: &mut egui::Ui, s: &mut Settings, locked: bool) {
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
        ui.add_enabled_ui(!locked, |ui| crate::ui::passes_picker(ui, &mut s.shred_passes));
        hint(ui, t("v.passes_hint"));
        combo(ui, "naming", t("set.naming"), &mut s.naming, &[(Naming::Append, "report.pdf.shd"), (Naming::Replace, "report.shd")]);
    });
    section(ui, t("set.fixed"), |ui| {
        egui::Grid::new("fixed").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            for (k, v) in [
                (t("set.fixed_aead"), "XChaCha20-Poly1305"),
                (t("set.fixed_kdf"), "Argon2id 256 MiB, 4 lanes, t = 3 + PIM"),
                (t("set.fixed_hash"), "SHA3-512 / SHAKE256"),
                (t("set.fixed_comp"), "7z (LZMA2 / Zstandard)"),
                (t("set.fixed_shred"), t("set.fixed_shred_v")),
            ] {
                ui.label(RichText::new(k).weak());
                ui.label(v);
                ui.end_row();
            }
        });
        hint(ui, t("set.fixed_hint"));
    });
}

fn explorer(ui: &mut egui::Ui, sh: &mut Shell) {
    let s = &mut sh.set;
    section(ui, t("set.cat_explorer"), |ui| {
        ui.checkbox(&mut s.show_hidden, t("set.hidden"));
        combo(ui, "startdir", t("set.start_folder"), &mut s.start_folder, &[(StartFolder::Drives, t("set.sf_drives")), (StartFolder::Home, t("set.sf_home")), (StartFolder::Documents, t("set.sf_docs"))]);
        combo(ui, "sort", t("set.sort"), &mut s.sort, &[(SortBy::Name, t("col.name")), (SortBy::Size, t("col.size")), (SortBy::Date, t("col.date")), (SortBy::Kind, t("col.kind"))]);
        ui.checkbox(&mut s.confirm_delete, t("set.confirm_delete"));
    });
    // portable / AppImage copies have no installer: menus for the current user only
    section(ui, t("set.integration"), |ui| {
        hint(ui, t("set.integration_hint"));
        ui.horizontal(|ui| {
            let p = shield_platform::platform();
            if ui.button(t("set.integration_add")).clicked() {
                let r = std::env::current_exe().map_err(|e| e.to_string()).and_then(|e| p.integration_register(&e).map_err(|e| e.to_string()));
                match r {
                    Ok(v) => sh.msg(true, crate::i18n::tf("set.integration_done", &[&v.len()])),
                    Err(e) => sh.msg(false, e),
                }
            }
            if ui.button(t("set.integration_remove")).clicked() {
                let r = p.integration_unregister().map_err(|e| e.to_string());
                match r {
                    Ok(v) => sh.msg(true, crate::i18n::tf("set.integration_removed", &[&v.len()])),
                    Err(e) => sh.msg(false, e),
                }
            }
        });
    });
}
