//! Screens of the encryption window (A-5): top tabs, a bottom bar with the main button and the
//! status line (always visible), and the form in two columns when the window is wide enough.
//! Advanced options are collapsed. Only the form area scrolls, and only when it must (small
//! window or a large UI scale).

use crate::compress::Strength;
use crate::enc_app::{EncApp, Tab};
use crate::i18n::{t, tf};
use crate::sysinfo::{self, is_shd, roots};
use crate::theme::pal;
use crate::ui::*;
use crate::{help, wipe};
use eframe::egui::{self, RichText};
use std::path::PathBuf;

#[derive(PartialEq)]
enum Pick {
    Any,
    Shd,
}

/// Two columns from 760 logical px on, one column below.
fn columns(ui: &mut egui::Ui, left: impl FnOnce(&mut egui::Ui), right: impl FnOnce(&mut egui::Ui)) {
    if ui.available_width() >= 760.0 {
        ui.columns(2, |c| {
            left(&mut c[0]);
            right(&mut c[1]);
        });
    } else {
        left(ui);
        right(ui);
    }
}

/// Selected target with its size and pick buttons. Returns a newly picked path.
fn target_card(ui: &mut egui::Ui, sel: &Option<PathBuf>, recent: &[PathBuf], pick: Pick) -> Option<PathBuf> {
    match sel {
        Some(p) => {
            let md = std::fs::metadata(p).ok();
            let kind = match &md {
                Some(m) if m.is_dir() => t("v.folder").to_string(),
                Some(m) => tf("v.file_size", &[&human(m.len())]),
                None => t("v.not_found").to_string(),
            };
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string());
            let w = ui.available_width();
            crate::ui_table::clipped_label(ui, &name, w).on_hover_text(p.display().to_string());
            hint(ui, kind);
        }
        None => hint(ui, t("v.nothing_selected")),
    }
    let mut out = None;
    ui.horizontal_wrapped(|ui| {
        if pick == Pick::Any {
            if ui.button(t("v.pick_file")).clicked() {
                out = rfd::FileDialog::new().set_title(t("v.pick_file")).pick_file();
            }
            if ui.button(t("v.pick_folder")).clicked() {
                out = rfd::FileDialog::new().set_title(t("v.pick_folder")).pick_folder();
            }
        } else if ui.button(t("v.pick_shd")).clicked() {
            out = rfd::FileDialog::new().set_title(t("v.pick_shd")).add_filter("Shield", &["shd"]).pick_file();
        }
        if !recent.is_empty() {
            egui::ComboBox::from_id_source("recent").selected_text(t("v.recent")).show_ui(ui, |ui| {
                for r in recent {
                    let n = r.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    if ui.selectable_label(false, n).on_hover_text(r.display().to_string()).clicked() {
                        out = Some(r.clone());
                    }
                }
            });
        }
    });
    out
}

fn kf_only_check(ui: &mut egui::Ui, ack: &mut bool) {
    ui.checkbox(ack, RichText::new(t("v.kf_only")).color(pal().warn));
}

pub fn frame(a: &mut EncApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
        ui.add_space(3.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Shield").strong().size(17.0));
            ui.separator();
            ui.add_enabled_ui(!a.busy(), |ui| {
                tabs(
                    ui,
                    &mut a.tab,
                    &[
                        (Tab::Encrypt, t("tab.encrypt")),
                        (Tab::Decrypt, t("tab.decrypt")),
                        (Tab::Rekey, t("tab.rekey")),
                        (Tab::Disk, t("tab.disk")),
                        (Tab::Settings, t("tab.settings")),
                        (Tab::Algo, t("tab.algo")),
                        (Tab::Help, t("tab.help")),
                    ],
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(t("tab.manager")).on_hover_text(t("v.manager_hover")).clicked() {
                    a.open_manager(None);
                }
            });
        });
        ui.add_space(2.0);
    });
    egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
        ui.add_space(3.0);
        if let Some(job) = &mut a.job {
            progress_view(ui, job);
        } else {
            action_bar(a, ui);
            if status_line(ui, a.sh.ok, &a.sh.status, t("v.drop_hint")) {
                a.sh.msg(true, t("v.retry_hint"));
            }
        }
        ui.add_space(2.0);
    });
    egui::CentralPanel::default().show(ctx, |ui| {
        let m = leftover_banner(ui, &mut a.sh.leftovers);
        a.sh.apply_msg(m);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_enabled_ui(!a.busy(), |ui| match a.tab {
                Tab::Encrypt => view_encrypt(a, ui),
                Tab::Decrypt => view_decrypt(a, ui),
                Tab::Rekey => view_rekey(a, ui),
                Tab::Disk => view_disk(a, ui),
                Tab::Settings => crate::settings_view::view(ui, &mut a.sh),
                Tab::Algo => view_algo(ui),
                Tab::Help => usage_view(ui, t("help.enc_title"), help::enc_usage()),
            });
        });
    });
}

/// The main button of the current tab, always visible at the bottom.
fn action_bar(a: &mut EncApp, ui: &mut egui::Ui) {
    let (problems, label) = match a.tab {
        Tab::Encrypt => (a.encrypt_problems(), t("v.start_encrypt")),
        Tab::Decrypt => (a.decrypt_problems(), t("v.start_decrypt")),
        Tab::Rekey => (a.rekey_problems(), if a.full_rekey { t("v.start_full_rekey") } else { t("v.start_change_pw") }),
        _ => return,
    };
    if action_button(ui, &problems, label) {
        match a.tab {
            Tab::Encrypt => a.request_encrypt(),
            Tab::Decrypt => a.start_decrypt(),
            _ => a.request_rekey(),
        }
    }
}

fn pick(a: &mut EncApp, p: Option<PathBuf>) {
    if let Some(p) = p {
        a.select(p);
    }
}

fn view_encrypt(a: &mut EncApp, ui: &mut egui::Ui) {
    ui.heading(t("v.enc_title"));
    hint(ui, t("v.enc_desc"));
    let (mut picked, mut msg) = (None, None);
    let allow = a.sh.set.allow_reveal;
    let dpim = a.sh.set.default_pim;
    columns(
        ui,
        |ui| {
            section(ui, t("v.s_target"), |ui| picked = target_card(ui, &a.selected, &a.recent, Pick::Any));
            section(ui, t("v.s_options"), |ui| {
                ui.checkbox(&mut a.choose_dest, t("v.choose_dest"));
                ui.checkbox(&mut a.shred_src, t("v.shred"));
                if a.shred_src {
                    ui.checkbox(&mut a.shred_ack, RichText::new(t("v.shred_ack")).color(pal().err));
                    warn(ui, t("v.shred_limits"));
                }
                advanced(ui, "enc_adv", |ui| {
                    ui.horizontal(|ui| {
                        ui.label(t("v.compression"));
                        egui::ComboBox::from_id_source("strength").selected_text(a.strength.label()).show_ui(ui, |ui| {
                            for s in Strength::ALL {
                                ui.selectable_value(&mut a.strength, s, s.label());
                            }
                        });
                    });
                    hint(ui, t("v.compression_hint"));
                    if a.shred_src {
                        ui.checkbox(&mut a.force7, t("v.force7"));
                        ui.checkbox(&mut a.trim_after, t("v.trim_after"));
                        ui.checkbox(&mut a.wipe_free_after, t("v.wipe_after"));
                        ui.checkbox(&mut a.include_streams, t("v.include_streams"));
                        hint(ui, t("v.shred_hint"));
                    }
                });
            });
        },
        |ui| {
            section(ui, t("v.s_password"), |ui| {
                secret_field(ui, "pw", &mut a.pw, t("v.pw_ph"), allow);
                strength_bar(ui, &a.pw);
                secret_field(ui, "pw2", &mut a.pw2, t("v.pw2_ph"), allow);
                match_label(ui, &a.pw, &a.pw2);
                pim_picker(ui, &mut a.custom_pim, &mut a.pim, false, dpim);
            });
            section(ui, t("v.s_keyfiles"), |ui| {
                msg = keyfile_list(ui, &mut a.keyfiles, Some(&mut a.gen_kib));
                if a.pw.is_empty() && !a.keyfiles.is_empty() {
                    kf_only_check(ui, &mut a.kf_only_ack);
                }
            });
            mouse_meter(ui, true);
            memory_warnings(ui);
        },
    );
    pick(a, picked);
    a.sh.apply_msg(msg);
}

fn view_decrypt(a: &mut EncApp, ui: &mut egui::Ui) {
    ui.heading(t("v.dec_title"));
    hint(ui, t("v.dec_desc"));
    let (mut picked, mut msg, mut mgr) = (None, None, None);
    let allow = a.sh.set.allow_reveal;
    let dpim = a.sh.set.default_pim;
    columns(
        ui,
        |ui| {
            section(ui, t("v.s_shd"), |ui| {
                picked = target_card(ui, &a.selected, &a.recent, Pick::Shd);
                if let Some(p) = a.selected.clone().filter(|p| is_shd(p)) {
                    if ui.button(t("v.view_in_manager")).clicked() {
                        mgr = Some(p);
                    }
                }
            });
            section(ui, t("v.s_dest"), |ui| {
                ui.checkbox(&mut a.choose_dest, t("v.choose_folder"));
                hint(ui, t("v.dest_hint"));
            });
        },
        |ui| {
            section(ui, t("v.s_password_used"), |ui| {
                secret_field(ui, "pw", &mut a.pw, t("v.pw_plain"), allow);
                pim_picker(ui, &mut a.custom_pim, &mut a.pim, true, dpim);
            });
            section(ui, t("v.s_keyfiles_used"), |ui| msg = keyfile_list(ui, &mut a.keyfiles, None));
            memory_warnings(ui);
        },
    );
    pick(a, picked);
    a.sh.apply_msg(msg);
    if let Some(p) = mgr {
        a.open_manager(Some(&p));
    }
}

fn view_rekey(a: &mut EncApp, ui: &mut egui::Ui) {
    ui.heading(t("v.rekey_title"));
    hint(ui, t("v.rekey_desc"));
    let (mut picked, mut m1, mut m2) = (None, None, None);
    let allow = a.sh.set.allow_reveal;
    let dpim = a.sh.set.default_pim;
    // The method sits above the columns in a compact form so it is visible at the default
    // window size without scrolling; the other method's explanation is on hover.
    let method = section(ui, t("v.s_method"), |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.radio_value(&mut a.full_rekey, false, t("v.rewrap")).on_hover_text(t("v.rewrap_hint"));
            ui.radio_value(&mut a.full_rekey, true, t("v.full")).on_hover_text(t("v.full_hint"));
        });
        hint(ui, if a.full_rekey { t("v.full_hint") } else { t("v.rewrap_hint") });
        warn(ui, t("v.backups_warn"));
    });
    if cfg!(test) {
        let clip = ui.clip_rect();
        ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new("rekey_method"), (method, clip)));
    }
    columns(
        ui,
        |ui| {
            section(ui, t("v.s_target_shd"), |ui| picked = target_card(ui, &a.selected, &a.recent, Pick::Shd));
            section(ui, t("v.s_current"), |ui| {
                secret_field(ui, "pw", &mut a.pw, t("v.pw_current"), allow);
                pim_picker(ui, &mut a.custom_pim, &mut a.pim, true, dpim);
                m1 = keyfile_list(ui, &mut a.keyfiles, None);
            });
        },
        |ui| {
            section(ui, t("v.s_new"), |ui| {
                secret_field(ui, "npw", &mut a.new_pw, t("v.pw_new"), allow);
                strength_bar(ui, &a.new_pw);
                secret_field(ui, "npw2", &mut a.new_pw2, t("v.pw_new2"), allow);
                match_label(ui, &a.new_pw, &a.new_pw2);
                pim_picker(ui, &mut a.new_custom_pim, &mut a.new_pim, false, dpim);
                m2 = keyfile_list(ui, &mut a.new_keyfiles, Some(&mut a.gen_kib));
                if a.new_pw.is_empty() && !a.new_keyfiles.is_empty() {
                    kf_only_check(ui, &mut a.new_kf_only_ack);
                }
            });
            mouse_meter(ui, true);
            memory_warnings(ui);
        },
    );
    pick(a, picked);
    a.sh.apply_msg(m1);
    a.sh.apply_msg(m2);
}

fn view_disk(a: &mut EncApp, ui: &mut egui::Ui) {
    ui.heading(t("v.disk_title"));
    hint(ui, t("v.disk_desc"));
    if a.disk_drive.is_none() {
        a.disk_drive = a.selected.as_deref().and_then(wipe::drive_letter).map(|l| format!("{l}:\\").into());
    }
    let (mut trim, mut wipe_free) = (false, false);
    section(ui, t("v.s_drive"), |ui| {
        let cur = a.disk_drive.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| t("v.choose").into());
        egui::ComboBox::from_id_source("drive").selected_text(cur).show_ui(ui, |ui| {
            for r in roots() {
                let s = r.display().to_string();
                ui.selectable_value(&mut a.disk_drive, Some(r), s);
            }
        });
        if a.disk_drive.as_deref().is_some_and(|d| wipe::drive_letter(d).is_none()) {
            warn(ui, t("v.no_letter"));
        }
    });
    columns(
        ui,
        |ui| {
            section(ui, t("v.s_trim"), |ui| {
                hint(ui, t("v.trim_hint"));
                trim = ui.add_enabled(a.disk_drive.is_some(), egui::Button::new(t("v.run_trim"))).clicked();
            });
        },
        |ui| {
            section(ui, t("v.s_wipe"), |ui| {
                hint(ui, t("v.wipe_hint"));
                ui.checkbox(&mut a.disk_trim_after_wipe, t("v.trim_after_wipe"));
                wipe_free = ui.add_enabled(a.disk_drive.is_some(), egui::Button::new(t("v.run_wipe"))).clicked();
            });
        },
    );
    if trim {
        a.start_trim();
    }
    if wipe_free {
        a.start_wipe_free();
    }
}

fn yes_no(ui: &mut egui::Ui, ok: bool, what: &str) {
    let (icon, c) = if ok { ("\u{25CF}", pal().ok) } else { ("\u{25CB}", pal().warn) };
    ui.label(RichText::new(format!("{icon} {what}")).color(c));
}

/// Algorithms tab: what Shield uses, and what this process actually managed to apply.
pub fn view_algo(ui: &mut egui::Ui) {
    use std::sync::atomic::Ordering;
    ui.heading(t("algo.title"));
    hint(ui, format!("Shield {} \u{00B7} {} {}", env!("CARGO_PKG_VERSION"), t("algo.format"), crate::format::FORMAT_VERSION));
    columns(
        ui,
        |ui| {
            section(ui, t("algo.s_crypto"), |ui| {
                egui::Grid::new("algo").num_columns(2).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
                    for (k, v) in help::algo_rows() {
                        ui.label(RichText::new(*k).strong());
                        ui.add(egui::Label::new(*v).wrap(true));
                        ui.end_row();
                    }
                });
            });
        },
        |ui| {
            section(ui, t("algo.s_pim"), |ui| {
                let d = crate::format::DEFAULT_PIM;
                let m = crate::format::MAX_PIM;
                ui.label(tf("algo.pim_line", &[&d, &(3 + d), &m, &(3 + m)]));
                hint(ui, t("algo.pim_hint"));
            });
            section(ui, t("algo.s_applied"), |ui| {
                let rep = crate::harden::REPORT.lock().map(|r| r.clone()).unwrap_or_default().unwrap_or_default();
                yes_no(ui, rep.dacl, t("algo.dacl"));
                yes_no(ui, rep.dll_dirs, t("algo.dll"));
                yes_no(ui, rep.image_policy, t("algo.image"));
                yes_no(ui, rep.no_crash_dialogs, t("algo.crash"));
                yes_no(ui, !crate::harden::LOCK_FAILED.load(Ordering::Relaxed), t("algo.vlock"));
                yes_no(ui, !crate::harden::KDF_LOCK_FAILED.load(Ordering::Relaxed), t("algo.kdf_lock"));
                hint(ui, tf("algo.machine", &[&sysinfo::cores(), &human(sysinfo::avail_mem())]));
            });
        },
    );
    section(ui, t("algo.s_limits"), |ui| {
        for n in help::algo_notes() {
            ui.label(*n);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    /// Lays the Rekey tab out at `w`×`h` (window size, 100 % scale) and returns the method
    /// section's rectangle and the visible part of the scrolling form.
    fn rekey_layout(w: f32, h: f32) -> (egui::Rect, egui::Rect) {
        let ctx = egui::Context::default();
        crate::theme::load_fonts(&ctx);
        let set = Settings::default();
        crate::theme::apply(&ctx, &set);
        let mut a = EncApp::new(set, None);
        a.tab = Tab::Rekey;
        for _ in 0..3 {
            let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(w, h))), ..Default::default() };
            let _ = ctx.run(input, |ctx| frame(&mut a, ctx));
        }
        ctx.data(|d| d.get_temp(egui::Id::new("rekey_method"))).expect("rekey view was drawn")
    }

    #[test]
    fn rekey_method_is_visible_without_scrolling() {
        for (w, h) in [(960.0, 640.0), (800.0, 560.0)] {
            let (method, visible) = rekey_layout(w, h);
            assert!(method.bottom() <= visible.bottom(), "{w}x{h}: method ends at {} but the form shows up to {}", method.bottom(), visible.bottom());
            assert!(method.right() <= visible.right() + 0.5, "{w}x{h}: method is wider than the window");
        }
    }
}