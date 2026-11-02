//! Screens of the file manager window: browse table, unlock panel, container table, info tab,
//! the credential dialog for every container operation (A-4) and the confirmation dialogs.

use crate::compress::Strength;
use crate::container::BodyCheck;
use crate::format::{self, comp_name};
use crate::i18n::{t, tf};
use crate::mgr_app::{Confirm, MTab, MgrApp, Op};
use crate::sysinfo::is_shd;
use crate::theme::pal;
use crate::ui::*;
use crate::ui_table::{date_min_width, Align, Col, Table};
use eframe::egui::{self, RichText};
use std::path::PathBuf;

enum Act {
    Select(usize, bool),
    Activate(usize),
}

fn cols(ui: &egui::Ui, kind: bool) -> Vec<Col> {
    let dmin = date_min_width(ui, crate::ui_fmt::seconds_on());
    let mut v = vec![
        Col { title: t("col.name"), width: 0.0, min: 90.0, align: Align::Left },
        Col { title: t("col.size"), width: 100.0, min: 70.0, align: Align::Right },
        Col { title: t("col.date"), width: dmin + 10.0, min: dmin, align: Align::Left },
    ];
    if kind {
        v.push(Col { title: t("col.kind"), width: 90.0, min: 60.0, align: Align::Left });
    }
    v
}

impl MgrApp {
    pub fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(t("m.title")).strong().size(17.0));
            ui.separator();
            let items: &[(MTab, &str)] = if self.open.is_some() {
                &[(MTab::Files, t("m.tab_files")), (MTab::Info, t("m.tab_info")), (MTab::Settings, t("tab.settings")), (MTab::Help, t("tab.help"))]
            } else {
                &[(MTab::Files, t("m.tab_browse")), (MTab::Settings, t("tab.settings")), (MTab::Help, t("tab.help"))]
            };
            tabs(ui, &mut self.tab, items);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(t("m.enc_window")).on_hover_text(t("m.enc_window_hover")).clicked() {
                    self.launch_enc_window();
                }
            });
        });
        if self.tab != MTab::Files {
            return;
        }
        ui.horizontal(|ui| {
            if let Some(o) = &self.open {
                let name = o.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if ui.button(t("m.close")).on_hover_text(t("m.close_hover")).clicked() {
                    self.close_container();
                    return;
                }
                if ui.add_enabled(!self.inner.is_empty(), egui::Button::new(t("m.up"))).clicked() {
                    self.inner_up();
                }
                let loc = if self.inner.is_empty() { name } else { format!("{name} \u{203A} {}", self.inner.replace('/', " \u{203A} ")) };
                let w = ui.available_width();
                crate::ui_table::clipped_label(ui, &loc, w).on_hover_text(&loc);
                return;
            }
            if ui.add_enabled(self.cwd.is_some(), egui::Button::new(t("m.up"))).clicked() {
                self.up();
            }
            if ui.button(t("m.drives")).clicked() {
                self.go(None);
            }
            if ui.button(t("m.refresh")).clicked() {
                self.refresh();
            }
            let w = (ui.available_width() - 180.0).max(120.0);
            let r = ui.add(egui::TextEdit::singleline(&mut self.addr).desired_width(w).hint_text(t("m.addr_hint")));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let p = PathBuf::from(self.addr.trim());
                if p.is_dir() {
                    self.go(Some(p));
                } else if is_shd(&p) {
                    self.go(p.parent().map(|x| x.to_path_buf()));
                    self.pending = Some(p);
                } else {
                    self.sh.msg(false, t("m.bad_path"));
                }
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(160.0).hint_text(t("m.filter")));
        });
    }

    pub fn view_browse(&mut self, ui: &mut egui::Ui) {
        let one = (self.sel.len() == 1).then(|| self.sel.iter().next().cloned()).flatten();
        let shd = one.clone().filter(|p| is_shd(p));
        ui.horizontal_wrapped(|ui| {
            if ui.button(t("m.encrypt")).on_hover_text(t("m.encrypt_hover")).clicked() {
                match &one {
                    Some(p) => self.launch_enc("--encrypt", &p.clone()),
                    None if self.sel.is_empty() => self.sh.msg(false, t("m.pick_one")),
                    None => self.sh.msg(false, t("m.one_at_a_time")),
                }
            }
            if ui.add_enabled(shd.is_some(), egui::Button::new(t("m.open"))).clicked() {
                self.pending = shd.clone();
            }
            if ui.add_enabled(shd.is_some(), egui::Button::new(t("m.decrypt"))).on_hover_text(t("m.decrypt_hover")).clicked() {
                if let Some(p) = &shd {
                    self.launch_enc("--decrypt", &p.clone());
                }
            }
            let n = self.sel.len();
            if n > 0 {
                let size: u64 = self.entries.iter().filter(|e| self.sel.contains(&e.path) && !e.is_dir).map(|e| e.size).sum();
                hint(ui, tf("m.selected", &[&n, &human(size)]));
            }
        });
        let mut table = Table::new(ui, "browse", cols(ui, true));
        table.header(ui);
        let f = self.filter.to_lowercase();
        let rows: Vec<usize> = (0..self.entries.len()).filter(|&i| f.is_empty() || self.entries[i].name.to_lowercase().contains(&f)).collect();
        let mut act = None;
        let ctrl = ui.input(|i| i.modifiers.command);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, crate::ui_table::ROW_H, rows.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for &i in &rows[range] {
                let e = &self.entries[i];
                let kind = if self.cwd.is_none() {
                    t("m.k_drive")
                } else if e.is_dir {
                    t("m.k_folder")
                } else if is_shd(&e.path) {
                    "Shield"
                } else {
                    t("m.k_file")
                };
                let size = if e.is_dir { String::new() } else { human(e.size) };
                let name = if e.is_dir && self.cwd.is_some() { format!("{}\\", e.name) } else { e.name.clone() };
                let dt = date(e.mtime);
                let r = table.row(ui, self.sel.contains(&e.path), &[&name, &size, &dt, kind]);
                if r.double_clicked() {
                    act = Some(Act::Activate(i));
                } else if r.clicked() {
                    act = Some(Act::Select(i, ctrl));
                }
            }
        });
        match act {
            Some(Act::Activate(i)) => {
                let (p, d) = (self.entries[i].path.clone(), self.entries[i].is_dir);
                self.activate(p, d);
            }
            Some(Act::Select(i, add)) => {
                let p = self.entries[i].path.clone();
                if !add {
                    self.sel.clear();
                    self.sel.insert(p);
                } else if !self.sel.remove(&p) {
                    self.sel.insert(p);
                }
            }
            None => {}
        }
    }

    /// Password / PIM / key files. Used to open, and again for every operation (A-4).
    fn cred_fields(&mut self, ui: &mut egui::Ui, id: &str) {
        let allow = self.sh.set.allow_reveal;
        let dpim = self.sh.set.default_pim;
        secret_field(ui, id, &mut self.pw, t("v.pw_plain"), allow);
        pim_picker(ui, &mut self.custom_pim, &mut self.pim, true, dpim);
        let m = keyfile_list(ui, &mut self.keyfiles, None);
        self.sh.apply_msg(m);
    }

    pub fn view_unlock(&mut self, ui: &mut egui::Ui) {
        let Some(p) = self.pending.clone() else { return };
        ui.heading(t("m.unlock_title"));
        hint(ui, t("m.unlock_desc"));
        section(ui, t("m.s_container"), |ui| {
            let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let w = ui.available_width();
            crate::ui_table::clipped_label(ui, &n, w).on_hover_text(p.display().to_string());
            let size = std::fs::metadata(&p).map(|m| human(m.len())).unwrap_or_else(|_| t("v.not_found").into());
            hint(ui, size);
        });
        section(ui, t("m.s_cred"), |ui| self.cred_fields(ui, "mpw"));
        memory_warnings(ui);
        let mut problems = vec![];
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            problems.push(t("p.need_pw").to_string());
        }
        let enter = problems.is_empty() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            if action_button(ui, &problems, t("m.open")) || enter {
                self.start_open();
            }
            if ui.button(t("m.back")).clicked() {
                self.pending = None;
                self.clear_credentials();
            }
        });
        hint(ui, t("m.same_message"));
    }

    pub fn view_container(&mut self, ui: &mut egui::Ui) {
        let mut req: Option<Op> = None;
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(!self.csel.is_empty(), egui::Button::new(t("m.extract_sel"))).clicked() {
                if let Some(dir) = rfd::FileDialog::new().set_title(t("m.extract_to")).pick_folder() {
                    req = Some(Op::ExtractSelected { sel: self.csel.clone(), base: self.inner.clone(), dir });
                }
            }
            if ui.button(t("m.extract_all")).on_hover_text(t("m.extract_all_hover")).clicked() {
                if let Some(dir) = rfd::FileDialog::new().set_title(t("m.extract_to")).pick_folder() {
                    req = Some(Op::ExtractAll { dir });
                }
            }
            ui.separator();
            if ui.button(t("m.add_files")).clicked() {
                if let Some(v) = rfd::FileDialog::new().set_title(t("m.add_files")).pick_files() {
                    self.request_add(v);
                }
            }
            if ui.button(t("m.add_folder")).clicked() {
                if let Some(d) = rfd::FileDialog::new().set_title(t("m.add_folder")).pick_folder() {
                    self.request_add(vec![d]);
                }
            }
            if ui.add_enabled(!self.csel.is_empty(), egui::Button::new(t("m.remove"))).clicked() {
                self.request_remove();
            }
            ui.separator();
            if ui.button(t("m.check")).on_hover_text(t("m.check_hover")).clicked() {
                req = Some(Op::Check);
            }
        });
        if let Some(op) = req {
            self.request(op);
        }
        advanced(ui, "mgr_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label(t("m.add_compression"));
                egui::ComboBox::from_id_source("mstrength").selected_text(self.strength.label()).show_ui(ui, |ui| {
                    for s in Strength::ALL {
                        ui.selectable_value(&mut self.strength, s, s.label());
                    }
                });
                ui.checkbox(&mut self.shred_added, t("m.shred_added"));
            });
        });
        let n = self.csel.len();
        if n > 0 {
            let size: u64 = self.children.iter().filter(|c| self.csel.contains(c.full.as_str())).map(|c| c.size).sum();
            hint(ui, tf("m.selected", &[&n, &human(size)]));
        }
        let mut table = Table::new(ui, "inner", cols(ui, false));
        table.header(ui);
        let mut act = None;
        let ctrl = ui.input(|i| i.modifiers.command);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, crate::ui_table::ROW_H, self.children.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in range {
                let c = &self.children[i];
                let name = if c.is_dir { format!("{}/", c.name.as_str()) } else { c.name.to_string() };
                let size = human(c.size);
                let dt = date(c.mtime);
                let r = table.row(ui, self.csel.contains(c.full.as_str()), &[&name, &size, &dt]);
                if r.double_clicked() && c.is_dir {
                    act = Some(Act::Activate(i));
                } else if r.clicked() {
                    act = Some(Act::Select(i, ctrl));
                }
            }
        });
        if self.children.is_empty() {
            hint(ui, t("m.empty"));
        }
        match act {
            Some(Act::Activate(i)) => {
                let f = self.children[i].full.to_string();
                self.enter(&f);
            }
            Some(Act::Select(i, add)) => {
                let f = self.children[i].full.to_string();
                if !add {
                    self.csel.clear();
                    self.csel.insert(f);
                } else if !self.csel.remove(&f) {
                    self.csel.insert(f);
                }
            }
            None => {}
        }
    }

    pub fn view_info(&mut self, ui: &mut egui::Ui) {
        let Some(o) = &self.open else { return };
        let m = &o.meta;
        let comp = match m.comp_method {
            format::COMP_LZMA2 => tf("eng.lzma2_desc", &[&m.comp_level, &human(m.comp_dict as u64)]),
            format::COMP_ZSTD => tf("eng.zstd_desc", &[&m.comp_level]),
            x => comp_name(x).to_string(),
        };
        let stored = if m.flags & format::FLAG_SOME_STORED != 0 { t("eng.some_stored") } else { "" };
        let created = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(m.created));
        let rows: Vec<(&str, String)> = vec![
            (t("i.version"), format!("Shield v{}", m.version)),
            (t("i.name"), m.name.clone()),
            (t("i.created"), date(created)),
            (t("i.aead"), "XChaCha20-Poly1305".into()),
            (t("i.kdf"), tf("i.kdf_val", &[&human(m.kdf_mem_kib as u64 * 1024), &m.kdf_lanes])),
            (t("i.hash"), "SHA3-512".into()),
            (t("i.comp"), format!("{comp}{stored}")),
            (t("i.size"), tf("i.size_val", &[&human(o.file_len), &o.file_len])),
            (t("i.real"), human(m.real_len)),
            (t("i.padding"), human(o.padding())),
            (t("i.chunks"), format!("{} \u{00D7} {}", o.chunk_count(), human(m.chunk as u64))),
            (t("i.counts"), format!("{} / {}", m.file_count, m.dir_count)),
            (t("i.unpacked"), human(m.total_unpacked)),
        ];
        let body = o.body;
        ui.heading(t("i.title"));
        let mut check = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            section(ui, t("i.s_config"), |ui| {
                egui::Grid::new("info").num_columns(2).striped(true).spacing([16.0, 4.0]).show(ui, |ui| {
                    for (k, v) in &rows {
                        ui.label(RichText::new(*k).strong());
                        ui.label(v);
                        ui.end_row();
                    }
                });
            });
            section(ui, t("i.s_checks"), |ui| {
                for k in ["i.c_slots", "i.c_meta", "i.c_7z"] {
                    ui.label(RichText::new(format!("\u{25CF} {}", t(k))).color(pal().ok));
                }
                match body {
                    BodyCheck::NotChecked => ui.label(RichText::new(t("i.body_unchecked")).color(pal().warn)),
                    BodyCheck::Ok => ui.label(RichText::new(t("i.body_ok")).color(pal().ok)),
                    BodyCheck::Failed => ui.label(RichText::new(t("i.body_failed")).color(pal().err)),
                };
                hint(ui, t("i.body_hint"));
                hint(ui, t("i.no_key_kept"));
                check = ui.button(t("m.check")).clicked();
            });
        });
        if check {
            self.request(Op::Check);
        }
    }

    /// The credential dialog of a pending operation (A-4): nothing runs without it.
    pub fn cred_window(&mut self, ctx: &egui::Context) {
        let Some(op) = self.op.clone() else { return };
        let what = match &op {
            Op::Check => t("job.check"),
            Op::ExtractSelected { .. } => t("job.extract_sel"),
            Op::ExtractAll { .. } => t("job.extract_all"),
            Op::Add { .. } => t("job.add"),
            Op::Remove { .. } => t("job.remove"),
        };
        let (mut run, mut cancel) = (false, false);
        egui::Window::new(tf("m.cred_title", &[&what])).id(egui::Id::new("cred")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            ui.set_max_width(460.0);
            hint(ui, t("m.cred_why"));
            self.cred_fields(ui, "opw");
            let ok = !(self.pw.is_empty() && self.keyfiles.is_empty());
            ui.horizontal(|ui| {
                run = ui.add_enabled(ok, egui::Button::new(RichText::new(t("m.run")).strong())).clicked() || (ok && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                cancel = ui.button(t("ui.cancel")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape));
            });
        });
        if cancel {
            self.op = None;
            self.clear_credentials();
        } else if run {
            self.run_op();
        }
    }

    pub fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let (lines, label, id) = match c {
            Confirm::Add { clash, .. } => {
                let mut l: Vec<String> = clash.iter().take(10).map(|c| tf("m.clash_item", &[c])).collect();
                if clash.len() > 10 {
                    l.push(tf("m.and_more", &[&(clash.len() - 10)]));
                }
                if !clash.is_empty() {
                    l.push(t("m.overwrite_note").into());
                }
                if self.shred_added {
                    l.push(t("m.shred_note").into());
                }
                (l, if clash.is_empty() { t("m.add") } else { t("m.overwrite_add") }, "c_add")
            }
            Confirm::Remove { sel } => {
                let mut l: Vec<String> = sel.iter().take(10).cloned().collect();
                l.push(t("m.remove_note").into());
                (l, t("m.remove"), "c_rm")
            }
        };
        let Some(yes) = confirm_modal(ctx, id, t("m.confirm"), &lines, label) else { return };
        let Some(c) = self.confirm.take() else { return };
        if yes {
            match c {
                Confirm::Add { paths, clash } => self.request(Op::Add { paths, overwrite: !clash.is_empty() }),
                Confirm::Remove { sel } => self.request(Op::Remove { sel }),
            }
        }
    }
}

impl eframe::App for MgrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.housekeeping(ctx);
        egui::TopBottomPanel::top("bar").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.add_enabled_ui(!self.busy(), |ui| self.top_bar(ui));
            ui.add_space(2.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(3.0);
            if let Some(job) = &mut self.job {
                progress_view(ui, job);
            } else {
                let h = if self.open.is_some() { t("m.drop_add") } else { t("m.drop_open") };
                if status_line(ui, self.sh.ok, &self.sh.status, h) {
                    self.sh.msg(true, t("v.retry_hint"));
                }
            }
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let m = leftover_banner(ui, &mut self.sh.leftovers);
            self.sh.apply_msg(m);
            ui.add_enabled_ui(!self.busy(), |ui| match self.tab {
                MTab::Help => {
                    egui::ScrollArea::vertical().show(ui, |ui| usage_view(ui, t("help.mgr_title"), crate::help::mgr_usage()));
                }
                MTab::Settings => {
                    egui::ScrollArea::vertical().show(ui, |ui| crate::settings_view::view(ui, &mut self.sh));
                }
                MTab::Info if self.open.is_some() => self.view_info(ui),
                _ if self.open.is_some() => self.view_container(ui),
                _ if self.pending.is_some() => egui::ScrollArea::vertical().show(ui, |ui| self.view_unlock(ui)).inner,
                _ => self.view_browse(ui),
            });
        });
        if !self.busy() {
            self.cred_window(ctx);
            self.confirm_window(ctx);
        }
    }
}
