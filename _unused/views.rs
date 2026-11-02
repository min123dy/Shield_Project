//! One screen per tab. Each screen is laid out as numbered steps, shows what is still missing,
//! and only enables its main button when the input is complete.

use crate::ui::*;
use crate::{help, roots, wipe, App};
use eframe::egui::{self, RichText};

impl App {
    fn apply_msg(&mut self, m: Option<(bool, String)>) {
        if let Some((ok, s)) = m {
            self.set(ok, s);
        }
    }

    pub fn view_encrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔒 파일·폴더 암호화");
        hint(ui, "선택한 항목을 7z로 압축한 뒤 암호화해 하나의 .shd 파일로 만듭니다. 원본은 그대로 남습니다(파쇄 선택 시 제외).");
        ui.add_space(6.0);
        section(ui, "① 대상", |ui| target_card(ui, &self.selected));
        section(ui, "② 비밀번호", |ui| {
            secret_field(ui, "pw", &mut self.pw, "비밀번호 (12자 이상 권장: 여러 단어 조합)");
            strength_bar(ui, &self.pw);
            secret_field(ui, "pw2", &mut self.pw2, "비밀번호 다시 입력");
            match_label(ui, &self.pw, &self.pw2);
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, false);
        });
        let mut msg = None;
        section(ui, "③ 키 파일 (선택)", |ui| msg = keyfile_list(ui, &mut self.keyfiles, true));
        self.apply_msg(msg);
        section(ui, "④ 옵션", |ui| {
            ui.checkbox(&mut self.choose_dest, "저장 위치 직접 선택");
            hint(ui, "끄면 원본 옆에 '이름.shd'로 저장합니다 (같은 이름이 있으면 번호를 붙임).");
            ui.checkbox(&mut self.shred_src, "암호화·검증이 끝나면 원본 파쇄 (영구 삭제)");
            if self.shred_src {
                ui.indent("shred", |ui| {
                    ui.checkbox(
                        &mut self.shred_ack,
                        RichText::new("원본이 영구 삭제되어 복구할 수 없음을 이해했습니다").color(RED),
                    );
                    ui.checkbox(&mut self.force7, "SSD여도 7회 덮어쓰기 (기본: HDD 7회 / SSD 1회)");
                    ui.checkbox(&mut self.trim_after, "파쇄 후 TRIM 실행 (SSD 권장, 빠름 · 관리자 확인 창이 뜰 수 있음)");
                    ui.checkbox(&mut self.wipe_free_after, "파쇄 후 드라이브 여유 공간 덮어쓰기 (선택 · 매우 오래 걸림)");
                    hint(ui, "SSD는 덮어쓰기/TRIM으로도 내부 예비 영역의 사본까지 지운다고 보장할 수 없습니다.");
                });
            }
        });
        let problems = self.encrypt_problems();
        if action_button(ui, &problems, "🔒 암호화 시작") {
            self.start_encrypt();
        }
    }

    pub fn view_decrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔓 복호화");
        hint(ui, ".shd 파일을 원래 파일/폴더로 되돌립니다. 같은 이름이 있으면 덮어쓰지 않고 '(decrypted)'를 붙입니다.");
        ui.add_space(6.0);
        section(ui, "① 암호화 파일 (.shd)", |ui| target_card(ui, &self.selected));
        section(ui, "② 암호화할 때 쓴 비밀번호", |ui| {
            secret_field(ui, "pw", &mut self.pw, "비밀번호");
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, true);
        });
        let mut msg = None;
        section(ui, "③ 키 파일 (사용했다면 모두)", |ui| msg = keyfile_list(ui, &mut self.keyfiles, false));
        self.apply_msg(msg);
        section(ui, "④ 저장 위치", |ui| {
            ui.checkbox(&mut self.choose_dest, "저장 폴더 직접 선택");
            hint(ui, "끄면 .shd 파일과 같은 폴더에 풉니다.");
        });
        let problems = self.decrypt_problems();
        if action_button(ui, &problems, "🔓 복호화 시작") {
            self.start_decrypt();
        }
    }

    pub fn view_rekey(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔑 비밀번호 변경");
        hint(ui, "파일 내용은 그대로 두고 .shd 파일의 키만 새 비밀번호로 다시 봉인합니다(크기와 상관없이 몇 초). 작업 전 백업을 권장합니다.");
        ui.add_space(6.0);
        section(ui, "① 대상 .shd 파일", |ui| target_card(ui, &self.selected));
        let mut msg = None;
        section(ui, "② 현재 비밀번호 / PIM / 키 파일", |ui| {
            secret_field(ui, "pw", &mut self.pw, "현재 비밀번호");
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, true);
            ui.label("현재 키 파일");
            msg = keyfile_list(ui, &mut self.keyfiles, false);
        });
        self.apply_msg(msg);
        let mut msg = None;
        section(ui, "③ 새 비밀번호 / PIM / 키 파일", |ui| {
            secret_field(ui, "npw", &mut self.new_pw, "새 비밀번호");
            strength_bar(ui, &self.new_pw);
            secret_field(ui, "npw2", &mut self.new_pw2, "새 비밀번호 다시 입력");
            match_label(ui, &self.new_pw, &self.new_pw2);
            pim_picker(ui, &mut self.new_custom_pim, &mut self.new_pim, false);
            ui.label("새 키 파일");
            msg = keyfile_list(ui, &mut self.new_keyfiles, true);
        });
        self.apply_msg(msg);
        let problems = self.rekey_problems();
        if action_button(ui, &problems, "🔑 비밀번호 변경") {
            self.start_rekey();
        }
    }

    pub fn view_disk(&mut self, ui: &mut egui::Ui) {
        ui.heading("💽 디스크 정리");
        hint(ui, "삭제한 파일의 흔적을 줄이는 기능입니다. 보통은 TRIM만으로 충분하며, 여유 공간 덮어쓰기는 선택 사항입니다.");
        ui.add_space(6.0);
        if self.disk_drive.is_none() {
            let here = self.selected.as_deref().or(self.cwd.as_deref());
            self.disk_drive = here.and_then(wipe::drive_letter).map(|l| format!("{l}:\\").into());
        }
        section(ui, "① 드라이브", |ui| {
            let cur = self.disk_drive.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "선택하세요".into());
            egui::ComboBox::from_id_source("drive").selected_text(cur).show_ui(ui, |ui| {
                for r in roots() {
                    let t = r.display().to_string();
                    ui.selectable_value(&mut self.disk_drive, Some(r), t);
                }
            });
        });
        section(ui, "② TRIM만 실행 (권장 · 빠름)", |ui| {
            hint(ui, "SSD에 '이미 삭제된 블록'을 알려 컨트롤러가 실제로 지우도록 합니다. 보통 수 초~수 분이면 끝납니다.");
            hint(ui, "관리자 권한이 필요해 Windows 확인 창(UAC)이 뜰 수 있습니다. HDD에서는 지원되지 않습니다.");
            if ui.add_enabled(self.disk_drive.is_some(), egui::Button::new("⚡ TRIM 실행")).clicked() {
                self.start_trim();
            }
        });
        section(ui, "③ 여유 공간 덮어쓰기 (선택)", |ui| {
            hint(ui, "드라이브의 빈 공간 전체를 3회(00 → FF → 난수) 덮어씁니다. 수십 분~수 시간이 걸리고 SSD 쓰기 수명을 소모합니다. 취소 가능.");
            ui.checkbox(&mut self.disk_trim_after_wipe, "끝난 뒤 TRIM도 실행");
            let enabled = self.disk_drive.is_some();
            if ui.add_enabled(enabled, egui::Button::new("🧽 여유 공간 덮어쓰기 시작")).clicked() {
                self.start_wipe_free();
            }
        });
        if let Some(d) = &self.disk_drive {
            if wipe::drive_letter(d).is_none() {
                ui.label(RichText::new("이 드라이브는 문자를 확인할 수 없습니다.").color(AMBER));
            }
        }
    }
}

pub fn view_help(ui: &mut egui::Ui) {
    ui.heading("❓ 사용법 · 주의사항");
    ui.add_space(6.0);
    for (title, lines) in help::SECTIONS {
        section(ui, title, |ui| {
            for l in *lines {
                ui.label(*l);
            }
        });
    }
    hint(ui, format!("Shield {}", env!("CARGO_PKG_VERSION")));
}
