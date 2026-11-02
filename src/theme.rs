//! E-4 Theme tokens (light / dark, or following Windows), fonts, UI scale and the dark title bar.
//! Widgets never hard-code colors: they ask `pal()`.

use crate::settings::{Settings, ThemePref};
use eframe::egui::{self, vec2, Color32};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy)]
pub struct Palette {
    pub ok: Color32,
    pub err: Color32,
    pub warn: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub disabled: Color32,
    pub bar: Color32,
    pub row_sel: Color32,
    pub row_hover: Color32,
    pub warn_bg: Color32,
}

pub const LIGHT: Palette = Palette {
    ok: Color32::from_rgb(34, 139, 70),
    err: Color32::from_rgb(200, 50, 50),
    warn: Color32::from_rgb(170, 105, 0),
    accent: Color32::from_rgb(38, 96, 196),
    on_accent: Color32::WHITE,
    disabled: Color32::from_gray(170),
    bar: Color32::from_rgb(140, 185, 245),
    row_sel: Color32::from_rgb(204, 224, 255),
    row_hover: Color32::from_rgb(235, 242, 255),
    warn_bg: Color32::from_rgb(255, 240, 210),
};

pub const DARK: Palette = Palette {
    ok: Color32::from_rgb(98, 200, 128),
    err: Color32::from_rgb(240, 110, 110),
    warn: Color32::from_rgb(235, 175, 70),
    accent: Color32::from_rgb(88, 145, 235),
    on_accent: Color32::WHITE,
    disabled: Color32::from_gray(80),
    bar: Color32::from_rgb(52, 90, 150),
    row_sel: Color32::from_rgb(45, 70, 115),
    row_hover: Color32::from_rgb(45, 50, 60),
    warn_bg: Color32::from_rgb(70, 55, 25),
};

static DARK_ON: AtomicBool = AtomicBool::new(false);

pub fn pal() -> Palette {
    if DARK_ON.load(Ordering::Relaxed) {
        DARK
    } else {
        LIGHT
    }
}

pub fn is_dark() -> bool {
    DARK_ON.load(Ordering::Relaxed)
}

pub fn wants_dark(p: ThemePref) -> bool {
    match p {
        ThemePref::Light => false,
        ThemePref::Dark => true,
        ThemePref::System => crate::capture::system_dark(),
    }
}

/// Applies theme, text sizes and UI scale. Cheap; called when a setting changes and periodically
/// (to follow the Windows theme when set to System).
pub fn apply(ctx: &egui::Context, s: &Settings) {
    let dark = wants_dark(s.theme);
    let changed = DARK_ON.swap(dark, Ordering::Relaxed) != dark;
    ctx.set_visuals(if dark { egui::Visuals::dark() } else { egui::Visuals::light() });
    let mut st = (*ctx.style()).clone();
    st.spacing.item_spacing = vec2(8.0, 6.0);
    st.spacing.button_padding = vec2(10.0, 4.0);
    use egui::{FontFamily, FontId, TextStyle as T};
    st.text_styles = [
        (T::Heading, FontId::new(19.0, FontFamily::Proportional)),
        (T::Body, FontId::new(14.5, FontFamily::Proportional)),
        (T::Button, FontId::new(14.5, FontFamily::Proportional)),
        (T::Small, FontId::new(12.5, FontFamily::Proportional)),
        (T::Monospace, FontId::new(13.5, FontFamily::Monospace)),
    ]
    .into();
    ctx.set_style(st);
    let z = s.ui_scale as f32 / 100.0;
    if (ctx.zoom_factor() - z).abs() > 0.001 {
        ctx.set_zoom_factor(z);
    }
    if changed {
        crate::capture::dark_title_bar(dark);
    }
}

/// Malgun Gothic first (Hangul and the symbols listed in `glyphs::ALLOWED`), egui's fonts after.
pub fn load_fonts(ctx: &egui::Context) {
    let mut cands = Vec::new();
    #[cfg(windows)]
    if let Some(p) = crate::sysinfo::system_dir().parent() {
        cands.push(p.join("Fonts").join("malgun.ttf"));
    }
    cands.extend(
        ["/System/Library/Fonts/AppleSDGothicNeo.ttc", "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"].map(std::path::PathBuf::from),
    );
    for p in cands {
        if let Ok(b) = std::fs::read(&p) {
            let mut f = egui::FontDefinitions::default();
            f.font_data.insert("kr".into(), egui::FontData::from_owned(b));
            for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                f.families.entry(fam).or_default().insert(0, "kr".into());
            }
            ctx.set_fonts(f);
            return;
        }
    }
}
