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

/// (ascent - descent) / em of Malgun Gothic (hhea 2229 / -495, 2048 units), the font the layout
/// was made with. egui sizes a font so that ascent - descent equals the font size, so a font with
/// taller metrics draws smaller letters at the same size.
pub const REFERENCE_HEIGHT_PER_EM: f32 = (2229.0 + 495.0) / 2048.0;

/// Glyph scale that gives a font the letter size of the reference font (3.0.0 §2-A: Noto Sans
/// CJK on Linux has 1.448 and was drawn about 8 % smaller than Malgun Gothic on Windows). Row
/// heights do not change (egui lays out with the font's own metrics), only the glyphs. Fonts
/// within 2 % keep 1.0.
pub fn glyph_scale(height_per_em: f32) -> f32 {
    if !height_per_em.is_finite() || height_per_em <= 0.0 {
        return 1.0;
    }
    let s = (height_per_em / REFERENCE_HEIGHT_PER_EM).clamp(0.85, 1.2);
    if (s - 1.0).abs() < 0.02 { 1.0 } else { s }
}

fn height_per_em(bytes: &[u8], index: u32) -> Option<f32> {
    use ab_glyph::Font;
    let f = ab_glyph::FontRef::try_from_slice_and_index(bytes, index).ok()?;
    let em = f.units_per_em()?;
    Some((f.ascent_unscaled() - f.descent_unscaled()) / em)
}

/// A Hangul-capable system font first (Windows: Malgun Gothic; Linux: Noto Sans CJK / Nanum /
/// Un fonts, see `shield_platform::sys::font_candidates`), egui's fonts after. The same on both
/// systems: the font is scaled to the letter size of Malgun Gothic (`glyph_scale`).
pub fn load_fonts(ctx: &egui::Context) {
    let cands = shield_platform::sys::font_candidates();
    for (p, index) in cands {
        if let Ok(b) = std::fs::read(&p) {
            let mut f = egui::FontDefinitions::default();
            let scale = height_per_em(&b, index).map(glyph_scale).unwrap_or(1.0);
            let mut data = egui::FontData::from_owned(b);
            data.index = index;
            data.tweak.scale = scale;
            f.font_data.insert("kr".into(), data);
            for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                f.families.entry(fam).or_default().insert(0, "kr".into());
            }
            ctx.set_fonts(f);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_fonts_get_the_letter_size_of_malgun_gothic() {
        assert_eq!(glyph_scale(REFERENCE_HEIGHT_PER_EM), 1.0, "Windows: unchanged");
        // Noto Sans CJK KR: hhea 1160 / -288, 1000 units
        let noto = glyph_scale((1160.0 + 288.0) / 1000.0);
        assert!((noto - 1.0887).abs() < 0.001, "{noto}");
        assert_eq!(glyph_scale(1.335), 1.0, "within 2 %");
        assert_eq!(glyph_scale(f32::NAN), 1.0);
        assert_eq!(glyph_scale(9.0), 1.2, "clamped");
        // the installed Malgun Gothic really has the reference metrics
        let p = std::path::Path::new(r"C:\Windows\Fonts\malgun.ttf");
        if let Ok(b) = std::fs::read(p) {
            let h = height_per_em(&b, 0).unwrap();
            assert!((h - REFERENCE_HEIGHT_PER_EM).abs() < 0.001, "{h}");
        }
    }
}
