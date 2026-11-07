use super::*;
use crate::settings::Settings;
use crate::Start;

/// Lays the Rekey tab out at `w`×`h` (window size, 100 % scale) and returns the method
/// section's rectangle and the visible part of the scrolling form.
fn rekey_layout(w: f32, h: f32) -> (egui::Rect, egui::Rect) {
    let ctx = egui::Context::default();
    crate::theme::load_fonts(&ctx);
    let set = Settings::default();
    crate::theme::apply(&ctx, &set);
    let mut a = EncApp::new(set, Start::Default);
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
