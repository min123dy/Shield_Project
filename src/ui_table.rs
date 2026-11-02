//! A-1 File tables (explorer and container listing): the first (name) column takes what is left
//! and is the first to shrink, with an ellipsis; the date column never goes below the width of a
//! full "YYYY-MM-DD HH:MM" (+":SS"); columns are resizable by dragging the header separators; a
//! truncated cell shows its full text as a tooltip; numbers are right-aligned.

use crate::theme::pal;
use eframe::egui::{self, pos2, text::LayoutJob, vec2, Color32, FontId, Rect, Response, Sense, Ui};

pub const ROW_H: f32 = 24.0;
const PAD: f32 = 6.0;
const NAME_MIN: f32 = 90.0;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// A column: header text, starting width, minimum width, alignment.
#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    pub width: f32,
    pub min: f32,
    pub align: Align,
}

fn one_line(ui: &Ui, text: &str, max_w: f32, font: FontId, color: Color32) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = egui::text::TextWrapping { max_width: max_w.max(1.0), max_rows: 1, break_anywhere: true, overflow_character: Some('\u{2026}') };
    ui.fonts(|f| f.layout_job(job))
}

/// Label cut to `w` with an ellipsis (the caller adds the tooltip).
pub fn clipped_label(ui: &mut Ui, text: &str, w: f32) -> Response {
    let c = ui.visuals().text_color();
    clipped_rich(ui, text, w, c)
}

pub fn clipped_rich(ui: &mut Ui, text: &str, w: f32, color: Color32) -> Response {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let g = one_line(ui, text, w, font, color);
    let (rect, resp) = ui.allocate_exact_size(vec2(g.size().x.min(w), g.size().y), Sense::hover());
    ui.painter().galley(rect.min, g, color);
    resp
}

/// Minimum width of the date column for the current format.
pub fn date_min_width(ui: &Ui, seconds: bool) -> f32 {
    let sample = if seconds { "0000-00-00 00:00:00" } else { "0000-00-00 00:00" };
    let font = FontId::proportional(13.5);
    one_line(ui, sample, f32::INFINITY, font, Color32::WHITE).size().x + 2.0 * PAD + 6.0
}

pub struct Table {
    id: egui::Id,
    cols: Vec<Col>,
    widths: Vec<f32>,
}

impl Table {
    /// `cols[0]` is the name column (its width is computed); the others keep the user's widths.
    pub fn new(ui: &Ui, id: &str, cols: Vec<Col>) -> Table {
        let id = egui::Id::new(("table", id));
        let saved: Option<Vec<f32>> = ui.data(|d| d.get_temp(id));
        let widths = match saved {
            Some(w) if w.len() == cols.len() => w.iter().zip(&cols).map(|(w, c)| w.max(c.min)).collect(),
            _ => cols.iter().map(|c| c.width.max(c.min)).collect(),
        };
        Table { id, cols, widths }
    }

    /// Final widths for `total`: fixed columns as set, the name column gets the rest (never below
    /// NAME_MIN; when the window is narrower the fixed columns give up space down to their minimums,
    /// the date column last).
    pub fn layout(&self, total: f32) -> Vec<f32> {
        let mut w = self.widths.clone();
        let fixed: f32 = w.iter().skip(1).sum();
        let mut name = total - fixed;
        if name < NAME_MIN {
            let mut need = NAME_MIN - name;
            // shrink the widest non-date columns first; the date column keeps its minimum
            for i in (1..w.len()).rev() {
                let room = w[i] - self.cols[i].min;
                let take = room.min(need);
                w[i] -= take;
                need -= take;
            }
            name = (total - w.iter().skip(1).sum::<f32>()).max(NAME_MIN);
        }
        w[0] = name;
        w
    }

    pub fn header(&mut self, ui: &mut Ui) {
        let total = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(vec2(total, ROW_H), Sense::hover());
        ui.painter().rect_filled(rect, 2.0, ui.visuals().faint_bg_color);
        let w = self.layout(total);
        let font = FontId::proportional(13.0);
        let color = ui.visuals().strong_text_color();
        let mut x = rect.left();
        for (i, c) in self.cols.iter().enumerate() {
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(w[i], ROW_H));
            paint_cell(ui, cell, c.title, c.align, font.clone(), color);
            x += w[i];
            if i + 1 < self.cols.len() {
                // drag handle on the left edge of the next column resizes that column
                let h = Rect::from_center_size(pos2(x, rect.center().y), vec2(8.0, ROW_H));
                let r = ui.interact(h, self.id.with(i), Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
                ui.painter().vline(x, rect.y_range(), ui.visuals().widgets.noninteractive.bg_stroke);
                if r.dragged() {
                    let k = i + 1;
                    self.widths[k] = (self.widths[k] - r.drag_delta().x).max(self.cols[k].min);
                }
            }
        }
        ui.data_mut(|d| d.insert_temp(self.id, self.widths.clone()));
    }

    /// One full-width row. Cells that don't fit are cut with an ellipsis and get a tooltip.
    pub fn row(&self, ui: &mut Ui, selected: bool, cells: &[&str]) -> Response {
        let total = ui.available_width();
        let (rect, mut resp) = ui.allocate_exact_size(vec2(total, ROW_H), Sense::click());
        let bg = if selected {
            Some(pal().row_sel)
        } else if resp.hovered() {
            Some(pal().row_hover)
        } else {
            None
        };
        if let Some(c) = bg {
            ui.painter().rect_filled(rect, 2.0, c);
        }
        let w = self.layout(total);
        let font = FontId::proportional(13.5);
        let color = ui.visuals().text_color();
        let mut x = rect.left();
        let mut cut = Vec::new();
        for (i, c) in self.cols.iter().enumerate() {
            let s = cells.get(i).copied().unwrap_or("");
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(w[i], ROW_H));
            if paint_cell(ui, cell, s, c.align, font.clone(), color) {
                cut.push(s);
            }
            x += w[i];
        }
        if !cut.is_empty() {
            let tip = cut.join("\n");
            resp = resp.on_hover_text(tip);
        }
        resp
    }
}

/// Paints one cell; returns true when the text had to be cut.
fn paint_cell(ui: &Ui, cell: Rect, s: &str, align: Align, font: FontId, color: Color32) -> bool {
    let inner = cell.shrink2(vec2(PAD, 0.0));
    let g = one_line(ui, s, inner.width(), font, color);
    let elided = g.elided;
    let pos = match align {
        Align::Left => pos2(inner.left(), inner.center().y - g.size().y / 2.0),
        Align::Right => pos2(inner.right() - g.size().x, inner.center().y - g.size().y / 2.0),
    };
    ui.painter().with_clip_rect(cell).galley(pos, g, color);
    elided
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(widths: &[f32], mins: &[f32]) -> Table {
        let cols = widths.iter().zip(mins).map(|(w, m)| Col { title: "", width: *w, min: *m, align: Align::Left }).collect();
        Table { id: egui::Id::new("t"), cols, widths: widths.to_vec() }
    }
    #[test]
    fn name_column_shrinks_first_and_date_keeps_its_minimum() {
        // name, size, date(min 140), kind
        let tb = t(&[0.0, 100.0, 150.0, 90.0], &[NAME_MIN, 60.0, 140.0, 50.0]);
        let wide = tb.layout(800.0);
        assert_eq!(&wide[1..], &[100.0, 150.0, 90.0]);
        assert_eq!(wide[0], 800.0 - 340.0);
        let narrow = tb.layout(360.0);
        assert!(narrow[0] >= NAME_MIN);
        assert!(narrow[2] >= 140.0, "date never below its minimum: {narrow:?}");
        assert!(narrow[1] >= 60.0 && narrow[3] >= 50.0);
    }
}
