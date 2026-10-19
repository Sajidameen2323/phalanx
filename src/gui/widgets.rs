//! Palette, styling and small reusable widgets.

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Layout, Margin, RichText, Stroke, TextStyle, Ui, Vec2,
};
use threat_scanner::posture::{self, Check, Status};
use std::path::PathBuf;
use std::time::Duration;
use threat_scanner::Category;

pub const APP_TITLE: &str = threat_scanner::system::APP_NAME;

pub const BG: Color32 = Color32::from_rgb(0x0E, 0x13, 0x1F);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x12, 0x18, 0x27);
pub const CARD: Color32 = Color32::from_rgb(0x18, 0x20, 0x33);
pub const CONTROL: Color32 = Color32::from_rgb(0x22, 0x2B, 0x42);
pub const BORDER: Color32 = Color32::from_rgb(0x26, 0x30, 0x48);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE9, 0xF0);
pub const MUTED: Color32 = Color32::from_rgb(0x8B, 0x95, 0xAB);
pub const ACCENT: Color32 = Color32::from_rgb(0x3B, 0x82, 0xF6);
pub const GREEN: Color32 = Color32::from_rgb(0x22, 0xC5, 0x5E);
pub const RED: Color32 = Color32::from_rgb(0xEF, 0x44, 0x44);
pub const ORANGE: Color32 = Color32::from_rgb(0xF9, 0x73, 0x16);
pub const AMBER: Color32 = Color32::from_rgb(0xF5, 0x9E, 0x0B);
pub const YELLOW: Color32 = Color32::from_rgb(0xEA, 0xB3, 0x08);
/// Outline of inputs, checkboxes and switches.
pub const CONTROL_EDGE: Color32 = Color32::from_rgb(0x3A, 0x46, 0x63);

pub fn apply_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = CARD;
    visuals.extreme_bg_color = Color32::from_rgb(0x0B, 0x0F, 0x19);
    visuals.faint_bg_color = Color32::from_rgb(0x1D, 0x26, 0x3B);
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.6);
    visuals.hyperlink_color = ACCENT;
    for w in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
    ] {
        w.corner_radius = CornerRadius::same(8);
    }
    visuals.widgets.inactive.weak_bg_fill = CONTROL;
    visuals.widgets.inactive.bg_fill = CONTROL;
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2B, 0x36, 0x52);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x2B, 0x36, 0x52);
    // Visible outlines, so checkboxes, radio buttons and text fields stand
    // out from the card behind them (egui's dark theme leaves them borderless).
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, CONTROL_EDGE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.8));
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.5, TEXT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, Color32::WHITE);
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 7.0);
        style.text_styles.insert(TextStyle::Body, FontId::proportional(14.0));
        style.text_styles.insert(TextStyle::Button, FontId::proportional(14.0));
        style.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
    });
}

/// The app icon: the emblem on transparency (its dark outline and visor keep
/// it readable on light and dark taskbars), 128×128 RGBA, rendered from
/// `assets/phalanx-emblem.svg`. Also the sidebar logo.
const ICON_RGBA: &[u8] = include_bytes!("../../assets/phalanx-128.rgba");
const ICON_SIZE: u32 = 128;
/// The emblem as PNG, for the notification icon.
pub const ICON_PNG: &[u8] = include_bytes!("../../assets/phalanx.png");
/// The emblem as a multi-size icon file (small sizes from the heavier
/// `phalanx-emblem-small.svg`), for the Start-menu shortcut and taskbar.
pub const ICON_ICO: &[u8] = include_bytes!("../../assets/phalanx.ico");

/// The window and tray icon: (RGBA pixels, width, height).
pub fn icon_rgba() -> (Vec<u8>, u32, u32) {
    (ICON_RGBA.to_vec(), ICON_SIZE, ICON_SIZE)
}

/// The emblem as an egui texture, for the sidebar.
pub fn logo_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let image = egui::ColorImage::from_rgba_unmultiplied([ICON_SIZE as usize; 2], ICON_RGBA);
    ctx.load_texture("phalanx-logo", image, egui::TextureOptions::LINEAR)
}

pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(26.0).strong().color(TEXT));
    ui.label(RichText::new(subtitle).color(MUTED));
    ui.add_space(18.0);
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(12.0)
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

pub fn section_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(16.0).strong().color(TEXT));
}

pub fn muted(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).color(MUTED));
}

pub fn small(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(12.0).color(MUTED));
}

/// Single-line text that shortens with "…" instead of widening the layout.
pub fn truncated(ui: &mut Ui, text: impl Into<String>, color: Color32, size: f32) {
    ui.add(egui::Label::new(RichText::new(text.into()).color(color).size(size)).truncate());
}

/// How many tiles fit side by side at a minimum width each (1 to `max`).
pub fn columns_for(ui: &Ui, min_width: f32, max: usize) -> usize {
    ((ui.available_width() / min_width).floor() as usize).clamp(1, max)
}

/// Stat tiles that reflow from 4 per row down to 1 as the window narrows.
pub fn stat_tiles(ui: &mut Ui, tiles: &[(&str, String)]) {
    let per_row = columns_for(ui, 150.0, tiles.len().max(1));
    for (index, row) in tiles.chunks(per_row).enumerate() {
        if index > 0 {
            ui.add_space(8.0);
        }
        ui.columns(per_row, |cols| {
            for (col, (label, value)) in cols.iter_mut().zip(row) {
                card(col, |ui| {
                    ui.label(RichText::new(*label).size(12.5).color(MUTED));
                    ui.label(RichText::new(value).size(24.0).strong().color(TEXT));
                });
            }
        });
    }
}

/// Label/value pairs that wrap onto more lines when narrow.
pub fn facts(ui: &mut Ui, items: &[(&str, String)]) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 18.0;
        for (label, value) in items {
            let mut job = egui::text::LayoutJob::default();
            let font = FontId::proportional(12.5);
            let format = |color| egui::TextFormat { font_id: font.clone(), color, ..Default::default() };
            job.append(&format!("{label} "), 0.0, format(MUTED));
            job.append(value, 0.0, format(TEXT));
            ui.label(job);
        }
    });
}

pub fn primary_button(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(ACCENT)
            .stroke(Stroke::NONE)
            .corner_radius(8.0)
            .min_size(Vec2::new(0.0, 36.0)),
    )
}

pub fn secondary_button(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(TEXT))
            .fill(CONTROL)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(8.0)
            .min_size(Vec2::new(0.0, 36.0)),
    )
}

pub fn small_button(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(12.5).color(TEXT))
            .fill(CONTROL)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(6.0),
    )
}

pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).strong().color(Color32::WHITE))
        .fill(RED.gamma_multiply(0.85))
        .stroke(Stroke::NONE)
        .corner_radius(8.0)
        .min_size(Vec2::new(0.0, 36.0))
}

/// A pill-shaped toggle chip; returns true when clicked.
pub fn chip(ui: &mut Ui, text: &str, active: bool) -> bool {
    ui.add(
        egui::Button::new(RichText::new(text).size(13.0).color(if active { Color32::WHITE } else { TEXT }))
            .fill(if active { ACCENT } else { CONTROL })
            .stroke(Stroke::new(1.0, if active { ACCENT } else { BORDER }))
            .corner_radius(14.0),
    )
    .clicked()
}

pub fn category_color(category: Category) -> Color32 {
    match category {
        Category::Malware => RED,
        Category::HackTool => ORANGE,
        Category::Pup => AMBER,
        Category::Suspicious => YELLOW,
    }
}

pub fn category_color_str(category: &str) -> Color32 {
    category.parse().map(category_color).unwrap_or(MUTED)
}

pub fn badge(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .corner_radius(6.0)
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.5).strong().color(color));
        });
}

pub fn status_dot(ui: &mut Ui, color: Color32, radius: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(radius * 2.0 + 6.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius, color);
}

/// Picks a folder and appends it unless already present. Returns true if added.
pub fn add_folder(list: &mut Vec<PathBuf>) -> bool {
    match rfd::FileDialog::new().pick_folder() {
        Some(dir) if !list.contains(&dir) => {
            list.push(dir);
            true
        }
        _ => false,
    }
}

/// A path shown as a bold file name over its (truncated) folder, so the
/// useful part survives narrow layouts.
pub fn path_lines(ui: &mut Ui, path: &str) {
    let p = std::path::Path::new(path);
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string());
    let parent = p.parent().map(|d| d.display().to_string()).unwrap_or_default();
    truncated(ui, name, TEXT, 13.5);
    if !parent.is_empty() {
        truncated(ui, parent, MUTED, 12.0);
    }
}

pub fn file_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

pub fn short_time(rfc3339: &str) -> String {
    rfc3339.get(..16).unwrap_or(rfc3339).replace('T', " ")
}

pub fn fmt_bytes(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1_073_741_824.0 {
        format!("{:.1} GB", b / 1_073_741_824.0)
    } else if b >= 1_048_576.0 {
        format!("{:.1} MB", b / 1_048_576.0)
    } else if b >= 1024.0 {
        format!("{:.0} KB", b / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

// ---------- settings controls ----------

/// An on/off switch. Keyboard- and screen-reader-accessible like a checkbox.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> egui::Response {
    let size = Vec2::new(42.0, 24.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let enabled = ui.is_enabled();
    response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, ""));
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool_responsive(response.id, *on);
        let track = lerp_color(CONTROL, ACCENT, t);
        let edge = if response.hovered() { ACCENT.gamma_multiply(0.8) } else { lerp_color(CONTROL_EDGE, ACCENT, t) };
        let (track, edge, knob) = if enabled {
            (track, edge, Color32::WHITE)
        } else {
            (track.gamma_multiply(0.45), edge.gamma_multiply(0.45), MUTED)
        };
        let radius = rect.height() / 2.0;
        ui.painter().rect(rect, radius, track, Stroke::new(1.0, edge), egui::StrokeKind::Inside);
        let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
        ui.painter().circle_filled(egui::pos2(x, rect.center().y), radius - 4.0, knob);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// A settings row: title and wrapped description on the left, the control
/// right-aligned. Clicking the text does not change anything; only the control does.
pub fn setting_row<R>(ui: &mut Ui, title: &str, description: &str, control: impl FnOnce(&mut Ui) -> R) -> R {
    let width = ui.available_width();
    let control_width = (width * 0.4).clamp(56.0, 360.0);
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new((width - control_width - 12.0).max(120.0), 0.0),
            Layout::top_down(Align::Min),
            |ui| {
                ui.add(egui::Label::new(RichText::new(title).size(14.0).color(TEXT)).wrap());
                if !description.is_empty() {
                    ui.add(egui::Label::new(RichText::new(description).size(12.5).color(MUTED)).wrap());
                }
            },
        );
        // Top-aligned with the title; a centred cross axis stretches framed
        // controls such as badges to the row height.
        ui.with_layout(Layout::right_to_left(Align::Min), control).inner
    })
    .inner
}

/// A row with a switch. Returns true when the user changed it.
pub fn setting_toggle(ui: &mut Ui, value: &mut bool, title: &str, description: &str) -> bool {
    setting_row(ui, title, description, |ui| toggle(ui, value).changed())
}

/// Thin divider between rows of one settings group.
pub fn row_divider(ui: &mut Ui) {
    ui.add_space(2.0);
    let rect = ui.available_rect_before_wrap();
    let y = rect.top();
    ui.painter().hline(rect.x_range(), y, Stroke::new(1.0, BORDER));
    ui.add_space(8.0);
}

/// A group heading inside the settings page.
pub fn group_title(ui: &mut Ui, title: &str, description: &str) {
    ui.label(RichText::new(title).size(16.0).strong().color(TEXT));
    if !description.is_empty() {
        ui.add(egui::Label::new(RichText::new(description).size(12.5).color(MUTED)).wrap());
    }
    ui.add_space(8.0);
}

/// One option of a single-choice list, drawn as a bordered row with a radio
/// circle; the whole row is clickable. Returns true when it was chosen.
pub fn choice_row(ui: &mut Ui, selected: bool, title: &str, description: &str) -> bool {
    let stroke = if selected { Stroke::new(1.5, ACCENT) } else { Stroke::new(1.0, BORDER) };
    let fill = if selected { ACCENT.gamma_multiply(0.10) } else { CONTROL.gamma_multiply(0.5) };
    let response = egui::Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(8.0)
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), egui::Sense::hover());
                let c = rect.center();
                ui.painter().circle(c, 8.0, CONTROL, Stroke::new(1.5, if selected { ACCENT } else { CONTROL_EDGE }));
                if selected {
                    ui.painter().circle_filled(c, 4.0, ACCENT);
                }
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).color(TEXT));
                    if !description.is_empty() {
                        ui.add(egui::Label::new(RichText::new(description).size(12.5).color(MUTED)).wrap());
                    }
                });
            });
        })
        .response;
    let response = ui.interact(response.rect, response.id.with("choice"), egui::Sense::click());
    response.clicked() && !selected
}

// ---------- Windows checks ----------

pub fn check_color(status: Status) -> Color32 {
    match status {
        Status::Good => GREEN,
        Status::Attention => AMBER,
        Status::Risk => RED,
        Status::Info | Status::Unknown => MUTED,
    }
}

pub fn check_label(status: Status, privacy: bool) -> &'static str {
    match (status, privacy) {
        (Status::Good, false) => "On",
        (Status::Good, true) => "Private",
        (Status::Attention, _) => "Review",
        (Status::Risk, false) => "Off",
        (Status::Risk, true) => "Sharing",
        (Status::Info, _) => "Info",
        (Status::Unknown, _) => "Unknown",
    }
}

/// What the user clicked on a check row.
#[derive(Clone, Copy, PartialEq)]
pub enum CheckAction {
    OpenSettings,
    ApplyFix,
}

/// One check: status badge, title, what was read, why it matters, a link to
/// the Windows page and, when the check offers one, a fix button.
pub fn check_row(ui: &mut Ui, check: &Check, privacy: bool) -> Option<CheckAction> {
    let mut action = None;
    ui.horizontal(|ui| {
        let width = ui.available_width();
        ui.allocate_ui_with_layout(Vec2::new(78.0, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.set_min_width(78.0);
            badge(ui, check_label(check.status, privacy), check_color(check.status));
        });
        ui.allocate_ui_with_layout(Vec2::new((width - 90.0).max(120.0), 0.0), Layout::top_down(Align::Min), |ui| {
            ui.add(egui::Label::new(RichText::new(check.title).strong().color(TEXT)).wrap());
            ui.add(egui::Label::new(RichText::new(&check.detail).size(13.0).color(check_color(check.status).lerp_to_gamma(TEXT, 0.35))).wrap());
            ui.add(egui::Label::new(RichText::new(check.why).size(12.0).color(MUTED)).wrap());
            ui.horizontal_wrapped(|ui| {
                if let Some(fix) = &check.fix {
                    if small_button(ui, fix.label).clicked() {
                        action = Some(CheckAction::ApplyFix);
                    }
                }
                if (check.status != Status::Good || privacy)
                    && ui.add(egui::Link::new(RichText::new(check.link.label).size(12.5).color(ACCENT))).clicked()
                {
                    action = Some(CheckAction::OpenSettings);
                }
            });
        });
    });
    action
}

/// Score ring: percentage and level in a coloured circle.
pub fn score_badge(ui: &mut Ui, percent: u32) {
    let color = match percent {
        85.. => GREEN,
        60..85 => AMBER,
        _ => RED,
    };
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(64.0), egui::Sense::hover());
    let c = rect.center();
    ui.painter().circle(c, 29.0, color.gamma_multiply(0.14), Stroke::new(3.0, color));
    ui.painter().text(c - Vec2::new(0.0, 6.0), egui::Align2::CENTER_CENTER, format!("{percent}"), FontId::proportional(20.0), TEXT);
    ui.painter().text(c + Vec2::new(0.0, 12.0), egui::Align2::CENTER_CENTER, posture::level(percent), FontId::proportional(10.5), color);
}

pub fn verdict_color(verdict: threat_scanner::ai::Verdict) -> Color32 {
    use threat_scanner::ai::Verdict;
    match verdict {
        Verdict::Safe => GREEN,
        Verdict::Suspicious => AMBER,
        Verdict::Malicious => RED,
        Verdict::Unknown => MUTED,
    }
}

pub fn severity_color(severity: &str) -> Color32 {
    match severity {
        "high" => RED,
        "medium" => ORANGE,
        "low" => YELLOW,
        _ => MUTED,
    }
}

pub fn score_color(percent: u32) -> Color32 {
    match percent {
        85.. => GREEN,
        60..85 => AMBER,
        _ => RED,
    }
}

/// A tinted callout with wrapped text.
pub fn notice(ui: &mut Ui, color: Color32, text: &str) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(8.0)
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).size(13.0).color(TEXT)).wrap());
        });
}
