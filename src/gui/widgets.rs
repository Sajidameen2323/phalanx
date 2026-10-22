//! Palette, styling and small reusable widgets.

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Layout, Margin, RichText, Stroke, TextStyle, Ui, Vec2,
};
use threat_scanner::posture::{self, Check, Status};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use threat_scanner::Category;

pub const APP_TITLE: &str = threat_scanner::system::APP_NAME;

/// Every colour the app draws with, for one appearance. Dark follows
/// Apple's dark system palette (near-black window, heavier sidebar, raised
/// grouped surfaces); light follows its light one. Status colours are the
/// darker, accessible variants in light mode so they stay readable as text.
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub sidebar: Color32,
    pub card: Color32,
    pub control: Color32,
    pub control_hover: Color32,
    pub control_active: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    /// Unselected sidebar items: quieter than text, louder than muted.
    pub nav_text: Color32,
    pub accent: Color32,
    pub green: Color32,
    pub red: Color32,
    pub orange: Color32,
    pub amber: Color32,
    pub yellow: Color32,
    /// Outline of inputs, checkboxes and switches.
    pub control_edge: Color32,
    /// Hairline edge that catches light on raised surfaces.
    pub hairline: Color32,
    /// Overlays for a hovered and a pressed surface.
    pub hover: Color32,
    pub press: Color32,
    pub toast: Color32,
    pub toast_edge: Color32,
    pub shadow: Color32,
    /// Dot graphics: the scan stage, the dot ink, the lit cyan and the
    /// opacity of a resting dot.
    pub stage: Color32,
    pub ink: Color32,
    pub cyan: Color32,
    pub dot_alpha: f32,
}

pub static DARK: Palette = Palette {
    dark: true,
    bg: Color32::from_rgb(0x0B, 0x0B, 0x0D),
    sidebar: Color32::from_rgb(0x13, 0x13, 0x16),
    card: Color32::from_rgb(0x1A, 0x1A, 0x1D),
    control: Color32::from_rgb(0x2A, 0x2A, 0x2E),
    control_hover: Color32::from_rgb(0x34, 0x34, 0x39),
    control_active: Color32::from_rgb(0x3C, 0x3C, 0x42),
    border: Color32::from_rgb(0x27, 0x27, 0x2B),
    text: Color32::from_rgb(0xF5, 0xF5, 0xF7),
    muted: Color32::from_rgb(0x98, 0x98, 0x9F),
    nav_text: Color32::from_rgb(0xC7, 0xC7, 0xCC),
    accent: Color32::from_rgb(0x0A, 0x84, 0xFF),
    green: Color32::from_rgb(0x30, 0xD1, 0x58),
    red: Color32::from_rgb(0xFF, 0x45, 0x3A),
    orange: Color32::from_rgb(0xFF, 0x9F, 0x0A),
    amber: Color32::from_rgb(0xFF, 0xB3, 0x40),
    yellow: Color32::from_rgb(0xFF, 0xD6, 0x0A),
    control_edge: Color32::from_rgb(0x3A, 0x3A, 0x3F),
    hairline: Color32::from_rgb(0x24, 0x24, 0x28),
    hover: Color32::from_rgba_premultiplied(18, 18, 18, 18),
    press: Color32::from_rgba_premultiplied(0, 0, 0, 50),
    toast: Color32::from_rgb(0x2C, 0x2C, 0x30),
    toast_edge: Color32::from_rgb(0x3A, 0x3A, 0x40),
    shadow: Color32::from_rgba_premultiplied(0, 0, 0, 140),
    stage: Color32::from_rgb(0x05, 0x05, 0x07),
    ink: Color32::from_rgb(0xF5, 0xF5, 0xF7),
    cyan: Color32::from_rgb(0x64, 0xD2, 0xFF),
    dot_alpha: 0.075,
};

pub static LIGHT: Palette = Palette {
    dark: false,
    bg: Color32::from_rgb(0xF5, 0xF5, 0xF7),
    sidebar: Color32::from_rgb(0xEC, 0xEC, 0xF0),
    card: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    control: Color32::from_rgb(0xE6, 0xE6, 0xEB),
    control_hover: Color32::from_rgb(0xDC, 0xDC, 0xE2),
    control_active: Color32::from_rgb(0xD2, 0xD2, 0xD9),
    border: Color32::from_rgb(0xD8, 0xD8, 0xDE),
    text: Color32::from_rgb(0x1D, 0x1D, 0x1F),
    muted: Color32::from_rgb(0x6E, 0x6E, 0x73),
    nav_text: Color32::from_rgb(0x3A, 0x3A, 0x3C),
    accent: Color32::from_rgb(0x00, 0x71, 0xE3),
    green: Color32::from_rgb(0x1F, 0x8A, 0x3B),
    red: Color32::from_rgb(0xD7, 0x00, 0x15),
    orange: Color32::from_rgb(0xC9, 0x34, 0x00),
    amber: Color32::from_rgb(0xB2, 0x50, 0x00),
    yellow: Color32::from_rgb(0x9A, 0x6A, 0x00),
    control_edge: Color32::from_rgb(0xC7, 0xC7, 0xCC),
    hairline: Color32::from_rgb(0xE3, 0xE3, 0xE8),
    hover: Color32::from_rgba_premultiplied(0, 0, 0, 10),
    press: Color32::from_rgba_premultiplied(0, 0, 0, 34),
    toast: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    toast_edge: Color32::from_rgb(0xDD, 0xDD, 0xE3),
    shadow: Color32::from_rgba_premultiplied(0, 0, 0, 46),
    stage: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    ink: Color32::from_rgb(0x1D, 0x1D, 0x1F),
    cyan: Color32::from_rgb(0x00, 0xA0, 0xDC),
    dot_alpha: 0.11,
};

static IS_DARK: AtomicBool = AtomicBool::new(true);

/// The palette for the appearance on screen this frame.
pub fn theme() -> &'static Palette {
    if IS_DARK.load(Ordering::Relaxed) { &DARK } else { &LIGHT }
}

/// Follows the appearance egui resolved for this frame (the user's choice,
/// or Windows' when it is set to follow the system). Returns the background
/// that was showing when the appearance just changed, so the switch can be
/// eased rather than cut.
pub fn sync_theme(ctx: &egui::Context) -> Option<Color32> {
    let dark = ctx.theme() == egui::Theme::Dark;
    let was = IS_DARK.swap(dark, Ordering::Relaxed);
    (was != dark).then(|| if was { DARK.bg } else { LIGHT.bg })
}


const SEMIBOLD: &str = "semibold";
const BOLD: &str = "bold";

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(BOLD.into()))
}

/// Segoe UI in real weights (egui's `strong` only changes colour), with
/// Segoe UI Symbol for anything the text faces lack. Falls back to egui's
/// own font when a file is missing.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let dir = std::env::var_os("WINDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows")).join("Fonts");
    let mut load = |name: &str, file: &str| -> bool {
        match std::fs::read(dir.join(file)) {
            Ok(bytes) => {
                fonts.font_data.insert(name.to_string(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    let regular = load("segoe", "segoeui.ttf");
    let semibold = load(SEMIBOLD, "seguisb.ttf");
    let bold = load(BOLD, "segoeuib.ttf");
    let symbols = load("segoe-symbol", "seguisym.ttf");
    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    if regular {
        proportional.insert(0, "segoe".to_string());
    }
    if symbols {
        proportional.push("segoe-symbol".to_string());
    }
    let fallback = proportional.clone();
    for (family, present) in [(SEMIBOLD, semibold), (BOLD, bold)] {
        let mut chain = if present { vec![family.to_string()] } else { Vec::new() };
        chain.extend(fallback.iter().cloned());
        fonts.families.insert(FontFamily::Name(family.into()), chain);
    }
    ctx.set_fonts(fonts);
}

pub fn apply_style(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_visuals_of(egui::Theme::Dark, visuals(&DARK));
    ctx.set_visuals_of(egui::Theme::Light, visuals(&LIGHT));
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 7.0);
        style.spacing.scroll = egui::style::ScrollStyle::floating();
        style.text_styles.insert(TextStyle::Body, FontId::proportional(14.0));
        style.text_styles.insert(TextStyle::Button, FontId::proportional(14.0));
        style.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
        style.text_styles.insert(TextStyle::Heading, bold(22.0));
    });
}

fn visuals(pal: &Palette) -> egui::Visuals {
    let mut visuals = if pal.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    visuals.panel_fill = pal.bg;
    visuals.window_fill = pal.card;
    visuals.window_stroke = Stroke::new(1.0, pal.hairline);
    visuals.window_corner_radius = CornerRadius::same(14);
    visuals.menu_corner_radius = CornerRadius::same(10);
    visuals.extreme_bg_color = if pal.dark { Color32::from_rgb(0x10, 0x10, 0x12) } else { Color32::WHITE };
    visuals.faint_bg_color = pal.control;
    visuals.override_text_color = Some(pal.text);
    visuals.selection.bg_fill = pal.accent.gamma_multiply(0.45);
    visuals.selection.stroke = Stroke::new(1.0, pal.accent);
    visuals.hyperlink_color = pal.accent;
    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.corner_radius = CornerRadius::same(9);
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, pal.hairline);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, pal.text);
    visuals.widgets.inactive.weak_bg_fill = pal.control;
    visuals.widgets.inactive.bg_fill = pal.control;
    visuals.widgets.hovered.weak_bg_fill = pal.control_hover;
    visuals.widgets.hovered.bg_fill = pal.control_hover;
    visuals.widgets.active.weak_bg_fill = pal.control_active;
    visuals.widgets.active.bg_fill = pal.control_active;
    visuals.widgets.open.weak_bg_fill = pal.control_hover;
    // Visible outlines, so checkboxes, radio buttons and text fields stand
    // out from the card behind them (egui's dark theme leaves them borderless).
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, pal.control_edge);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, pal.control_edge.lerp_to_gamma(pal.text, 0.25));
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, pal.accent);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.5, pal.text);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, pal.text);
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, pal.text);
    visuals
}

const ICON_SIZE: u32 = 128;
/// The mark as PNG, for the notification icon. Drawn by the build script.
pub const ICON_PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/phalanx.png"));
/// The mark as a multi-size icon file, for the Start-menu shortcut and taskbar.
pub const ICON_ICO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/phalanx.ico"));

/// The window and tray icon: the mark drawn in code, (RGBA pixels, width, height).
pub fn icon_rgba() -> (Vec<u8>, u32, u32) {
    (super::mark::mark_rgba(ICON_SIZE as usize, super::mark::Style::Icon), ICON_SIZE, ICON_SIZE)
}

pub fn page_header(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).font(bold(30.0)).extra_letter_spacing(-0.6).color(theme().text));
    ui.add_space(16.0);
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme().card)
        .stroke(Stroke::new(1.0, theme().hairline))
        .corner_radius(16.0)
        .inner_margin(Margin::same(20))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

pub fn section_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(semibold(16.0)).extra_letter_spacing(-0.1).color(theme().text));
}

pub fn muted(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).color(theme().muted));
}

pub fn small(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(12.0).color(theme().muted));
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
                    ui.label(RichText::new(*label).size(12.5).color(theme().muted));
                    ui.label(RichText::new(value).font(semibold(28.0)).extra_letter_spacing(-0.6).color(theme().text));
                });
            }
        });
    }
}

/// Label/value pairs that wrap onto more lines when narrow.
pub fn facts(ui: &mut Ui, items: &[(&str, String)]) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 20.0;
        for (label, value) in items {
            let mut job = egui::text::LayoutJob::default();
            let format = |font_id, color| egui::TextFormat { font_id, color, ..Default::default() };
            job.append(&format!("{label} "), 0.0, format(FontId::proportional(12.5), theme().muted));
            job.append(value, 0.0, format(semibold(12.5), theme().text));
            ui.label(job);
        }
    });
}

/// A button whose fill brightens on hover and dims while pressed, eased so
/// the change reads as light on a surface rather than a hard swap.
fn filled_button(ui: &mut Ui, text: RichText, fill: Color32, height: f32, radius: f32) -> egui::Response {
    let button = egui::Button::new(text).fill(fill).stroke(Stroke::NONE).corner_radius(radius).min_size(Vec2::new(0.0, height));
    let response = ui.add(button);
    if ui.is_enabled() && ui.is_rect_visible(response.rect) {
        let id = response.id.with("press");
        let target = if response.is_pointer_button_down_on() { -1.0 } else if response.hovered() { 1.0 } else { 0.0 };
        let t = super::motion::spring(ui.ctx(), id, target, 0.18, 1.0);
        if t.abs() > 0.001 {
            let overlay = if t > 0.0 { theme().hover.gamma_multiply(t) } else { theme().press.gamma_multiply(-t) };
            ui.painter().rect_filled(response.rect, radius, overlay);
        }
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn primary_button(ui: &mut Ui, text: &str) -> egui::Response {
    filled_button(ui, RichText::new(text).font(semibold(14.0)).color(Color32::WHITE), theme().accent, 36.0, 10.0)
}

pub fn secondary_button(ui: &mut Ui, text: &str) -> egui::Response {
    filled_button(ui, RichText::new(text).font(semibold(14.0)).color(theme().text), theme().control, 36.0, 10.0)
}

pub fn small_button(ui: &mut Ui, text: &str) -> egui::Response {
    filled_button(ui, RichText::new(text).size(12.5).color(theme().text), theme().control, 26.0, 8.0)
}

pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).font(semibold(14.0)).color(Color32::WHITE))
        .fill(theme().red.gamma_multiply(0.9))
        .stroke(Stroke::NONE)
        .corner_radius(10.0)
        .min_size(Vec2::new(0.0, 36.0))
}

/// A capsule toggle chip; the selected one is a light pill. Returns true when clicked.
pub fn chip(ui: &mut Ui, text: &str, active: bool) -> bool {
    let text = if active { RichText::new(text).font(semibold(13.0)).color(theme().bg) } else { RichText::new(text).size(13.0).color(theme().text) };
    filled_button(ui, text, if active { theme().text } else { theme().control }, 28.0, 14.0).clicked()
}

pub fn category_color(category: Category) -> Color32 {
    match category {
        Category::Malware => theme().red,
        Category::HackTool => theme().orange,
        Category::Pup => theme().amber,
        Category::Suspicious => theme().yellow,
    }
}

pub fn category_color_str(category: &str) -> Color32 {
    category.parse().map(category_color).unwrap_or(theme().muted)
}

pub fn badge(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .corner_radius(10.0)
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).font(semibold(11.0)).extra_letter_spacing(0.3).color(color));
        });
}

pub fn status_dot(ui: &mut Ui, color: Color32, radius: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(radius * 2.0 + 6.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius + 2.5, color.gamma_multiply(0.18));
    ui.painter().circle_filled(rect.center(), radius, color);
}

/// The dot spinner, in place of egui's arc.
pub fn spinner(ui: &mut Ui) -> egui::Response {
    super::dots::spinner(ui)
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
    truncated(ui, name, theme().text, 13.5);
    if !parent.is_empty() {
        truncated(ui, parent, theme().muted, 12.0);
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
/// The knob travels on a spring and stretches while pressed, like iOS.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> egui::Response {
    let size = Vec2::new(44.0, 26.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let enabled = ui.is_enabled();
    response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, ""));
    if ui.is_rect_visible(rect) {
        let ctx = ui.ctx().clone();
        let t = super::motion::spring(&ctx, response.id.with("on"), *on as u8 as f32, 0.28, 1.0);
        let pressed = response.is_pointer_button_down_on();
        let stretch = super::motion::spring(&ctx, response.id.with("press"), pressed as u8 as f32, 0.18, 1.0);
        let track = lerp_color(theme().control, theme().green, t);
        let (track, knob) = if enabled { (track, Color32::WHITE) } else { (track.gamma_multiply(0.45), theme().control_hover) };
        let radius = rect.height() / 2.0;
        ui.painter().rect_filled(rect, radius, track);
        let knob_r = radius - 2.5;
        let grow = stretch * 6.0;
        let left = egui::lerp((rect.left() + 2.5)..=(rect.right() - 2.5 - knob_r * 2.0 - grow), t);
        let knob_rect = egui::Rect::from_min_size(egui::pos2(left, rect.top() + 2.5), Vec2::new(knob_r * 2.0 + grow, knob_r * 2.0));
        ui.painter().rect_filled(knob_rect.translate(Vec2::new(0.0, 1.0)), knob_r, Color32::from_rgba_premultiplied(0, 0, 0, 60));
        ui.painter().rect_filled(knob_rect, knob_r, knob);
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
                ui.add(egui::Label::new(RichText::new(title).size(14.0).color(theme().text)).wrap());
                if !description.is_empty() {
                    ui.add(egui::Label::new(RichText::new(description).size(12.5).color(theme().muted)).wrap());
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
    ui.painter().hline(rect.x_range(), y, Stroke::new(1.0, theme().hairline));
    ui.add_space(8.0);
}

/// A group heading inside the settings page.
pub fn group_title(ui: &mut Ui, title: &str, description: &str) {
    section_title(ui, title);
    if !description.is_empty() {
        ui.add(egui::Label::new(RichText::new(description).size(12.5).color(theme().muted)).wrap());
    }
    ui.add_space(8.0);
}

/// One option of a single-choice list, drawn as a bordered row with a radio
/// circle; the whole row is clickable. Returns true when it was chosen.
pub fn choice_row(ui: &mut Ui, selected: bool, title: &str, description: &str) -> bool {
    let stroke = if selected { Stroke::new(1.5, theme().accent) } else { Stroke::new(1.0, theme().border) };
    let fill = if selected { theme().accent.gamma_multiply(0.10) } else { theme().control.gamma_multiply(0.5) };
    let response = egui::Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(12.0)
        .inner_margin(Margin::symmetric(14, 11))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), egui::Sense::hover());
                let c = rect.center();
                ui.painter().circle(c, 8.0, theme().control, Stroke::new(1.5, if selected { theme().accent } else { theme().control_edge }));
                if selected {
                    ui.painter().circle_filled(c, 4.0, theme().accent);
                }
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).color(theme().text));
                    if !description.is_empty() {
                        ui.add(egui::Label::new(RichText::new(description).size(12.5).color(theme().muted)).wrap());
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
        Status::Good => theme().green,
        Status::Attention => theme().amber,
        Status::Risk => theme().red,
        Status::Info | Status::Unknown => theme().muted,
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
            ui.add(egui::Label::new(RichText::new(check.title).strong().color(theme().text)).wrap());
            ui.add(egui::Label::new(RichText::new(&check.detail).size(13.0).color(check_color(check.status).lerp_to_gamma(theme().text, 0.35))).wrap());
            ui.add(egui::Label::new(RichText::new(check.why).size(12.0).color(theme().muted)).wrap());
            ui.horizontal_wrapped(|ui| {
                if let Some(fix) = &check.fix {
                    if small_button(ui, fix.label).clicked() {
                        action = Some(CheckAction::ApplyFix);
                    }
                }
                if (check.status != Status::Good || privacy)
                    && ui.add(egui::Link::new(RichText::new(check.link.label).size(12.5).color(theme().accent))).clicked()
                {
                    action = Some(CheckAction::OpenSettings);
                }
            });
        });
    });
    action
}

/// Score ring: percentage and level in a ring of dots.
pub fn score_badge(ui: &mut Ui, percent: u32) {
    super::dots::score_ring(ui, percent, score_color(percent), posture::level(percent));
}

pub fn verdict_color(verdict: threat_scanner::ai::Verdict) -> Color32 {
    use threat_scanner::ai::Verdict;
    match verdict {
        Verdict::Safe => theme().green,
        Verdict::Suspicious => theme().amber,
        Verdict::Malicious => theme().red,
        Verdict::Unknown => theme().muted,
    }
}

pub fn severity_color(severity: &str) -> Color32 {
    match severity {
        "high" => theme().red,
        "medium" => theme().orange,
        "low" => theme().yellow,
        _ => theme().muted,
    }
}

pub fn score_color(percent: u32) -> Color32 {
    match percent {
        85.. => theme().green,
        60..85 => theme().amber,
        _ => theme().red,
    }
}

/// A tinted callout with wrapped text.
pub fn notice(ui: &mut Ui, color: Color32, text: &str) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.3)))
        .corner_radius(12.0)
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).size(13.0).color(theme().text)).wrap());
        });
}
