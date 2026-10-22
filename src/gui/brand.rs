//! The Phalanx mark and wordmark, drawn in code so each appearance gets its
//! own version and nothing is a flattened image of the logo.
//!
//! The mark (see `mark.rs`) is rasterised once with 4×4 supersampling,
//! for the window icon and for the sidebar (one texture
//! per appearance: in dark mode the shield is lifted and given a bright rim
//! so it does not sink into the near-black sidebar). The wordmark is drawn
//! as strokes, letter by letter, in the logo's geometric style (the A has no
//! crossbar), so it stays sharp at any size and takes the theme's text colour.

use eframe::egui::{self, vec2, Color32, Pos2, Shape, Stroke, Ui, Vec2};
use std::f32::consts::{FRAC_PI_2, PI};

pub use super::mark::{part_at, shield_outline, Part, ASPECT};
use super::mark::{mark_rgba, Style};

/// The mark as textures, one per appearance.
pub struct Logo {
    dark: egui::TextureHandle,
    light: egui::TextureHandle,
}

const TEXTURE_SIZE: usize = 96;

impl Logo {
    pub fn new(ctx: &egui::Context) -> Self {
        let load = |name: &str, dark: bool| {
            let image = egui::ColorImage::from_rgba_unmultiplied([TEXTURE_SIZE; 2], &mark_rgba(TEXTURE_SIZE, if dark { Style::Dark } else { Style::Light }));
            ctx.load_texture(name, image, egui::TextureOptions::LINEAR)
        };
        Self { dark: load("phalanx-mark-dark", true), light: load("phalanx-mark-light", false) }
    }

    pub fn show(&self, ui: &mut Ui, size: f32) {
        let texture = if super::widgets::theme().dark { &self.dark } else { &self.light };
        ui.add(egui::Image::new(egui::load::SizedTexture::new(texture.id(), Vec2::splat(size))));
    }
}

/// "PHALANX" as strokes, `height` tall, in the logo's letterforms.
pub fn wordmark(ui: &mut Ui, height: f32, color: Color32) -> egui::Response {
    // Each glyph: its width (in units of the cap height) and its strokes.
    let p: Vec<Vec<Vec2>> = {
        let mut bowl = vec![vec2(0.0, 0.0), vec2(0.42, 0.0)];
        for i in 0..=12 {
            let a = -FRAC_PI_2 + PI * i as f32 / 12.0;
            bowl.push(vec2(0.42 + 0.27 * a.cos(), 0.27 + 0.27 * a.sin()));
        }
        bowl.push(vec2(0.0, 0.54));
        vec![vec![vec2(0.0, 1.0), vec2(0.0, 0.0)], bowl]
    };
    let h = vec![vec![vec2(0.0, 0.0), vec2(0.0, 1.0)], vec![vec2(0.78, 0.0), vec2(0.78, 1.0)], vec![vec2(0.0, 0.5), vec2(0.78, 0.5)]];
    let a = vec![vec![vec2(0.0, 1.0), vec2(0.43, 0.0), vec2(0.86, 1.0)]];
    let l = vec![vec![vec2(0.0, 0.0), vec2(0.0, 1.0), vec2(0.6, 1.0)]];
    let n = vec![vec![vec2(0.0, 1.0), vec2(0.0, 0.0), vec2(0.78, 1.0), vec2(0.78, 0.0)]];
    let x = vec![vec![vec2(0.0, 0.0), vec2(0.8, 1.0)], vec![vec2(0.8, 0.0), vec2(0.0, 1.0)]];
    let glyphs: [(f32, &Vec<Vec<Vec2>>); 7] = [(0.69, &p), (0.78, &h), (0.86, &a), (0.6, &l), (0.86, &a), (0.78, &n), (0.8, &x)];
    let gap = 0.34;
    let weight = 0.125;
    let total = glyphs.iter().map(|(w, _)| w).sum::<f32>() + gap * (glyphs.len() - 1) as f32 + weight;
    let (rect, response) = ui.allocate_exact_size(vec2(total * height, height + weight * height), egui::Sense::hover());
    let painter = ui.painter();
    let stroke = Stroke::new(weight * height, color);
    let origin: Pos2 = rect.min + Vec2::splat(weight * height / 2.0);
    let mut x0 = 0.0;
    for (width, strokes) in glyphs {
        for line in strokes.iter() {
            let points: Vec<Pos2> = line.iter().map(|v| origin + vec2(x0 + v.x, v.y) * height).collect();
            painter.add(Shape::line(points, stroke));
        }
        x0 += width + gap;
    }
    response
}
