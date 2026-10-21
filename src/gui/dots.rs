//! Dot-matrix graphics, after the Helarix site: a lattice of faint dots,
//! lit blue and cyan by activity and warm red where threats are. Used in a
//! few places only (the dashboard hero, the scan stage, the score ring and
//! the spinner). Motion runs while something is happening (an arrival, a
//! scan, the pointer, the protection pulse) and stops otherwise, so the app
//! is calm at rest and costs nothing when idle.

use super::motion;
use super::widgets::{semibold, theme};
use eframe::egui::{self, pos2, vec2, Align2, Color32, FontId, Pos2, Rect, Sense, Ui, Vec2};
use std::f32::consts::{PI, TAU};

type Rgb = [u8; 3];

/// Lattice pitch of the scan stage, in points.
const GAP: f32 = 8.0;
/// Lattice pitch of the dashboard hero, in points.
const HERO_GAP: f32 = 9.0;

fn rgba(c: Rgb, alpha: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(c[0], c[1], c[2], (alpha.clamp(0.0, 1.0) * 255.0) as u8)
}

fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let t = t.clamp(0.0, 1.0);
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    [m(a[0], b[0]), m(a[1], b[1]), m(a[2], b[2])]
}

fn rgb(c: Color32) -> Rgb {
    [c.r(), c.g(), c.b()]
}

/// The resting dot colour.
fn ink() -> Rgb {
    rgb(theme().ink)
}

/// The colour of a dot that just lit up: white on dark, the accent on light.
fn flash() -> Rgb {
    if theme().dark { [255, 255, 255] } else { rgb(theme().accent) }
}

fn smoothstep(x: f32) -> f32 {
    let x = x.clamp(0.0, 1.0);
    x * x * (3.0 - 2.0 * x)
}

/// Stable pseudo-random value in [0, 1) for an integer.
fn hash(n: u32) -> f32 {
    let mut x = n.wrapping_mul(0x9E37_79B1).wrapping_add(0x7F4A_7C15);
    x ^= x >> 15;
    x = x.wrapping_mul(0x85EB_CA77);
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2_AE3D);
    x ^= x >> 16;
    (x & 0x00FF_FFFF) as f32 / 16_777_216.0
}

/// Distance from `p` to the segment `a`–`b`.
fn segment_distance(p: Vec2, a: Vec2, b: Vec2) -> f32 {
    let ab = b - a;
    let t = ((p - a).dot(ab) / ab.length_sq().max(1e-6)).clamp(0.0, 1.0);
    (p - (a + ab * t)).length()
}

fn polyline_distance(p: Vec2, points: &[Vec2]) -> f32 {
    points.windows(2).map(|w| segment_distance(p, w[0], w[1])).fold(f32::MAX, f32::min)
}

fn rect_distance(rect: Rect, p: Pos2) -> f32 {
    let dx = (rect.left() - p.x).max(p.x - rect.right()).max(0.0);
    let dy = (rect.top() - p.y).max(p.y - rect.bottom()).max(0.0);
    (dx * dx + dy * dy).sqrt()
}

// ---------- 5×7 dot font ----------

/// One row per byte, leftmost dot in the highest of `width` bits.
fn glyph(ch: char) -> Option<(i32, [u8; 7])> {
    Some(match ch {
        '0' => (5, [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110]),
        '1' => (5, [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110]),
        '2' => (5, [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111]),
        '3' => (5, [0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110]),
        '4' => (5, [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010]),
        '5' => (5, [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110]),
        '6' => (5, [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110]),
        '7' => (5, [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000]),
        '8' => (5, [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110]),
        '9' => (5, [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100]),
        'K' => (5, [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001]),
        'M' => (5, [0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001]),
        ',' => (1, [0, 0, 0, 0, 0, 1, 1]),
        '.' => (1, [0, 0, 0, 0, 0, 0, 1]),
        _ => return None,
    })
}

/// Lit cells of `text` from (0, 0), one blank column between glyphs, and the total width.
fn text_cells(text: &str) -> (Vec<(i32, i32)>, i32) {
    let mut cells = Vec::new();
    let mut x = 0;
    for ch in text.chars() {
        let Some((width, rows)) = glyph(ch) else { continue };
        if x > 0 {
            x += 1;
        }
        for (y, bits) in rows.iter().enumerate() {
            for col in 0..width {
                if bits & (1 << (width - 1 - col)) != 0 {
                    cells.push((x + col, y as i32));
                }
            }
        }
        x += width;
    }
    (cells, x)
}

fn grouped(n: i64) -> String {
    let digits = n.max(0).to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn compact(n: i64) -> String {
    match n {
        1_000_000.. => format!("{:.1}M", n as f64 / 1e6),
        10_000.. => format!("{}K", n / 1000),
        _ => n.max(0).to_string(),
    }
}

struct Ripple {
    /// Centre, relative to the field's top-left corner.
    at: Vec2,
    born: f64,
    color: Rgb,
    strength: f32,
}

const RIPPLE_SPEED: f32 = 380.0;
const RIPPLE_WIDTH: f32 = 22.0;
const RIPPLE_LIFE: f32 = 1.6;

/// How far a ripple pushes the dot at `p`, and which way. Returns (displacement, strength, colour).
fn ripple_at(ripples: &[Ripple], origin: Pos2, p: Pos2, now: f64) -> (Vec2, f32, Rgb) {
    let (mut push, mut boost, mut tint, mut best) = (Vec2::ZERO, 0.0, [0, 0, 0], 0.0);
    for r in ripples {
        let age = (now - r.born) as f32;
        let d = p - (origin + r.at);
        let len = d.length().max(0.001);
        let k = (-((len - age * RIPPLE_SPEED) / RIPPLE_WIDTH).powi(2)).exp() * r.strength * (1.0 - age / RIPPLE_LIFE).max(0.0).powi(2);
        push += d / len * k * 6.0;
        boost += k;
        if k > best {
            (tint, best) = (r.color, k);
        }
    }
    (push, boost, tint)
}

// ---------- the scan stage ----------

#[derive(Clone, Copy, PartialEq)]
pub enum Outcome {
    Clean,
    Threats,
    Cancelled,
}

pub enum StageMode {
    Scanning { files: i64, threats: usize, cancelling: bool },
    Done(Outcome),
}

struct ThreatDot {
    col: i32,
    row: i32,
    born: f64,
}

/// The live scan: the lattice unfolds from the centre, a beam sweeps it,
/// every file scanned sparks a dot in its wake, the running file count is
/// written in lifted dots, and each threat lands as a red cluster with a
/// shockwave. When the scan ends the dots gather into a check mark, an alert
/// or a dash. The pointer bends the dots around it, and a click sends a ripple.
#[derive(Default)]
pub struct ScanStage {
    run: u64,
    born: f64,
    cols: i32,
    rows: i32,
    heat: Vec<f32>,
    flash: Vec<f32>,
    digit: Vec<f32>,
    threats: Vec<ThreatDot>,
    ripples: Vec<Ripple>,
    files_seen: i64,
    threats_seen: usize,
    /// The count as drawn; rolls towards the real one.
    shown: f64,
    beam: f32,
    done: Option<(Outcome, f64)>,
    landed: bool,
    pointer: Option<Pos2>,
    lens: f32,
    last: f64,
    seed: u32,
}

impl ScanStage {
    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        hash(self.seed)
    }

    fn index(&self, col: i32, row: i32) -> Option<usize> {
        (col >= 0 && row >= 0 && col < self.cols && row < self.rows).then(|| (row * self.cols + col) as usize)
    }

    /// A random cell away from the edges and the counter.
    fn free_cell(&mut self) -> (i32, i32) {
        let mut best = (self.cols / 4, self.rows / 2);
        for _ in 0..16 {
            let col = 2 + (self.rand() * (self.cols - 4).max(1) as f32) as i32;
            let row = 2 + (self.rand() * (self.rows - 4).max(1) as f32) as i32;
            best = (col, row);
            let clear = (-2..=2).all(|dr| (-3..=3).all(|dc| self.index(col + dc, row + dr).is_none_or(|i| self.digit[i] < 0.05)));
            if clear {
                break;
            }
        }
        best
    }

    /// `run` identifies the scan; a new value starts a fresh stage.
    pub fn show(&mut self, ui: &mut Ui, run: u64, mode: StageMode) {
        let width = ui.available_width();
        let height = if width < 520.0 { 220.0 } else { 280.0 };
        let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
        let now = ui.input(|i| i.time);
        let still = motion::reduced_motion();
        if run != self.run {
            *self = Self { run, born: now, seed: run as u32 ^ 0x5EED, last: now, ..Default::default() };
        }
        let dt = (now - self.last).clamp(0.0, 0.05) as f32;
        self.last = now;
        let age = (now - self.born) as f32;

        let cols = ((rect.width() - 20.0) / GAP).floor() as i32 + 1;
        let rows = ((rect.height() - 20.0) / GAP).floor() as i32 + 1;
        if cols != self.cols || rows != self.rows {
            let n = (cols.max(1) * rows.max(1)) as usize;
            (self.cols, self.rows) = (cols, rows);
            self.heat = vec![0.0; n];
            self.flash = vec![0.0; n];
            self.digit = vec![0.0; n];
            self.threats.retain(|t| t.col < cols && t.row < rows);
        }
        let origin = rect.center() - vec2((cols - 1) as f32 * GAP, (rows - 1) as f32 * GAP) / 2.0;
        let cell = |col: i32, row: i32| origin + vec2(col as f32 * GAP, row as f32 * GAP);

        let (files, threats, cancelling) = match mode {
            StageMode::Scanning { files, threats, cancelling } => (files, threats, cancelling),
            StageMode::Done(outcome) => {
                if self.done.is_none() {
                    self.done = Some((outcome, now));
                }
                (self.files_seen, self.threats_seen, false)
            }
        };

        // ---- scanning: beam, sparks, threats ----
        if self.done.is_none() {
            // The beam waits for the lattice to unfold.
            if age > 0.5 || still {
                self.beam = (self.beam + dt * if cancelling { 0.08 } else { 0.36 }).fract();
            }
            let front = self.beam * (cols as f32 + 16.0) - 8.0;
            let strength = if cancelling { 0.35 } else { 0.9 };
            for row in 0..rows {
                // A slow wave in the front, so it reads as a liquid sweep rather than a ruler.
                let x = front + 1.6 * (row as f32 * 0.32 + now as f32 * 1.1).sin();
                for col in (x - 1.5).floor() as i32..=(x + 1.0).ceil() as i32 {
                    if let Some(i) = self.index(col, row) {
                        let v = (1.0 - (col as f32 - x).abs() / 1.5).max(0.0) * strength;
                        self.heat[i] = self.heat[i].max(v);
                    }
                }
            }
            // Each file scanned sparks a dot in the beam's wake (a few per frame at most).
            for _ in 0..(files - self.files_seen).clamp(0, 6) {
                let col = (front - self.rand() * 14.0).round() as i32;
                let row = (self.rand() * rows as f32) as i32;
                if let Some(i) = self.index(col, row) {
                    self.flash[i] = 1.0;
                    self.heat[i] = self.heat[i].max(0.6);
                }
            }
            self.files_seen = files;
            while self.threats_seen < threats {
                self.threats_seen += 1;
                let (col, row) = self.free_cell();
                self.threats.push(ThreatDot { col, row, born: now });
                self.ripples.push(Ripple { at: cell(col, row) - rect.min, born: now, color: rgb(theme().red), strength: 1.0 });
            }
            self.threats.truncate(40);
        }

        let settled = self.done.is_some();
        let (heat_decay, flash_decay) = if settled { (5.0, 8.0) } else { (1.6, 6.0) };
        let (kh, kf) = ((-dt * heat_decay).exp(), (-dt * flash_decay).exp());
        self.heat.iter_mut().for_each(|h| *h *= kh);
        self.flash.iter_mut().for_each(|f| *f *= kf);

        // ---- the counter, in lifted dots ----
        let target = self.files_seen as f64;
        self.shown += (target - self.shown) * (1.0 - (-(dt as f64) * 7.0).exp());
        if still || (target - self.shown).abs() < 0.5 {
            self.shown = target;
        }
        let mut lit = vec![false; self.digit.len()];
        let (mut digits_bottom, mut digits_shown) = (0.0, false);
        if !settled {
            let mut text = grouped(self.shown.round() as i64);
            if text_cells(&text).1 > cols - 6 {
                text = compact(self.shown.round() as i64);
            }
            let (cells, w) = text_cells(&text);
            if w <= cols - 2 {
                let (x0, y0) = ((cols - w) / 2, (rows - 7) / 2 - 1);
                for (x, y) in cells {
                    if let Some(i) = self.index(x0 + x, y0 + y) {
                        lit[i] = true;
                    }
                }
                digits_bottom = cell(0, y0 + 6).y;
                digits_shown = true;
            }
        }
        let rate = if still { 1.0 } else { 1.0 - (-dt * 16.0).exp() };
        for (d, on) in self.digit.iter_mut().zip(&lit) {
            *d += (*on as u8 as f32 - *d) * rate;
        }

        // ---- the pointer ----
        let hover = response.hover_pos();
        let previous = self.pointer;
        if let Some(pt) = hover {
            self.pointer = Some(match self.pointer {
                Some(q) if self.lens > 0.01 => q + (pt - q) * (1.0 - (-dt * 18.0).exp()),
                _ => pt,
            });
        }
        let lens_before = self.lens;
        self.lens += (hover.is_some() as u8 as f32 - self.lens) * (1.0 - (-dt * 10.0).exp());
        if response.clicked() {
            if let Some(pt) = hover {
                self.ripples.push(Ripple { at: pt - rect.min, born: now, color: rgb(theme().accent), strength: 0.8 });
            }
        }
        if still {
            self.lens = 0.0;
            self.ripples.clear();
        }
        self.ripples.retain(|r| ((now - r.born) as f32) < RIPPLE_LIFE);

        // ---- the closing glyph ----
        let glyph = self.done.map(|(outcome, since)| (outcome, (now - since) as f32));
        if let Some((outcome, t)) = glyph {
            if t > 0.8 && !self.landed {
                self.landed = true;
                let color = rgb(outcome_color(outcome));
                self.ripples.push(Ripple { at: rect.center() - rect.min, born: now, color, strength: 0.6 });
            }
        }

        // ---- draw ----
        let pal = theme();
        let (ink, flash, blue, cyan, red) = (ink(), flash(), rgb(pal.accent), rgb(pal.cyan), rgb(pal.red));
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 18.0, pal.stage);
        if !pal.dark {
            painter.rect_stroke(rect, 18.0, egui::Stroke::new(1.0, pal.hairline), egui::StrokeKind::Inside);
        }
        let pulse_on = !settled && !still;
        let threat_fade = match glyph {
            Some((_, t)) => 1.0 - motion::settle(t, 0.5),
            None => 1.0,
        };
        let reach = (rect.width().hypot(rect.height())) / 2.0;
        for row in 0..rows {
            for col in 0..cols {
                let i = (row * cols + col) as usize;
                let mut pt = cell(col, row);
                // The lattice unfolds from the centre when a scan starts.
                let unfold = motion::settle(age - 0.05 - (pt - rect.center()).length() / reach * 0.45, 0.5);
                if unfold <= 0.0 {
                    continue;
                }
                let (push, boost, tint) = ripple_at(&self.ripples, rect.min, pt, now);
                pt += push;
                let mut lens = 0.0;
                if let Some(q) = self.pointer.filter(|_| self.lens > 0.001) {
                    let d = pt - q;
                    let len = d.length().max(0.001);
                    if len < 84.0 {
                        lens = (1.0 - len / 84.0).powi(2) * self.lens;
                        pt += d / len * lens * 5.0;
                    }
                }
                let (h, f, dg) = (self.heat[i], self.flash[i], self.digit[i]);
                let mut threat = 0.0f32;
                for t in &self.threats {
                    let d = (((col - t.col).pow(2) + (row - t.row).pow(2)) as f32).sqrt();
                    if d < 2.3 {
                        let appear = motion::settle((now - t.born) as f32, 0.35);
                        let pulse = if pulse_on { 0.82 + 0.18 * (now as f32 * 3.0 + t.col as f32).sin() } else { 1.0 };
                        threat = threat.max((1.0 - d / 2.3) * appear * pulse);
                    }
                }
                threat *= threat_fade;

                let mut color = if h < 0.02 { ink } else { mix(blue, cyan, h) };
                let mut alpha = pal.dot_alpha + 0.8 * h;
                let mut radius = 0.85 + 1.2 * h;
                color = mix(color, flash, f);
                alpha = alpha.max(f);
                radius += 0.8 * f;
                if threat > 0.0 {
                    color = mix(color, red, threat * 1.4);
                    alpha = alpha.max(0.25 + 0.75 * threat);
                    radius = radius.max(0.9 + 1.7 * threat);
                }
                if dg > 0.0 {
                    color = mix(color, mix(ink, cyan, h * 0.6), dg);
                    alpha += (0.95 - alpha) * dg;
                    radius += (2.4 + 0.4 * h - radius) * dg;
                }
                color = mix(color, tint, (boost * 0.8).min(0.7));
                alpha += boost * 0.5 + lens * 0.3;
                radius += boost * 1.1 + lens * 1.2;
                if alpha > 0.02 {
                    painter.circle_filled(pt, radius * (0.4 + 0.6 * unfold), rgba(color, alpha * unfold));
                }
            }
        }
        if digits_shown {
            let alpha = self.digit.iter().copied().fold(0.0, f32::max);
            painter.text(
                pos2(rect.center().x, digits_bottom + 18.0),
                Align2::CENTER_TOP,
                "Files scanned",
                FontId::proportional(12.5),
                rgba(rgb(pal.muted), alpha),
            );
        }
        if let Some((outcome, t)) = glyph {
            self.paint_glyph(&painter, rect.center(), outcome, t);
        }

        // ---- keep moving only while something moves ----
        let pointer_moving = match (previous, self.pointer) {
            (Some(a), Some(b)) => (a - b).length() > 0.05,
            _ => false,
        };
        let animating = !settled
            || age < 1.2
            || glyph.is_some_and(|(_, t)| t < 2.6)
            || !self.ripples.is_empty()
            || pointer_moving
            || (self.lens - lens_before).abs() > 0.0005
            || self.digit.iter().zip(&lit).any(|(d, on)| (*d - *on as u8 as f32).abs() > 0.01);
        if animating && !(still && settled) {
            ui.ctx().request_repaint();
        }
    }

    /// The closing mark: a ring of dots drawn around, and the symbol's dots
    /// lifted from random places on the lattice into position.
    fn paint_glyph(&self, painter: &egui::Painter, center: Pos2, outcome: Outcome, t: f32) {
        let color = rgb(outcome_color(outcome));
        let half = (self.rows as f32 * 0.36).max(5.0);
        let (gc, gr) = ((self.cols - 1) as f32 / 2.0, (self.rows - 1) as f32 / 2.0);
        let s = half; // symbol units → cells
        let symbol: Vec<Vec<Vec2>> = match outcome {
            Outcome::Clean => vec![vec![vec2(-0.52, 0.02) * s, vec2(-0.16, 0.38) * s, vec2(0.55, -0.36) * s]],
            Outcome::Threats => vec![vec![vec2(0.0, -0.52) * s, vec2(0.0, 0.12) * s], vec![vec2(0.0, 0.46) * s, vec2(0.0, 0.47) * s]],
            Outcome::Cancelled => vec![vec![vec2(-0.45, 0.0) * s, vec2(0.45, 0.0) * s]],
        };
        let origin = center - vec2(gc, gr) * GAP;
        for row in 0..self.rows {
            for col in 0..self.cols {
                let rel = vec2(col as f32 - gc, row as f32 - gr);
                let i = (row * self.cols + col) as u32;
                let on_ring = (rel.length() - half).abs() < 0.55;
                let on_symbol = symbol.iter().any(|line| polyline_distance(rel, line) < 1.05);
                if !on_ring && !on_symbol {
                    continue;
                }
                let delay = if on_symbol {
                    0.35 + 0.35 * hash(i ^ 0xA11)
                } else {
                    let angle = (rel.y.atan2(rel.x) + PI / 2.0).rem_euclid(TAU) / TAU;
                    0.05 + 0.5 * angle
                };
                let k = motion::settle(t - delay, 0.6);
                if k <= 0.0 {
                    continue;
                }
                let target = origin + vec2(col as f32, row as f32) * GAP;
                let from = origin + vec2(hash(i ^ 0xB0B) * self.cols as f32, hash(i ^ 0xC0C) * self.rows as f32).floor() * GAP;
                let at = if on_symbol { from + (target - from) * k } else { target };
                let (radius, alpha) = if on_symbol { (1.0 + 1.6 * k, 0.3 + 0.7 * k) } else { (0.5 + 1.0 * k, 0.55 * k) };
                painter.circle_filled(at, radius, rgba(color, alpha));
            }
        }
    }
}

fn outcome_color(outcome: Outcome) -> Color32 {
    match outcome {
        Outcome::Clean => theme().green,
        Outcome::Threats => theme().red,
        Outcome::Cancelled => theme().amber,
    }
}

// ---------- the dashboard hero ----------

/// A scan in progress, as the hero shows it.
pub struct HeroScan {
    pub files: i64,
    pub threats: usize,
}

pub struct HeroStatus {
    pub color: Color32,
    /// Real-time protection is running: the field pulses outward from the shield.
    pub live: bool,
    /// Unresolved threats, shown as warm embers around the shield.
    pub threats: usize,
    /// A scan is running: the shield holds still and takes the arrows.
    pub scan: Option<HeroScan>,
}

/// Seconds between protection pulses, and how long one is visible.
const PULSE_EVERY: f32 = 5.0;
const PULSE_LIFE: f32 = 2.4;
/// Distance to the viewer, in points: smaller gives a stronger perspective.
const FOCAL: f32 = 1100.0;
/// How fast an arrow crosses the field, in points per second.
const ARROW_SPEED: f32 = 820.0;
/// An arrow's length, in lattice cells.
const ARROW_CELLS: i32 = 7;

#[derive(Clone, Copy)]
struct V3 {
    x: f32,
    y: f32,
    z: f32,
}

fn v3(x: f32, y: f32, z: f32) -> V3 {
    V3 { x, y, z }
}

impl V3 {
    fn add(self, o: V3) -> V3 {
        v3(self.x + o.x, self.y + o.y, self.z + o.z)
    }
    fn scale(self, k: f32) -> V3 {
        v3(self.x * k, self.y * k, self.z * k)
    }
    fn dot(self, o: V3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }
    fn normalized(self) -> V3 {
        self.scale(1.0 / self.dot(self).sqrt().max(1e-6))
    }
    /// Turns about the vertical axis (`yaw`), then tips about the horizontal one (`pitch`).
    fn turned(self, yaw: f32, pitch: f32) -> V3 {
        let (sy, cy) = yaw.sin_cos();
        let (x, z) = (self.x * cy + self.z * sy, -self.x * sy + self.z * cy);
        let (sp, cp) = pitch.sin_cos();
        v3(x, self.y * cp - z * sp, self.y * sp + z * cp)
    }
}

fn shade(c: Rgb, k: f32) -> Rgb {
    let m = |x: u8| (x as f32 * k).clamp(0.0, 255.0) as u8;
    [m(c[0]), m(c[1]), m(c[2])]
}

/// One shield dot, ready to paint back to front.
struct Particle {
    depth: f32,
    at: Pos2,
    radius: f32,
    color: Rgb,
    alpha: f32,
}

/// A file, as an arrow flying in from the right along one row of the
/// lattice, and how far across the shield's face it strikes (0 at the
/// shield's right edge, 1 at its middle).
struct Arrow {
    born: f64,
    row: i32,
    depth: f32,
    threat: bool,
}

/// A spark knocked off the shield by a blocked arrow.
struct Spark {
    at: Pos2,
    velocity: Vec2,
    born: f64,
}

/// A threat's arrow, stuck in the shield's face where it struck (offset
/// from the shield's centre).
struct Stuck {
    at: Vec2,
    born: f64,
}

/// The dashboard's open field of dots, with no frame: it fades out at its
/// edges into the window. Out of it rises the logo's shield, built of dots
/// with real depth: a curved face with the P standing proud of it.
///
/// - On arrival every shield dot flies in from somewhere in the field on a
///   curved path; the P's dots arrive last, so the letter writes itself in.
/// - The shield turns to face the pointer wherever it is in the window, and
///   is lit from the upper left: as it turns, a sheen slides across the face
///   and the P catches the light. At rest it sways very slightly.
/// - During a scan it holds still and takes the hits. Every file is an
///   arrow of dots that runs in from the right along a row of the lattice,
///   in volleys, faster as the scan speeds up, and strikes the face. A
///   clean file breaks on it: the face flares where it was struck, the
///   shield gives a little and sparks fall away. A threat is a red arrow
///   that sticks, its shaft left standing out of the face, with a red
///   shockwave across the field. When the scan ends the shield flashes the
///   result colour; stuck arrows stay until the next scan.
/// - Dots part around the pointer; clicking the shield bursts it and it
///   springs back together; clicking the field sends a ripple. While
///   real-time protection runs, a pulse leaves the shield every few seconds.
#[derive(Default)]
pub struct Hero {
    cols: i32,
    rows: i32,
    /// Pointer displacement per field dot, eased.
    offsets: Vec<Vec2>,
    born: Option<f64>,
    burst: Option<f64>,
    ripples: Vec<Ripple>,
    last: f64,
    seed: u32,
    /// The status colour as drawn; eases towards the real one.
    color: Option<[f32; 3]>,
    files_seen: i64,
    threats_seen: usize,
    /// Files per second, smoothed, and arrows owed to the volley.
    rate: f32,
    owed: f32,
    threats_due: usize,
    arrows: Vec<Arrow>,
    sparks: Vec<Spark>,
    stuck: Vec<Stuck>,
    /// Where arrows struck the face (offset from the centre), when, and
    /// whether it was a threat.
    impacts: Vec<(Vec2, f64, bool)>,
    /// How hard the last arrows knocked the shield, easing off.
    recoil: f32,
    /// A scan ran since the shield last flashed its result, and when it did.
    scanned: bool,
    flashed: Option<f64>,
    /// The dots of the shield (offset from its centre, on the P or not, how
    /// far down, and an index for randomness), which field dots it covers,
    /// and how far right the shield reaches on each lattice row, for the
    /// layout they were computed for.
    shield_dots: Vec<(Vec2, bool, f32, u32)>,
    covered: Vec<bool>,
    reach: Vec<Option<f32>>,
    cells_for: Option<[i32; 5]>,
}

impl Hero {
    fn rand(&mut self) -> f32 {
        self.seed = self.seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        hash(self.seed)
    }

    /// Draws the field in `rect`, the shield centred on `center` and `half`
    /// points from its middle to its top, keeping the dots under `clear`
    /// (the headline and buttons) faint so the text stays legible.
    pub fn show(&mut self, ui: &mut Ui, rect: Rect, center: Pos2, half: f32, clear: Rect, status: HeroStatus) {
        let ctx = ui.ctx().clone();
        let response = ui.interact(rect, ui.id().with("hero-field"), Sense::click());
        let now = ui.input(|i| i.time);
        let still = motion::reduced_motion();
        let dt = (now - self.last).clamp(0.0, 0.05) as f32;
        self.last = now;
        let age = (now - *self.born.get_or_insert(now)) as f32;
        let goal = [status.color.r() as f32, status.color.g() as f32, status.color.b() as f32];
        let eased = self.color.get_or_insert(goal);
        let k = if still { 1.0 } else { 1.0 - (-dt * 5.0).exp() };
        for (c, g) in eased.iter_mut().zip(goal) {
            *c += (g - *c) * k;
        }
        let base: Rgb = [eased[0] as u8, eased[1] as u8, eased[2] as u8];

        let cols = (rect.width() / HERO_GAP).floor() as i32 + 1;
        let rows = (rect.height() / HERO_GAP).floor() as i32 + 1;
        let count = (cols * rows).max(0) as usize;
        if cols != self.cols || rows != self.rows {
            (self.cols, self.rows) = (cols, rows);
            self.offsets = vec![Vec2::ZERO; count];
        }
        let origin = rect.center() - vec2((cols - 1) as f32, (rows - 1) as f32) * HERO_GAP / 2.0;
        let cell = |i: usize| origin + vec2((i as i32 % cols) as f32, (i as i32 / cols) as f32) * HERO_GAP;
        let cell_at = |col: i32, row: i32| origin + vec2(col as f32, row as f32) * HERO_GAP;
        let row_of = |y: f32| ((y - origin.y) / HERO_GAP).round() as i32;
        let col_of = |x: f32| ((x - origin.x) / HERO_GAP).round() as i32;

        // The shield is the logo's: its outline and its P, sampled on the
        // lattice once per layout.
        let layout = [cols, rows, (center.x - rect.left()) as i32, (center.y - rect.top()) as i32, half as i32];
        if self.cells_for != Some(layout) {
            let outline = super::brand::shield_outline();
            let mark_width = 2.0 * half / super::brand::ASPECT;
            let mark_origin = center - vec2(mark_width / 2.0, half);
            self.shield_dots.clear();
            self.covered = vec![false; count];
            self.reach = vec![None; rows.max(0) as usize];
            for i in 0..count {
                let u = (cell(i) - mark_origin) / mark_width;
                if let Some(part) = super::brand::part_at(&outline, [u.x, u.y]) {
                    self.covered[i] = true;
                    let letter = part == super::brand::Part::Letter;
                    let local = cell(i) - center;
                    self.shield_dots.push((local, letter, u.y / super::brand::ASPECT, i as u32));
                    let row = i / cols as usize;
                    self.reach[row] = Some(self.reach[row].map_or(local.x, |r: f32| r.max(local.x)));
                }
            }
            self.cells_for = Some(layout);
        }
        let mark_half_width = half / super::brand::ASPECT;
        let depth = 0.26 * half;
        // How far a point on the shield's face stands out towards the viewer.
        let face_z = |local: Vec2, letter: bool| -> f32 {
            let u = (local.x / mark_half_width).clamp(-1.0, 1.0);
            let w = (local.y / half).clamp(-1.0, 1.0);
            -depth * (1.0 - u * u) - 0.25 * depth * (1.0 - w * w) - if letter { 0.09 * half } else { 0.0 }
        };

        // ---- the scan ----
        let blend = motion::spring(&ctx, ui.id().with("hero-scan"), status.scan.is_some() as u8 as f32, 0.8, 1.0);
        let scan_on = blend.clamp(0.0, 1.0);
        let e = smoothstep(blend);
        match &status.scan {
            Some(scan) => {
                if !self.scanned {
                    self.stuck.clear();
                }
                let new = if self.files_seen == 0 { 0 } else { (scan.files - self.files_seen).max(0) };
                let instant = new as f32 / dt.max(1.0 / 240.0);
                self.rate += (instant - self.rate) * (1.0 - (-dt * 1.5).exp());
                self.threats_due += scan.threats.saturating_sub(self.threats_seen);
                self.threats_seen = scan.threats;
                self.files_seen = scan.files.max(1);
                self.scanned = true;
                // One arrow stands for many files when the scan is fast, so
                // the volleys stay readable rather than a blur.
                if !still && blend > 0.6 {
                    self.owed += dt * (self.rate / 45.0).clamp(4.0, 14.0);
                }
            }
            None => {
                // Threats found too late to fly are lodged straight away.
                for _ in 0..self.threats_due {
                    let at = vec2((0.1 + 0.5 * self.rand()) * mark_half_width, (self.rand() - 0.6) * 1.1 * half);
                    self.stuck.push(Stuck { at, born: now });
                }
                self.files_seen = 0;
                self.threats_seen = 0;
                self.threats_due = 0;
                self.owed = 0.0;
                self.rate *= (-dt * 2.0).exp();
                // The volley is over: the shield flashes the result and a ripple rolls out.
                if self.scanned && self.arrows.is_empty() && blend < 0.3 {
                    self.scanned = false;
                    self.flashed = Some(now);
                    self.ripples.push(Ripple { at: center - rect.min, born: now, color: base, strength: 1.0 });
                }
            }
        }
        // Arrows come in on the rows the shield covers, its upper part most.
        let shield_rows: Vec<i32> = (0..rows).filter(|&r| self.reach.get(r as usize).copied().flatten().is_some()).collect();
        while self.owed >= 1.0 && !shield_rows.is_empty() {
            self.owed -= 1.0;
            let threat = self.threats_due > 0;
            if threat {
                self.threats_due -= 1;
            }
            let pick = (self.rand().powf(1.3) * shield_rows.len() as f32 * 0.85) as usize;
            let row = shield_rows[pick.min(shield_rows.len() - 1)];
            let depth = 0.2 + 0.6 * self.rand();
            self.arrows.push(Arrow { born: now, row, depth, threat });
        }
        self.owed = self.owed.min(3.0);
        self.recoil *= (-dt * 8.0).exp();
        let glow = self.flashed.map_or(0.0, |f| (-((now - f) as f32) * 3.0).exp());
        if glow < 0.01 {
            self.flashed = None;
        }

        // ---- the camera: the shield faces the pointer; during a scan it holds still ----
        let pointer_anywhere = ctx.pointer_latest_pos().filter(|_| ctx.input(|i| i.pointer.has_pointer()));
        let (px, py) = pointer_anywhere
            .map(|q| (((q.x - center.x) / (rect.width() * 0.55)).clamp(-1.0, 1.0), ((q.y - center.y) / (rect.height() * 0.7)).clamp(-1.0, 1.0)))
            .unwrap_or((0.0, 0.0));
        let (px, py) = if still { (0.0, 0.0) } else { (px, py) };
        let yaw = motion::spring(&ctx, ui.id().with("hero-yaw"), -px * 0.42, 0.8, 1.0);
        let pitch = motion::spring(&ctx, ui.id().with("hero-pitch"), py * 0.3, 0.8, 1.0);
        let sway = if still { 0.0 } else { 1.0 - scan_on };
        let t = now as f32;
        // Each hit turns it a touch away from the arrows, and it comes back.
        let give = self.recoil.min(1.5);
        let yaw = yaw * (1.0 - e) + 0.07 * (t * 0.45).sin() * sway + 0.035 * give;
        let pitch = pitch * (1.0 - e) + 0.035 * (t * 0.31).sin() * sway;
        let knock = vec2(-3.0 * give, 0.0);
        let light = v3(-0.45, -0.65, -1.0).normalized();
        let half_vector = light.add(v3(0.0, 0.0, -1.0)).normalized();
        let project = |p: V3| {
            let p = p.add(v3(knock.x, knock.y, 0.0)).turned(yaw, pitch);
            let s = FOCAL / (FOCAL + p.z).max(200.0);
            (p.z, center + vec2(p.x, p.y) * s, s)
        };
        // Where an arrow on `row` strikes the face, `depth` of the way in from the right edge.
        let strike = |row: i32, depth: f32| -> Option<Vec2> {
            let edge = self.reach.get(row as usize).copied().flatten()?;
            Some(vec2(edge * (1.0 - depth), cell_at(0, row).y - center.y))
        };

        // ---- arrows ----
        let pal = theme();
        let (ink, red, cyan) = (ink(), rgb(pal.red), rgb(pal.cyan));
        let start_x = rect.right() - 14.0;
        let mut landed = Vec::new();
        for (index, arrow) in self.arrows.iter().enumerate() {
            let x = start_x - ARROW_SPEED * (now - arrow.born) as f32;
            match strike(arrow.row, arrow.depth) {
                Some(hit) if x <= center.x + hit.x => landed.push((index, hit)),
                None => landed.push((index, vec2(0.0, 0.0))),
                _ => {}
            }
        }
        for &(index, hit) in &landed {
            let threat = self.arrows[index].threat;
            let at = center + hit + knock;
            self.impacts.push((hit, now, threat));
            self.recoil = (self.recoil + 0.5).min(2.0);
            if threat {
                self.stuck.push(Stuck { at: hit, born: now });
                self.ripples.push(Ripple { at: at - rect.min, born: now, color: red, strength: 1.0 });
            } else {
                // Broken on the shield: sparks fly back and fall.
                for _ in 0..6 {
                    let velocity = vec2(70.0 + 170.0 * self.rand(), -60.0 - 170.0 * self.rand());
                    self.sparks.push(Spark { at, velocity, born: now });
                }
            }
        }
        let mut index = 0;
        self.arrows.retain(|_| {
            index += 1;
            !landed.iter().any(|(i, _)| *i == index - 1)
        });
        for spark in &mut self.sparks {
            spark.velocity.y += 560.0 * dt;
            spark.at += spark.velocity * dt;
        }
        self.sparks.retain(|s| now - s.born < 0.6);
        self.impacts.retain(|(_, born, _)| now - born < 0.4);
        self.stuck.truncate(14);

        // ---- pointer, click, burst ----
        let pointer = response.hover_pos();
        if response.clicked() {
            if let Some(pt) = pointer {
                if (pt - center).x.abs() < half && (pt - center).y.abs() < half && blend < 0.1 {
                    self.burst = Some(now);
                } else {
                    self.ripples.push(Ripple { at: pt - rect.min, born: now, color: base, strength: 0.9 });
                }
            }
        }
        if still {
            self.ripples.clear();
            self.burst = None;
        }
        self.ripples.retain(|r| ((now - r.born) as f32) < RIPPLE_LIFE);
        let burst = self.burst.map(|b| (now - b) as f32).filter(|t| *t < 1.6);
        if burst.is_none() {
            self.burst = None;
        }
        let pulse_t = (age - 2.6).rem_euclid(PULSE_EVERY);
        let pulsing = status.live && status.scan.is_none() && !still && age > 2.6 && pulse_t < PULSE_LIFE;

        let painter = ui.painter_at(rect);
        let mut moving = false;
        let follow = if still { 1.0 } else { 1.0 - (-dt * 14.0).exp() };
        const REACH: f32 = 72.0;

        // ---- the field ----
        for i in 0..count {
            if self.covered[i] {
                continue;
            }
            let n = i as u32;
            let home = cell(i);
            // Parts around the pointer like water, and springs back.
            let mut target = Vec2::ZERO;
            if let Some(q) = pointer.filter(|_| !still) {
                let d = home - q;
                let len = d.length();
                if len < REACH {
                    target = d / len.max(0.001) * (1.0 - len / REACH).powi(2) * 16.0;
                }
            }
            let offset = &mut self.offsets[i];
            *offset += (target - *offset) * follow;
            if offset.length_sq() < 0.0025 && target == Vec2::ZERO {
                *offset = Vec2::ZERO;
            } else {
                moving = true;
            }
            let mut pt = home + *offset;
            let (push, boost, tint) = ripple_at(&self.ripples, rect.min, pt, now);
            pt += push;
            let mut pulse = 0.0;
            if pulsing {
                let d = (home - center).length();
                let wave = pulse_t * 330.0;
                let fade = (1.0 - pulse_t / PULSE_LIFE).powf(1.5);
                pulse = ((-((d - wave) / 30.0).powi(2)).exp() + 0.4 * (-((d - wave + 70.0) / 26.0).powi(2)).exp()) * fade;
                pt += (home - center) / d.max(1.0) * pulse * 4.0;
            }
            // Fades at the field's edges and under the headline.
            let edge_x = (home.x - rect.left()).min(rect.right() - home.x) / 90.0;
            let edge_y = (home.y - rect.top()).min(rect.bottom() - home.y) / 70.0;
            let mut alpha = pal.dot_alpha * 1.4 * smoothstep(edge_x.min(edge_y));
            let under_text = smoothstep(rect_distance(clear, home) / 46.0);
            alpha *= 0.15 + 0.85 * under_text;
            let mut color = ink;
            let mut radius = 0.95;
            // Unresolved threats: a few warm embers close around the shield.
            let around = (home - center).length() / half;
            if status.threats > 0 && status.scan.is_none() && under_text > 0.9 && (1.1..1.7).contains(&around) && hash(n ^ 0xE3) < status.threats.min(6) as f32 / 700.0 {
                color = red;
                alpha = 0.8 * (1.0 - scan_on);
                radius = 2.0 + hash(n ^ 0xE4) * 0.8;
            }
            color = mix(color, base, pulse.min(1.0));
            color = mix(color, tint, (boost * 0.8).min(0.7));
            alpha += pulse * 0.55 * under_text + boost * 0.5;
            radius += pulse * 1.2 + boost * 1.1;
            if alpha > 0.01 {
                painter.circle_filled(pt, radius, rgba(color, alpha));
            }
        }

        // ---- the shield ----
        let mut particles: Vec<Particle> = Vec::new();
        for &(local, letter, v, n) in &self.shield_dots {
            let z = face_z(local, letter);
            let normal = v3(2.0 * depth * (local.x / mark_half_width).clamp(-1.0, 1.0) / mark_half_width, 0.5 * depth * (local.y / half).clamp(-1.0, 1.0) / half, -1.0).normalized();
            // Arrival: from somewhere in the field (and behind it), on a curve.
            let delay = 0.12 + 0.55 * hash(n ^ 0x51) + 0.3 * v + if letter { 0.45 } else { 0.0 };
            let arrive = motion::settle(age - delay, 0.85);
            let home = center + local;
            let from = origin + vec2(hash(n ^ 0xF00) * cols as f32, hash(n ^ 0xBA5) * rows as f32).floor() * HERO_GAP;
            let path = home - from;
            let side = vec2(-path.y, path.x) / path.length().max(1.0) * (hash(n ^ 0xC17) - 0.5) * 180.0 * (PI * arrive).sin();
            let flat = from + path * arrive + side - center;
            let mut point = v3(flat.x, flat.y, z * arrive + (1.0 - arrive) * 240.0 * hash(n ^ 0xA7));
            if let Some(bt) = burst {
                // Thrown out towards the viewer, then sprung back into place.
                let amount = motion::settle(bt, 0.14) - motion::settle(bt - 0.22, 0.75);
                let out = v3(local.x / half, local.y / half, -0.7 - hash(n ^ 0xD1));
                point = point.add(out.scale(amount * half * 0.85));
            }
            // A strike flares the face around where it hit, and dents it in.
            let mut flare = 0.0f32;
            let mut flare_red = false;
            for &(hit, born, threat) in &self.impacts {
                let f = (-((local - hit).length() / (0.14 * half)).powi(2)).exp() * (1.0 - (now - born) as f32 / 0.4);
                if f > flare {
                    (flare, flare_red) = (f, threat);
                }
            }
            let (depth_z, at, s) = project(point.add(v3(0.0, 0.0, flare * 0.06 * half)));
            // Light: diffuse from the upper left, and a specular glint.
            let lit = normal.turned(yaw, pitch);
            let diffuse = lit.dot(light).max(0.0);
            let glint = lit.dot(half_vector).max(0.0).powi(30);
            // The P is silver on dark backgrounds and graphite on light ones.
            let face = if letter && pal.dark {
                mix(mix([150, 150, 158], [255, 255, 255], diffuse), [255, 255, 255], glint)
            } else if letter {
                mix(mix([20, 20, 22], [86, 86, 92], diffuse), [200, 200, 210], glint)
            } else {
                mix(shade(base, 0.45 + 0.75 * diffuse), [255, 255, 255], glint * 0.45)
            };
            let struck = if flare_red { red } else { mix(cyan, [255, 255, 255], 0.4) };
            let color = mix(mix(face, struck, flare), [255, 255, 255], glow * 0.6);
            let alpha = 0.15 + 0.85 * arrive;
            let size = HERO_GAP * (0.1 + if letter { 0.22 } else { 0.17 } * arrive) * s * (1.0 + 0.5 * flare + 0.3 * glow);
            particles.push(Particle { depth: depth_z, at, radius: size, color, alpha });
        }
        // Back to front, so near dots cover far ones as the shield turns.
        particles.sort_by(|a, b| b.depth.total_cmp(&a.depth));
        for d in &particles {
            painter.circle_filled(d.at, d.radius, rgba(d.color, d.alpha));
        }

        // ---- threats' arrows, standing out of the face ----
        let pulse = 0.8 + 0.2 * (t * 4.0).sin();
        for arrow in &self.stuck {
            let appear = motion::settle((now - arrow.born) as f32, 0.15);
            let (_, at, _) = project(v3(arrow.at.x, arrow.at.y, face_z(arrow.at, false)));
            let (col, row) = (col_of(at.x), row_of(at.y));
            // Red at the point and the fletching, a pale shaft, so it reads on a red shield too.
            painter.circle_filled(cell_at(col, row), HERO_GAP * 0.75, rgba(red, 0.18 * appear * pulse));
            painter.circle_filled(cell_at(col, row), HERO_GAP * 0.3, rgba(red, appear));
            for d in 1..ARROW_CELLS - 1 {
                painter.circle_filled(cell_at(col + d, row), HERO_GAP * 0.2, rgba(ink, appear * (0.95 - d as f32 * 0.06)));
            }
            for fin in [-1, 1] {
                painter.circle_filled(cell_at(col + ARROW_CELLS - 1, row + fin), HERO_GAP * 0.18, rgba(red, appear * pulse));
                painter.circle_filled(cell_at(col + ARROW_CELLS - 2, row + fin), HERO_GAP * 0.15, rgba(red, 0.7 * appear));
            }
        }

        // ---- arrows in flight, along their rows ----
        for arrow in &self.arrows {
            let x = start_x - ARROW_SPEED * (now - arrow.born) as f32;
            let head = col_of(x);
            let shaft = if arrow.threat { red } else { ink };
            for d in 0..ARROW_CELLS {
                let at = cell_at(head + d, arrow.row);
                if at.x > rect.right() - 6.0 {
                    continue;
                }
                // Faint where it passes behind the headline.
                let behind_text = 0.2 + 0.8 * smoothstep(rect_distance(clear, at) / 18.0);
                let (radius, color, alpha) = if d == 0 { (0.3, if arrow.threat { red } else { [255, 255, 255] }, 1.0) } else { (0.2, shaft, 0.9 - d as f32 * 0.06) };
                painter.circle_filled(at, HERO_GAP * radius, rgba(color, alpha * behind_text * scan_on.max(0.4)));
            }
            for fin in [-1, 1] {
                let at = cell_at(head + ARROW_CELLS, arrow.row + fin);
                let behind_text = 0.2 + 0.8 * smoothstep(rect_distance(clear, at) / 18.0);
                painter.circle_filled(at, HERO_GAP * 0.16, rgba(shaft, 0.55 * behind_text));
            }
        }
        // Sparks, snapped to the lattice like everything else.
        for spark in &self.sparks {
            let life = 1.0 - (now - spark.born) as f32 / 0.6;
            let at = cell_at(col_of(spark.at.x), row_of(spark.at.y));
            painter.circle_filled(at, HERO_GAP * 0.2 * life + 0.5, rgba([255, 214, 150], life));
        }

        let busy = age < 2.8
            || moving
            || pulsing
            || burst.is_some()
            || !self.ripples.is_empty()
            || status.scan.is_some()
            || !self.arrows.is_empty()
            || !self.sparks.is_empty()
            || !self.stuck.is_empty()
            || (blend - blend.round()).abs() > 0.001
            || self.flashed.is_some();
        if still {
            return;
        }
        if busy {
            ctx.request_repaint();
        } else {
            // The gentle sway, at a relaxed frame rate.
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }
    }
}

// ---------- the score ring ----------

/// A ring of dots, lit clockwise up to `percent`, with the number inside.
/// It fills once when shown.
pub fn score_ring(ui: &mut Ui, percent: u32, color: Color32, label: &str) {
    const DOTS: usize = 36;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(68.0), Sense::hover());
    let id = ui.make_persistent_id("score-ring");
    let filled = motion::spring(ui.ctx(), id, percent as f32 / 100.0, 0.9, 1.0) * DOTS as f32;
    let c = rect.center();
    let painter = ui.painter();
    for k in 0..DOTS {
        let angle = k as f32 / DOTS as f32 * TAU - PI / 2.0;
        let at = c + vec2(angle.cos(), angle.sin()) * 29.0;
        let on = (filled - k as f32).clamp(0.0, 1.0);
        let fill = rgba(mix(ink(), rgb(color), on), 0.14 + 0.86 * on);
        painter.circle_filled(at, 1.3 + 0.9 * on, fill);
    }
    painter.text(c - vec2(0.0, 5.0), Align2::CENTER_CENTER, percent.to_string(), semibold(19.0), theme().text);
    painter.text(c + vec2(0.0, 12.0), Align2::CENTER_CENTER, label, FontId::proportional(10.5), color);
}

// ---------- the spinner ----------

/// Eight dots chasing round a circle.
pub fn spinner(ui: &mut Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
    let still = motion::reduced_motion();
    let head = if still { 0.0 } else { (ui.input(|i| i.time) as f32 * 11.0).rem_euclid(8.0) };
    let painter = ui.painter();
    for k in 0..8 {
        let angle = k as f32 / 8.0 * TAU - PI / 2.0;
        let at = rect.center() + vec2(angle.cos(), angle.sin()) * 6.5;
        let behind = (head - k as f32).rem_euclid(8.0) / 8.0;
        let alpha = if still { 0.6 } else { 1.0 - behind * 0.85 };
        painter.circle_filled(at, 1.7, rgba(ink(), alpha));
    }
    if !still {
        ui.ctx().request_repaint();
    }
    response
}
