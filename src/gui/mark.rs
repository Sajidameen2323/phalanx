//! The Phalanx mark (a shield with a folded silver P) as geometry and
//! pixels, with no dependencies, so the build script can include it too and
//! make the executable's icon from the same drawing the app shows.

#![allow(dead_code)]

use std::f32::consts::{FRAC_PI_2, PI};

/// Shield height over width.
pub const ASPECT: f32 = 1.16;

type Pt = [f32; 2];

fn quad(a: Pt, c: Pt, b: Pt, steps: usize, out: &mut Vec<Pt>) {
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        let u = 1.0 - t;
        out.push([u * u * a[0] + 2.0 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2.0 * u * t * c[1] + t * t * b[1]]);
    }
}

fn cubic(a: Pt, c1: Pt, c2: Pt, b: Pt, steps: usize, out: &mut Vec<Pt>) {
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        let u = 1.0 - t;
        let (w0, w1, w2, w3) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
        out.push([
            w0 * a[0] + w1 * c1[0] + w2 * c2[0] + w3 * b[0],
            w0 * a[1] + w1 * c1[1] + w2 * c2[1] + w3 * b[1],
        ]);
    }
}

/// The shield outline, clockwise from the peak, in units of the shield's width.
fn shield() -> Vec<Pt> {
    let mut right = vec![[0.5, 0.0]];
    quad([0.5, 0.0], [0.74, 0.055], [0.965, 0.14], 10, &mut right);
    quad([0.965, 0.14], [1.0, 0.152], [1.0, 0.2], 6, &mut right);
    right.push([1.0, 0.5]);
    cubic([1.0, 0.5], [0.985, 0.84], [0.72, 1.04], [0.5, ASPECT], 18, &mut right);
    let mut all = right.clone();
    // The left half mirrors the right, walked back up to the peak.
    all.extend(right.iter().rev().skip(1).map(|p| [1.0 - p[0], p[1]]).take(right.len() - 2));
    all
}

fn inside(poly: &[Pt], p: Pt) -> bool {
    let mut inside = false;
    let mut j = poly.len() - 1;
    for i in 0..poly.len() {
        let (a, b) = (poly[i], poly[j]);
        if (a[1] > p[1]) != (b[1] > p[1]) && p[0] < (b[0] - a[0]) * (p[1] - a[1]) / (b[1] - a[1]) + a[0] {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn segment_distance(p: Pt, a: Pt, b: Pt) -> f32 {
    let (abx, aby) = (b[0] - a[0], b[1] - a[1]);
    let t = (((p[0] - a[0]) * abx + (p[1] - a[1]) * aby) / (abx * abx + aby * aby).max(1e-9)).clamp(0.0, 1.0);
    ((p[0] - a[0] - abx * t).powi(2) + (p[1] - a[1] - aby * t).powi(2)).sqrt()
}

fn edge_distance(poly: &[Pt], p: Pt) -> f32 {
    (0..poly.len()).map(|i| segment_distance(p, poly[i], poly[(i + 1) % poly.len()])).fold(f32::MAX, f32::min)
}

/// The P's bowl: the centre line of the folded ribbon.
fn bowl() -> Vec<Pt> {
    let (cx, cy, r) = (0.6, 0.445, 0.145);
    let mut pts = vec![[0.3, 0.3]];
    for i in 0..=16 {
        let a = -FRAC_PI_2 + PI * i as f32 / 16.0;
        pts.push([cx + r * a.cos(), cy + r * a.sin()]);
    }
    pts.push([0.36, 0.59]);
    pts
}

const STEM: [Pt; 4] = [[0.24, 0.255], [0.36, 0.255], [0.36, 0.93], [0.24, 0.81]];
/// Where the ribbon folds over at the top of the stem.
const FOLD: [Pt; 3] = [[0.24, 0.255], [0.36, 0.315], [0.24, 0.375]];
const BOWL_HALF_WIDTH: f32 = 0.058;

fn lerp(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    let t = t.clamp(0.0, 1.0);
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
}

/// Which part of the mark a point falls on, in units of the shield's width
/// from its top-left corner. `outline` is [`shield_outline`], passed in so
/// callers testing many points build it once.
#[derive(Clone, Copy, PartialEq)]
pub enum Part {
    Shield,
    Letter,
}

pub fn shield_outline() -> Vec<[f32; 2]> {
    shield()
}

pub fn part_at(outline: &[[f32; 2]], point: [f32; 2]) -> Option<Part> {
    if !inside(outline, point) {
        return None;
    }
    let path = bowl();
    let on_bowl = (0..path.len() - 1).any(|i| segment_distance(point, path[i], path[i + 1]) < BOWL_HALF_WIDTH);
    Some(if inside(&STEM, point) || on_bowl { Part::Letter } else { Part::Shield })
}

/// Which background a rendering of the mark is for.
#[derive(Clone, Copy, PartialEq)]
pub enum Style {
    /// Light backgrounds: the logo as drawn, a dark shield.
    Light,
    /// Dark backgrounds: the shield lifted, with a bright rim.
    Dark,
    /// The app icon: the dark shield with a faint rim, so it reads on light
    /// and dark taskbars alike.
    Icon,
}

/// The mark as RGBA pixels, `size` square. Small sizes get a heavier P so
/// the letter survives at 16 and 24 pixels.
pub fn mark_rgba(size: usize, style: Style) -> Vec<u8> {
    let dark = style == Style::Dark;
    let rim = match style {
        Style::Light => None,
        Style::Dark => Some(([0.78, 0.78, 0.82], 0.7)),
        Style::Icon => Some(([0.62, 0.62, 0.66], 0.6)),
    };
    let heavy = if size <= 32 { 1.35 } else { 1.0 };
    let outline = shield();
    let path = bowl();
    let (shield_low, shield_high) = if dark { ([0.16, 0.16, 0.18], [0.40, 0.40, 0.44]) } else { ([0.05, 0.05, 0.06], [0.30, 0.30, 0.33]) };
    let (silver_low, silver_high) = ([0.55, 0.55, 0.58], [1.0, 1.0, 1.0]);
    // Fit the shield's height to the square, centred.
    let scale = size as f32 * 0.96 / ASPECT;
    let ox = (size as f32 - scale) / 2.0;
    let oy = size as f32 * 0.02;
    const SS: usize = 4;
    let mut out = vec![0u8; size * size * 4];
    for py in 0..size {
        for px in 0..size {
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32 - ox) / scale;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32 - oy) / scale;
                    let p = [x, y];
                    if !inside(&outline, p) {
                        continue;
                    }
                    // Light falls from the upper right, as in the logo.
                    let mut c = lerp(shield_low, shield_high, 0.55 * x + 0.45 * (1.0 - y / ASPECT));
                    if let Some((edge, amount)) = rim {
                        if edge_distance(&outline, p) < 0.022 * heavy {
                            c = lerp(c, edge, amount);
                        }
                    }
                    let on_bowl = (0..path.len() - 1).any(|i| segment_distance(p, path[i], path[i + 1]) < BOWL_HALF_WIDTH * heavy);
                    let on_stem = inside(&STEM, p) || (heavy > 1.0 && segment_distance(p, [0.3, 0.27], [0.3, 0.86]) < 0.075);
                    if on_stem || on_bowl {
                        c = lerp(silver_low, silver_high, 1.0 - (y - 0.25) / 0.7 * 0.9 + (x - 0.3) * 0.4);
                        if inside(&FOLD, p) {
                            c = lerp(c, silver_low, 0.55);
                        }
                    }
                    r += c[0];
                    g += c[1];
                    b += c[2];
                    a += 1.0;
                }
            }
            if a > 0.0 {
                let i = (py * size + px) * 4;
                out[i] = (r / a * 255.0) as u8;
                out[i + 1] = (g / a * 255.0) as u8;
                out[i + 2] = (b / a * 255.0) as u8;
                out[i + 3] = (a / (SS * SS) as f32 * 255.0) as u8;
            }
        }
    }
    out
}


// ---------- files ----------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// RGBA pixels as a PNG. The image data is stored uncompressed (deflate's
/// "stored" blocks): these are small icons, and it keeps this dependency-free.
pub fn png(rgba: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut raw = Vec::with_capacity((width * 4 + 1) * height);
    for row in rgba.chunks(width * 4) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65_535).peekable();
    while let Some(block) = chunks.next() {
        z.push(chunks.peek().is_none() as u8);
        let len = block.len() as u16;
        z.extend_from_slice(&len.to_le_bytes());
        z.extend_from_slice(&(!len).to_le_bytes());
        z.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in &raw {
        a = (a + byte as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut chunk = |kind: &[u8; 4], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    };
    let mut header = Vec::new();
    header.extend_from_slice(&(width as u32).to_be_bytes());
    header.extend_from_slice(&(height as u32).to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(b"IHDR", &header);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    out
}

/// One icon image as a 32-bit DIB (BGRA rows bottom-up, then an empty AND
/// mask), the form every part of the Windows shell reads.
fn dib(rgba: &[u8], size: usize) -> Vec<u8> {
    let mask_row = size.div_ceil(32) * 4;
    let mut out = Vec::with_capacity(40 + size * size * 4 + mask_row * size);
    for value in [40u32, size as u32, 2 * size as u32] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((size * size * 4 + mask_row * size) as u32).to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    for row in rgba.chunks(size * 4).rev() {
        for px in row.chunks(4) {
            out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }
    out.resize(out.len() + mask_row * size, 0);
    out
}

/// A Windows icon holding the mark at the usual sizes: bitmaps up to 64
/// pixels, PNG at 256 (as Windows expects for the large size).
pub fn ico(style: Style) -> Vec<u8> {
    const SIZES: [usize; 8] = [16, 20, 24, 32, 40, 48, 64, 256];
    let images: Vec<Vec<u8>> = SIZES
        .iter()
        .map(|&s| if s >= 256 { png(&mark_rgba(s, style), s, s) } else { dib(&mark_rgba(s, style), s) })
        .collect();
    let mut out = vec![0, 0, 1, 0];
    out.extend_from_slice(&(SIZES.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * SIZES.len();
    for (&size, image) in SIZES.iter().zip(&images) {
        let side = if size >= 256 { 0 } else { size as u8 };
        out.extend_from_slice(&[side, side, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += image.len();
    }
    for image in images {
        out.extend_from_slice(&image);
    }
    out
}
