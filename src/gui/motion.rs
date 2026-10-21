//! Springs for interface motion. A spring keeps its current value and
//! velocity when its target changes, so every animation can be interrupted
//! and redirected mid-flight. Defaults are critically damped (no overshoot).
//!
//! When Windows' "Animation effects" setting is off, springs jump straight
//! to their target and the dot graphics stay still.

use eframe::egui::{self, Id};
use std::sync::OnceLock;

#[derive(Clone, Copy)]
struct State {
    value: f32,
    velocity: f32,
}

/// Animates towards `target`. `response` is roughly how long the spring
/// takes to get there, in seconds; `damping` 1.0 settles without bouncing,
/// lower values overshoot. Repaints until the value has settled.
pub fn spring(ctx: &egui::Context, id: Id, target: f32, response: f32, damping: f32) -> f32 {
    let mut s = ctx.data(|d| d.get_temp::<State>(id)).unwrap_or(State { value: target, velocity: 0.0 });
    if reduced_motion() {
        s = State { value: target, velocity: 0.0 };
    } else {
        let dt = ctx.input(|i| i.stable_dt).clamp(0.0, 1.0 / 20.0);
        let omega = std::f32::consts::TAU / response.max(0.02);
        // A few semi-implicit Euler substeps keep stiff springs stable at low frame rates.
        const STEPS: usize = 4;
        let h = dt / STEPS as f32;
        for _ in 0..STEPS {
            let accel = -omega * omega * (s.value - target) - 2.0 * damping * omega * s.velocity;
            s.velocity += accel * h;
            s.value += s.velocity * h;
        }
        let epsilon = 0.0015 * (1.0 + target.abs());
        if (s.value - target).abs() < epsilon && s.velocity.abs() < epsilon * 10.0 {
            s = State { value: target, velocity: 0.0 };
        } else {
            ctx.request_repaint();
        }
    }
    ctx.data_mut(|d| d.insert_temp(id, s));
    s.value
}

/// Places a spring at `value`, at rest, so the next [`spring`] call animates from there.
pub fn set(ctx: &egui::Context, id: Id, value: f32) {
    ctx.data_mut(|d| d.insert_temp(id, State { value, velocity: 0.0 }));
}

/// The step response of a critically damped spring released `t` seconds ago:
/// 0 before release, rising smoothly to 1 without overshoot. Closed form, so
/// thousands of staggered dots can share it without storing any state.
pub fn settle(t: f32, response: f32) -> f32 {
    if t <= 0.0 {
        return 0.0;
    }
    if reduced_motion() {
        return 1.0;
    }
    let wt = std::f32::consts::TAU / response.max(0.02) * t;
    (1.0 - (1.0 + wt) * (-wt).exp()).clamp(0.0, 1.0)
}

/// Windows' "Animation effects" (Settings > Accessibility > Visual effects) is off.
pub fn reduced_motion() -> bool {
    static REDUCED: OnceLock<bool> = OnceLock::new();
    *REDUCED.get_or_init(read_reduced_motion)
}

#[cfg(windows)]
fn read_reduced_motion() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETCLIENTAREAANIMATION};
    let mut animate: i32 = 1;
    // SAFETY: SPI_GETCLIENTAREAANIMATION writes one BOOL to the pointer given.
    let ok = unsafe { SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&mut animate as *mut i32).cast(), 0) };
    ok != 0 && animate == 0
}

#[cfg(not(windows))]
fn read_reduced_motion() -> bool {
    false
}
