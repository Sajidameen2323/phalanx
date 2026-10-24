//! Signature updates in the service: on request, and on the schedule in the
//! protection settings, with nobody needing to be signed in. When new
//! signatures or web rules arrive, the engine and the web rules are reloaded.

use super::protect::Hub;
use super::settings::ProtectionSettings;
use crate::ipc::Event;
use crate::update;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When the service last checked the feeds (unix seconds).
const CHECKED: &str = "update-checked";
/// How often the schedule is looked at.
const SCHEDULE_TICK: Duration = Duration::from_secs(5 * 60);

pub(crate) struct Updater {
    data_dir: PathBuf,
    hub: Arc<Hub>,
    running: AtomicBool,
    /// Called after an update that installed something.
    on_installed: Box<dyn Fn() + Send + Sync>,
}

impl Updater {
    pub fn new(data_dir: &Path, hub: Arc<Hub>, on_installed: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self { data_dir: data_dir.to_path_buf(), hub, running: AtomicBool::new(false), on_installed: Box::new(on_installed) })
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Downloads every feed that changed (every feed with `force`) on a thread
    /// of its own; progress and the outcome arrive as events.
    pub fn start(self: &Arc<Self>, force: bool) -> Result<()> {
        if self.running.swap(true, Ordering::Relaxed) {
            bail!("an update is already running");
        }
        let this = Arc::clone(self);
        let spawned = std::thread::Builder::new().name("signature-update".into()).spawn(move || {
            crate::system::enter_background_mode();
            let sig_dir = update::signature_dir(&this.data_dir);
            let outcome = update::update_all(&sig_dir, force, &mut |step| this.hub.send(&Event::UpdateProgress { step: step.to_string() }));
            save_checked(&this.data_dir);
            match outcome {
                Ok(manifest) => {
                    let installed = manifest.installed_anything();
                    let failed = manifest.sources.iter().filter(|s| s.failed()).map(|s| s.name.clone()).collect();
                    if installed {
                        (this.on_installed)();
                    }
                    this.hub.send(&Event::UpdateFinished { installed, last_success: manifest.last_success().map(str::to_string), failed });
                }
                Err(e) => this.hub.send(&Event::UpdateFailed { error: format!("{e:#}") }),
            }
            this.running.store(false, Ordering::Relaxed);
        });
        if let Err(e) = spawned {
            self.running.store(false, Ordering::Relaxed);
            bail!("could not start the update: {e}");
        }
        Ok(())
    }

    /// Checks the feeds when the settings' interval has passed and updates
    /// if any changed, until `stop` is set.
    pub fn schedule(self: &Arc<Self>, stop: Arc<AtomicBool>) {
        let this = Arc::clone(self);
        let _ = std::thread::Builder::new().name("update-schedule".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let settings = ProtectionSettings::load(&this.data_dir).unwrap_or_default();
                let interval = u64::from(settings.auto_update_hours.max(1)) * 3600;
                let due = load_checked(&this.data_dir).is_none_or(|t| now().saturating_sub(t) >= interval);
                if settings.auto_update && due && !this.running() {
                    let check = update::check_for_updates(&update::signature_dir(&this.data_dir));
                    save_checked(&this.data_dir);
                    if !check.changed.is_empty() {
                        let _ = this.start(false);
                    }
                }
                // Sleep in short steps, so stopping the service is quick.
                for _ in 0..SCHEDULE_TICK.as_secs() {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn load_checked(data_dir: &Path) -> Option<u64> {
    std::fs::read_to_string(data_dir.join(CHECKED)).ok()?.trim().parse().ok()
}

fn save_checked(data_dir: &Path) {
    let _ = std::fs::write(data_dir.join(CHECKED), now().to_string());
}

/// Saves the abuse.ch key as the service (encrypted for SYSTEM, readable
/// only by administrators), or removes it with `None`.
pub fn save_auth_key(data_dir: &Path, key: Option<&str>) -> Result<()> {
    let sig_dir = update::signature_dir(data_dir);
    update::save_auth_key(&sig_dir, key)?;
    let path = sig_dir.join(update::AUTH_KEY_FILE);
    if path.is_file() {
        super::data::set_permissions(&path, super::data::SECRET_SDDL)?;
    }
    Ok(())
}
