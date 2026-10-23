//! Windows desktop integration: one running copy, and the tray icon.

use eframe::egui;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[cfg(windows)]
const MUTEX_NAME: &str = "Local\\ThreatScanner.SingleInstance";
/// Signalled by a second launch; the running copy then shows its window
/// itself, so its own idea of "hidden in the tray" stays correct.
#[cfg(windows)]
const SHOW_EVENT_NAME: &str = "Local\\ThreatScanner.Show";
/// Signalled by `--quit` (the installer and uninstaller): the running copy
/// quits as the tray's Quit does, stopping protection cleanly.
#[cfg(windows)]
const QUIT_EVENT_NAME: &str = "Local\\ThreatScanner.Quit";
/// A copy asked to quit that has not exited by then is ended.
const QUIT_GRACE: std::time::Duration = std::time::Duration::from_secs(8);

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Held for the life of the process (the handles are never closed); a second
/// copy sees the mutex and exits.
pub struct SingleInstance {
    /// Event handles as integers so they can move to the listener threads.
    #[cfg(windows)]
    show_event: usize,
    #[cfg(windows)]
    quit_event: usize,
}

impl SingleInstance {
    /// `None` when another copy is already running for this user.
    pub fn acquire() -> Option<Self> {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
            use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW};
            let mutex = CreateMutexW(std::ptr::null(), 0, wide(MUTEX_NAME).as_ptr());
            if mutex.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
                return None;
            }
            // Auto-reset: each signal shows the window once.
            let show_event = CreateEventW(std::ptr::null(), 0, 0, wide(SHOW_EVENT_NAME).as_ptr());
            let quit_event = CreateEventW(std::ptr::null(), 0, 0, wide(QUIT_EVENT_NAME).as_ptr());
            Some(Self { show_event: show_event as usize, quit_event: quit_event as usize })
        }
        #[cfg(not(windows))]
        Some(Self {})
    }

    /// Shows the window whenever another launch asks for it.
    pub fn listen_for_show_requests(&self, ctx: egui::Context) {
        #[cfg(windows)]
        {
            let event = self.show_event;
            if event == 0 {
                return;
            }
            let _ = std::thread::Builder::new().name("show-requests".into()).spawn(move || {
                use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
                use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
                while unsafe { WaitForSingleObject(event as _, INFINITE) } == WAIT_OBJECT_0 {
                    show_window(&ctx);
                }
            });
        }
        #[cfg(not(windows))]
        let _ = ctx;
    }
}

impl SingleInstance {
    /// Quits whenever `--quit` asks: `quitting` makes the close a real quit,
    /// not hide-to-tray.
    pub fn listen_for_quit_requests(&self, ctx: egui::Context, quitting: Arc<AtomicBool>) {
        #[cfg(windows)]
        {
            let event = self.quit_event;
            if event == 0 {
                return;
            }
            let _ = std::thread::Builder::new().name("quit-requests".into()).spawn(move || {
                use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
                use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
                if unsafe { WaitForSingleObject(event as _, INFINITE) } != WAIT_OBJECT_0 {
                    return;
                }
                quitting.store(true, Ordering::Relaxed);
                // A window held hidden is not painted, so it could not close.
                release_hold();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                ctx.request_repaint();
                std::thread::sleep(QUIT_GRACE);
                std::process::exit(0);
            });
        }
        #[cfg(not(windows))]
        let _ = (ctx, quitting);
    }
}

/// Asks the running copy to quit and waits for it to exit. `true` once no
/// copy is running (also when none was).
pub fn quit_existing() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenEventW, OpenMutexW, SetEvent, EVENT_MODIFY_STATE};
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let running = || {
            let mutex = OpenMutexW(SYNCHRONIZE, 0, wide(MUTEX_NAME).as_ptr());
            !mutex.is_null() && CloseHandle(mutex) != 0
        };
        if !running() {
            return true;
        }
        let event = OpenEventW(EVENT_MODIFY_STATE, 0, wide(QUIT_EVENT_NAME).as_ptr());
        if event.is_null() {
            return false; // an older copy that cannot be asked
        }
        SetEvent(event);
        CloseHandle(event);
        let until = std::time::Instant::now() + QUIT_GRACE + std::time::Duration::from_secs(4);
        while std::time::Instant::now() < until {
            if !running() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        false
    }
    #[cfg(not(windows))]
    true
}

/// Asks the already-running copy to show its window.
pub fn show_existing_window() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
        let event = OpenEventW(EVENT_MODIFY_STATE, 0, wide(SHOW_EVENT_NAME).as_ptr());
        if !event.is_null() {
            SetEvent(event);
            CloseHandle(event);
        }
    }
}

pub struct Tray {
    _icon: TrayIcon,
}

/// The main window while it is held hidden (see [`hold_hidden`]), else 0.
#[cfg(windows)]
static HELD_WINDOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Keeps the main window hidden until the user opens it (started at
/// sign-in). eframe shows a new window as soon as it has painted a frame,
/// and on Windows it paints hidden windows too, so the window would pop up
/// and take the focus at every sign-in. A minimized window is never painted,
/// so the hidden window is marked minimized (the style bit only: nothing is
/// shown or animated) until [`show_window`] lifts it.
pub fn hold_hidden(cc: &eframe::CreationContext<'_>) {
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowLongPtrW, IsWindowVisible, SetWindowLongPtrW, GWL_STYLE, WS_MINIMIZE};
        let Ok(handle) = cc.window_handle() else { return };
        let RawWindowHandle::Win32(win32) = handle.as_raw() else { return };
        let hwnd = win32.hwnd.get() as windows_sys::Win32::Foundation::HWND;
        unsafe {
            if IsWindowVisible(hwnd) != 0 {
                return;
            }
            let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
            SetWindowLongPtrW(hwnd, GWL_STYLE, style | WS_MINIMIZE as isize);
        }
        HELD_WINDOW.store(hwnd as usize, Ordering::Relaxed);
    }
    #[cfg(not(windows))]
    let _ = cc;
}

/// Ends the hold, so the window can be shown and painted again.
fn release_hold() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowLongPtrW, SetWindowLongPtrW, GWL_STYLE, WS_MINIMIZE};
        let hwnd = HELD_WINDOW.swap(0, Ordering::Relaxed) as windows_sys::Win32::Foundation::HWND;
        if !hwnd.is_null() {
            unsafe {
                let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
                SetWindowLongPtrW(hwnd, GWL_STYLE, style & !(WS_MINIMIZE as isize));
            }
        }
    }
}

/// Shows and focuses the main window (it may be hidden in the tray).
pub fn show_window(ctx: &egui::Context) {
    release_hold();
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    ctx.request_repaint();
}

impl Tray {
    /// Tray icon with Open/Quit. Clicking the icon opens the window. `quitting`
    /// tells the app that a close request is a real quit, not hide-to-tray.
    pub fn create(ctx: &egui::Context, quitting: Arc<AtomicBool>) -> anyhow::Result<Self> {
        let (rgba, w, h) = crate::widgets::icon_rgba();
        let icon = tray_icon::Icon::from_rgba(rgba, w, h)?;
        let open = MenuItem::new(format!("Open {}", crate::widgets::APP_TITLE), true, None);
        let quit = MenuItem::new("Quit (stops real-time protection)", true, None);
        let menu = Menu::new();
        menu.append(&open)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit)?;
        let tray = TrayIconBuilder::new()
            .with_tooltip(crate::widgets::APP_TITLE)
            .with_icon(icon)
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .build()?;

        // Handlers run on the UI thread's message loop, even while the window is hidden.
        let (open_id, quit_id) = (open.id().clone(), quit.id().clone());
        let menu_ctx = ctx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == open_id {
                show_window(&menu_ctx);
            } else if event.id == quit_id {
                quitting.store(true, Ordering::Relaxed);
                menu_ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                menu_ctx.request_repaint();
            }
        }));
        let click_ctx = ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let open = matches!(
                event,
                TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
                    | TrayIconEvent::DoubleClick { button: MouseButton::Left, .. }
            );
            if open {
                show_window(&click_ctx);
            }
        }));
        Ok(Self { _icon: tray })
    }
}
