//! Per-user Start-menu shortcut that carries the app's notification identity.
//!
//! Windows delivers toasts from an unpackaged app to the notification centre
//! but only shows them as pop-up banners when a Start-menu shortcut carries the
//! same `System.AppUserModel.ID`. This writes that shortcut through the shell's
//! own COM objects (IShellLinkW, IPropertyStore, IPersistFile).

use std::ffi::c_void;
use std::path::Path;
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};

const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
const IID_SHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
const IID_PROPERTY_STORE: GUID = GUID::from_u128(0x886d8eeb_8cf2_4446_8d02_cdba1dbdcf99);
const IID_PERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);

#[repr(C)]
struct PropertyKey {
    fmtid: GUID,
    pid: u32,
}

/// PKEY_AppUserModel_ID.
const PKEY_APP_USER_MODEL_ID: PropertyKey =
    PropertyKey { fmtid: GUID::from_u128(0x9f4c2855_9f79_4b39_a8d0_e1d42de1d5f3), pid: 5 };

/// PROPVARIANT holding a VT_LPWSTR (layout of the real union on x86 and x64).
#[repr(C)]
struct PropVariant {
    vt: u16,
    reserved: [u16; 3],
    pwsz: *const u16,
    padding: usize,
}
const VT_LPWSTR: u16 = 31;

// Vtable slots (IUnknown occupies 0..=2).
const QUERY_INTERFACE: usize = 0;
const RELEASE: usize = 2;
const LINK_GET_PATH: usize = 3;
const LINK_GET_ICON_LOCATION: usize = 16;
const LINK_SET_DESCRIPTION: usize = 7;
const LINK_SET_ARGUMENTS: usize = 11;
const LINK_SET_ICON_LOCATION: usize = 17;
const LINK_SET_PATH: usize = 20;
const STORE_SET_VALUE: usize = 6;
const STORE_COMMIT: usize = 7;
const FILE_LOAD: usize = 5;
const FILE_SAVE: usize = 6;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// An owned COM interface pointer, released on drop.
struct Com(*mut c_void);

impl Com {
    /// # Safety
    /// `index` must be a slot of this interface whose signature is `F`.
    unsafe fn slot<F: Copy>(&self, index: usize) -> F {
        unsafe {
            let vtable = *(self.0 as *const *const *const c_void);
            std::mem::transmute_copy(&*vtable.add(index))
        }
    }

    fn query(&self, iid: &GUID) -> Result<Com, String> {
        let mut out = std::ptr::null_mut();
        let qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT =
            unsafe { self.slot(QUERY_INTERFACE) };
        check(unsafe { qi(self.0, iid, &mut out) }, "QueryInterface")?;
        Ok(Com(out))
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        let release: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { self.slot(RELEASE) };
        unsafe { release(self.0) };
    }
}

fn check(hr: HRESULT, what: &str) -> Result<(), String> {
    if hr < 0 {
        Err(format!("{what} failed (0x{:08X})", hr as u32))
    } else {
        Ok(())
    }
}

type SetText = unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT;

/// Creates `link` to start `exe` with `aumid` and the icon file `icon`.
///
/// An existing shortcut keeps its program while that program exists, so
/// starting another copy (a test build) does not take it over; it is only
/// re-pointed at `exe` when its program is gone (the app moved or was
/// renamed). Its icon is updated whenever `icon` differs: Windows caches a
/// shortcut's icon by path, so callers give a changed icon a new file name.
/// The shell is then told icons changed, so the taskbar and Start menu
/// redraw. Returns whether it wrote the shortcut. Runs COM on its own thread
/// so it never disturbs the caller's apartment.
pub fn ensure(link: &Path, exe: &Path, icon: &Path, aumid: &str, description: &str) -> Result<bool, String> {
    let (link, exe, icon, aumid, description) =
        (link.to_path_buf(), exe.to_path_buf(), icon.to_path_buf(), aumid.to_string(), description.to_string());
    std::thread::spawn(move || {
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        let result = write(&link, &exe, &icon, &aumid, &description);
        if hr >= 0 {
            unsafe { CoUninitialize() };
        }
        result
    })
    .join()
    .map_err(|_| "shortcut thread panicked".to_string())?
}

fn new_shell_link() -> Result<Com, String> {
    let mut raw = std::ptr::null_mut();
    check(
        unsafe { CoCreateInstance(&CLSID_SHELL_LINK, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IID_SHELL_LINK_W, &mut raw) },
        "creating a shell link",
    )?;
    Ok(Com(raw))
}

/// The target and icon file of an existing shortcut, or `None` if it cannot be read.
fn current(link_w: &[u16]) -> Option<(String, String)> {
    let shell_link = new_shell_link().ok()?;
    let file = shell_link.query(&IID_PERSIST_FILE).ok()?;
    let load: unsafe extern "system" fn(*mut c_void, *const u16, u32) -> HRESULT = unsafe { file.slot(FILE_LOAD) };
    if unsafe { load(file.0, link_w.as_ptr(), 0) } < 0 {
        return None;
    }
    let mut buf = [0u16; 1024];
    let get_path: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut c_void, u32) -> HRESULT =
        unsafe { shell_link.slot(LINK_GET_PATH) };
    if unsafe { get_path(shell_link.0, buf.as_mut_ptr(), buf.len() as i32, std::ptr::null_mut(), 0) } < 0 {
        return None;
    }
    let text = |buf: &[u16]| String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]);
    let target = text(&buf);
    let mut icon = [0u16; 1024];
    let mut index = 0i32;
    let get_icon: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut i32) -> HRESULT =
        unsafe { shell_link.slot(LINK_GET_ICON_LOCATION) };
    let icon = if unsafe { get_icon(shell_link.0, icon.as_mut_ptr(), icon.len() as i32, &mut index) } >= 0 { text(&icon) } else { String::new() };
    Some((target, icon))
}

/// Tells Explorer that icons may have changed, so cached ones are redrawn.
fn notify_icons_changed() {
    use windows_sys::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, std::ptr::null(), std::ptr::null()) };
}

fn write(link: &Path, exe: &Path, icon: &Path, aumid: &str, description: &str) -> Result<bool, String> {
    let link_w = wide(&link.display().to_string());
    let icon_text = icon.display().to_string();
    let existing = if link.exists() { current(&link_w) } else { None };
    // Keep a working program; replace a missing one.
    let exe_text = match &existing {
        Some((target, _)) if Path::new(target).is_file() => target.clone(),
        _ => exe.display().to_string(),
    };
    if existing.as_ref().is_some_and(|(target, current_icon)| *target == exe_text && current_icon.eq_ignore_ascii_case(&icon_text)) {
        return Ok(false);
    }

    // A fresh object: one loaded read-only above would refuse the app ID.
    let shell_link = new_shell_link()?;
    let file = shell_link.query(&IID_PERSIST_FILE)?;
    let exe_w = wide(&exe_text);
    unsafe {
        let set_path: SetText = shell_link.slot(LINK_SET_PATH);
        check(set_path(shell_link.0, exe_w.as_ptr()), "setting the shortcut target")?;
        let set_args: SetText = shell_link.slot(LINK_SET_ARGUMENTS);
        check(set_args(shell_link.0, wide("").as_ptr()), "setting the shortcut arguments")?;
        let set_desc: SetText = shell_link.slot(LINK_SET_DESCRIPTION);
        check(set_desc(shell_link.0, wide(description).as_ptr()), "setting the shortcut description")?;
        let set_icon: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> HRESULT =
            shell_link.slot(LINK_SET_ICON_LOCATION);
        check(set_icon(shell_link.0, wide(&icon_text).as_ptr(), 0), "setting the shortcut icon")?;
    }

    let store = shell_link.query(&IID_PROPERTY_STORE)?;
    let aumid_w = wide(aumid);
    let value = PropVariant { vt: VT_LPWSTR, reserved: [0; 3], pwsz: aumid_w.as_ptr(), padding: 0 };
    unsafe {
        let set_value: unsafe extern "system" fn(*mut c_void, *const PropertyKey, *const PropVariant) -> HRESULT =
            store.slot(STORE_SET_VALUE);
        check(set_value(store.0, &PKEY_APP_USER_MODEL_ID, &value), "setting the shortcut's app ID")?;
        let commit: unsafe extern "system" fn(*mut c_void) -> HRESULT = store.slot(STORE_COMMIT);
        check(commit(store.0), "saving the shortcut's app ID")?;
    }

    if let Some(dir) = link.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let save: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> HRESULT = unsafe { file.slot(FILE_SAVE) };
    check(unsafe { save(file.0, link_w.as_ptr(), 1) }, "saving the shortcut")?;
    notify_icons_changed();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_keeps_a_working_program_and_follows_icon_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("Programs").join("Test App.lnk");
        let (first, second) = (tmp.path().join("first.exe"), tmp.path().join("second.exe"));
        let (icon_a, icon_b) = (tmp.path().join("app-1.ico"), tmp.path().join("app-2.ico"));
        for f in [&first, &second, &icon_a, &icon_b] {
            std::fs::write(f, b"x").unwrap();
        }
        let link_w = wide(&link.display().to_string());
        let read = || std::thread::spawn({
            let link_w = link_w.clone();
            move || {
                unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
                current(&link_w).unwrap()
            }
        }).join().unwrap();

        assert!(ensure(&link, &first, &icon_a, "Test.App.Id", "test").unwrap());
        assert!(!ensure(&link, &first, &icon_a, "Test.App.Id", "test").unwrap(), "unchanged: nothing written");
        assert!(!ensure(&link, &second, &icon_a, "Test.App.Id", "test").unwrap(), "another copy does not take it over");

        // A new icon file: rewritten, same program.
        assert!(ensure(&link, &second, &icon_b, "Test.App.Id", "test").unwrap());
        let (target, icon) = read();
        assert_eq!((Path::new(&target), Path::new(&icon)), (first.as_path(), icon_b.as_path()));

        std::fs::remove_file(&first).unwrap();
        assert!(ensure(&link, &second, &icon_b, "Test.App.Id", "test").unwrap(), "re-pointed once the old program is gone");
        assert_eq!(Path::new(&read().0), second.as_path());
    }
}
