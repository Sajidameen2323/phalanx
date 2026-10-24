//! The service's data folder, `%ProgramData%\Phalanx`, and who may touch it.
//!
//! SYSTEM and administrators have full control. Users may read (the browser
//! connector reads the web rules) but not change anything, so a program
//! running as a user cannot edit settings, allowed sites or history. The
//! quarantine is not even readable by users. The permissions are protected:
//! nothing is inherited from `ProgramData`, which lets users create files.

use std::io;
use std::path::{Path, PathBuf};

/// Subfolder that users may not read.
pub const QUARANTINE: &str = "quarantine";

/// SYSTEM and administrators: full control; users: read and list. Inherited
/// by everything inside (files and folders).
const FOLDER_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// SYSTEM and administrators only.
const PRIVATE_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// A secret file (the abuse.ch key): SYSTEM and administrators only.
pub const SECRET_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// `%ProgramData%\Phalanx`.
pub fn machine_data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("Phalanx")
}

/// Creates the folder and its quarantine, and sets their permissions (the
/// service runs this at every start, so changed permissions are put back).
pub fn prepare(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir.join(QUARANTINE))?;
    set_permissions(dir, FOLDER_SDDL)?;
    set_permissions(&dir.join(QUARANTINE), PRIVATE_SDDL)
}

/// Replaces `path`'s permissions with `sddl`'s (protected: none inherited),
/// and Windows applies the inheritable entries to what is already inside.
#[cfg(windows)]
pub(crate) fn set_permissions(path: &Path, sddl: &str) -> io::Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let wide = |s: &std::ffi::OsStr| -> Vec<u16> { std::os::windows::ffi::OsStrExt::encode_wide(s).chain([0]).collect() };
    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl.as_ref()).as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(io::Error::last_os_error());
        }
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let result = if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(io::Error::last_os_error())
        } else {
            let mut name = wide(path.as_os_str());
            let code = SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            );
            if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code as i32)) }
        };
        LocalFree(descriptor as _);
        result
    }
}

#[cfg(not(windows))]
pub(crate) fn set_permissions(_path: &Path, _sddl: &str) -> io::Result<()> {
    Ok(())
}

/// `path`'s permissions as SDDL (the DACL only).
#[cfg(windows)]
pub fn permissions(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let name: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str()).chain([0]).collect();
    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut text, std::ptr::null_mut());
        LocalFree(descriptor as _);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as _);
        Ok(sddl)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn the_folder_is_locked_down() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Phalanx");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("settings.json"), "{}").unwrap();
        prepare(&dir).unwrap();

        let folder = permissions(&dir).unwrap();
        assert!(folder.starts_with("D:P"), "nothing inherited from ProgramData: {folder}");
        assert!(folder.contains(";;;SY)") && folder.contains(";;;BA)") && folder.contains(";;;BU)"), "{folder}");
        assert!(!folder.contains("WD") && !folder.contains(";;;AU)"), "{folder}");
        let quarantine = permissions(&dir.join(QUARANTINE)).unwrap();
        assert!(quarantine.starts_with("D:P") && !quarantine.contains(";;;BU)"), "users may not read the quarantine: {quarantine}");
        // What was already inside got the folder's permissions.
        assert!(permissions(&dir.join("settings.json")).unwrap().contains(";;;BU)"));

        // As a standard user (unless these tests run elevated), the folder can
        // be read but not changed.
        let elevated = unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 };
        assert!(std::fs::read(dir.join("settings.json")).is_ok());
        if !elevated {
            assert!(std::fs::write(dir.join("settings.json"), "changed").is_err());
            assert!(std::fs::write(dir.join("new.txt"), "x").is_err());
            assert!(std::fs::read_dir(dir.join(QUARANTINE)).is_err());
        }

        // As the owner we may still change the permissions back, to clean up.
        for path in [dir.join(QUARANTINE), dir.clone()] {
            set_permissions(&path, "D:(A;OICI;FA;;;WD)").unwrap();
        }
        std::fs::remove_file(dir.join("settings.json")).unwrap();
    }
}
