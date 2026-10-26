//! Authenticode trust: whether a file carries a valid publisher signature,
//! either embedded or through a Windows security catalog (how most of
//! Windows' own programs are signed).
//!
//! Used to keep heuristics from flagging validly signed software. Revocation
//! is not checked and nothing is fetched from the network, so a check is
//! fast and works offline.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// A valid signature that chains to a trusted root.
    Signed {
        /// The signing certificate's display name, when it could be read.
        signer: Option<String>,
        /// Signed through a security catalog rather than an embedded signature.
        catalog: bool,
    },
    Unsigned,
    /// An embedded signature whose hash no longer matches the file: it was
    /// changed after it was signed (patched, cracked or infected).
    Tampered,
    /// A signature is present but does not verify (untrusted root, expired
    /// without a timestamp...): the WinVerifyTrust result.
    Invalid(String),
    /// The check could not run (unreadable file, or not Windows).
    Unknown(String),
}

impl Trust {
    pub fn is_signed(&self) -> bool {
        matches!(self, Trust::Signed { .. })
    }
}

#[cfg(windows)]
pub fn verify(path: &Path) -> Trust {
    imp::verify(path)
}

#[cfg(not(windows))]
pub fn verify(_path: &Path) -> Trust {
    Trust::Unknown("signature checks are only available on Windows".into())
}

#[cfg(windows)]
mod imp {
    use super::Trust;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr;
    use windows_sys::Win32::Foundation::{HANDLE, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN};
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
        CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    pub fn verify(path: &Path) -> Trust {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) => return Trust::Unknown(e.to_string()),
        };
        let path_w = wide(path.as_os_str());
        let handle = file.as_raw_handle() as HANDLE;
        match embedded(&path_w, handle) {
            Ok(signer) => Trust::Signed { signer, catalog: false },
            Err(code) if [TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN].contains(&code) => {
                match catalog(&path_w, handle) {
                    Some(Ok(signer)) => Trust::Signed { signer, catalog: true },
                    Some(Err(code)) => Trust::Invalid(format!("catalog signature does not verify (0x{code:08X})")),
                    None => Trust::Unsigned,
                }
            }
            Err(TRUST_E_BAD_DIGEST) => Trust::Tampered,
            Err(code) => Trust::Invalid(format!("signature does not verify (0x{code:08X})")),
        }
    }

    fn base_data() -> WINTRUST_DATA {
        WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
            ..Default::default()
        }
    }

    /// Runs WinVerifyTrust on `data`, reads the signer on success and always
    /// releases the verification state.
    ///
    /// SAFETY: every pointer inside `data` must be valid for the call.
    unsafe fn run(data: &mut WINTRUST_DATA) -> Result<Option<String>, i32> {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe { WinVerifyTrust(ptr::null_mut(), &mut action, data as *mut _ as *mut _) };
        let signer = (status == 0).then(|| unsafe { signer_name(data.hWVTStateData) }).flatten();
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe { WinVerifyTrust(ptr::null_mut(), &mut action, data as *mut _ as *mut _) };
        if status == 0 { Ok(signer) } else { Err(status) }
    }

    unsafe fn signer_name(state: HANDLE) -> Option<String> {
        let prov = unsafe { WTHelperProvDataFromStateData(state) };
        if prov.is_null() {
            return None;
        }
        let signer = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
        if signer.is_null() || unsafe { (*signer).csCertChain } == 0 || unsafe { (*signer).pasCertChain.is_null() } {
            return None;
        }
        let cert = unsafe { (*(*signer).pasCertChain).pCert };
        if cert.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null(), buf.as_mut_ptr(), buf.len() as u32) };
        // `len` counts the terminating NUL; 1 means an empty name.
        (len > 1).then(|| String::from_utf16_lossy(&buf[..len as usize - 1]))
    }

    fn embedded(path_w: &[u16], handle: HANDLE) -> Result<Option<String>, i32> {
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_w.as_ptr(),
            hFile: handle,
            pgKnownSubject: ptr::null_mut(),
        };
        let mut data = base_data();
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut info;
        // SAFETY: `info` and the path it points to outlive the call.
        unsafe { run(&mut data) }
    }

    /// `None` when no installed catalog lists the file.
    fn catalog(path_w: &[u16], handle: HANDLE) -> Option<Result<Option<String>, i32>> {
        // Current catalogs use SHA-256; older ones SHA-1.
        ["SHA256", "SHA1"].iter().find_map(|alg| catalog_with(path_w, handle, alg))
    }

    fn catalog_with(path_w: &[u16], handle: HANDLE, algorithm: &str) -> Option<Result<Option<String>, i32>> {
        let alg_w: Vec<u16> = algorithm.encode_utf16().chain(Some(0)).collect();
        let mut admin: isize = 0;
        // SAFETY: plain FFI with valid out-pointers; every handle acquired
        // here is released before returning.
        unsafe {
            if CryptCATAdminAcquireContext2(&mut admin, ptr::null(), alg_w.as_ptr(), ptr::null(), 0) == 0 {
                return None;
            }
            let result = (|| {
                let mut size = 0u32;
                CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, ptr::null_mut(), 0);
                if size == 0 || size > 128 {
                    return None;
                }
                let mut hash = vec![0u8; size as usize];
                if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, hash.as_mut_ptr(), 0) == 0 {
                    return None;
                }
                let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), size, 0, ptr::null_mut());
                if cat == 0 {
                    return None;
                }
                let mut info = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                let found = CryptCATCatalogInfoFromContext(cat, &mut info, 0) != 0;
                let outcome = found.then(|| {
                    let tag: Vec<u16> = hex::encode_upper(&hash).encode_utf16().chain(Some(0)).collect();
                    let mut member = WINTRUST_CATALOG_INFO {
                        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                        pcwszMemberTag: tag.as_ptr(),
                        pcwszMemberFilePath: path_w.as_ptr(),
                        hMemberFile: handle,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: size,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut data = base_data();
                    data.dwUnionChoice = WTD_CHOICE_CATALOG;
                    data.Anonymous.pCatalog = &mut member;
                    run(&mut data)
                });
                CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                outcome
            })();
            CryptCATAdminReleaseContext(admin, 0);
            result
        }
    }
}

/// A copy, in `dir`, of a System32 program with an embedded signature, one
/// byte of its code changed. `None` when no such program is found.
#[cfg(all(test, windows))]
pub(crate) fn tampered_copy(dir: &Path) -> Option<std::path::PathBuf> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut programs: Vec<_> = std::fs::read_dir(Path::new(&root).join("System32"))
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.len() < 8 << 20))
        .collect();
    programs.sort();
    let original = programs.into_iter().find(|p| matches!(verify(p), Trust::Signed { catalog: false, .. }))?;
    let mut data = std::fs::read(&original).ok()?;
    data[0x400] ^= 0xFF;
    let copy = dir.join("tampered.exe");
    std::fs::write(&copy, data).ok()?;
    Some(copy)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_programs_are_signed_and_plain_files_are_not() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        // notepad.exe is catalog-signed on current Windows, embedded on older.
        let notepad = Path::new(&root).join(r"System32\notepad.exe");
        match verify(&notepad) {
            Trust::Signed { signer, .. } => assert!(signer.unwrap_or_default().contains("Microsoft")),
            other => panic!("notepad.exe: {other:?}"),
        }

        let tmp = tempfile::tempdir().unwrap();
        let plain = tmp.path().join("plain.exe");
        std::fs::write(&plain, b"MZ not really a program").unwrap();
        assert!(!verify(&plain).is_signed());
        assert!(matches!(verify(&tmp.path().join("missing.exe")), Trust::Unknown(_)));
    }

    #[test]
    fn a_program_changed_after_signing_is_tampered() {
        let tmp = tempfile::tempdir().unwrap();
        let Some(copy) = tampered_copy(tmp.path()) else {
            eprintln!("no program with an embedded signature in System32; skipped");
            return;
        };
        assert_eq!(verify(&copy), Trust::Tampered);
    }
}
