//! Draws the Phalanx icon from the mark's geometry (`src/gui/mark.rs`) into
//! `OUT_DIR` (`phalanx.ico` for Windows, `phalanx.png` for notifications)
//! and embeds the icon and version information into the executables on
//! Windows: with `rc.exe` from the Windows SDK on MSVC toolchains, `windres`
//! on GNU ones. Without either, the build continues without them and says so.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "src/gui/mark.rs"]
mod mark;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/gui/mark.rs");
    println!("cargo:rerun-if-env-changed=WINDRES");
    println!("cargo:rerun-if-env-changed=RC");
    println!("cargo::rustc-check-cfg=cfg(embedded_icon)");
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let out = PathBuf::from(var("OUT_DIR"));
    let icon = out.join("phalanx.ico");
    std::fs::write(&icon, mark::ico(mark::Style::Icon)).expect("writing the icon");
    std::fs::write(out.join("phalanx.png"), mark::png(&mark::mark_rgba(256, mark::Style::Icon), 256, 256)).expect("writing the notification icon");
    if var("CARGO_CFG_TARGET_OS") != "windows" {
        return;
    }
    let version = var("CARGO_PKG_VERSION");
    let numeric = version.split(['-', '+']).next().unwrap_or("0.0.0").replace('.', ",");
    let rc = format!(
        r#"1 ICON "{icon}"
1 VERSIONINFO
FILEVERSION {numeric},0
PRODUCTVERSION {numeric},0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Phalanx"
      VALUE "FileDescription", "Phalanx"
      VALUE "ProductName", "Phalanx"
      VALUE "FileVersion", "{version}"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = icon.display().to_string().replace('\\', "/"),
    );
    let rc_path = out.join("phalanx.rc");
    std::fs::write(&rc_path, rc).expect("writing the resource script");
    match var("CARGO_CFG_TARGET_ENV").as_str() {
        "gnu" => {
            let obj = out.join("phalanx-res.o");
            let windres = std::env::var("WINDRES").unwrap_or_else(|_| "windres".into());
            let status = Command::new(&windres).arg("-i").arg(&rc_path).args(["-O", "coff", "-o"]).arg(&obj).status();
            link_or_warn(&windres, status, &obj);
        }
        "msvc" => {
            let res = out.join("phalanx.res");
            let Some(rc_exe) = std::env::var_os("RC").map(PathBuf::from).or_else(find_rc) else {
                println!("cargo:warning=skipping the executable icon: rc.exe was not found (install the Windows SDK or set RC)");
                return;
            };
            let status = Command::new(&rc_exe).args(["/nologo", "/fo"]).arg(&res).arg(&rc_path).status();
            link_or_warn(&rc_exe.display().to_string(), status, &res);
        }
        other => println!("cargo:warning=skipping the executable icon: unsupported toolchain {other}"),
    }
}

fn link_or_warn(tool: &str, status: std::io::Result<std::process::ExitStatus>, resource: &Path) {
    match status {
        Ok(status) if status.success() => {
            println!("cargo:rustc-link-arg-bins={}", resource.display());
            println!("cargo:rustc-cfg=embedded_icon");
        }
        Ok(status) => println!("cargo:warning=skipping the executable icon: {tool} exited with {status}"),
        Err(e) => println!("cargo:warning=skipping the executable icon: could not run {tool}: {e}"),
    }
}

/// The newest x64 `rc.exe` in the Windows 10/11 SDK.
fn find_rc() -> Option<PathBuf> {
    let base = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(base).ok()?.flatten().map(|e| e.path()).filter(|p| p.join("x64").join("rc.exe").is_file()).collect();
    versions.sort();
    versions.pop().map(|v| v.join("x64").join("rc.exe"))
}
