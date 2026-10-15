//! Embeds the Phalanx icon and version information into the executables
//! (Windows GNU toolchains, via `windres`). Elsewhere, or without `windres`,
//! the build continues without them and says so.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/phalanx.ico");
    println!("cargo:rerun-if-env-changed=WINDRES");
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    if var("CARGO_CFG_TARGET_OS") != "windows" {
        return;
    }
    if var("CARGO_CFG_TARGET_ENV") != "gnu" {
        println!("cargo:warning=skipping the executable icon: only the GNU toolchain (windres) is supported");
        return;
    }
    let out = PathBuf::from(var("OUT_DIR"));
    let icon = PathBuf::from(var("CARGO_MANIFEST_DIR")).join("assets").join("phalanx.ico");
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
    let obj = out.join("phalanx-res.o");
    std::fs::write(&rc_path, rc).expect("writing the resource script");
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "windres".into());
    match Command::new(&windres).arg("-i").arg(&rc_path).args(["-O", "coff", "-o"]).arg(&obj).status() {
        Ok(status) if status.success() => println!("cargo:rustc-link-arg-bins={}", obj.display()),
        Ok(status) => println!("cargo:warning=skipping the executable icon: {windres} exited with {status}"),
        Err(e) => println!("cargo:warning=skipping the executable icon: could not run {windres}: {e}"),
    }
}
