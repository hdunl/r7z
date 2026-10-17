// Windows resources for r7z.exe and r7z-gui.exe: version information and, for the desktop
// app, the icon. Included by both build scripts. `rc.exe` from the Windows SDK compiles
// them; without it the build continues and the program has no version information.

/// Writes `<name>.rc` into `out`, compiles it and links it into the crate's programs.
/// `icon` is an .ico file to embed as icon 1. Returns false when rc.exe is missing or
/// fails, which fails the build when R7Z_REQUIRE_RESOURCES is set (release builds).
fn compile_resources(
    out: &std::path::Path,
    name: &str,
    description: &str,
    icon: Option<&std::path::Path>,
) -> bool {
    println!("cargo:rerun-if-env-changed=R7Z_REQUIRE_RESOURCES");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut parts = version.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    let mut next = || parts.next().unwrap_or(0);
    let (major, minor, patch) = (next(), next(), next());

    let mut rc = String::new();
    if let Some(icon) = icon {
        let path = icon.display().to_string().replace('\\', "\\\\");
        rc.push_str(&format!("1 ICON \"{path}\"\n"));
    }
    rc.push_str(&format!(
        r#"1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3F
FILEFLAGS 0x0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "r7z"
      VALUE "FileDescription", "{description}"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "{name}"
      VALUE "LegalCopyright", "Copyright 2026 the r7z contributors. Apache License 2.0."
      VALUE "OriginalFilename", "{name}.exe"
      VALUE "ProductName", "r7z"
      VALUE "ProductVersion", "{version}"
      VALUE "Comments", "https://github.com/hdunl/r7z"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
    ));
    let rc_path = out.join(format!("{name}.rc"));
    std::fs::write(&rc_path, rc).unwrap();
    let res = out.join(format!("{name}.res"));
    let ok = std::process::Command::new(rc_exe())
        .args(["/nologo", "/fo"])
        .arg(&res)
        .arg(&rc_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("cargo:rustc-link-arg-bins={}", res.display());
    } else if std::env::var_os("R7Z_REQUIRE_RESOURCES").is_some() {
        panic!("rc.exe was not found, so {name}.exe would ship without its version information and icon (R7Z_REQUIRE_RESOURCES is set)");
    } else {
        println!("cargo:warning=rc.exe not found; {name}.exe will have no version information or icon");
    }
    ok
}

/// rc.exe from PATH (a developer prompt), or else the newest Windows 10/11 SDK, which is
/// installed with the C++ build tools but not put on PATH outside a developer prompt.
fn rc_exe() -> std::path::PathBuf {
    use std::path::PathBuf;
    let on_path = std::process::Command::new("rc.exe")
        .arg("/?")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if on_path {
        return PathBuf::from("rc.exe");
    }
    let kits = std::env::var_os("ProgramFiles(x86)")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"))
        .join(r"Windows Kits\10\bin");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&kits)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join(r"x64\rc.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort();
    found.pop().unwrap_or_else(|| PathBuf::from("rc.exe"))
}
