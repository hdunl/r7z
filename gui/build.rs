//! Embeds the r7z icon in the Windows executable. The icon is rendered from the same code
//! as the window icon; `rc.exe` (Windows SDK) compiles it. Without `rc.exe` the build
//! continues and the executable shows the default icon.

include!("src/logo.rs");

use std::io::Write;
use std::path::PathBuf;

/// A multi-resolution .ico with 32-bit BMP images (alpha in the color data).
fn ico(sizes: &[u32]) -> Vec<u8> {
    let mut images = Vec::new();
    for &s in sizes {
        let rgba = logo_rgba(s);
        let mut img = Vec::new();
        let mask_row = s.div_ceil(32) * 4;
        let header: [u32; 10] = [40, s, s * 2, 0, 0, s * s * 4 + mask_row * s, 0, 0, 0, 0];
        for (k, v) in header.iter().enumerate() {
            match k {
                // biPlanes (u16) and biBitCount (u16) share the fourth u32 slot.
                3 => img.extend_from_slice(&[1, 0, 32, 0]),
                _ => img.extend_from_slice(&v.to_le_bytes()),
            }
        }
        for y in (0..s).rev() {
            for x in 0..s {
                let i = ((y * s + x) * 4) as usize;
                img.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
            }
        }
        img.extend(std::iter::repeat_n(0u8, (mask_row * s) as usize));
        images.push((s, img));
    }
    let mut out = vec![0, 0, 1, 0];
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (s, img) in &images {
        let d = if *s >= 256 { 0 } else { *s as u8 };
        out.extend_from_slice(&[d, d, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for (_, img) in images {
        out.extend_from_slice(&img);
    }
    out
}

fn main() {
    println!("cargo:rerun-if-changed=src/logo.rs");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // Without a manifest Windows hands the process the legacy common controls, and the
    // system file dialogs draw parts of themselves (the address bar) black.
    println!("cargo:rerun-if-changed=res/r7z-gui.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("res/r7z-gui.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico_path = out.join("r7z.ico");
    std::fs::write(&ico_path, ico(&[16, 20, 24, 32, 40, 48, 64, 128, 256])).unwrap();
    let rc_path = out.join("r7z.rc");
    let mut rc = std::fs::File::create(&rc_path).unwrap();
    let escaped = ico_path.display().to_string().replace('\\', "\\\\");
    writeln!(rc, "1 ICON \"{escaped}\"").unwrap();
    let res = out.join("r7z.res");
    let ok = std::process::Command::new("rc.exe")
        .args(["/nologo", "/fo"])
        .arg(&res)
        .arg(&rc_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("cargo:rustc-link-arg-bins={}", res.display());
    } else {
        println!("cargo:warning=rc.exe not found; r7z-gui.exe will use the default icon");
    }
}
