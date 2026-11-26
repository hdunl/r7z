//! Inputs that once crashed a fuzz target, replayed through the same code paths. Each
//! file in `tests/fixtures/fuzz/<target>/` must now be handled without a panic. Run in a
//! debug build too (CI does), so arithmetic overflow is caught as well.

use std::fs;
use std::path::Path;

use r7z::format::{self, Ctx, Flow, OpenRequest};
use r7z::ops::extract::{Callbacks, ExtractOptions, Target};
use r7z::ops::recover::{recover, RecoverOptions};

struct Quiet;
impl Callbacks for Quiet {}

fn inputs(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fuzz")
        .join(target);
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    rd.map(|e| {
        let p = e.unwrap().path();
        (
            p.file_name().unwrap().to_string_lossy().into_owned(),
            fs::read(&p).unwrap(),
        )
    })
    .collect()
}

#[test]
fn open_inputs_decode_without_panicking() {
    // Same choices as fuzz/fuzz_targets/open.rs: the last byte picks the file name and
    // whether a password is offered.
    const NAMES: [&str; 25] = [
        "a.7z", "a.zip", "a.tar", "a.gz", "a.bz2", "a.xz", "a.zst", "a.lz4", "a.Z", "a.lzma",
        "a.cab", "a.rpm", "a.deb", "a.wim", "a.001", "a.b64", "a.hex", "a.lzh", "a.vhd", "a.vhdx",
        "a.vmdk", "a.qcow2", "a.msi", "a.chm", "a.exe",
    ];
    for (_, data) in inputs("open") {
        let pick = data.last().copied().unwrap_or(0);
        let name = NAMES[pick as usize % NAMES.len()];
        let password = (pick & 0x80 != 0).then(|| "password".to_string());
        let req = OpenRequest {
            password: password.clone(),
            ..Default::default()
        };
        let Ok(opened) = format::open_bytes(data, name, &req) else {
            continue;
        };
        let ctx = Ctx {
            password,
            threads: 1,
        };
        let mut buf = vec![0u8; 64 << 10];
        for level in &opened.levels {
            let a = &level.archive;
            let _ = a.properties();
            for unit in 0..a.units().len() {
                let _ = a.extract_unit(unit, &ctx, &mut |_, reader| loop {
                    if reader.read(&mut buf).map_err(r7z::Error::from_codec)? == 0 {
                        return Ok(Flow::Continue);
                    }
                });
            }
        }
    }
}

#[test]
fn recover_inputs_run_without_panicking() {
    for (_, data) in inputs("recover") {
        // The fuzz target picks the file name from the input's last byte.
        let names = ["a.7z", "a.zip", "a.tar", "a.gz", "a.xz", "a.bz2"];
        let hint = names[*data.last().unwrap_or(&0) as usize % names.len()];
        let Ok(opened) = format::open_bytes_recover(data, hint, &OpenRequest::default()) else {
            continue;
        };
        let opts = ExtractOptions {
            password: None,
            threads: 1,
            target: Target::Test,
            selected: None,
            base: None,
        };
        let _ = recover(&opened, &opts, RecoverOptions::default(), &Quiet);
    }
}

/// An NSIS 2 installer, not inside a PE image, with a stored header holding one `File`
/// instruction named by a string of shell folder codes that each name the same string.
fn nsis_shell_folder_bomb(codes: usize) -> Vec<u8> {
    let fixed = 300;
    let mut header = vec![0u8; fixed];
    // Instruction table (2) and string table (3) descriptors.
    for (i, o, n) in [(2usize, fixed, 1usize), (3, fixed + 28, 0)] {
        header[4 + 8 * i..8 + 8 * i].copy_from_slice(&(o as u32).to_le_bytes());
        header[8 + 8 * i..12 + 8 * i].copy_from_slice(&(n as u32).to_le_bytes());
    }
    for v in [20u32, 0, 0, 0, u32::MAX, u32::MAX, 0] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    // 0xFE is a shell folder in NSIS 2; 0x80 reads its registry value name from the string
    // at offset 0, which is this one, without a NUL.
    header.extend([0xFE, 0x80, 0x80].repeat(codes));
    let mut file = b"MZ\0\0".to_vec();
    file.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    file.extend_from_slice(b"NullsoftInst");
    file.extend_from_slice(&(header.len() as u32).to_le_bytes());
    file.extend_from_slice(&(28 + 4 + header.len() as u32).to_le_bytes());
    file.extend_from_slice(&(header.len() as u32).to_le_bytes());
    file.extend_from_slice(&header);
    file
}

#[test]
fn nsis_shell_folder_names_stay_bounded() {
    // At full size (a MiB of codes) this decoded hundreds of GB of names; a few KiB already
    // made one of megabytes.
    let opened = format::open_bytes(
        nsis_shell_folder_bomb(4 << 10),
        "a.exe",
        &OpenRequest::default(),
    )
    .unwrap();
    let a = &opened.levels.last().unwrap().archive;
    assert_eq!(a.format().name, "Nsis");
    let longest = a.entries().iter().map(|e| e.name.len()).max().unwrap();
    assert!(longest <= 64 << 10, "a name of {longest} bytes");
}
