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
    for (name, data) in inputs("open") {
        let Ok(opened) = format::open_bytes(data, &name, &OpenRequest::default()) else {
            continue;
        };
        let ctx = Ctx {
            password: None,
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
