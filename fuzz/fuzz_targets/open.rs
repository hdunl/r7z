//! Opens arbitrary bytes as an archive and decodes every entry, as `r7z t` does. A panic,
//! an out-of-bounds access, an allocation driven by a header value, or a hang is a bug.
#![no_main]

use libfuzzer_sys::fuzz_target;
use r7z::format::{self, Ctx, Flow, OpenRequest};

/// File names that steer detection toward the formats recognised by their extension.
const NAMES: [&str; 18] = [
    "a.7z", "a.zip", "a.tar", "a.gz", "a.bz2", "a.xz", "a.zst", "a.lz4", "a.Z", "a.lzma", "a.cab",
    "a.rpm", "a.deb", "a.wim", "a.001", "a.b64", "a.hex", "a.lzh",
];

/// Decoded bytes per input before the rest is skipped, so each run stays short.
const BUDGET: usize = 64 << 20;

fuzz_target!(|data: &[u8]| {
    // The last byte picks the name and whether a password is offered, so seed archives
    // keep their signatures at the start.
    let pick = data.last().copied().unwrap_or(0);
    let name = NAMES[pick as usize % NAMES.len()];
    let password = (pick & 0x80 != 0).then(|| "password".to_string());
    let req = OpenRequest {
        password: password.clone(),
        ..Default::default()
    };
    let Ok(opened) = format::open_bytes(data.to_vec(), name, &req) else {
        return;
    };
    let ctx = Ctx {
        password,
        threads: 1,
    };
    let mut budget = BUDGET;
    let mut buf = vec![0u8; 64 << 10];
    for level in &opened.levels {
        let a = &level.archive;
        let _ = a.properties();
        for unit in 0..a.units().len() {
            if budget == 0 {
                return;
            }
            let _ = a.extract_unit(unit, &ctx, &mut |_, reader| loop {
                let n = reader.read(&mut buf).map_err(r7z::Error::from_codec)?;
                if n == 0 {
                    return Ok(Flow::Continue);
                }
                budget = budget.saturating_sub(n);
                if budget == 0 {
                    return Ok(Flow::Stop);
                }
            });
        }
    }
});
