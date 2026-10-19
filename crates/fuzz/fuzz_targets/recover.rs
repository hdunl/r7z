//! Runs damaged-archive recovery (`r7z t -recover`) on arbitrary bytes. Recovery parses
//! input that is known to be broken, so it must never panic or allocate without bound.
#![no_main]

use libfuzzer_sys::fuzz_target;
use r7z::format::{self, OpenRequest};
use r7z::ops::extract::{Callbacks, ExtractOptions, Target};
use r7z::ops::recover::{recover, RecoverOptions};

const NAMES: [&str; 6] = ["a.7z", "a.zip", "a.tar", "a.gz", "a.xz", "a.bz2"];

struct Quiet;
impl Callbacks for Quiet {}

fuzz_target!(|data: &[u8]| {
    let pick = data.last().copied().unwrap_or(0);
    let name = NAMES[pick as usize % NAMES.len()];
    let Ok(opened) = format::open_bytes_recover(data.to_vec(), name, &OpenRequest::default())
    else {
        return;
    };
    let opts = ExtractOptions {
        password: None,
        threads: 1,
        target: Target::Test,
        selected: None,
        base: None,
    };
    let _ = recover(&opened, &opts, RecoverOptions::default(), &Quiet);
});
