//! Pieces shared by recovery opens: a stream reader that ends at the first decoding error
//! (so an archive nested in a damaged `.gz` opens as far as the data goes) and a wrapper
//! that attaches damage notes to a rebuilt archive.

use std::io::{self, Read};
use std::sync::Arc;

use super::data::{BoxRead, Input, Opener};
use super::{Archive, Columns, Ctx, Entry, EntryFn, Format, Level, Notes, Unit};
use crate::error::Result;

/// Ends at the first read error instead of failing, and notes where that happened.
struct UntilError {
    inner: BoxRead,
    pos: u64,
    what: String,
    notes: Notes,
    done: bool,
}

impl Read for UntilError {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        loop {
            match self.inner.read(buf) {
                Ok(n) => {
                    self.pos += n as u64;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.done = true;
                    let err = super::data::data_err(e);
                    if matches!(err, crate::error::Error::Cancelled) {
                        return Err(err.into_io());
                    }
                    let note = format!(
                        "{}: decoding stopped after {} bytes ({err}); the data after that point is lost",
                        self.what, self.pos
                    );
                    let mut n = self.notes.lock().unwrap();
                    if !n.contains(&note) {
                        n.push(note);
                    }
                    return Ok(0);
                }
            }
        }
    }
}

/// Wraps the stream `lvl` holds so that it ends at its first error.
pub(super) fn until_error(input: Input, lvl: &Level, notes: &Notes) -> Input {
    match input {
        Input::Stream { open, size_hint } => {
            let what = format!("{} ({})", lvl.name, lvl.archive.format().name);
            let notes = notes.clone();
            let open: Opener = Arc::new(move || {
                Ok(Box::new(UntilError {
                    inner: open()?,
                    pos: 0,
                    what: what.clone(),
                    notes: notes.clone(),
                    done: false,
                }) as BoxRead)
            });
            Input::Stream { open, size_hint }
        }
        mem => mem,
    }
}

/// An archive rebuilt by a recovery open, with notes on what was rebuilt.
pub struct Salvaged {
    pub inner: Box<dyn Archive>,
    pub notes: Vec<String>,
}

impl Archive for Salvaged {
    fn format(&self) -> &'static Format {
        self.inner.format()
    }
    fn entries(&self) -> &[Entry] {
        self.inner.entries()
    }
    fn units(&self) -> &[Unit] {
        self.inner.units()
    }
    fn extract_unit(&self, unit: usize, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        self.inner.extract_unit(unit, ctx, f)
    }
    fn properties(&self) -> Vec<(&'static str, String)> {
        self.inner.properties()
    }
    fn columns(&self) -> Columns {
        self.inner.columns()
    }
    fn verifies_data(&self) -> bool {
        self.inner.verifies_data()
    }
    fn has_encrypted_data(&self) -> bool {
        self.inner.has_encrypted_data()
    }
    fn damage(&self) -> Vec<String> {
        let mut d = self.notes.clone();
        d.extend(self.inner.damage());
        d
    }
    fn restart_points(&self, unit: usize) -> Vec<u64> {
        self.inner.restart_points(unit)
    }
    fn extract_unit_at(&self, unit: usize, at: u64, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        self.inner.extract_unit_at(unit, at, ctx, f)
    }
}
