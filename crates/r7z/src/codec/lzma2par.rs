//! Parallel LZMA2 encoder with dictionary priming.
//!
//! The stream is cut into *groups* that start with a dictionary reset (independently
//! decodable, like 7-Zip's LZMA2 blocks of 4x dictionary). Each group is cut further into
//! *sub-blocks* that are compressed concurrently. A sub-block's encoder is primed with the
//! data preceding it in its group as a preset dictionary, and its first chunk resets only
//! the coder state, not the dictionary. A sequential decoder therefore sees one continuous
//! dictionary, so the ratio stays close to single-threaded encoding while every core works.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::lzenc::{Lzma2Options, Lzma2Writer, LzmaOptions};

use super::encode::{Hooks, Sink};
use super::{lzma2_dict_from_prop, lzma2_prop_for_dict};
use crate::error::Error;

struct Job {
    seq: u64,
    preset: Option<Vec<u8>>,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct ParPlan {
    /// Bytes between dictionary resets.
    pub group: u64,
    /// Bytes per concurrently encoded sub-block.
    pub sub: usize,
    /// Preset-dictionary bytes given to each sub-block (at most the dictionary size).
    pub prime: usize,
    pub workers: usize,
}

pub struct ParLzma2Writer<'a> {
    inner: Box<dyn Sink + 'a>,
    plan: ParPlan,
    history: Vec<u8>,
    group_pos: u64,
    pending: Vec<u8>,
    tx: Option<Sender<Job>>,
    results: Receiver<(u64, io::Result<Vec<u8>>)>,
    workers: Vec<JoinHandle<()>>,
    next_seq: u64,
    next_out: u64,
    reorder: BTreeMap<u64, Vec<u8>>,
    in_flight: usize,
    hooks: Hooks<'a>,
    /// Input size of each job in flight, reported to `hooks.progress` when written.
    lens: BTreeMap<u64, u64>,
    /// Cancelled: workers are left to finish their current job and exit on their own.
    abandoned: bool,
}

fn encode_job(opts: &LzmaOptions, job: Job) -> io::Result<Vec<u8>> {
    let mut o = opts.clone();
    // Matches never reach past the preset, so the job only needs a dictionary covering
    // preset + data. The stream still declares the full dictionary for the decoder.
    let reach = job.preset.as_ref().map_or(0, |p| p.len()) + job.data.len();
    let need =
        lzma2_dict_from_prop(lzma2_prop_for_dict(reach.min(u32::MAX as usize) as u32)).unwrap();
    o.dict_size = o.dict_size.min(need).max(4096);
    o.preset_dict = job.preset;
    let options = Lzma2Options {
        lzma_options: o,
        chunk_size: None::<NonZeroU64>,
    };
    let mut w = Lzma2Writer::new(Vec::with_capacity(job.data.len() / 2 + 1024), options);
    w.write_all(&job.data)?;
    w.flush()?;
    Ok(w.into_inner())
}

impl<'a> ParLzma2Writer<'a> {
    pub fn new(
        inner: Box<dyn Sink + 'a>,
        opts: LzmaOptions,
        plan: ParPlan,
        hooks: Hooks<'a>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let (rtx, results) = mpsc::channel();
        let opts = Arc::new(opts);
        let workers = (0..plan.workers.max(1))
            .map(|_| {
                let rx = Arc::clone(&rx);
                let rtx = rtx.clone();
                let opts = Arc::clone(&opts);
                std::thread::spawn(move || loop {
                    let job = match rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => return,
                    };
                    let seq = job.seq;
                    let r = encode_job(&opts, job);
                    if rtx.send((seq, r)).is_err() {
                        return;
                    }
                })
            })
            .collect();
        ParLzma2Writer {
            inner,
            plan,
            history: Vec::new(),
            group_pos: 0,
            pending: Vec::with_capacity(plan.sub),
            tx: Some(tx),
            results,
            workers,
            next_seq: 0,
            next_out: 0,
            reorder: BTreeMap::new(),
            in_flight: 0,
            hooks,
            lens: BTreeMap::new(),
            abandoned: false,
        }
    }

    /// Bytes still wanted for the current sub-block (sub-blocks never cross groups).
    fn want(&self) -> usize {
        let to_group_end = self.plan.group - self.group_pos - self.pending.len() as u64;
        (self.plan.sub - self.pending.len()).min(to_group_end as usize)
    }

    fn take_result(&mut self) -> io::Result<()> {
        // Waits in short slices so a cancel request is noticed while workers are busy.
        let (seq, r) = loop {
            match self.results.recv_timeout(Duration::from_millis(100)) {
                Ok(x) => break x,
                Err(RecvTimeoutError::Timeout) => {
                    if self.hooks.cancel.is_some_and(|c| c()) {
                        self.abandoned = true;
                        return Err(Error::Cancelled.into_io());
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("LZMA2 worker stopped unexpectedly"))
                }
            }
        };
        self.in_flight -= 1;
        self.reorder.insert(seq, r?);
        while let Some(buf) = self.reorder.remove(&self.next_out) {
            self.inner.write_all(&buf)?;
            if let (Some(p), Some(n)) = (self.hooks.progress, self.lens.remove(&self.next_out)) {
                p(n);
            }
            self.next_out += 1;
        }
        Ok(())
    }

    fn dispatch(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        // One queued job per worker keeps everyone busy; more only costs memory.
        while self.in_flight > self.plan.workers {
            self.take_result()?;
        }
        let data = std::mem::replace(&mut self.pending, Vec::with_capacity(self.plan.sub));
        let preset = if self.group_pos == 0 || self.plan.prime == 0 {
            None
        } else {
            Some(self.history.clone())
        };
        self.group_pos += data.len() as u64;
        if self.group_pos >= self.plan.group {
            self.group_pos = 0;
            self.history.clear();
        } else if self.plan.prime > 0 {
            self.history.extend_from_slice(&data);
            if self.history.len() > self.plan.prime {
                let cut = self.history.len() - self.plan.prime;
                self.history.drain(..cut);
            }
        }
        self.lens.insert(self.next_seq, data.len() as u64);
        let job = Job {
            seq: self.next_seq,
            preset,
            data,
        };
        self.next_seq += 1;
        self.in_flight += 1;
        self.tx
            .as_ref()
            .unwrap()
            .send(job)
            .map_err(|_| io::Error::other("LZMA2 workers unavailable"))
    }
}

impl Write for ParLzma2Writer<'_> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        while !buf.is_empty() {
            let take = self.want().min(buf.len());
            self.pending.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
            if self.want() == 0 {
                self.dispatch()?;
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink for ParLzma2Writer<'_> {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.dispatch()?;
        while self.in_flight > 0 {
            self.take_result()?;
        }
        self.tx = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        self.inner.write_all(&[0x00])?;
        let inner = std::mem::replace(&mut self.inner, Box::new(NullSink));
        inner.finish()
    }
}

impl Drop for ParLzma2Writer<'_> {
    fn drop(&mut self) {
        self.tx = None;
        if self.abandoned {
            return;
        }
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

struct NullSink;
impl Write for NullSink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Sink for NullSink {
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}
