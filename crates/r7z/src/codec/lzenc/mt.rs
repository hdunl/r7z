//! Binary tree match finding on a thread of its own.
//!
//! The optimal parser asks for the matches of each position in order, and skips the
//! positions a chosen match covers. The binary tree update is the expensive part, and it
//! depends only on the input, not on the parser's choices. So a producer thread runs the
//! match finder over every position of the stream it is fed, and publishes each position's
//! match list keyed by its absolute position. The parser takes the lists it asks for and
//! passes over the rest. Because the lists are the ones the single-threaded finder would
//! return, the encoded bytes do not change.
//!
//! Positions the producer does not process are the ones the parser does not process
//! either: a position is left out only while it still lacks lookahead, which happens at
//! the group flush and at the end of the stream. The `Flush` and `Finish` messages carry
//! that boundary, so both sides see the same end of data.

use std::io;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TryRecvError};

use crate::codec::lzenc::lz::{
    Bt4, LzEncoder, MatchFind, MatchFinders, Matches, DEFAULT_RESERVE_DIV,
};
use crate::codec::lzenc::MATCH_LEN_MAX;

/// Positions per block sent from the producer to the parser.
const BLOCK_POSITIONS: usize = 4096;

/// Blocks in flight. Bounds how far the producer runs ahead of the parser.
const BLOCKS_IN_FLIGHT: usize = 8;

/// Slack of the producer's window, which only needs the dictionary and the lookahead. The
/// parser's window keeps the inline encoder's slack: how much input the window holds changes
/// the parser's choices (see `window.rs`), so the two must match for identical output.
const PRODUCER_RESERVE_DIV: u32 = 8;

/// Messages from the parser to the producer, in stream order.
pub(crate) enum Msg {
    /// Bytes accepted by the parser's window.
    Input(Vec<u8>),
    /// The parser closes a group here (`Lzma2Writer` starts a new dictionary).
    Flush,
    /// The stream ends here.
    Finish,
}

/// One position's match list, located in `Block::pairs`.
#[derive(Clone, Copy)]
struct Entry {
    key: u64,
    start: u32,
    count: u32,
}

#[derive(Default)]
pub(crate) struct Block {
    entries: Vec<Entry>,
    /// `(len, dist)` pairs of all entries, back to back.
    pairs: Vec<u32>,
}

/// Match finder side of the parser: takes the lists the producer computed.
pub(crate) struct Consumer {
    rx: Receiver<Block>,
    cur: Block,
    idx: usize,
    failed: bool,
}

impl Consumer {
    /// True once a list was missing or the producer stopped early. The stream is then
    /// not encodable and the writer reports an error.
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    /// Copies the list of the position with absolute key `key` into `matches`. Entries
    /// for positions the parser passed over are dropped on the way.
    fn fetch(&mut self, key: u64, matches: &mut Matches) {
        loop {
            while self.idx < self.cur.entries.len() && self.cur.entries[self.idx].key < key {
                self.idx += 1;
            }
            if self.idx < self.cur.entries.len() {
                let e = self.cur.entries[self.idx];
                if e.key != key {
                    self.failed = true;
                    matches.count = 0;
                    return;
                }
                self.idx += 1;
                let n = e.count as usize;
                let start = e.start as usize;
                let pairs = &self.cur.pairs[start..start + 2 * n];
                matches.count = e.count;
                for (i, p) in pairs.as_chunks::<2>().0.iter().enumerate() {
                    matches.len[i] = p[0];
                    matches.dist[i] = p[1] as i32;
                }
                return;
            }
            match self.rx.recv() {
                Ok(block) => {
                    self.cur = block;
                    self.idx = 0;
                }
                Err(_) => {
                    self.failed = true;
                    matches.count = 0;
                    return;
                }
            }
        }
    }
}

impl MatchFind for Consumer {
    fn find_matches(
        &mut self,
        encoder: &mut crate::codec::lzenc::lz::LzEncoderData,
        matches: &mut Matches,
    ) {
        matches.count = 0;
        let avail = encoder.move_pos(encoder.nice_len as _, 4);
        if avail == 0 {
            // Pending positions have no list; the producer skipped them as well.
            return;
        }
        let key = encoder.base + encoder.read_pos as u64;
        self.fetch(key, matches);
    }

    fn skip(&mut self, encoder: &mut crate::codec::lzenc::lz::LzEncoderData, len: usize) {
        // Lists are located by key, so passing over a position only moves the window.
        for _ in 0..len {
            encoder.move_pos(encoder.nice_len as _, 4);
        }
    }
}

/// The producer's side: runs the binary tree over the stream and publishes the lists.
struct Producer {
    lz: LzEncoder,
    block: Block,
    tx: SyncSender<Block>,
}

impl Producer {
    /// Matches of the next position. Returns false when the parser has gone away.
    fn step(&mut self) -> bool {
        let pending = self.lz.pending_size;
        self.lz.find_matches();
        if self.lz.pending_size == pending {
            let key = self.lz.base + self.lz.read_pos as u64;
            let m = self.lz.matches();
            let n = m.count as usize;
            let start = self.block.pairs.len() as u32;
            for i in 0..n {
                self.block.pairs.push(m.len[i]);
                self.block.pairs.push(m.dist[i] as u32);
            }
            self.block.entries.push(Entry {
                key,
                start,
                count: n as u32,
            });
            if self.block.entries.len() >= BLOCK_POSITIONS {
                return self.send();
            }
        }
        true
    }

    fn send(&mut self) -> bool {
        if self.block.entries.is_empty() {
            return true;
        }
        let block = std::mem::take(&mut self.block);
        self.tx.send(block).is_ok()
    }

    /// Processes every position that has the lookahead the parser needs. A position has
    /// `MATCH_LEN_MAX` bytes of lookahead when at least that many follow it, so its
    /// result does not depend on how much input has arrived.
    fn pump(&mut self) -> bool {
        while self.lz.write_pos - self.lz.read_pos > MATCH_LEN_MAX as i32 {
            if !self.step() {
                return false;
            }
        }
        true
    }

    fn ingest(&mut self, input: &[u8]) -> bool {
        let mut off = 0;
        while off < input.len() {
            off += self.lz.fill_window(&input[off..]);
            if !self.pump() {
                return false;
            }
        }
        true
    }

    /// Processes the rest of the input once the stream end is known.
    fn tail(&mut self) -> bool {
        while self.lz.read_pos + 1 < self.lz.write_pos {
            if !self.step() {
                return false;
            }
        }
        self.send()
    }
}

fn run(mut p: Producer, rx: Receiver<Msg>) {
    loop {
        // Before waiting for input, publish every list computed so far: the parser may be
        // waiting for one of them, and it cannot send more input until it gets it.
        let msg = match rx.try_recv() {
            Ok(msg) => msg,
            Err(TryRecvError::Empty) => {
                if !p.send() {
                    return;
                }
                match rx.recv() {
                    Ok(msg) => msg,
                    Err(_) => return,
                }
            }
            Err(TryRecvError::Disconnected) => return,
        };
        let alive = match msg {
            Msg::Input(bytes) => p.ingest(&bytes),
            Msg::Flush => {
                p.lz.set_flushing();
                p.tail();
                false
            }
            Msg::Finish => {
                p.lz.set_finishing();
                p.tail();
                false
            }
        };
        if !alive {
            return;
        }
    }
}

/// Starts a producer for a window of `dict_size` bytes. Returns the sender for the input
/// stream and the parser's side of the match lists.
pub(crate) fn spawn(
    dict_size: u32,
    extra_before: u32,
    extra_after: u32,
    nice_len: usize,
    depth_limit: i32,
) -> io::Result<(Sender<Msg>, LzEncoder)> {
    let (in_tx, in_rx) = channel::<Msg>();
    let (blk_tx, blk_rx) = sync_channel::<Block>(BLOCKS_IN_FLIGHT);
    let producer_lz = LzEncoder::new(
        dict_size,
        extra_before,
        extra_after,
        nice_len as u32,
        MATCH_LEN_MAX as u32,
        MatchFinders::Bt4(Bt4::new(dict_size, nice_len as u32, depth_limit)),
        PRODUCER_RESERVE_DIV,
    );
    let producer = Producer {
        lz: producer_lz,
        block: Block::default(),
        tx: blk_tx,
    };
    std::thread::Builder::new()
        .name("r7z-match-finder".into())
        .spawn(move || run(producer, in_rx))?;
    let consumer = Consumer {
        rx: blk_rx,
        cur: Block::default(),
        idx: 0,
        failed: false,
    };
    let lz = LzEncoder::new(
        dict_size,
        extra_before,
        extra_after,
        nice_len as u32,
        MATCH_LEN_MAX as u32,
        MatchFinders::Threaded(consumer),
        DEFAULT_RESERVE_DIV,
    );
    Ok((in_tx, lz))
}
