//! Async emission types and helpers.
//!
//! This module contains the types and free functions that support the async
//! emission path: the queue item ([`RawBlock`]), the caller-facing
//! [`ShutdownHandle`], the background writer loop, and the cursor-file writer.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::pb::sf::ethereum::r#type::v2::Block;

/// An already-collected block ready for protobuf serialisation in the
/// background writer thread.
pub(crate) struct RawBlock {
    pub block: Block,
    pub lib_num: u64,
    pub printed_flash_block_index: u64,
    pub block_num: u64,
}

/// A handle that, when dropped or [`drain`](ShutdownHandle::drain)ed, waits
/// for the background writer thread to flush all queued blocks and exit.
///
/// Obtained from [`Tracer::shutdown_handle`].
///
/// # Shutdown protocol
///
/// The handle owns the *only* sender on the channel.  Dropping the handle
/// (or calling `drain`) closes the channel, which signals EOF to the writer
/// thread.  The writer thread drains any remaining items and then exits.
pub struct ShutdownHandle {
    pub(crate) sender: SyncSender<RawBlock>,
    pub(crate) thread: Option<JoinHandle<()>>,
}

impl ShutdownHandle {
    /// Block until the background writer has flushed all queued blocks and exited.
    pub fn drain(mut self) {
        // Closing the channel signals EOF to the writer thread.
        drop(self.sender);
        if let Some(t) = self.thread.take() {
            t.join().ok();
        }
    }
}

/// Atomically write the block number to the cursor file.
///
/// Writes to `<path>.tmp` first, then renames to `<path>` to avoid torn reads.
/// Format: single decimal integer followed by `\n`.
pub(crate) fn update_cursor_file(cursor_path: &Path, block_num: u64) {
    let tmp_path = {
        let mut p = cursor_path.to_path_buf();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        p.set_file_name(name);
        p
    };
    let content = format!("{}\n", block_num);
    if std::fs::write(&tmp_path, content.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp_path, cursor_path);
    }
}

/// Reads the last confirmed block number from the cursor file, if it exists.
///
/// Returns `None` when the file is absent or cannot be parsed.
pub(crate) fn read_cursor_file(cursor_path: &Path) -> Option<u64> {
    std::fs::read_to_string(cursor_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Background writer thread loop.
///
/// Receives [`RawBlock`] messages, serialises them to protobuf, base64-encodes
/// the result, writes the Firehose line to `writer`, and optionally updates the
/// cursor file.  The loop exits cleanly when the channel is closed (all senders
/// dropped).
pub(crate) fn background_writer_loop(
    rx: Receiver<RawBlock>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    cursor_path: Option<PathBuf>,
) {
    loop {
        match rx.recv() {
            Ok(raw) => {
                crate::printer::print_block_to_firehose(
                    &mut *writer.lock().unwrap(),
                    raw.block,
                    raw.lib_num,
                    raw.printed_flash_block_index,
                );
                if let Some(path) = &cursor_path {
                    update_cursor_file(path, raw.block_num);
                }
            }
            Err(_) => break, // sender dropped → drain complete → exit
        }
    }
}
