use alloy_primitives::Address;

use crate::{tracer::Tracer, StringError};

/// A call frame that has been entered but not yet exited. The exit is deferred
/// until the next call frame arrives, or until an explicit flush is requested
pub struct OpenCall {
    pub depth: i32,
    pub addr: Address,
    pub call_type: i32,
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub error: Option<StringError>,
    pub is_last: bool,
}

/// OpenCallStack holds call frames that have been entered but not yet exited.
/// Frames are flushed (closed) when a shallower-or-equal-depth call arrives,
/// or when flush() / flush_at_or_below() is called explicitly
pub struct OpenCallStack {
    stack: Vec<OpenCall>,
}

impl Default for OpenCallStack {
    fn default() -> Self {
        Self { stack: Vec::new() }
    }
}

impl OpenCallStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, call: OpenCall) {
        self.stack.push(call);
    }

    /// Returns the top frame without removing it.
    pub fn peek_depth(&self) -> Option<i32> {
        self.stack.last().map(|c| c.depth)
    }

    /// Pops and returns the top frame.
    pub fn pop(&mut self) -> Option<OpenCall> {
        self.stack.pop()
    }

    /// Flushes all open calls whose depth is >= min_depth, closing them (deepest first)
    /// Use min_depth = 0 to flush everything, min_depth = 1 to keep the root call open
    pub fn flush(&mut self, min_depth: i32, tracer: &mut Tracer) {
        while self.peek_depth().map_or(false, |d| d >= min_depth) {
            let open = self.stack.pop().unwrap();
            let is_last = open.is_last;
            Self::close(open, tracer);
            if is_last {
                self.flush(0, tracer);
                return;
            }
        }
    }

    /// Flushes open calls at depth >= incoming_depth to make room for a new call at that depth.
    pub fn flush_at_or_below(&mut self, incoming_depth: i32, tracer: &mut Tracer) {
        while self.peek_depth().map_or(false, |d| d >= incoming_depth) {
            let open = self.stack.pop().unwrap();
            let is_last = open.is_last;
            Self::close(open, tracer);
            if is_last {
                self.flush(0, tracer);
                return;
            }
        }
    }

    fn close(open: OpenCall, tracer: &mut Tracer) {
        let failed = open.error.is_some();
        let err = open.error.as_ref().map(|e| e as &dyn std::error::Error);
        tracer.on_call_exit(open.depth, &open.output, open.gas_used, err, failed);
    }

    pub fn reset(&mut self) {
        self.stack.clear();
    }
}
