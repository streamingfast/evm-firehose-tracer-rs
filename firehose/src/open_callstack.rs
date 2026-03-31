use alloy_primitives::Address;

use crate::StringError;

/// A call frame that has been entered but not yet exited. The exit is deferred
/// until the next call frame arrives, or until an explicit flush is requested
pub struct OpenCall {
    pub depth: i32,
    pub addr: Address,
    pub call_type: i32,
    pub output: Box<[u8]>,
    pub gas_used: u64,
    pub failed: bool,
    pub error: Option<StringError>,
}

/// OpenCallStack holds call frames that have been entered but not yet exited.
/// Frames are flushed (closed) when a shallower-or-equal-depth call arrives,
/// or when flush() / flush_at_or_below() is called explicitly
pub struct OpenCallStack {
    stack: Vec<OpenCall>,
}

impl OpenCallStack {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
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

    pub fn clear(&mut self) {
        self.stack.clear();
    }
}
