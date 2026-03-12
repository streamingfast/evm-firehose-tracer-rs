use pb::sf::ethereum::r#type::v2::Call;

/// CallStack manages the hierarchy of EVM calls during transaction execution.
/// It tracks the depth-based call tree and maintains parent-child relationships.
pub struct CallStack {
    stack: Vec<Call>,
    index: u32, // Call index counter (starts at 0, first call gets index 1)
    depth: i32, // Current call depth for tracking nested calls
}

impl CallStack {
    /// Creates a new empty call stack.
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(32), // Pre-allocate for typical call depth
            index: 0,
            depth: 0,
        }
    }

    /// Adds a new call to the stack and assigns Index, Depth, and ParentIndex.
    /// This matches the native Firehose tracer behavior.
    pub fn push(&mut self, call: &mut Call) {
        // Increment index first, so first call gets index 1
        self.index += 1;
        call.index = self.index;

        // Set depth from current stack depth
        call.depth = self.depth as u32;
        self.depth += 1;

        // If there's a parent call, set ParentIndex
        if let Some(parent) = self.peek() {
            call.parent_index = parent.index;
        }

        self.stack.push(call.clone());
    }

    /// Removes and returns the top call from the stack.
    /// Returns None if the stack is empty.
    pub fn pop(&mut self) -> Option<Call> {
        if self.stack.is_empty() {
            return None;
        }

        self.depth -= 1;
        self.stack.pop()
    }

    /// Returns a reference to the top call without removing it.
    /// Returns None if the stack is empty.
    pub fn peek(&self) -> Option<&Call> {
        self.stack.last()
    }

    /// Returns a mutable reference to the top call without removing it.
    /// Returns None if the stack is empty.
    pub fn peek_mut(&mut self) -> Option<&mut Call> {
        self.stack.last_mut()
    }

    /// Returns true if there's at least one call on the stack.
    pub fn has_active_call(&self) -> bool {
        !self.stack.is_empty()
    }

    /// Clears the call stack and resets counters.
    pub fn reset(&mut self) {
        self.stack.clear();
        self.index = 0;
        self.depth = 0;
    }
}

impl Default for CallStack {
    fn default() -> Self {
        Self::new()
    }
}
