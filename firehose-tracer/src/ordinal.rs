/// Ordinal is a monotonically increasing counter for assigning sequential IDs
/// to events within a block. This ensures all events have a deterministic ordering.
#[derive(Debug, Default)]
pub(super) struct Ordinal {
    value: u64,
}

impl Ordinal {
    /// Returns the next ordinal value and increments the counter.
    pub(super) fn next(&mut self) -> u64 {
        self.value += 1;
        self.value
    }

    /// Returns the current ordinal value without incrementing.
    pub(super) fn peek(&self) -> u64 {
        self.value
    }

    /// Resets the ordinal back to 0.
    pub(super) fn reset(&mut self) {
        self.value = 0;
    }

    /// Restores the ordinal to a previously saved value.
    /// This is the counterpart to peek; used in flash block snapshot restoration.
    pub(super) fn restore(&mut self, value: u64) {
        self.value = value;
    }
}
