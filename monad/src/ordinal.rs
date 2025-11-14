//! Ordinal tracking for execution ordering

/// Tracks ordinal numbers for execution ordering in Firehose
#[derive(Debug, Clone)]
pub struct Ordinal {
    current: u64,
}

impl Ordinal {
    /// Create a new ordinal counter starting at 0
    pub fn new() -> Self {
        Self { current: 0 }
    }

    /// Get the next ordinal number
    pub fn next(&mut self) -> u64 {
        let current = self.current;
        self.current += 1;
        current
    }

    /// Get the current ordinal without incrementing
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Reset the ordinal counter
    pub fn reset(&mut self) {
        self.current = 0;
    }
}

impl Default for Ordinal {
    fn default() -> Self {
        Self::new()
    }
}
