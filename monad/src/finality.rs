//! Block finality management

/// Tracks block finality status for Firehose
#[derive(Debug, Clone)]
pub struct FinalityStatus {
    /// Last irreversible block number
    lib_num: u64,
}

impl FinalityStatus {
    /// Create a new finality status
    pub fn new() -> Self {
        Self {
            lib_num: 0,
        }
    }

    /// Update the last irreversible block number
    pub fn update_lib(&mut self, lib_num: u64) {
        self.lib_num = lib_num;
    }

    /// Get the last irreversible block number
    pub fn lib_num(&self) -> u64 {
        self.lib_num
    }

    /// Check if a block is final
    pub fn is_block_final(&self, block_num: u64) -> bool {
        block_num <= self.lib_num
    }
}

impl Default for FinalityStatus {
    fn default() -> Self {
        Self::new()
    }
}
