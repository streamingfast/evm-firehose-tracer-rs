/// FinalityStatus tracks the finality status of blocks.
/// This is used to mark blocks as finalized in consensus mechanisms.
#[derive(Debug, Clone, Copy, Default)]
pub struct FinalityStatus {
    last_finalized_block_number: u64,
}

impl FinalityStatus {
    /// Clears the finality status.
    pub(super) fn reset(&mut self) {
        self.last_finalized_block_number = 0;
    }

    /// Updates the last finalized block number.
    pub(super) fn set_last_finalized_block(&mut self, block_number: u64) {
        self.last_finalized_block_number = block_number;
    }

    /// Returns true if finality status is not set (for backward compatibility with printer).
    pub(super) fn is_empty(&self) -> bool {
        self.last_finalized_block_number == 0
    }

    /// Returns the last irreversible block number (alias for backward compatibility).
    pub(super) fn last_irreversible_block_number(&self) -> u64 {
        self.last_finalized_block_number
    }
}
