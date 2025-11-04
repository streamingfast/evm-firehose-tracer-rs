/// Helper structure for tracking finality status
#[derive(Debug, Clone, Copy, Default)]
pub struct FinalityStatus {
    last_irreversible_block_number: u64,
}

impl FinalityStatus {
    pub(super) fn reset(&mut self) {
        self.last_irreversible_block_number = 0;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.last_irreversible_block_number == 0
    }

    pub(super) fn last_irreversible_block_number(&self) -> u64 {
        self.last_irreversible_block_number
    }

    pub(super) fn populate_from_chain(&mut self, _finalized: Option<u64>) {
        // TODO: Implement proper finality tracking from chain data
        // For now, we'll use the hardcoded -200 approach in on_block_end
    }
}
