use super::HexView;

/// Tracer state checking functionality
impl super::Tracer {
    /// Ensure that blockchain has been initialized (chain_config is set)
    /// Note: chain_config is now always set in the constructor, so this check is a no-op
    #[inline]
    pub(super) fn ensure_init(&self) {
        // chain_config is always set in constructor, so nothing to check
    }

    /// Ensure that we are currently in a block processing state
    #[inline]
    #[allow(dead_code)]
    pub(super) fn ensure_in_block(&self) {
        if self.current_block.is_none() {
            self.panic_invalid_state(
                "caller expected to be in block state but we were not, this is a bug",
            );
        }

        // chain_config is always set in constructor, no need to check
    }

    /// Ensure that we are NOT currently in a block processing state
    #[inline]
    pub(super) fn ensure_not_in_block(&self) {
        if self.current_block.is_some() {
            self.panic_invalid_state(
                "caller expected to not be in block state but we were, this is a bug",
            );
        }
    }

    /// Ensure that we are currently in a transaction processing state
    #[inline]
    pub(super) fn ensure_in_transaction(&self) {
        if self.current_transaction.is_none() {
            self.panic_invalid_state(
                "caller expected to be in transaction state but we were not, this is a bug",
            );
        }
    }

    /// Panic with invalid state message, providing context similar to Go version
    pub(super) fn panic_invalid_state(&self, msg: &str) -> ! {
        let mut enhanced_msg = msg.to_string();

        // Add block context if we're in a block
        if let Some(ref block) = self.current_block {
            enhanced_msg.push_str(&format!(
                " at block #{} ({})",
                block.number,
                HexView(&block.hash)
            ));
        }

        // TODO: Add transaction context when transaction tracing is implemented
        // if let Some(ref transaction) = self.current_transaction {
        //     enhanced_msg.push_str(&format!(
        //         " in transaction {}",
        //         hex::encode(&transaction.hash)
        //     ));
        // }

        // Add state information similar to Go version
        let state_info = format!(
            " (init={}, in_block={})",
            true, // chain_config is always set
            self.current_block.is_some()
        );
        enhanced_msg.push_str(&state_info);

        panic!("Firehose invalid state: {}", enhanced_msg);
    }
}
