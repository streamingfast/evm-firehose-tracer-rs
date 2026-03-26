use pb::sf::ethereum::r#type::v2::{
    AccountCreation, BalanceChange, Call, CodeChange, NonceChange, StorageChange,
};

/// DeferredCallState holds state changes that need to be attached to a call
/// after certain operations complete. This handles edge cases where state changes
/// occur outside normal call boundaries (e.g., during contract creation).
#[derive(Default)]
pub struct DeferredCallState {
    account_creations: Vec<AccountCreation>,
    balance_changes: Vec<BalanceChange>,
    nonce_changes: Vec<NonceChange>,
    code_changes: Vec<CodeChange>,
    storage_changes: Vec<StorageChange>,
}

impl DeferredCallState {
    /// Creates a new empty deferred call state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no deferred state changes.
    pub fn is_empty(&self) -> bool {
        self.account_creations.is_empty()
            && self.balance_changes.is_empty()
            && self.nonce_changes.is_empty()
            && self.code_changes.is_empty()
            && self.storage_changes.is_empty()
    }

    /// Clears all deferred state.
    pub fn reset(&mut self) {
        self.account_creations.clear();
        self.balance_changes.clear();
        self.nonce_changes.clear();
        self.code_changes.clear();
        self.storage_changes.clear();
    }

    /// Adds a balance change to deferred state.
    pub fn add_balance_change(&mut self, change: BalanceChange) {
        self.balance_changes.push(change);
    }

    /// Adds a nonce change to deferred state.
    pub fn add_nonce_change(&mut self, change: NonceChange) {
        self.nonce_changes.push(change);
    }

    /// Adds a code change to deferred state.
    pub fn add_code_change(&mut self, change: CodeChange) {
        self.code_changes.push(change);
    }

    /// Adds a storage change to deferred state.
    pub fn add_storage_change(&mut self, change: StorageChange) {
        self.storage_changes.push(change);
    }

    /// Populates the call with deferred state if any exists and then resets the deferred state.
    /// This should only be called for root calls.
    ///
    /// source can be:
    /// - "enter": Deferred state from BEFORE the root call starts (e.g., EIP-7702 nonce changes)
    ///            These are PREPENDED to maintain chronological order
    /// - "root": Deferred state from AFTER the root call ends (e.g., gas refunds)
    ///           These are APPENDED to maintain chronological order
    pub fn maybe_populate_call_and_reset(
        &mut self,
        source: &str,
        call: &mut Call,
    ) -> Result<(), String> {
        if self.is_empty() {
            return Ok(());
        }

        match source {
            "enter" => {
                // PREPEND deferred state (changes that happened BEFORE the call)
                // This maintains chronological order: before -> during -> after
                #[allow(deprecated)]
                {
                    let mut new_account_creations = std::mem::take(&mut self.account_creations);
                    new_account_creations.append(&mut call.account_creations);
                    call.account_creations = new_account_creations;
                }

                let mut new_balance_changes = std::mem::take(&mut self.balance_changes);
                new_balance_changes.append(&mut call.balance_changes);
                call.balance_changes = new_balance_changes;

                let mut new_nonce_changes = std::mem::take(&mut self.nonce_changes);
                new_nonce_changes.append(&mut call.nonce_changes);
                call.nonce_changes = new_nonce_changes;

                let mut new_code_changes = std::mem::take(&mut self.code_changes);
                new_code_changes.append(&mut call.code_changes);
                call.code_changes = new_code_changes;

                let mut new_storage_changes = std::mem::take(&mut self.storage_changes);
                new_storage_changes.append(&mut call.storage_changes);
                call.storage_changes = new_storage_changes;
            }
            "root" => {
                // APPEND deferred state (changes that happened AFTER the call)
                // This maintains chronological order: before -> during -> after
                #[allow(deprecated)]
                {
                    call.account_creations.append(&mut self.account_creations);
                }
                call.balance_changes.append(&mut self.balance_changes);
                call.nonce_changes.append(&mut self.nonce_changes);
                call.code_changes.append(&mut self.code_changes);
                call.storage_changes.append(&mut self.storage_changes);
            }
            _ => {
                return Err(format!(
                    "unexpected source for deferred call state, expected 'root' or 'enter' but got {}",
                    source
                ));
            }
        }

        self.reset();
        Ok(())
    }
}
