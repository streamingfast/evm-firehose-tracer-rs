//! `ChainRevertOverlay`: a [`StateProvider`] that serves pre-chain state from
//! a committed [`Chain`]'s own [`BundleState`], layered on top of a baseline
//! (typically the latest state).
//!
//! # Why
//!
//! During pipeline backfill, the Execution stage emits `ExExNotification::ChainCommitted`
//! BEFORE the history indexing stages (`IndexAccountHistory`, `IndexStorageHistory`)
//! and `Finish` stage run. As a result:
//!
//! - `HistoricalStateProvider` cannot reconstruct pre-chain state: its `AccountsHistory`
//!   / `StoragesHistory` sharded indexes are empty, so every lookup returns
//!   `HistoryInfo::NotYetWritten` and `basic_account` / `storage` return `None`.
//! - `BlockchainProvider::history_by_block_{hash,number}` rejects the call outright via
//!   `ConsistentProvider::ensure_canonical_block`, because the in-memory canonical head
//!   and the `StageId::Finish` checkpoint are still at 0.
//!
//! However, the [`Chain`] notification itself carries all the information needed to
//! reconstruct pre-chain state for the accounts and slots the chain touched:
//! `bundle.state()` stores, for every touched account, both its post-chain `info`/`storage`
//! and its pre-chain `original_info`/`previous_or_original_value`. For accounts and slots
//! the chain did NOT touch, the latest persisted plain state is already equal to the
//! pre-chain value (no modification took place).
//!
//! This module exploits that invariant to build a [`StateProvider`] that:
//!
//! 1. Overrides `basic_account` with `BundleAccount::original_info` for touched accounts.
//! 2. Overrides `storage` / `storage_by_hashed_key` with
//!    `StorageSlot::previous_or_original_value` for touched slots, and returns `ZERO` for
//!    any slot on an account that was created during the chain (no pre-chain state).
//! 3. Delegates everything else — and untouched accounts/slots — to an inner baseline
//!    [`StateProvider`] (typically [`LatestStateProvider`] built from a read-only DB
//!    provider, which reflects post-chain plain state written by the Execution stage).
//!
//! # Correctness
//!
//! `BundleAccount::original_info` is set when revm first loads an account and is preserved
//! across every subsequent `update_and_create_revert`, so it always reflects the value
//! before the FIRST touch in the chain — i.e. the fork-block value. Same contract for
//! `StorageSlot::previous_or_original_value`. This means the override maps we build from
//! a single pass over `bundle.state()` are exactly the pre-chain delta.
//!
//! # Known limitations
//!
//! For accounts with status `Destroyed` / `DestroyedChanged` / `DestroyedAgain`, slots that
//! were NOT explicitly touched by the chain cannot be reconstructed from the overlay. The
//! plain-state lookup for such a slot may have been wiped by the destruction, so the
//! inner provider would return the wrong value (typically `ZERO`). In practice this is
//! fine: re-execution only reads slots that the original execution also read (the EVM is
//! deterministic w.r.t. its inputs), and those slots are all tracked in `bundle.state()`
//! already.

use alloy_primitives::{map::HashMap, Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use reth_execution_types::Chain;
use reth_primitives_traits::{Account, Bytecode};
use reth_provider::{
    AccountReader, BlockHashReader, HashedPostStateProvider, StateProvider, StateProviderBox,
    StateRootProvider, StorageRootProvider,
};
use reth_storage_api::{BytecodeReader, StateProofProvider};
use reth_provider::ProviderResult;
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm_database::BundleState;

/// A [`StateProvider`] that serves pre-chain state for a committed
/// [`Chain`] by overlaying the chain's [`BundleState`] pre-images on top of an
/// inner baseline provider.
///
/// See the [module-level docs](self) for motivation and correctness notes.
pub struct ChainRevertOverlay {
    /// Baseline provider. Expected to serve post-chain plain state (e.g. a
    /// `LatestStateProvider` built from a read-only DB provider).
    inner: StateProviderBox,
    /// Pre-chain account info for every address touched by the chain.
    ///
    /// - `Some(account)` — account existed pre-chain with these values.
    /// - `None` — account did NOT exist pre-chain (created during the chain).
    account_overrides: HashMap<Address, Option<Account>>,
    /// Pre-chain storage values for slots touched by the chain, keyed by (address, slot).
    ///
    /// The outer key is an address present in `account_overrides` (with a `Some` value,
    /// since created accounts' slots are handled via the `account_overrides` check).
    storage_overrides: HashMap<Address, HashMap<B256, StorageValue>>,
}

impl core::fmt::Debug for ChainRevertOverlay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainRevertOverlay")
            .field("account_overrides", &self.account_overrides.len())
            .field(
                "storage_overrides",
                &self.storage_overrides.values().map(|m| m.len()).sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl ChainRevertOverlay {
    /// Build an overlay from a committed [`Chain`] on top of a baseline [`StateProvider`].
    ///
    /// The baseline should reflect the state AFTER the chain was applied (typically the
    /// latest persisted plain state). The overlay "rewinds" touched accounts and slots to
    /// their pre-chain values using `chain.execution_outcome().bundle`.
    pub fn from_chain<N: reth_primitives_traits::NodePrimitives>(
        inner: StateProviderBox,
        chain: &Chain<N>,
    ) -> Self {
        let bundle: &BundleState = &chain.execution_outcome().bundle;
        let mut account_overrides: HashMap<Address, Option<Account>> = HashMap::default();
        let mut storage_overrides: HashMap<Address, HashMap<B256, StorageValue>> =
            HashMap::default();

        for (address, bundle_account) in bundle.state() {
            // Pre-chain account info: `original_info` is the value at first touch, which
            // equals the fork-block value because revm never overwrites it after load.
            let pre_chain_account = bundle_account.original_info.clone().map(Account::from);
            let was_created = pre_chain_account.is_none();
            account_overrides.insert(*address, pre_chain_account);

            if was_created {
                // Account didn't exist pre-chain: every slot reads as ZERO. We don't need
                // per-slot overrides — the `basic_account` override covers it and the
                // `storage` impl short-circuits on the `None` account override.
                continue;
            }

            // Pre-chain storage slot values for every slot the chain touched on this
            // account. Untouched slots on a touched account fall through to the baseline
            // (which is correct because, by definition, they weren't modified).
            //
            // `revm` keys storage by `U256`; the `StateProvider::storage` interface keys
            // by `B256` (big-endian bytes). We materialize both representations here so
            // lookups are O(1) either way.
            let overrides = storage_overrides.entry(*address).or_default();
            for (slot_u256, storage_slot) in &bundle_account.storage {
                let slot_b256 = B256::from(slot_u256.to_be_bytes::<32>());
                overrides.insert(slot_b256, storage_slot.previous_or_original_value);
            }
        }

        Self { inner, account_overrides, storage_overrides }
    }
}

impl AccountReader for ChainRevertOverlay {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        if let Some(pre_chain) = self.account_overrides.get(address) {
            return Ok(pre_chain.clone());
        }
        self.inner.basic_account(address)
    }
}

impl BlockHashReader for ChainRevertOverlay {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BytecodeReader for ChainRevertOverlay {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        // Bytecode is content-addressed and never pruned; the baseline always has it.
        // This includes code for contracts deployed DURING the chain, because the
        // Execution stage writes `Bytecodes` entries for new contracts too. Pre-chain
        // `code_hash` values in `account_overrides` will resolve against this base.
        self.inner.bytecode_by_hash(code_hash)
    }
}

impl StateRootProvider for ChainRevertOverlay {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(hashed_state)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_with_updates(hashed_state)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl StorageRootProvider for ChainRevertOverlay {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner.storage_multiproof(address, slots, hashed_storage)
    }
}

impl StateProofProvider for ChainRevertOverlay {
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.inner.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.inner.multiproof(input, targets)
    }

    fn witness(&self, input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>> {
        self.inner.witness(input, target)
    }
}

impl HashedPostStateProvider for ChainRevertOverlay {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
        self.inner.hashed_post_state(bundle_state)
    }
}

impl StateProvider for ChainRevertOverlay {
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        if let Some(pre_chain_account) = self.account_overrides.get(&account) {
            if pre_chain_account.is_none() {
                // Account did not exist pre-chain; every slot reads ZERO.
                return Ok(Some(StorageValue::ZERO));
            }
            if let Some(overrides) = self.storage_overrides.get(&account) {
                if let Some(value) = overrides.get(&storage_key) {
                    return Ok(Some(*value));
                }
            }
            // Account was touched but this specific slot wasn't. The chain did not modify
            // this slot, so the baseline's plain-state value is still the pre-chain value.
            // (See the "Known limitations" note in the module docs for the edge case of
            // destroyed accounts.)
        }
        self.inner.storage(account, storage_key)
    }

    fn storage_by_hashed_key(
        &self,
        address: Address,
        hashed_storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        // We can't translate a hashed key back into the plain key that our overrides are
        // indexed by, so we delegate. `StateProviderDatabase` (the only caller used in our
        // re-execution path) only invokes the plain `storage` method above, so this branch
        // is currently unused in practice.
        self.inner.storage_by_hashed_key(address, hashed_storage_key)
    }
}
