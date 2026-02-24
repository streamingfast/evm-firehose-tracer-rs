# Tracer Refactoring Plan - Remove Reth Dependencies

This document outlines the plan to refactor `firehose/src/tracer.rs` to remove Reth dependencies and use our new `ChainConfig` and `Rules`.

## Current Reth Dependencies

### 1. Type Dependencies
- `Node: FullNodeComponents` - Generic parameter throughout the tracer
- `ChainSpec<Node>` - Chain specification
- `RecoveredBlock<Node>` - Block type with recovered transactions
- `SignedTx<Node>` - Signed transaction type
- `reth::primitives::TransactionSigned` - Reth transaction type
- `reth::core::primitives::Receipt` - Receipt type
- `reth_tracing` - Logging/tracing

### 2. Where They're Used
- **Line 12**: Type aliases from Reth
- **Line 20**: `chain_spec: Option<Arc<ChainSpec<Node>>>`
- **Line 53**: `impl<Node: FullNodeComponents> Tracer<Node>`
- **Line 78-89**: `on_init()` uses `ChainSpec<Node>`
- **Line 100-104**: `on_genesis_block()` uses chain_spec
- **Line 118-122**: `on_genesis_block()` uses `TransactionSigned`
- **Line 195-199**: `on_block_start()` uses `RecoveredBlock<Node>`
- **Line 273-277**: `on_tx_end()` uses `Receipt` trait
- **Line 396-408**: `on_tx_start()` uses `SignedTx<Node>`
- **Line 564-569**: `on_tx_start_inner()` uses `TransactionSigned`
- **Line 688**: Trait bound on helper functions

### 3. REVM Dependencies (Keep These)
These are fundamental to EVM execution and not specific to Reth:
- `reth::revm::revm::inspector::JournalExt`
- `reth::revm::revm::interpreter::*`
- `reth::revm::context::*`
- All REVM types used in inspector hooks

## Refactoring Strategy

### Phase 1: Replace Chain Configuration
**Before:**
```rust
pub struct Tracer<Node: FullNodeComponents> {
    chain_spec: Option<Arc<ChainSpec<Node>>>,
    _phantom: std::marker::PhantomData<Node>,
}

pub fn on_init(&mut self, spec: Arc<ChainSpec<Node>>) {
    self.chain_spec = Some(spec.clone());
    info!("chain_id={}", spec.chain().id());
}
```

**After:**
```rust
use crate::config::{ChainConfig, Rules};

pub struct Tracer {
    chain_config: Arc<ChainConfig>,
    block_rules: Option<Rules>, // Computed per block
}

pub fn on_init(&mut self, config: Arc<ChainConfig>) {
    self.chain_config = config;
    info!("chain_id={}", self.chain_config.chain_id);
}
```

### Phase 2: Replace Block Types
**Before:**
```rust
pub fn on_block_start(&mut self, block: &RecoveredBlock<Node>) {
    let pb_block = mapper::recovered_block_to_protobuf::<Node>(block);
    // ...
}
```

**After:**
```rust
use alloy_consensus::Header;
use alloy_primitives::{BlockNumber, BlockHash};

pub struct BlockInfo {
    pub number: BlockNumber,
    pub hash: BlockHash,
    pub header: Header,
    pub transactions: Vec<alloy_consensus::TxEnvelope>,
}

pub fn on_block_start(&mut self, block: &BlockInfo) {
    // Compute rules for this block
    self.block_rules = Some(self.chain_config.rules(
        block.number,
        true, // is_merge (could be determined from header)
        block.header.timestamp,
    ));

    let pb_block = mapper::block_info_to_protobuf(block);
    // ...
}
```

### Phase 3: Replace Transaction Types
**Before:**
```rust
pub fn on_tx_start(&mut self, tx: &SignedTx<Node>)
where
    SignedTx<Node>: SignedTransaction + Transaction + SignerRecoverable,
{
    let hash = *tx.tx_hash();
    let from = tx.recover_signer().unwrap_or_default();
    // ...
}
```

**After:**
```rust
use alloy_consensus::TxEnvelope;
use alloy_primitives::{TxHash, Address};

pub fn on_tx_start(&mut self,
    tx: &TxEnvelope,
    hash: TxHash,
    from: Address,
) {
    // No need to recover signer, already provided
    let to = tx.to().unwrap_or_default();
    // ...
}
```

### Phase 4: Replace Receipt Type
**Before:**
```rust
pub fn on_tx_end<R>(&mut self, receipt: &R)
where
    R: Receipt,
{
    let cumulative_gas_used = receipt.cumulative_gas_used();
    let status = receipt.status();
    // ...
}
```

**After:**
```rust
use alloy_consensus::Receipt as AlloyReceipt;

pub fn on_tx_end(&mut self, receipt: &AlloyReceipt) {
    let cumulative_gas_used = receipt.cumulative_gas_used;
    let status = receipt.status;
    // ...
}
```

### Phase 5: Replace Logging
**Before:**
```rust
use reth_tracing::tracing::{debug, info};
```

**After:**
```rust
use tracing::{debug, info};
```

### Phase 6: Update Helper Functions
Remove `Node` generic from all helper function implementations:

**Before:**
```rust
impl<Node: FullNodeComponents> Tracer<Node> {
    fn create_gas_price_big_int<T>(&self, tx: &T)
    where T: Transaction
    {
        // ...
    }
}
```

**After:**
```rust
impl Tracer {
    fn create_gas_price_big_int(&self, tx: &TxEnvelope)
        -> Option<BigInt>
    {
        // ...
    }
}
```

## Implementation Steps

1. **Update Cargo.toml**
   - Remove `reth` dependency
   - Remove `reth-tracing` dependency
   - Add `tracing` dependency
   - Keep REVM dependencies

2. **Update imports**
   - Replace `reth_tracing::tracing` with `tracing`
   - Replace Reth transaction types with alloy
   - Keep REVM imports

3. **Remove generic parameter**
   - Remove `<Node: FullNodeComponents>` from struct and impls
   - Remove `_phantom: PhantomData<Node>`

4. **Update struct fields**
   - Replace `chain_spec` with `chain_config: Arc<ChainConfig>`
   - Add `block_rules: Option<Rules>`

5. **Update method signatures**
   - `on_init()` takes `Arc<ChainConfig>`
   - `on_block_start()` takes concrete block type
   - `on_tx_start()` takes alloy transaction types
   - `on_tx_end()` takes alloy receipt type

6. **Update implementations**
   - Use `ChainConfig` and `Rules` for fork detection
   - Use alloy types throughout
   - Keep REVM integration unchanged

## Benefits

1. **Reduced Dependencies**: No longer depends on Reth's node infrastructure
2. **Simpler Types**: Uses standard alloy types instead of generic node types
3. **Better Separation**: Clear separation between EVM execution (REVM) and chain config
4. **Fork Detection**: Uses our new `ChainConfig` and `Rules` for proper fork handling
5. **Reusability**: Can be used with any EVM-compatible chain without Reth node

## Migration Notes

Code using the tracer will need to:
1. Create a `ChainConfig` instead of providing a `ChainSpec`
2. Convert blocks to the new `BlockInfo` struct (or use alloy types directly)
3. Pass transaction hash and sender explicitly to `on_tx_start()`
4. Use alloy receipts instead of Reth receipts

## Next Steps

1. Create `BlockInfo` struct or decide on alloy block representation
2. Update imports and remove Reth dependencies
3. Refactor struct definition and fields
4. Update all method signatures
5. Update implementations
6. Update tests
7. Update documentation
