# Change log

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased (v5.0.0)

### Added

* `OpCodeView` opcode logging: `on_opcode` and `on_opcode_fault` now emit trace-full-level log lines (enabled via `FIREHOSE_ETHEREUM_TRACER_LOG_LEVEL=trace_full`) including the opcode name, gas, cost, and error. All standard EVM opcodes (including Cancun additions) resolve to their human-readable name (e.g. `CALL`, `SSTORE`); unknown opcodes fall back to `0x??` hex.
* `FlashBlockData` struct and `BlockEvent.flash_block` field to support Optimism/Katana flash block iterations. `FlashBlockData.is_final` marks the final iteration; when set, the emitted `FIRE BLOCK` line encodes the flash block index as `idx + 1000`.
* Flash block snapshot/restore support: `snapshot_flash_block_for_next_iteration()`, `restore_flash_block_snapshot()`, and related methods allow incremental block building across multiple flash block iterations.
* EIP-7843 (Amsterdam): `BlockData.slot_number` field and `BlockHeader.slot_number` propagation.

### Changed

* `on_balance_change`, `on_nonce_change`, `on_code_change`, and `on_storage_change` now skip recording when old and new values are equal, avoiding no-op state changes in the block model.
* `FIRE BLOCK` output line now includes a flash block index slot and a computed `lib_num`. New format: `FIRE BLOCK <block_num> <flash_block_idx> <block_hash> <prev_num> <prev_hash> <lib_num> <timestamp_unix_nano> <payload_base64>`. `flash_block_idx` is `0` for non-flash blocks. `lib_num` is derived from finality (falling back to `max(block_num-200, 0)` when no finality is known, capped to no more than 200 blocks behind `block_num`).
* Protocol version bumped from `3.0` to `3.1`.

* `ChainConfig` is now deferred to `on_blockchain_init` instead of being required at `Tracer::new` construction time, aligning with the Go implementation. `Tracer::new` and `Tracer::new_with_writer` no longer accept a `chain_config` argument; pass it as the third argument to `on_blockchain_init` instead.
* `ChainConfig` has been removed from `Config`; it is now passed directly to `on_blockchain_init`.
* `Config::new` no longer takes a `chain_config` argument.
* Block withdrawals are now always recorded. The `Config.skip_withdrawals` flag has been removed; consumers that previously relied on it to suppress withdrawals should handle filtering on their side if needed.

### Removed

* Gas changes tracking (`on_gas_change`, per-opcode gas recording) is no longer supported. The `gas_changes` field on calls will always be empty. Consumers that relied on this data must migrate to alternative gas accounting.
* Remove `Config.skip_withdrawals` flag (see above).

## v4.0.4

### Fixed

* SetCode authorization `r` and `s` signature fields now serialize as empty string (`""`) when zero, matching production behavior of the native tracer.

## v4.0.3

### Added

* Add `Tracer::get_config() -> &Config` getter to expose the tracer's runtime configuration.
* Add `Config::log_key_values() -> Vec<(String, String)>` returning a flat key-value list (keys prefixed with `config_`, values as human-readable strings) suitable for structured logging.

## v4.0.2

### Added

* Add optional `config_func: impl FnOnce(&mut Config)` parameter to `on_blockchain_init` allowing callers to tweak `Config` fields based on chain-specific knowledge available at init time (e.g. setting `skip_withdrawals` based on chain ID).

## v4.0.1

### Added

* Add `Config.skip_withdrawals` flag to suppress recording of `block.withdrawals` entries (e.g. Ethereum Mainnet which does not record withdrawals in the block model).

### Removed

* Remove gas changes tracking: `on_gas_change` hook, per-opcode gas recording, and all `GasChange` fields from the block model. This produces [Ethereum Mainnet Block version 5](https://docs.substreams.dev/reference-material/chain-support/ethereum-data-model#version-5).
* Remove all backward compatibility code that was present for prior block model versions.

## v4.0.0

### Added

* First release of the Rust EVM Firehose Tracer, aligned with the Golang version `v4.0.0` and [Ethereum Mainnet Block version 4](https://docs.substreams.dev/reference-material/chain-support/ethereum-data-model#version-4) for the Ethereum Block `sf.ethereum.type.v2.Block` protobuf model.
