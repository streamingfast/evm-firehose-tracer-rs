# Change log

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

* SetCode authorization `r` and `s` signature fields now serialize as empty bytes when zero, matching production behavior of the native tracer.

## v5.0.0

### Changed

* Block withdrawals are now always recorded. The `Config.skip_withdrawals` flag has been removed; consumers that previously relied on it to suppress withdrawals should handle filtering on their side if needed.

### Removed

* Gas changes tracking (`on_gas_change`, per-opcode gas recording) is no longer supported. The `gas_changes` field on calls will always be empty. Consumers that relied on this data must migrate to alternative gas accounting.
* Remove `Config.skip_withdrawals` flag (see above).

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
