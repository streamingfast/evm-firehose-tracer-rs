# Change log

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v5.0.0

### Changed

* Block withdrawals are now always recorded. The `Config.skip_withdrawals` flag has been removed; consumers that previously relied on it to suppress withdrawals should handle filtering on their side if needed.

### Removed

* Gas changes tracking (`on_gas_change`, per-opcode gas recording) is no longer supported. The `gas_changes` field on calls will always be empty. Consumers that relied on this data must migrate to alternative gas accounting.
* Remove `Config.skip_withdrawals` flag (see above).

## v4.0.0

### Added

* First release of the Rust EVM Firehose Tracer, aligned with the Golang version `v4.0.0` and [Ethereum Mainnet Block version 4](https://docs.substreams.dev/reference-material/chain-support/ethereum-data-model#version-4) for the Ethereum Block `sf.ethereum.type.v2.Block` protobuf model.
