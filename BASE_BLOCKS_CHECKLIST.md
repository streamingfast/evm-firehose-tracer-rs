# Firehose BASE Blocks - Monad Implementation Checklist

## Overview

BASE blocks contain only RPC-extractable data:
- Block headers
- Transaction receipts
- Event logs

NO execution traces (calls, balance changes, storage changes) - those are EXTENDED only.

---

## Block (`sf.ethereum.type.v2.Block`)

```protobuf
message Block {
  int32 ver = 1;
  bytes hash = 2;
  uint64 number = 3;
  uint64 size = 4;
  BlockHeader header = 5;
  repeated BlockHeader uncles = 6;
  repeated TransactionTrace transaction_traces = 10;

  // Set to DETAILLEVEL_BASE (value 2)
  DetailLevel detail_level = 12;

  // Shanghai fork only
  repeated Withdrawal withdrawals = 22;

  // NOT included in BASE:
  // repeated BalanceChange balance_changes = 11;
  // repeated CodeChange code_changes = 20;
  // repeated Call system_calls = 21;
}
```

---

## BlockHeader (`sf.ethereum.type.v2.BlockHeader`)

All fields required:

```protobuf
message BlockHeader {
  bytes parent_hash = 1;
  bytes uncle_hash = 2;
  bytes coinbase = 3;
  bytes state_root = 4;
  bytes transactions_root = 5;
  bytes receipt_root = 6;
  bytes logs_bloom = 7;
  BigInt difficulty = 8;
  uint64 number = 9;
  uint64 gas_limit = 10;
  uint64 gas_used = 11;
  google.protobuf.Timestamp timestamp = 12;
  bytes extra_data = 13;
  bytes mix_hash = 14;
  uint64 nonce = 15; 
  bytes hash = 16;

  // London fork
  BigInt base_fee_per_gas = 18;

  // Shanghai fork
  bytes withdrawals_root = 19;

  // Cancun fork
  optional uint64 blob_gas_used = 22;
  optional uint64 excess_blob_gas = 23;
  bytes parent_beacon_root = 24;

  // Prague fork
  bytes requests_hash = 25;
}
```

---

## TransactionTrace (`sf.ethereum.type.v2.TransactionTrace`)

```protobuf
message TransactionTrace {
  bytes to = 1;
  uint64 nonce = 2;
  BigInt gas_price = 3;
  uint64 gas_limit = 4;
  BigInt value = 5;
  bytes input = 6;
  bytes v = 7;
  bytes r = 8;
  bytes s = 9;
  uint64 gas_used = 10;
  // 0=legacy, 1=access_list, 2=dynamic_fee
  Type type = 12;

  // Type >= TRX_TYPE_ACCESS_LIST
  repeated AccessTuple access_list = 14;

  uint32 index = 20;
  bytes hash = 21;
  bytes from = 22;

  // Can be 0 or sequential for BASE
  uint64 begin_ordinal = 25;
  uint64 end_ordinal = 26;

  // 1=SUCCEEDED, 2=FAILED, 3=REVERTED
  TransactionTraceStatus status = 30;
  TransactionReceipt receipt = 31;

  // Type == TRX_TYPE_BLOB only
  optional uint64 blob_gas = 33;
  optional BigInt blob_gas_fee_cap = 34;
  repeated bytes blob_hashes = 35;

}
```

---

## TransactionReceipt (`sf.ethereum.type.v2.TransactionReceipt`)

```protobuf
message TransactionReceipt {
  // Empty before Byzantium
  bytes state_root = 1;
  uint64 cumulative_gas_used = 2;
  bytes logs_bloom = 3;
  repeated Log logs = 4;

  // Type == TRX_TYPE_BLOB only
  optional uint64 blob_gas_used = 5;
  optional BigInt blob_gas_price = 6;
}
```

---

## Log (`sf.ethereum.type.v2.Log`)

```protobuf
message Log {
  bytes address = 1;
  repeated bytes topics = 2;
  bytes data = 3;
```

---

## Transaction Types

```
TRX_TYPE_LEGACY = 0
TRX_TYPE_ACCESS_LIST = 1
TRX_TYPE_DYNAMIC_FEE = 2        // EIP-1559, most common
TRX_TYPE_BLOB = 3               // EIP-4844
```

---

## Transaction Status

```
UNKNOWN = 0      // Do not use
SUCCEEDED = 1
FAILED = 2
REVERTED = 3
```

---

## Monad Data Sources

| Field | Source |
|-------|--------|
| Block header | `monad_exec_block_start` event |
| Execution results | `monad_exec_block_end` event |
| Transaction header | `monad_exec_txn_header_start` event |
| Receipt | `monad_exec_txn_evm_output` event |
| Logs | `monad_exec_txn_log` event |

---

## Validation

Run battlefield tests:

```bash
pnpm test:fh3.0:monad-dev --grep "Blocks"
```

Expected passing tests:
- Header corresponds to RPC

Expected failing tests (require EXTENDED):
- System call ProcessBeaconRoot
- System call ProcessParentBlockHash

---

## Common Issues

1. Missing `transaction_traces` array
2. Empty receipts (every transaction needs one)
3. Logs in wrong location (must be in `receipt.logs`)
4. `detail_level` not set to `DETAILLEVEL_BASE` (value 2)
5. Hex values not compacted (strip leading zeros from BigInt)
