use alloy_primitives::{Address, B256, U256};
use firehose::{LogData, ReceiptData};
use std::str::FromStr;

// Common test addresses (for readability in tests)
// These are derived from deterministic private keys
// Private key 0x01 -> Alice
// Private key 0x02 -> Bob
// Private key 0x03 -> Charlie
// Private key 0x04 -> Miner
pub const ALICE: &str = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
pub const BOB: &str = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf";
pub const CHARLIE: &str = "0x6813eb9362372eef6200f3b1dbc3f819671cba69";
pub const MINER: &str = "0x1eff47bc3a10a45d4b230b5d10e37751fe6aa718";

// Private keys for test accounts
pub fn alice_key() -> [u8; 32] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]
}

pub fn bob_key() -> [u8; 32] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ]
}

pub fn charlie_key() -> [u8; 32] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ]
}

// Test addresses as Address types
pub fn alice_addr() -> Address {
    Address::from_str(ALICE).unwrap()
}

pub fn bob_addr() -> Address {
    Address::from_str(BOB).unwrap()
}

pub fn charlie_addr() -> Address {
    Address::from_str(CHARLIE).unwrap()
}

pub fn miner_addr() -> Address {
    Address::from_str(MINER).unwrap()
}

// System call address constants (matching go-ethereum params package)

/// SystemAddress is the address used as 'from' for system calls (0xfffffffffffffffffffffffffffffffffffffffe)
pub fn system_address() -> Address {
    // System address used for system calls (EIP-4788, EIP-2935, etc.)
    // This matches the Golang constant: 0xfffffffffffffffffffffffffffffffffffffffe
    Address::from([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe,
    ])
}

/// BeaconRootsAddress is the EIP-4788 beacon roots contract
pub fn beacon_roots_address() -> Address {
    Address::from_str("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").unwrap()
}

/// HistoryStorageAddress is the EIP-2935/7709 parent block hash storage contract
pub fn history_storage_address() -> Address {
    Address::from_str("0x0aae40965e6800cd9b1f4b05ff21581047e3f91e").unwrap()
}

/// WithdrawalQueueAddress is the EIP-7002 withdrawal queue contract
pub fn withdrawal_queue_address() -> Address {
    Address::from_str("0x0b5df45689000000000000000000000000000000").unwrap()
}

/// ConsolidationQueueAddress is the EIP-7251 consolidation queue contract
pub fn consolidation_queue_address() -> Address {
    Address::from_str("0x0c0d961020000000000000000000000000000000").unwrap()
}

// Helper functions for creating test values

/// Creates a U256 from an i64 value
pub fn big_int(n: i64) -> U256 {
    if n >= 0 {
        U256::from(n as u64)
    } else {
        // For negative numbers, we need to use two's complement
        U256::from_be_bytes([0xff; 32]) - U256::from((-n - 1) as u64)
    }
}

/// Creates a U256 from a string (for large values that don't fit in i64)
pub fn must_big_int(s: &str) -> U256 {
    U256::from_str(s).expect(&format!("invalid big int: {}", s))
}

/// Converts a U256 to trimmed big-endian bytes (matching protobuf BigInt encoding)
/// This removes leading zeros to match what protobuf produces
pub fn u256_to_trimmed_bytes(value: U256) -> Vec<u8> {
    let bytes = value.to_be_bytes::<32>();

    // Find the first non-zero byte
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(31);

    // Return trimmed bytes (at least 1 byte for zero)
    bytes[first_non_zero..].to_vec()
}

/// Converts a hex string to a B256 hash
pub fn hash_from_hex(s: &str) -> B256 {
    B256::from_str(s.trim_start_matches("0x")).expect(&format!("invalid hash hex: {}", s))
}

/// Converts a hex string to bytes
pub fn bytes_from_hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect(&format!("invalid bytes hex: {}", s))
}

/// Creates an address from a hex string
pub fn addr_from_hex(s: &str) -> Address {
    Address::from_str(s).expect(&format!("invalid address hex: {}", s))
}

// Test error constants matching VM errors
// These error messages match go-ethereum's VM errors exactly
pub const ERR_EXECUTION_REVERTED: &str = "execution reverted";
pub const ERR_INSUFFICIENT_BALANCE_TRANSFER: &str = "insufficient balance for transfer";
pub const ERR_MAX_CALL_DEPTH: &str = "max call depth exceeded";
pub const ERR_OUT_OF_GAS: &str = "out of gas";
pub const ERR_CODE_STORE_OUT_OF_GAS: &str = "contract creation code storage out of gas";

// Receipt helper functions

/// Creates a successful receipt (status 1) with the given gas used
pub fn success_receipt(gas_used: u64) -> ReceiptData {
    ReceiptData {
        transaction_index: 0,
        status: 1,
        gas_used,
        logs_bloom: [0u8; 256], // Empty bloom (no logs)
        cumulative_gas_used: gas_used,
        logs: vec![],
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    }
}

/// Creates a failed receipt (status 0) with the given gas used
pub fn failed_receipt(gas_used: u64) -> ReceiptData {
    ReceiptData {
        transaction_index: 0,
        status: 0,
        gas_used,
        logs_bloom: [0u8; 256],
        cumulative_gas_used: gas_used,
        logs: vec![],
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    }
}

/// Creates a 32-byte hash from a u64 value (for testing)
/// Encodes the value in the last 8 bytes (big-endian)
pub fn hash32(n: u64) -> B256 {
    let mut hash = [0u8; 32];
    // Encode value in last 8 bytes (big-endian)
    for i in 0..8 {
        hash[31 - i] = (n >> (i * 8)) as u8;
    }
    B256::from(hash)
}

/// Compute keccak256 hash of a string (for creating topics)
pub fn topic(s: &str) -> B256 {
    alloy_primitives::keccak256(s.as_bytes())
}

/// Calculate CREATE address from sender and nonce
/// CREATE address = keccak256(rlp([sender, nonce]))[12:]
pub fn create_address(sender: Address, nonce: u64) -> Address {
    use alloy_rlp::Encodable;

    let mut rlp_buf = Vec::new();
    // RLP encode [sender, nonce] as a list
    alloy_rlp::Header {
        list: true,
        payload_length: sender.length() + nonce.length(),
    }
    .encode(&mut rlp_buf);
    sender.encode(&mut rlp_buf);
    nonce.encode(&mut rlp_buf);

    // Hash and take last 20 bytes
    let hash = alloy_primitives::keccak256(&rlp_buf);
    Address::from_slice(&hash.as_slice()[12..])
}

/// Calculate CREATE2 address from sender, salt, and init code
/// CREATE2 address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
pub fn create2_address(sender: Address, salt: B256, init_code: &[u8]) -> Address {
    let init_code_hash = alloy_primitives::keccak256(init_code);

    let mut hasher_input = Vec::with_capacity(1 + 20 + 32 + 32);
    hasher_input.push(0xff);
    hasher_input.extend_from_slice(sender.as_slice());
    hasher_input.extend_from_slice(salt.as_slice());
    hasher_input.extend_from_slice(init_code_hash.as_slice());

    let hash = alloy_primitives::keccak256(&hasher_input);
    Address::from_slice(&hash.as_slice()[12..])
}

/// Log helper functions for creating test logs with various topic counts

/// Create a log with 0 topics (anonymous event)
pub fn log0(addr: Address, data: Vec<u8>) -> LogData {
    LogData {
        address: addr,
        topics: vec![],
        data: alloy_primitives::Bytes::from(data),
        block_index: 0,
    }
}

/// Create a log with 1 topic
pub fn log1(addr: Address, topic0: B256, data: Vec<u8>) -> LogData {
    LogData {
        address: addr,
        topics: vec![topic0],
        data: alloy_primitives::Bytes::from(data),
        block_index: 0,
    }
}

/// Create a log with 2 topics
pub fn log2(addr: Address, topic0: B256, topic1: B256, data: Vec<u8>) -> LogData {
    LogData {
        address: addr,
        topics: vec![topic0, topic1],
        data: alloy_primitives::Bytes::from(data),
        block_index: 0,
    }
}

/// Create a log with 3 topics
pub fn log3(addr: Address, topic0: B256, topic1: B256, topic2: B256, data: Vec<u8>) -> LogData {
    LogData {
        address: addr,
        topics: vec![topic0, topic1, topic2],
        data: alloy_primitives::Bytes::from(data),
        block_index: 0,
    }
}

/// Create a log with 4 topics
pub fn log4(
    addr: Address,
    topic0: B256,
    topic1: B256,
    topic2: B256,
    topic3: B256,
    data: Vec<u8>,
) -> LogData {
    LogData {
        address: addr,
        topics: vec![topic0, topic1, topic2, topic3],
        data: alloy_primitives::Bytes::from(data),
        block_index: 0,
    }
}

/// Creates a successful receipt with logs
pub fn receipt_with_logs(gas_used: u64, logs: Vec<LogData>) -> ReceiptData {
    ReceiptData {
        transaction_index: 0,
        status: 1,
        gas_used,
        logs_bloom: [0u8; 256],
        cumulative_gas_used: gas_used,
        logs,
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    }
}

/// Creates a failed receipt (status=0) with logs
pub fn failed_receipt_with_logs(gas_used: u64, logs: Vec<LogData>) -> ReceiptData {
    ReceiptData {
        transaction_index: 0,
        status: 0, // Failed status
        gas_used,
        logs_bloom: [0u8; 256],
        cumulative_gas_used: gas_used,
        logs,
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    }
}

/// Creates a receipt with specific index, status, gas_used, cumulative_gas, and logs
pub fn receipt_at(
    index: u32,
    status: u64,
    gas_used: u64,
    cumulative_gas: u64,
    logs: Vec<LogData>,
) -> ReceiptData {
    ReceiptData {
        transaction_index: index,
        status,
        gas_used,
        logs_bloom: [0u8; 256], // Empty bloom (tests don't require accurate bloom)
        cumulative_gas_used: cumulative_gas,
        logs,
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addresses() {
        assert_eq!(alice_addr(), Address::from_str(ALICE).unwrap());
        assert_eq!(bob_addr(), Address::from_str(BOB).unwrap());
        assert_eq!(charlie_addr(), Address::from_str(CHARLIE).unwrap());
        assert_eq!(miner_addr(), Address::from_str(MINER).unwrap());
    }

    #[test]
    fn test_big_int() {
        assert_eq!(big_int(0), U256::ZERO);
        assert_eq!(big_int(1), U256::from(1));
        assert_eq!(big_int(100), U256::from(100));
    }

    #[test]
    fn test_must_big_int() {
        assert_eq!(must_big_int("12345"), U256::from(12345_u64));
        assert_eq!(
            must_big_int("1000000000000000000"),
            U256::from(1000000000000000000_u64)
        );
    }

    #[test]
    fn test_hash_from_hex() {
        let hash =
            hash_from_hex("0x0100000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(hash.0[0], 0x01);
        assert_eq!(hash.0[1], 0x00);
    }

    #[test]
    fn test_bytes_from_hex() {
        let bytes = bytes_from_hex("0x010203");
        assert_eq!(bytes, vec![0x01, 0x02, 0x03]);
    }
}
