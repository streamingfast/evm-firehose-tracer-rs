//! Utility functions for the Firehose tracer
//! Matches utilities from types.go and other helper functions

use alloy_primitives::{Address, Keccak256, B256, U256};
use pb::sf::ethereum::r#type::v2::BigInt;

/// Empty hash constant (32 bytes of zeros)
pub const EMPTY_HASH: B256 = B256::ZERO;

/// Empty address constant (20 bytes of zeros)
pub const EMPTY_ADDRESS: Address = Address::ZERO;

/// Converts a U256 to protobuf BigInt
/// Matches the semantics of bigIntToProtobuf in types.go:
/// - Returns None for zero values (protobuf omits zero/nil fields)
/// - Trims leading zeros for non-zero values
pub fn u256_to_protobuf(value: U256) -> Option<BigInt> {
    if value.is_zero() {
        return None;
    }
    Some(crate::mapper::big_int_from_u256(value))
}

/// Converts a U256 to protobuf BigInt, always including zero as [0]
/// Use this for fields that must be present even when zero (like difficulty, gas_price, value in transactions)
pub fn u256_to_protobuf_always(value: U256) -> Option<BigInt> {
    Some(crate::mapper::big_int_from_u256(value))
}

/// Computes the Keccak256 hash of the given data
pub fn hash_bytes(data: &[u8]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Checks if an error message matches a target string
/// This is NOT a replacement for proper error matching - it uses string matching
/// to avoid dependencies on specific EVM implementations
pub fn error_is_string(err: &dyn std::error::Error, target: &str) -> bool {
    if err.to_string() == target {
        return true;
    }

    // Check source errors recursively
    if let Some(source) = err.source() {
        return error_is_string(source, target);
    }

    false
}

/// VM error messages that indicate reverted state
/// These match the error strings from go-ethereum/core/vm/errors.go
pub const TEXT_EXECUTION_REVERTED_ERR: &str = "execution reverted";
pub const TEXT_INSUFFICIENT_BALANCE_TRANSFER_ERR: &str = "insufficient balance for transfer";
pub const TEXT_MAX_CALL_DEPTH_ERR: &str = "max call depth exceeded";

/// Normalizes a signature point (R or S) to match native tracer behavior:
/// - Returns None if the value is all zeros (empty/unsigned transaction)
/// - Otherwise returns the value as-is
///
/// This matches the native tracer's normalizeSignaturePoint which returns None for zero big.Int values.
pub fn normalize_signature_point(value: &[u8]) -> Option<Vec<u8>> {
    // Check if all bytes are zero
    if value.iter().all(|&b| b == 0) {
        return None;
    }
    Some(value.to_vec())
}

/// Parses a delegation designator from bytecode
/// EIP-7702: Delegation format is 0xef0100 + 20-byte address (23 bytes total)
pub fn parse_delegation(code: &[u8]) -> Option<Address> {
    const DELEGATION_PREFIX: &[u8] = &[0xef, 0x01, 0x00];

    if code.len() != 23 || !code.starts_with(DELEGATION_PREFIX) {
        return None;
    }

    let addr_bytes = &code[DELEGATION_PREFIX.len()..];
    Some(Address::from_slice(addr_bytes))
}

/// Computes the Ethereum address for a contract created using CREATE opcode.
/// The address is derived as: keccak256(rlp([sender, nonce]))[12:]
///
/// This matches go-ethereum's crypto.CreateAddress function behavior.
pub fn create_address(sender: Address, nonce: u64) -> Address {
    // Use alloy's built-in implementation which matches go-ethereum exactly
    sender.create(nonce)
}

/// Computes the Ethereum address for a contract created using CREATE2 opcode.
/// The address is derived as: keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
///
/// This matches go-ethereum's crypto.CreateAddress2 function behavior.
pub fn create2_address(sender: Address, salt: B256, init_code_hash: B256) -> Address {
    // Use alloy's built-in implementation which matches go-ethereum exactly
    sender.create2(salt, init_code_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_to_protobuf_zero() {
        assert_eq!(u256_to_protobuf(U256::ZERO), None);
    }

    #[test]
    fn test_u256_to_protobuf_nonzero() {
        let value = U256::from(12345);
        let result = u256_to_protobuf(value);
        assert!(result.is_some());
        let bigint = result.unwrap();
        assert_eq!(U256::from_be_slice(&bigint.bytes), value);
    }

    #[test]
    fn test_normalize_signature_point_zero() {
        let zeros = vec![0u8; 32];
        assert_eq!(normalize_signature_point(&zeros), None);
    }

    #[test]
    fn test_normalize_signature_point_nonzero() {
        let mut data = vec![0u8; 32];
        data[31] = 1;
        assert_eq!(normalize_signature_point(&data), Some(data.clone()));
    }

    #[test]
    fn test_parse_delegation_valid() {
        let mut code = vec![0xef, 0x01, 0x00];
        let addr = Address::repeat_byte(0x42);
        code.extend_from_slice(addr.as_slice());

        let result = parse_delegation(&code);
        assert_eq!(result, Some(addr));
    }

    #[test]
    fn test_parse_delegation_invalid_prefix() {
        let code = vec![0xff; 23];
        assert_eq!(parse_delegation(&code), None);
    }

    #[test]
    fn test_parse_delegation_invalid_length() {
        let code = vec![0xef, 0x01, 0x00, 0x42];
        assert_eq!(parse_delegation(&code), None);
    }

    #[test]
    fn test_create_address() {
        // Test that create_address produces deterministic results
        // Using alloy's built-in implementation which matches go-ethereum
        let sender =
            Address::from_slice(&hex::decode("0000000000000000000000000000000000000001").unwrap());
        let nonce = 0u64;

        let result = create_address(sender, nonce);
        // Verify it's not zero and deterministic
        assert_ne!(result, Address::ZERO);

        // Call again with same inputs should give same result
        let result2 = create_address(sender, nonce);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_create_address_with_nonce() {
        // Another test with non-zero nonce
        let sender =
            Address::from_slice(&hex::decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf").unwrap());
        let nonce = 5u64;

        let result = create_address(sender, nonce);
        // Result should be deterministic
        assert_ne!(result, Address::ZERO);
    }
}
