//! Mapper functions for converting between Rust types and protobuf types

use alloy_primitives::U256;
use pb::sf::ethereum::r#type::v2::BigInt;

/// Converts a U256 to a trimmed big-endian byte array
/// Removes leading zeros for more efficient protobuf encoding
pub fn u256_trimmed_be_bytes(value: U256) -> Vec<u8> {
    let bytes = value.to_be_bytes::<32>();

    // Find the first non-zero byte
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(32);

    // If all zeros, return a single zero byte
    if first_non_zero == 32 {
        return vec![0];
    }

    bytes[first_non_zero..].to_vec()
}

/// Converts a U256 to a protobuf BigInt
pub fn big_int_from_u256(value: U256) -> BigInt {
    BigInt {
        bytes: u256_trimmed_be_bytes(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_trimmed_be_bytes_zero() {
        let value = U256::ZERO;
        let bytes = u256_trimmed_be_bytes(value);
        assert_eq!(bytes, vec![0]);
    }

    #[test]
    fn test_u256_trimmed_be_bytes_small() {
        let value = U256::from(255u64);
        let bytes = u256_trimmed_be_bytes(value);
        assert_eq!(bytes, vec![255]);
    }

    #[test]
    fn test_u256_trimmed_be_bytes_large() {
        let value = U256::from(0x1234_5678_u64);
        let bytes = u256_trimmed_be_bytes(value);
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_u256_trimmed_be_bytes_max() {
        let value = U256::MAX;
        let bytes = u256_trimmed_be_bytes(value);
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 255));
    }

    #[test]
    fn test_big_int_from_u256() {
        let value = U256::from(1000u64);
        let big_int = big_int_from_u256(value);
        assert_eq!(big_int.bytes, vec![0x03, 0xe8]);
    }
}
