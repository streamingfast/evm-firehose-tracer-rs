use super::sf::ethereum::r#type::v2::BigInt;
use crate::prelude::*;

impl BigInt {
    /// Creates an Option<BigInt> from a U256 value, following Go's nil semantics
    /// Zero values return None, non-zero values return Some(BigInt)
    pub fn from_optional_u256(value: U256) -> Option<Self> {
        if value.is_zero() {
            None // Return None for zero values (equivalent to Go's nil)
        } else {
            Some(Self::from(value))
        }
    }

    /// Creates an Option<BigInt> from a u64 value, following Go's nil semantics
    /// Zero values return None, non-zero values return Some(BigInt)
    pub fn from_optional_u64(value: u64) -> Option<Self> {
        if value == 0 {
            None // Return None for zero values (equivalent to Go's nil)
        } else {
            Some(Self::from(value))
        }
    }
}

// Implement From trait for supported types
impl From<U256> for BigInt {
    /// Creates a BigInt from a U256 value, following the Go firehoseBigIntFromNative behavior
    /// Zero values return empty bytes, non-zero values return big-endian byte representation
    fn from(value: U256) -> Self {
        if value.is_zero() {
            Self { bytes: Vec::new() }
        } else {
            let bytes = value.to_be_bytes_vec();
            // Remove leading zeros
            let start = bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(bytes.len() - 1);
            Self {
                bytes: bytes[start..].to_vec(),
            }
        }
    }
}

impl From<u64> for BigInt {
    /// Creates a BigInt from a u64 value, following the Go firehoseBigIntFromNative behavior
    /// Zero values return empty bytes, non-zero values return big-endian byte representation
    fn from(value: u64) -> Self {
        if value == 0 {
            Self { bytes: Vec::new() }
        } else {
            let bytes = value.to_be_bytes();
            // Remove leading zeros
            let start = bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(bytes.len() - 1);
            Self {
                bytes: bytes[start..].to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigint_from_zero() {
        // Zero values should return empty bytes (equivalent to nil in Go)
        let zero_u64 = BigInt::from(0u64);
        assert!(
            zero_u64.bytes.is_empty(),
            "Zero u64 should produce empty bytes"
        );

        let zero_u256 = BigInt::from(U256::ZERO);
        assert!(
            zero_u256.bytes.is_empty(),
            "Zero U256 should produce empty bytes"
        );
    }

    #[test]
    fn test_bigint_from_optional_zero() {
        // Zero values should return None (equivalent to Go's nil)
        let zero_u64_opt = BigInt::from_optional_u64(0u64);
        assert!(zero_u64_opt.is_none(), "Zero u64 should produce None");

        let zero_u256_opt = BigInt::from_optional_u256(U256::ZERO);
        assert!(zero_u256_opt.is_none(), "Zero U256 should produce None");
    }

    #[test]
    fn test_bigint_from_optional_nonzero() {
        // Non-zero values should return Some(BigInt)
        let nonzero_u64_opt = BigInt::from_optional_u64(42u64);
        assert!(
            nonzero_u64_opt.is_some(),
            "Non-zero u64 should produce Some"
        );
        assert_eq!(nonzero_u64_opt.unwrap().bytes, vec![42]);

        let nonzero_u256_opt = BigInt::from_optional_u256(U256::from(0x1234));
        assert!(
            nonzero_u256_opt.is_some(),
            "Non-zero U256 should produce Some"
        );
        assert_eq!(nonzero_u256_opt.unwrap().bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_bigint_from_nonzero() {
        // Non-zero values should return proper big-endian byte representation
        let bigint_255 = BigInt::from(255u64);
        assert_eq!(bigint_255.bytes, vec![255], "255 should produce [255]");

        let bigint_256 = BigInt::from(256u64);
        assert_eq!(bigint_256.bytes, vec![1, 0], "256 should produce [1, 0]");

        let bigint_65535 = BigInt::from(65535u64);
        assert_eq!(
            bigint_65535.bytes,
            vec![255, 255],
            "65535 should produce [255, 255]"
        );
    }

    #[test]
    fn test_bigint_u256_behavior() {
        // Test U256 specific cases
        let small_u256 = BigInt::from(U256::from(42));
        assert_eq!(small_u256.bytes, vec![42], "U256(42) should produce [42]");

        let large_u256 = BigInt::from(U256::from(0x1234));
        assert_eq!(
            large_u256.bytes,
            vec![0x12, 0x34],
            "U256(0x1234) should produce [0x12, 0x34]"
        );

        // Test a larger U256 value
        let very_large = U256::from_str_radix("123456789abcdef0", 16).unwrap();
        let bigint_large = BigInt::from(very_large);
        assert_eq!(
            bigint_large.bytes,
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
            "Large U256 should produce correct big-endian bytes"
        );
    }

    #[test]
    fn test_bigint_behavior_matches_go() {
        // Test that our behavior matches Go's firehoseBigIntFromNative:
        // - Zero -> empty bytes (nil equivalent)
        // - Non-zero -> big-endian bytes without leading zeros

        // Zero case
        let zero = BigInt::from(0u64);
        assert!(zero.bytes.is_empty());

        // Small non-zero case
        let small = BigInt::from(42u64);
        assert_eq!(small.bytes, vec![42]);

        // Larger case
        let large = BigInt::from(0x1234u64);
        assert_eq!(large.bytes, vec![0x12, 0x34]);
    }
}
