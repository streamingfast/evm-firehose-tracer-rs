//! EIP-7702 SetCode Authorization utilities
//!
//! This module provides signature recovery for EIP-7702 SetCode authorizations.

use alloy_primitives::{keccak256, Address, B256, U256};

/// Recovers the authority (signer) address from an EIP-7702 SetCode authorization signature.
///
/// This function computes the signature hash and recovers the public key using ECDSA recovery,
/// then derives the Ethereum address from the public key.
///
/// # Parameters
/// - `chain_id`: Chain ID bytes (32 bytes)
/// - `delegate_address`: Address of the contract being delegated to
/// - `nonce`: Nonce of the authorizing account
/// - `v`: Recovery ID
/// - `r`, `s`: Signature components
///
/// # Returns
/// The Ethereum address that signed the authorization, or None if recovery fails
pub fn recover_authority(
    chain_id: B256,
    delegate_address: Address,
    nonce: u64,
    v: u32,
    r: B256,
    s: B256,
) -> Option<Address> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // Compute signature hash: keccak256(0x05 || rlp([chainID, address, nonce]))
    let sighash = compute_sighash(chain_id, delegate_address, nonce);

    // Convert r and s to Signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.0);
    sig_bytes[32..].copy_from_slice(&s.0);

    let signature = Signature::from_bytes(&sig_bytes.into()).ok()?;

    // Normalize v to 0 or 1
    let rec_id_byte = if v >= 27 { v - 27 } else { v } as u8;
    let recovery_id = RecoveryId::try_from(rec_id_byte).ok()?;

    // Recover public key
    let verifying_key =
        VerifyingKey::recover_from_prehash(&sighash.0, &signature, recovery_id).ok()?;

    // Get uncompressed public key (65 bytes: 0x04 || x || y)
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();

    // Public key should be 65 bytes: 0x04 prefix + 64 bytes coordinates
    if public_key_bytes.len() != 65 {
        return None;
    }

    // Ethereum address = keccak256(pubkey[1..])[12:]
    // (skip the 0x04 prefix, hash the 64-byte coordinates, take last 20 bytes)
    let hash = keccak256(&public_key_bytes[1..]);
    let mut address = Address::ZERO;
    address.0.copy_from_slice(&hash.0[12..]);

    Some(address)
}

/// Computes the signature hash for EIP-7702 SetCode authorization
/// Hash = keccak256(0x05 || rlp([chainID, address, nonce]))
fn compute_sighash(chain_id: B256, address: Address, nonce: u64) -> B256 {
    use alloy_rlp::Encodable;

    // Convert chain_id to U256 for RLP encoding
    let chain_id_u256 = U256::from_be_bytes(chain_id.0);

    // Calculate the payload length for the list
    let chain_id_len = chain_id_u256.length();
    let address_len = address.length();
    let nonce_len = nonce.length();
    let payload_len = chain_id_len + address_len + nonce_len;

    // Allocate buffer for RLP list
    let mut rlp_buffer = Vec::new();

    // Encode list header
    if payload_len < 56 {
        rlp_buffer.push(0xc0 + payload_len as u8);
    } else {
        let len_bytes = payload_len.to_be_bytes();
        let len_bytes_trimmed: Vec<u8> =
            len_bytes.iter().skip_while(|&&b| b == 0).copied().collect();
        rlp_buffer.push(0xf7 + len_bytes_trimmed.len() as u8);
        rlp_buffer.extend_from_slice(&len_bytes_trimmed);
    }

    // Encode list elements
    chain_id_u256.encode(&mut rlp_buffer);
    address.encode(&mut rlp_buffer);
    nonce.encode(&mut rlp_buffer);

    // Prepend 0x05 prefix
    let mut prefixed = vec![0x05];
    prefixed.extend_from_slice(&rlp_buffer);

    // Hash with keccak256
    keccak256(&prefixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover_authority_from_alice_signature() {
        // Test data from test_set_code_trx()
        // Signature was generated: SignSetCodeAuth(AliceKey=0x01, chainID=1, CharlieAddr, nonce=0)
        let chain_id = B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let delegate_addr = Address::from([
            0x68, 0x13, 0xeb, 0x93, 0x62, 0x37, 0x2e, 0xef, 0x62, 0x00, 0xf3, 0xb1, 0xdb, 0xc3,
            0xf8, 0x19, 0x67, 0x1c, 0xba, 0x69,
        ]); // Charlie
        let nonce = 0u64;
        let v = 1u32;
        let r = B256::from([
            0x3d, 0x89, 0xbd, 0x9f, 0x90, 0xdd, 0x37, 0x01, 0xc1, 0xfd, 0x28, 0xaa, 0x68, 0xfe,
            0xac, 0x0f, 0xd0, 0x85, 0x8e, 0xc6, 0xd9, 0x66, 0x83, 0xf8, 0x8b, 0x30, 0x61, 0x7b,
            0x17, 0x63, 0xc8, 0x39,
        ]);
        let s = B256::from([
            0x15, 0xd0, 0x36, 0xef, 0x3d, 0xe2, 0xbc, 0x0c, 0x45, 0x82, 0xfe, 0x7d, 0x45, 0x5a,
            0xaf, 0xa9, 0x78, 0xe4, 0x74, 0x8e, 0x16, 0x9c, 0x5b, 0xa5, 0x9f, 0x0b, 0x8f, 0x23,
            0xf2, 0x89, 0x2d, 0x98,
        ]);

        let expected_alice = Address::from([
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
            0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
        ]);

        let recovered = recover_authority(chain_id, delegate_addr, nonce, v, r, s);

        println!("Expected Alice: {:?}", expected_alice);
        println!("Recovered:      {:?}", recovered);

        assert!(recovered.is_some(), "Recovery should succeed");
        assert_eq!(
            recovered.unwrap(),
            expected_alice,
            "Recovered address should match Alice"
        );
    }
}
