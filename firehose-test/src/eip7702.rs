//! EIP-7702 SetCode Authorization Signing
//!
//! This module provides functionality to sign EIP-7702 SetCode authorizations
//! for testing purposes, matching the Golang implementation.

use alloy_primitives::{keccak256, Address, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

/// Helper to create a SetCodeAuthorization from a signature
pub fn sign_set_code_auth_as_struct(
    private_key: &[u8; 32],
    chain_id: u64,
    delegate_address: Address,
    nonce: u64,
) -> firehose::types::SetCodeAuthorization {
    let (chain_id_bytes, address, nonce, v, r, s) =
        sign_set_code_auth(private_key, chain_id, delegate_address, nonce);
    firehose::types::SetCodeAuthorization {
        chain_id: chain_id_bytes,
        address,
        nonce,
        v,
        r,
        s,
    }
}

/// Signs an EIP-7702 SetCode authorization
///
/// Creates a signed authorization that allows the specified address to execute
/// code on behalf of the signer's account.
///
/// # Parameters
/// - `private_key`: 32-byte private key
/// - `chain_id`: Chain ID (e.g., 1 for Ethereum mainnet)
/// - `delegate_address`: Address of the contract to delegate code execution to
/// - `nonce`: Nonce of the authorizing account
///
/// # Returns
/// A tuple of (chain_id, address, nonce, v, r, s) for use in SetCodeAuthorization
pub fn sign_set_code_auth(
    private_key: &[u8; 32],
    chain_id: u64,
    delegate_address: Address,
    nonce: u64,
) -> (B256, Address, u64, u32, B256, B256) {
    // Create signing key
    let signing_key = SigningKey::from_bytes(private_key.into()).expect("Invalid private key");

    // Convert chain_id to B256
    let chain_id_u256 = U256::from(chain_id);
    let mut chain_id_bytes = B256::ZERO;
    chain_id_u256
        .to_be_bytes_trimmed_vec()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| {
            chain_id_bytes[32 - chain_id_u256.to_be_bytes_trimmed_vec().len() + i] = b;
        });

    // Compute signature hash
    let sighash = compute_set_code_sighash(chain_id_bytes, delegate_address, nonce);

    // Sign the hash (use prehash to avoid double-hashing, matching Go's ecdsa.Sign behavior)
    let signature: Signature = signing_key
        .sign_prehash(&sighash.0)
        .expect("failed to sign prehash");

    // Extract r and s
    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();

    let mut r = B256::ZERO;
    let mut s = B256::ZERO;
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    // Determine recovery ID (v)
    let v = find_recovery_id(&signing_key, &sighash.0, &signature);

    (chain_id_bytes, delegate_address, nonce, v, r, s)
}

/// Computes the signature hash for EIP-7702 SetCode authorization
/// Hash = keccak256(0x05 || rlp([chainID, address, nonce]))
fn compute_set_code_sighash(chain_id: B256, address: Address, nonce: u64) -> B256 {
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

    // Debug output
    if std::env::var("DEBUG_SIGNING").is_ok() {
        eprintln!("RLP encoded: {}", hex::encode(&rlp_buffer));
        eprintln!("Prefixed: {}", hex::encode(&prefixed));
    }

    // Hash with keccak256
    let hash = keccak256(&prefixed);

    if std::env::var("DEBUG_SIGNING").is_ok() {
        eprintln!("Signature hash: {}", hex::encode(&hash));
    }

    hash
}

/// Finds the recovery ID (v) for the signature
fn find_recovery_id(signing_key: &SigningKey, hash: &[u8], signature: &Signature) -> u32 {
    use k256::ecdsa::RecoveryId;
    use k256::ecdsa::VerifyingKey;

    // Get the expected public key
    let verifying_key = VerifyingKey::from(signing_key);
    let expected_point = verifying_key.to_encoded_point(false);
    let expected_pubkey = expected_point.as_bytes();

    // Try both recovery IDs
    for rec_id in 0u8..2 {
        if let Ok(recovery_id) = RecoveryId::try_from(rec_id) {
            if let Ok(recovered_key) =
                VerifyingKey::recover_from_prehash(hash, signature, recovery_id)
            {
                let recovered_point = recovered_key.to_encoded_point(false);
                let recovered_pubkey = recovered_point.as_bytes();

                // Compare public keys
                if expected_pubkey == recovered_pubkey {
                    return rec_id as u32;
                }
            }
        }
    }

    // Default to 0 if recovery fails
    0
}

/// Recovers the authority (signer) address from an EIP-7702 SetCode authorization signature.
///
/// This is the recovery counterpart to `sign_set_code_auth`.
///
/// # Parameters
/// - `chain_id`: Chain ID bytes
/// - `delegate_address`: Address of the contract being delegated to
/// - `nonce`: Nonce of the authorizing account
/// - `v`: Recovery ID
/// - `r`, `s`: Signature components
///
/// # Returns
/// The Ethereum address that signed the authorization, or None if recovery fails
pub fn recover_set_code_auth_authority(
    chain_id: B256,
    delegate_address: Address,
    nonce: u64,
    v: u32,
    r: B256,
    s: B256,
) -> Option<Address> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // Compute the same signature hash
    let sighash = compute_set_code_sighash(chain_id, delegate_address, nonce);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_set_code_auth() {
        // Test with a known private key
        let private_key = [1u8; 32];
        let chain_id = 1u64;
        let delegate_address = Address::repeat_byte(0x42);
        let nonce = 0u64;

        let (_chain_id_bytes, addr, n, v, r, s) =
            sign_set_code_auth(&private_key, chain_id, delegate_address, nonce);

        // Verify the returned values
        assert_eq!(addr, delegate_address);
        assert_eq!(n, nonce);
        assert!(v <= 1, "v should be 0 or 1");
        assert_ne!(r, B256::ZERO, "r should not be zero");
        assert_ne!(s, B256::ZERO, "s should not be zero");
    }
}
