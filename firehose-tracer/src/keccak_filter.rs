//! Reduces `Call.keccak_preimages` to the preimages that explain a storage slot of the
//! transaction.
//!
//! The map exists so a consumer can walk a storage key back to the expression that produced
//! it. A preimage is kept when:
//!
//! * a storage change key of the transaction is its hash, or its hash plus a small offset
//!   (array elements and struct fields live at `keccak(p) + i`), or
//! * its hash, or its hash plus a small offset, appears inside the preimage of a kept entry
//!   (nested mappings, a mapping inside a struct or array element, and `string` or `bytes`
//!   keys), following at most [`MAX_DEPTH`] such levels.
//!
//! Everything else is dropped: hashes only used to read storage, signatures, CREATE2
//! addresses and contract-level hashing. Those can make up tens of MB for a single
//! transaction while never matching a storage change.

use std::collections::{HashMap, HashSet};

use alloy_primitives::U256;

use crate::pb::sf::ethereum::r#type::v2::Call;

/// Levels of nested hashing followed from a storage key, e.g. `mapping(a => mapping(b => T))`
/// is one level.
const MAX_DEPTH: usize = 16;

/// Largest distance between a slot and the hash it is derived from, for arrays and struct
/// fields. A random key lands this close to an unrelated hash with probability
/// about 2^-192 per pair.
const MAX_SLOT_OFFSET: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);

type Hash = [u8; 32];

/// Turns the filter off when set to `true`, `1` or `yes`, whatever the config says.
pub(crate) const DISABLE_ENV: &str = "FIREHOSE_ETHEREUM_TRACER_DISABLE_KECCAK_FILTER";

pub(crate) fn disabled_by_env() -> bool {
    std::env::var(DISABLE_ENV).is_ok_and(|value| is_truthy(&value))
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

/// Keeps only the keccak preimages of `calls` that explain one of their storage change keys.
/// `calls` are all the calls of one transaction or system call, and must run once all of
/// their storage changes are attached.
pub(crate) fn retain_storage_slot_preimages(calls: &mut [Call]) {
    let mut preimages: HashMap<Hash, Vec<u8>> = HashMap::new();
    for call in calls.iter() {
        for (hash, preimage) in &call.keccak_preimages {
            let Some(hash) = decode_hash(hash) else {
                continue;
            };
            if preimages.contains_key(&hash) {
                continue;
            }
            if let Ok(preimage) = hex::decode(preimage) {
                preimages.insert(hash, preimage);
            }
        }
    }
    if preimages.is_empty() {
        return;
    }

    let mut sorted: Vec<Hash> = preimages.keys().copied().collect();
    sorted.sort_unstable();

    let mut kept: HashSet<Hash> = HashSet::new();
    let mut frontier: Vec<Hash> = Vec::new();
    for call in calls.iter() {
        for change in &call.storage_changes {
            let Ok(key) = <Hash>::try_from(change.key.as_slice()) else {
                continue;
            };
            if let Some(base) = slot_base(&sorted, &key) {
                if kept.insert(base) {
                    frontier.push(base);
                }
            }
        }
    }

    for _ in 0..MAX_DEPTH {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for hash in &frontier {
            for word in inner_hash_candidates(&preimages[hash]) {
                if let Some(inner) = slot_base(&sorted, &word) {
                    if kept.insert(inner) {
                        next.push(inner);
                    }
                }
            }
        }
        frontier = next;
    }

    let kept_hex: HashSet<String> = kept.iter().map(hex::encode).collect();
    for call in calls.iter_mut() {
        call.keccak_preimages
            .retain(|hash, _| kept_hex.contains(hash));
    }
}

/// Returns the largest hash at or below `key` when `key` is at most [`MAX_SLOT_OFFSET`]
/// above it, which covers an exact match.
fn slot_base(sorted: &[Hash], key: &Hash) -> Option<Hash> {
    let idx = sorted.partition_point(|hash| hash <= key);
    let base = sorted[..idx].last()?;
    let distance = U256::from_be_bytes(*key) - U256::from_be_bytes(*base);
    (distance <= MAX_SLOT_OFFSET).then_some(*base)
}

/// The places an inner hash sits in a preimage: each 32-byte word (value-type mapping keys,
/// Vyper's slot-first layout) and the last 32 bytes (Solidity puts the slot after a
/// `string` or `bytes` key).
fn inner_hash_candidates(preimage: &[u8]) -> impl Iterator<Item = Hash> + '_ {
    let words = preimage.chunks_exact(32);
    let tail = (preimage.len() > 32 && !preimage.len().is_multiple_of(32))
        .then(|| &preimage[preimage.len() - 32..]);
    words
        .chain(tail)
        .map(|word| <Hash>::try_from(word).expect("32-byte slice"))
}

fn decode_hash(hash: &str) -> Option<Hash> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hash, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::sf::ethereum::r#type::v2::{Call, StorageChange};
    use alloy_primitives::keccak256;

    /// Hashes `preimage`, records it on `call` and returns the hash.
    fn record(call: &mut Call, preimage: &[u8]) -> Hash {
        let hash = keccak256(preimage).0;
        call.keccak_preimages
            .insert(hex::encode(hash), hex::encode(preimage));
        hash
    }

    fn store(call: &mut Call, key: Hash) {
        call.storage_changes.push(StorageChange {
            address: vec![0xAA; 20],
            key: key.to_vec(),
            old_value: vec![0; 32],
            new_value: vec![1; 32],
            ordinal: 0,
        });
    }

    fn word(v: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[31] = v;
        w
    }

    fn kept(calls: &[Call]) -> HashSet<String> {
        calls
            .iter()
            .flat_map(|c| c.keccak_preimages.keys().cloned())
            .collect()
    }

    fn set(hashes: &[Hash]) -> HashSet<String> {
        hashes.iter().map(hex::encode).collect()
    }

    fn add(hash: Hash, offset: u64) -> Hash {
        (U256::from_be_bytes(hash) + U256::from(offset)).to_be_bytes()
    }

    #[test]
    fn env_values_that_disable_the_filter() {
        for value in ["true", "TRUE", " 1 ", "yes"] {
            assert!(is_truthy(value), "{value:?} should disable");
        }
        for value in ["", "false", "0", "no"] {
            assert!(!is_truthy(value), "{value:?} should not disable");
        }
    }

    #[test]
    fn keeps_mapping_slot_and_drops_unrelated_hashes() {
        let mut call = Call::default();
        let slot = record(&mut call, &[word(1), word(0)].concat());
        let unrelated = record(&mut call, &[word(9), word(9)].concat());
        store(&mut call, slot);
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        assert_eq!(kept(&calls), set(&[slot]));
        assert!(!kept(&calls).contains(&hex::encode(unrelated)));
    }

    #[test]
    fn keeps_array_element_and_struct_field_slots() {
        let mut call = Call::default();
        let base = record(&mut call, &word(3));
        store(&mut call, add(base, 7));
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        assert_eq!(kept(&calls), set(&[base]));
    }

    #[test]
    fn drops_hash_too_far_below_a_storage_key() {
        let mut call = Call::default();
        let base = record(&mut call, &word(3));
        let too_far = U256::from_be_bytes(base) + (U256::from(1u64) << 64usize);
        store(&mut call, too_far.to_be_bytes());
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        assert!(kept(&calls).is_empty());
    }

    #[test]
    fn follows_nested_mappings_and_string_keys() {
        let mut call = Call::default();
        // mapping(uint => mapping(uint => T)) at slot 2: keccak(k2 . keccak(k1 . 2))
        let inner = record(&mut call, &[word(1), word(2)].concat());
        let outer = record(&mut call, &[word(5), inner].concat());
        // mapping(string => T) at slot 4 nested under a mapping: keccak("abc" . keccak(k . 4))
        let string_parent = record(&mut call, &[word(8), word(4)].concat());
        let string_slot = record(&mut call, &[b"abc".as_slice(), &string_parent].concat());
        store(&mut call, outer);
        store(&mut call, string_slot);
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        assert_eq!(
            kept(&calls),
            set(&[inner, outer, string_parent, string_slot])
        );
    }

    #[test]
    fn follows_mapping_inside_struct_in_mapping() {
        // struct Pool { uint total; mapping(address => uint) shares; }
        // mapping(uint => Pool) pools at slot 3: pools[id].shares[user] is at
        // keccak(user . (keccak(id . 3) + 1)).
        let mut call = Call::default();
        let pool = record(&mut call, &[word(7), word(3)].concat());
        let share = record(&mut call, &[word(0xEE), add(pool, 1)].concat());
        store(&mut call, share);
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        assert_eq!(kept(&calls), set(&[pool, share]));
    }

    #[test]
    fn keeps_preimage_recorded_in_another_call() {
        let mut hashing = Call::default();
        let slot = record(&mut hashing, &[word(1), word(0)].concat());
        let mut writing = Call::default();
        store(&mut writing, slot);
        let mut calls = vec![hashing, writing];

        retain_storage_slot_preimages(&mut calls);

        assert_eq!(kept(&calls), set(&[slot]));
    }

    #[test]
    fn stops_after_max_depth() {
        let mut call = Call::default();
        let mut chain = vec![record(&mut call, &[word(1), word(0)].concat())];
        for i in 0..MAX_DEPTH + 1 {
            let parent = *chain.last().unwrap();
            chain.push(record(&mut call, &[word(i as u8 + 10), parent].concat()));
        }
        store(&mut call, *chain.last().unwrap());
        let mut calls = vec![call];

        retain_storage_slot_preimages(&mut calls);

        // The storage key's own entry is depth 0, then MAX_DEPTH levels below it.
        assert_eq!(kept(&calls), set(&chain[1..]));
    }
}
