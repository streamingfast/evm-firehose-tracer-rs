use crate::firehose::BLOCK_VERSION;
use crate::pb::sf::ethereum::r#type::v2::block::DetailLevel;
use crate::pb::sf::ethereum::r#type::v2::{BigInt, Block, BlockHeader};
use crate::prelude::*;
use alloy_consensus::BlockHeader as ConsensusBlockHeader;
use alloy_primitives::{FixedBytes, Sealable};
use alloy_rlp::Encodable;
use prost_types::Timestamp;
use reth::api::BlockBody;

/// Maps a RecoveredBlock to a Protobuf Block following the Go implementation behavior
pub(super) fn recovered_block_to_protobuf<Node: FullNodeComponents>(
    recovered_block: &RecoveredBlock<Node>,
) -> Block {
    let hash = recovered_block.hash();
    let header = recovered_block.header();
    let size = recovered_block.sealed_block().length() as u64;
    let uncles = map_uncles::<Node>(recovered_block);

    block_header_to_protobuf(hash, header, size, uncles)
}

/// Maps a RecoveredBlock to a Protobuf Block following the Go implementation behavior
pub(super) fn block_header_to_protobuf<H: ConsensusBlockHeader>(
    hash: FixedBytes<32>,
    block_header: &H,
    size: u64,
    uncles: Vec<BlockHeader>,
) -> Block {
    let pb_header = create_block_header_protobuf(hash.to_vec(), block_header);

    Block {
        hash: hash.to_vec(),
        number: block_header.number(),
        size: size,
        header: Some(pb_header),
        uncles: uncles,
        transaction_traces: Vec::new(),
        balance_changes: Vec::new(),
        code_changes: Vec::new(),
        system_calls: Vec::new(),
        ver: BLOCK_VERSION,
        detail_level: DetailLevel::DetaillevelExtended as i32,
        ..Default::default()
    }
}

/// Maps uncle headers to protobuf format
fn map_uncles<Node: FullNodeComponents>(
    recovered_block: &RecoveredBlock<Node>,
) -> Vec<BlockHeader> {
    if let Some(ommers) = recovered_block.body().ommers() {
        ommers
            .iter()
            .map(|ommer_header| {
                // For ommer headers, we need to compute the hash using hash_slow()
                // FIXME: Ask in Reth community if there is not a way to retrieve the hash without recomputing it
                create_block_header_protobuf(ommer_header.hash_slow().to_vec(), ommer_header)
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// Creates a protobuf BlockHeader from any header implementing ConsensusBlockHeader trait
/// This helper function eliminates duplication between main block header and uncle headers
fn create_block_header_protobuf<H: ConsensusBlockHeader>(hash: Vec<u8>, header: &H) -> BlockHeader {
    BlockHeader {
        hash,
        number: header.number(),
        parent_hash: header.parent_hash().to_vec(),
        uncle_hash: header.ommers_hash().to_vec(),
        coinbase: header.beneficiary().to_vec(),
        state_root: header.state_root().to_vec(),
        transactions_root: header.transactions_root().to_vec(),
        receipt_root: header.receipts_root().to_vec(),
        logs_bloom: header.logs_bloom().to_vec(),
        difficulty: BigInt::from_optional_u256(header.difficulty()),
        gas_limit: header.gas_limit(),
        gas_used: header.gas_used(),
        timestamp: Some(Timestamp {
            seconds: header.timestamp() as i64,
            nanos: 0,
        }),
        extra_data: header.extra_data().to_vec(),
        mix_hash: header.mix_hash().map(|h| h.to_vec()).unwrap_or_default(),
        nonce: header
            .nonce()
            .map(|n| u64::from_be_bytes(n.into()))
            .unwrap_or_default(),
        base_fee_per_gas: header
            .base_fee_per_gas()
            .and_then(|fee| BigInt::from_optional_u64(fee)),
        withdrawals_root: header
            .withdrawals_root()
            .map(|root| root.to_vec())
            .unwrap_or_default(),
        blob_gas_used: header.blob_gas_used(),
        excess_blob_gas: header.excess_blob_gas(),
        parent_beacon_root: header
            .parent_beacon_block_root()
            .map(|root| root.to_vec())
            .unwrap_or_default(),
        requests_hash: header
            .requests_hash()
            .map(|hash| hash.to_vec())
            .unwrap_or_default(),

        // Deprecated across the ecosystem, setting to None
        #[allow(deprecated)]
        total_difficulty: None,

        // Not used anymore
        tx_dependency: None,
    }
}
