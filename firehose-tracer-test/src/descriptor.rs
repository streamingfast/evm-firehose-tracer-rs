//! Runtime access to the `sf.ethereum` protobuf descriptors.
//!
//! [`crate::BlockProjection`] renders a captured block by walking it against its descriptor rather
//! than by naming each field in Rust. That is what keeps the projection honest: a field added
//! upstream shows up in the golden on the next regeneration instead of being silently invisible,
//! which is the failure mode a hand-written projection has.
//!
//! The descriptor set is checked in as `descriptor.binpb` next to `Cargo.toml`. Regenerate it
//! alongside the generated Rust types with `scripts/generate-protobuf.sh` — it runs both `buf`
//! steps from one source so they cannot disagree. The `descriptor_drift` tests below fail if the
//! checked-in set stops covering the fields the generated types carry, so the two cannot drift
//! apart unnoticed.

use std::sync::OnceLock;

use prost_reflect::{DescriptorPool, MessageDescriptor};

/// Raw `FileDescriptorSet` for the `sf.ethereum` packages.
const DESCRIPTOR_SET: &[u8] = include_bytes!("../descriptor.binpb");

/// Full protobuf name of the block message the tracer emits.
pub const BLOCK_MESSAGE: &str = "sf.ethereum.type.v2.Block";

/// Returns the process-wide descriptor pool holding every `sf.ethereum` message.
///
/// Decoding the set is done once and cached; it is infallible in practice because the bytes are
/// compiled in, so a failure here means the checked-in file is corrupt.
pub fn descriptor_pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();

    POOL.get_or_init(|| {
        DescriptorPool::decode(DESCRIPTOR_SET)
            .expect("descriptor.binpb must be a valid FileDescriptorSet")
    })
}

/// Looks up a message descriptor by its fully qualified protobuf name.
pub fn message_descriptor(full_name: &str) -> eyre::Result<MessageDescriptor> {
    descriptor_pool()
        .get_message_by_name(full_name)
        .ok_or_else(|| eyre::eyre!("descriptor set has no message named {full_name}"))
}

/// Looks up the descriptor for [`BLOCK_MESSAGE`].
pub fn block_descriptor() -> eyre::Result<MessageDescriptor> {
    message_descriptor(BLOCK_MESSAGE)
}

#[cfg(test)]
mod tests {
    //! Beyond resolving names, these guard `descriptor.binpb` against drifting *behind* the
    //! generated Rust types: a descriptor missing a field the types carry would quietly stop the
    //! projection from rendering it — the silent-omission failure reflection exists to prevent.
    //! Regenerate both together; see the crate `AGENTS.md` and `scripts/generate-protobuf.sh`.

    use alloy_primitives::{Bytes, B256, U256};
    use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
    use firehose_tracer::types::LogData;
    use prost::Message as _;
    use prost_reflect::{DynamicMessage, Value};

    use super::*;
    use crate::{alice_addr, bob_addr, hash32, receipt_with_logs, test_legacy_trx, TracerTester};

    #[test]
    fn pool_holds_the_block_message() {
        let block = block_descriptor().expect("block descriptor must resolve");

        assert_eq!(block.full_name(), BLOCK_MESSAGE);
    }

    #[test]
    fn pool_holds_every_generated_package() {
        for package in [
            "sf.ethereum.type.v2.Block",
            "sf.ethereum.transform.v1.CombinedFilter",
            "sf.ethereum.substreams.v1.RpcCalls",
        ] {
            assert!(
                descriptor_pool().get_message_by_name(package).is_some(),
                "descriptor set must cover {package}"
            );
        }
    }

    #[test]
    fn unknown_message_is_an_error() {
        assert!(message_descriptor("sf.ethereum.type.v2.Nope").is_err());
    }

    #[test]
    fn every_message_the_projection_names_exists() {
        for full_name in [
            BLOCK_MESSAGE,
            "sf.ethereum.type.v2.TransactionTrace",
            "sf.ethereum.type.v2.BigInt",
            "sf.ethereum.type.v2.BalanceChange",
            "sf.ethereum.type.v2.NonceChange",
        ] {
            assert!(
                descriptor_pool().get_message_by_name(full_name).is_some(),
                "the projection hardcodes {full_name}, so the descriptor must define it"
            );
        }
    }

    /// Emits a block exercising as many message types as the tester can reach.
    fn with_rich_block(assert: impl FnOnce(&pbeth::Block)) {
        let mut tester = TracerTester::new();
        tester
            .start_block_trx(test_legacy_trx())
            .start_call(
                alice_addr(),
                bob_addr(),
                U256::from(100),
                100_000,
                vec![1, 2, 3, 4],
            )
            .storage_change(bob_addr(), hash32(1), hash32(100), hash32(200))
            .balance_change(
                alice_addr(),
                U256::from(1000),
                U256::from(900),
                pbeth::balance_change::Reason::Transfer,
            )
            .nonce_change(alice_addr(), 4, 5)
            .code_change(bob_addr(), B256::ZERO, hash32(9), vec![], vec![0x60, 0x60])
            .log(bob_addr(), vec![hash32(7)], vec![1, 2, 3], 0)
            .end_call(vec![0xff], 90_000)
            .end_block_trx(
                Some(receipt_with_logs(
                    90_000,
                    vec![LogData {
                        address: bob_addr(),
                        topics: vec![hash32(7)],
                        data: Bytes::from(vec![1, 2, 3]),
                        block_index: 0,
                    }],
                )),
                None,
                None,
            )
            .validate(assert);
    }

    /// Collects the paths of every unknown field found anywhere under `message`.
    fn unknown_field_paths(message: &DynamicMessage, path: &str, out: &mut Vec<String>) {
        for unknown in message.unknown_fields() {
            out.push(format!("{path} (field number {})", unknown.number()));
        }

        for (field, value) in message.fields() {
            let child = format!("{path}.{}", field.name());
            match value {
                Value::Message(nested) => unknown_field_paths(nested, &child, out),
                Value::List(items) => {
                    for (index, item) in items.iter().enumerate() {
                        if let Value::Message(nested) = item {
                            unknown_field_paths(nested, &format!("{child}[{index}]"), out);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn the_descriptor_covers_every_field_the_tracer_emits() {
        with_rich_block(|block| {
            let message = DynamicMessage::decode(
                block_descriptor().expect("block descriptor"),
                block.encode_to_vec().as_slice(),
            )
            .expect("an emitted block must decode against the checked-in descriptor");

            let mut unknown = Vec::new();
            unknown_field_paths(&message, "Block", &mut unknown);

            assert!(
                unknown.is_empty(),
                "descriptor.binpb is behind the generated types; regenerate it with \
                 scripts/generate-protobuf.sh. Unknown: {unknown:?}"
            );
        });
    }

    #[test]
    fn a_block_survives_a_round_trip_through_its_descriptor() {
        with_rich_block(|block| {
            let encoded = block.encode_to_vec();
            let message =
                DynamicMessage::decode(block_descriptor().expect("descriptor"), encoded.as_slice())
                    .expect("decode");

            let round_tripped = pbeth::Block::decode(message.encode_to_vec().as_slice())
                .expect("re-encoding must produce a valid block");

            assert_eq!(
                &round_tripped, block,
                "the descriptor must preserve every field"
            );
        });
    }
}
