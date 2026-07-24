//! Normalised JSON projection of a captured Firehose block.
//!
//! A full-block protobuf golden is maximally sensitive: any upstream field addition, ordinal shift
//! or gas-accounting tweak rewrites the file, so a port produces a diff nobody can triage. The
//! projection instead renders the block as readable JSON and lets a [`VolatilePolicy`] remove the
//! dimensions that genuinely cannot reproduce between runs.
//!
//! The walk is driven by the protobuf **descriptor**, not by a field-by-field mapping in Rust.
//! That is the point: a field added upstream appears in the projection on the next golden
//! regeneration instead of being silently invisible, which is exactly what a hand-written
//! projection gets wrong. Knowing each field's real kind also lets the renderer do better than
//! canonical protobuf-JSON, which would emit every address and storage key as opaque base64:
//!
//! * `bytes` render as `0x…` hex, or as `@alias` when the [`SymbolTable`] names them,
//! * enum fields render as their protobuf value name rather than a bare discriminant,
//! * `BigInt` collapses to minimal hex instead of a nested `{ "bytes": … }` object,
//! * unset, default and empty-repeated fields are omitted, using real presence information.
//!
//! Because volatile fields are *excluded* rather than normalised, any diff [`crate::Golden`]
//! surfaces against a projection golden is either structural (an entity appeared or disappeared) or
//! semantic (a value the tracer is responsible for changed) — never gas or ordinal churn.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::U256;
use firehose_tracer::pb::sf::ethereum::r#type::v2::{Block, TransactionTrace};
use prost::Message as _;
use prost_reflect::{
    DynamicMessage, FieldDescriptor, Kind, ReflectMessage as _, Value as ProtoValue,
};
use serde_json::{Map, Value};

use crate::descriptor::message_descriptor;

/// Fully qualified name of the arbitrary-precision integer wrapper the tracer uses.
const BIG_INT: &str = "sf.ethereum.type.v2.BigInt";

/// Fully qualified name of the block message.
const BLOCK: &str = "sf.ethereum.type.v2.Block";

/// Fully qualified name of the transaction message.
const TRANSACTION_TRACE: &str = "sf.ethereum.type.v2.TransactionTrace";

/// Field names a deltaized message collapses into a single `delta`.
const OLD_VALUE: &str = "old_value";
/// See [`OLD_VALUE`].
const NEW_VALUE: &str = "new_value";

/// `BalanceChange.Reason` value names whose amount is derived from gas, and therefore moves with
/// the base fee rather than with anything the tracer controls.
const GAS_DERIVED_BALANCE_REASONS: &[&str] = &[
    "REASON_GAS_BUY",
    "REASON_GAS_REFUND",
    "REASON_REWARD_TRANSACTION_FEE",
    "REASON_REWARD_FEE_RESET",
];

/// Human-readable aliases for the addresses a test cares about.
///
/// Rendering an address as `@admin` instead of its hex keeps the golden readable and stable across
/// runs where an address is derived — a `CREATE2` token address, for instance.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    names: BTreeMap<Vec<u8>, String>,
}

impl SymbolTable {
    /// Creates an empty symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `name` as the alias for `address`.
    pub fn with(mut self, address: impl AsRef<[u8]>, name: impl Into<String>) -> Self {
        self.names.insert(address.as_ref().to_vec(), name.into());
        self
    }

    /// Renders `bytes` as `@name` when known, and as lowercase hex otherwise.
    pub fn render(&self, bytes: &[u8]) -> String {
        self.names.get(bytes).map_or_else(
            || format!("0x{}", hex::encode(bytes)),
            |name| format!("@{name}"),
        )
    }
}

/// Which parts of a block cannot reproduce between runs, and how to normalise them.
///
/// Selectors are protobuf paths. Each accepts either a fully qualified name
/// (`sf.ethereum.type.v2.Call.gas_limit`), a `Message.field` suffix (`Call.gas_limit`), or a bare
/// field name (`ordinal`, matching every message that has one). An explicit
/// [`keep_field`](Self::keep_field) always wins over a drop, so a broad drop can be narrowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolatilePolicy {
    dropped: BTreeSet<String>,
    kept: BTreeSet<String>,
    deltaized: BTreeSet<String>,
    drop_gas_derived_balance_amounts: bool,
}

impl VolatilePolicy {
    /// Keeps everything.
    ///
    /// This is the right default. A prestate-driven test runs a fixed pre-state through the tracer
    /// with no network involved, so every field down to the gas accounting is reproducible, and
    /// erasing any of it only narrows what the golden can catch.
    pub fn none() -> Self {
        Self::default()
    }

    /// Drops what a test against a live node genuinely cannot reproduce.
    ///
    /// A real sequencer moves the base fee, the block number and the wall clock between runs, so
    /// hashes, timestamps, gas amounts and absolute ordinals all churn without any tracing change
    /// behind them. Balance and nonce changes are deltaized instead of dropped: a moving starting
    /// balance makes the absolute values useless, but the delta is exactly what the tracer decided
    /// and stays stable.
    ///
    /// Storage changes keep their `old_value` / `new_value` verbatim — those are precisely what
    /// the tracer is under test for.
    pub fn live_node() -> Self {
        let mut policy = Self::default();

        // Block and header identity: hashes, roots and the wall clock.
        for field in [
            "Block.hash",
            "Block.number",
            "Block.size",
            "BlockHeader.hash",
            "BlockHeader.parent_hash",
            "BlockHeader.number",
            "BlockHeader.timestamp",
            "BlockHeader.state_root",
            "BlockHeader.transactions_root",
            "BlockHeader.receipt_root",
            "BlockHeader.mix_hash",
            "BlockHeader.nonce",
            "BlockHeader.difficulty",
            "BlockHeader.total_difficulty",
            "BlockHeader.base_fee_per_gas",
            "BlockHeader.parent_beacon_root",
            "BlockHeader.withdrawals_root",
            "logs_bloom",
        ] {
            policy = policy.drop_field(field);
        }

        // Transaction identity and signature.
        for field in [
            "TransactionTrace.hash",
            "TransactionTrace.nonce",
            "TransactionTrace.v",
            "TransactionTrace.r",
            "TransactionTrace.s",
        ] {
            policy = policy.drop_field(field);
        }

        // Absolute ordinals. Their *relative* order is asserted by BlockInvariants instead.
        for field in ["ordinal", "begin_ordinal", "end_ordinal"] {
            policy = policy.drop_field(field);
        }

        // Gas, in every message that accounts for it.
        for field in [
            "gas_limit",
            "gas_used",
            "gas_consumed",
            "gas_price",
            "gas_changes",
            "cumulative_gas_used",
            "blob_gas_used",
            "blob_gas_fee_cap",
            "excess_blob_gas",
            "max_fee_per_gas",
            "max_priority_fee_per_gas",
        ] {
            policy = policy.drop_field(field);
        }

        policy
            .deltaize("BalanceChange")
            .deltaize("NonceChange")
            .drop_gas_derived_balance_amounts()
    }

    /// Removes every field matching `selector` from the projection.
    pub fn drop_field(mut self, selector: impl Into<String>) -> Self {
        self.dropped.insert(selector.into());
        self
    }

    /// Keeps every field matching `selector`, overriding any drop that would also match it.
    pub fn keep_field(mut self, selector: impl Into<String>) -> Self {
        self.kept.insert(selector.into());
        self
    }

    /// Collapses `old_value` / `new_value` into a signed `delta` for messages matching `selector`.
    pub fn deltaize(mut self, selector: impl Into<String>) -> Self {
        self.deltaized.insert(selector.into());
        self
    }

    /// Also omits the amount of balance changes whose reason makes it gas-derived.
    ///
    /// Deltaizing is not enough for these: the delta of a gas buy *is* the gas cost, so it moves
    /// with the base fee. The address and the reason are kept, which is what the tracer decides.
    pub fn drop_gas_derived_balance_amounts(mut self) -> Self {
        self.drop_gas_derived_balance_amounts = true;
        self
    }

    /// Whether the field at `path` survives into the projection.
    fn keeps(&self, path: &str) -> bool {
        if Self::matches(&self.kept, path) {
            return true;
        }

        !Self::matches(&self.dropped, path)
    }

    /// Whether messages named `full_name` collapse their old/new pair into a delta.
    fn is_deltaized(&self, full_name: &str) -> bool {
        Self::matches(&self.deltaized, full_name)
    }

    /// Whether any selector matches `path` exactly or as a dot-delimited suffix of it.
    fn matches(selectors: &BTreeSet<String>, path: &str) -> bool {
        selectors.iter().any(|selector| {
            path == selector
                || (path.len() > selector.len()
                    && path.ends_with(selector.as_str())
                    && path.as_bytes()[path.len() - selector.len() - 1] == b'.')
        })
    }
}

/// Projects a captured block into the normalised JSON used as a golden.
#[derive(Debug, Default, Clone)]
pub struct BlockProjection {
    symbols: SymbolTable,
    policy: VolatilePolicy,
}

impl BlockProjection {
    /// Creates a projection with no aliases and no erasure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses `symbols` to alias known addresses.
    pub fn with_symbols(mut self, symbols: SymbolTable) -> Self {
        self.symbols = symbols;
        self
    }

    /// Applies `policy` when deciding what survives into the projection.
    pub fn with_policy(mut self, policy: VolatilePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Projects a whole block.
    pub fn block(&self, block: &Block) -> eyre::Result<Value> {
        self.project(BLOCK, &block.encode_to_vec())
    }

    /// Projects the single transaction whose hash is `tx_hash`.
    ///
    /// Prefer this over [`Self::block`] for goldens on an L2: a whole block also contains the
    /// L1-info deposit transaction, whose calldata and storage values carry the L1 head and
    /// therefore change on every run.
    pub fn transaction(&self, block: &Block, tx_hash: &[u8]) -> eyre::Result<Value> {
        let trace = Self::find_transaction(block, tx_hash)?;

        self.project(TRANSACTION_TRACE, &trace.encode_to_vec())
    }

    /// Locates the transaction with the given hash, reporting what the block does hold otherwise.
    fn find_transaction<'a>(
        block: &'a Block,
        tx_hash: &[u8],
    ) -> eyre::Result<&'a TransactionTrace> {
        block
            .transaction_traces
            .iter()
            .find(|trace| trace.hash == tx_hash)
            .ok_or_else(|| {
                eyre::eyre!(
                    "block #{} has no transaction 0x{}; it holds {:?}",
                    block.number,
                    hex::encode(tx_hash),
                    block
                        .transaction_traces
                        .iter()
                        .map(|trace| format!("0x{}", hex::encode(&trace.hash)))
                        .collect::<Vec<_>>()
                )
            })
    }

    /// Decodes `encoded` against the descriptor for `full_name` and renders it.
    fn project(&self, full_name: &str, encoded: &[u8]) -> eyre::Result<Value> {
        let descriptor = message_descriptor(full_name)?;
        let message = DynamicMessage::decode(descriptor, encoded)
            .map_err(|error| eyre::eyre!("decoding {full_name} against its descriptor: {error}"))?;

        Ok(self.message(&message))
    }

    /// Renders every populated field of `message`, honouring the policy.
    fn message(&self, message: &DynamicMessage) -> Value {
        let descriptor = message.descriptor();
        let full_name = descriptor.full_name();

        if self.policy.is_deltaized(full_name) {
            if let Some(value) = self.deltaized_message(message) {
                return value;
            }
        }

        let suppress_amount =
            self.policy.drop_gas_derived_balance_amounts && Self::has_gas_derived_reason(message);

        let mut out = Map::new();
        for (field, value) in message.fields() {
            let path = format!("{full_name}.{}", field.name());
            if !self.policy.keeps(&path) {
                continue;
            }

            if suppress_amount && Self::is_amount_field(field.name()) {
                continue;
            }

            out.insert(field.name().to_owned(), self.value(&field, value));
        }

        Value::Object(out)
    }

    /// Renders `value`, which belongs to `field`.
    fn value(&self, field: &FieldDescriptor, value: &ProtoValue) -> Value {
        match value {
            ProtoValue::Bool(inner) => Value::Bool(*inner),
            ProtoValue::I32(inner) => Value::from(*inner),
            ProtoValue::I64(inner) => Value::from(*inner),
            ProtoValue::U32(inner) => Value::from(*inner),
            ProtoValue::U64(inner) => Value::from(*inner),
            ProtoValue::F32(inner) => Value::from(*inner),
            ProtoValue::F64(inner) => Value::from(*inner),
            ProtoValue::String(inner) => Value::String(inner.clone()),
            ProtoValue::Bytes(inner) => Value::String(self.symbols.render(inner)),
            ProtoValue::EnumNumber(number) => Self::enum_name(field, *number),
            ProtoValue::Message(inner) => self.nested_message(inner),
            ProtoValue::List(items) => {
                Value::Array(items.iter().map(|item| self.value(field, item)).collect())
            }
            ProtoValue::Map(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, item)| (format!("{key:?}"), self.value(field, item)))
                    .collect(),
            ),
        }
    }

    /// Renders a nested message, collapsing `BigInt` to minimal hex.
    fn nested_message(&self, message: &DynamicMessage) -> Value {
        if message.descriptor().full_name() == BIG_INT {
            return Value::String(Self::big_int(message));
        }

        self.message(message)
    }

    /// Renders an enum discriminant as its protobuf value name, falling back to the number.
    fn enum_name(field: &FieldDescriptor, number: i32) -> Value {
        let Kind::Enum(descriptor) = field.kind() else {
            return Value::from(number);
        };

        descriptor.get_value(number).map_or_else(
            || Value::from(number),
            |value| Value::String(value.name().to_owned()),
        )
    }

    /// Renders a `BigInt` as minimal hex, so leading zeroes and an absent value never matter.
    fn big_int(message: &DynamicMessage) -> String {
        let bytes = Self::big_int_bytes(message);
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        if first == bytes.len() {
            return "0x0".to_owned();
        }

        format!("0x{}", hex::encode(&bytes[first..]))
    }

    /// Extracts a `BigInt`'s raw big-endian bytes.
    fn big_int_bytes(message: &DynamicMessage) -> Vec<u8> {
        message
            .descriptor()
            .get_field_by_name("bytes")
            .and_then(|field| {
                message
                    .get_field(&field)
                    .as_bytes()
                    .map(|bytes| bytes.to_vec())
            })
            .unwrap_or_default()
    }

    /// Renders a message whose `old_value` / `new_value` collapse into a signed `delta`.
    ///
    /// Returns `None` when the message has no such pair, so the caller falls back to the normal
    /// rendering rather than silently producing something unexpected.
    fn deltaized_message(&self, message: &DynamicMessage) -> Option<Value> {
        let descriptor = message.descriptor();
        let old = descriptor.get_field_by_name(OLD_VALUE)?;
        let new = descriptor.get_field_by_name(NEW_VALUE)?;
        let delta = Self::delta(&message.get_field(&old), &message.get_field(&new))?;

        let suppress_amount =
            self.policy.drop_gas_derived_balance_amounts && Self::has_gas_derived_reason(message);

        let full_name = descriptor.full_name();
        let mut out = Map::new();
        for (field, value) in message.fields() {
            if field.name() == OLD_VALUE || field.name() == NEW_VALUE {
                continue;
            }

            let path = format!("{full_name}.{}", field.name());
            if !self.policy.keeps(&path) {
                continue;
            }

            out.insert(field.name().to_owned(), self.value(&field, value));
        }

        if !suppress_amount {
            out.insert("delta".to_owned(), Value::String(delta));
        }

        Some(Value::Object(out))
    }

    /// Computes `new - old` as a signed string, for the value shapes state changes actually use.
    fn delta(old: &ProtoValue, new: &ProtoValue) -> Option<String> {
        match (old, new) {
            (ProtoValue::U64(old), ProtoValue::U64(new)) => {
                Some(Self::signed_decimal(i128::from(*new) - i128::from(*old)))
            }
            (ProtoValue::U32(old), ProtoValue::U32(new)) => {
                Some(Self::signed_decimal(i128::from(*new) - i128::from(*old)))
            }
            (ProtoValue::Message(old), ProtoValue::Message(new))
                if old.descriptor().full_name() == BIG_INT =>
            {
                Some(Self::big_int_delta(old, new))
            }
            _ => None,
        }
    }

    /// Renders `value` with an explicit sign, so a golden never hides a direction change.
    fn signed_decimal(value: i128) -> String {
        if value < 0 {
            format!("-{}", value.unsigned_abs())
        } else {
            format!("+{value}")
        }
    }

    /// Computes the signed difference between two `BigInt`s as sign-prefixed minimal hex.
    ///
    /// Balances reach 2^256, so the subtraction goes through `U256` and the sign is carried
    /// separately rather than by a wider signed type.
    fn big_int_delta(old: &DynamicMessage, new: &DynamicMessage) -> String {
        let old = Self::u256(old);
        let new = Self::u256(new);

        if new >= old {
            format!("+0x{:x}", new - old)
        } else {
            format!("-0x{:x}", old - new)
        }
    }

    /// Reads a `BigInt` as a `U256`, saturating rather than failing on an oversized value.
    fn u256(message: &DynamicMessage) -> U256 {
        let bytes = Self::big_int_bytes(message);
        if bytes.len() > 32 {
            return U256::MAX;
        }

        U256::from_be_slice(&bytes)
    }

    /// Whether this message carries a `reason` whose amount is derived from gas.
    fn has_gas_derived_reason(message: &DynamicMessage) -> bool {
        let descriptor = message.descriptor();
        let Some(field) = descriptor.get_field_by_name("reason") else {
            return false;
        };
        let Kind::Enum(reasons) = field.kind() else {
            return false;
        };
        let Some(number) = message.get_field(&field).as_enum_number() else {
            return false;
        };

        reasons
            .get_value(number)
            .is_some_and(|value| GAS_DERIVED_BALANCE_REASONS.contains(&value.name()))
    }

    /// Whether `name` holds the amount of a state change, as opposed to its identity.
    fn is_amount_field(name: &str) -> bool {
        matches!(name, OLD_VALUE | NEW_VALUE | "delta")
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, U256};
    use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
    use firehose_tracer::types::LogData;
    use serde_json::Value;

    use super::*;
    use crate::{alice_addr, bob_addr, hash32, receipt_with_logs, test_legacy_trx, TracerTester};

    /// Runs a transaction exercising every state-change kind and hands the emitted block to
    /// `assert`.
    ///
    /// Building the block through the tracer rather than by hand keeps these tests honest about
    /// what the tracer actually emits.
    fn with_block(assert: impl FnOnce(&pbeth::Block)) {
        let mut tester = TracerTester::new();
        tester
            .start_block_trx(test_legacy_trx())
            .start_call(alice_addr(), bob_addr(), U256::from(100), 21000, vec![])
            .storage_change(bob_addr(), hash32(1), hash32(100), hash32(200))
            .balance_change(
                alice_addr(),
                U256::from(1000),
                U256::from(900),
                pbeth::balance_change::Reason::Transfer,
            )
            .balance_change(
                alice_addr(),
                U256::from(900),
                U256::from(880),
                pbeth::balance_change::Reason::GasBuy,
            )
            .nonce_change(alice_addr(), 4, 5)
            .log(bob_addr(), vec![hash32(7)], vec![1, 2, 3], 0)
            .end_call(vec![], 21000)
            .end_block_trx(
                Some(receipt_with_logs(
                    21000,
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

    /// Aliases for the two addresses the fixture uses.
    fn symbols() -> SymbolTable {
        SymbolTable::new()
            .with(alice_addr(), "alice")
            .with(bob_addr(), "bob")
    }

    /// Projects the fixture block under `policy`.
    fn project(block: &pbeth::Block, policy: VolatilePolicy) -> Value {
        BlockProjection::new()
            .with_symbols(symbols())
            .with_policy(policy)
            .block(block)
            .expect("projecting the block must succeed")
    }

    /// The fixture's only call, as projected.
    fn only_call(projection: &Value) -> &Value {
        &projection["transaction_traces"][0]["calls"][0]
    }

    #[test]
    fn known_addresses_render_as_aliases_and_the_rest_as_hex() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());
            let call = only_call(&projection);

            assert_eq!(call["caller"], Value::from("@alice"));
            assert_eq!(call["address"], Value::from("@bob"));

            // The coinbase has no alias, so it must fall back to lowercase hex rather than base64.
            let coinbase = projection["header"]["coinbase"]
                .as_str()
                .expect("coinbase is a string");
            assert!(
                coinbase.starts_with("0x"),
                "unaliased bytes must render as hex, got {coinbase}"
            );
            assert_eq!(
                coinbase.len(),
                42,
                "an address renders as 20 hex-encoded bytes"
            );
        });
    }

    #[test]
    fn bytes_render_as_hex_everywhere_including_nested_lists() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());
            let log = &only_call(&projection)["logs"][0];

            assert_eq!(log["data"], Value::from("0x010203"));
            assert_eq!(
                log["topics"][0],
                Value::from("0x0000000000000000000000000000000000000000000000000000000000000007"),
                "a repeated bytes field renders each element as hex"
            );
        });
    }

    #[test]
    fn enum_fields_render_as_their_protobuf_names() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());
            let call = only_call(&projection);

            assert_eq!(call["call_type"], Value::from("CALL"));
            assert_eq!(
                projection["transaction_traces"][0]["status"],
                Value::from("SUCCEEDED")
            );
            assert_eq!(
                call["balance_changes"][0]["reason"],
                Value::from("REASON_TRANSFER")
            );
            assert_eq!(
                call["balance_changes"][1]["reason"],
                Value::from("REASON_GAS_BUY")
            );
        });
    }

    #[test]
    fn big_int_collapses_to_minimal_hex_rather_than_a_nested_object() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());

            assert_eq!(only_call(&projection)["value"], Value::from("0x64"));
            assert_eq!(
                only_call(&projection)["balance_changes"][0]["old_value"],
                Value::from("0x03e8"),
                "1000 renders as its minimal big-endian bytes"
            );
        });
    }

    #[test]
    fn unset_and_default_valued_fields_are_omitted() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());
            let trace = &projection["transaction_traces"][0];
            let call = only_call(&projection);

            assert!(
                trace.get("index").is_none(),
                "a zero transaction index is the proto3 default"
            );
            assert!(
                call.get("suicide").is_none(),
                "a false bool is the proto3 default"
            );
            assert!(
                call.get("parent_index").is_none(),
                "the root call has no parent"
            );
            assert!(
                call.get("code_changes").is_none(),
                "an empty repeated field is omitted"
            );
        });
    }

    #[test]
    fn the_none_policy_erases_nothing() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none());
            let call = only_call(&projection);

            assert_eq!(call["gas_limit"], Value::from(21000));
            assert_eq!(call["gas_consumed"], Value::from(21000));
            assert_eq!(call["begin_ordinal"], Value::from(2));
            assert_eq!(projection["number"], Value::from(100));
            assert!(projection["header"].get("timestamp").is_some());
            assert!(projection["header"].get("state_root").is_some());
        });
    }

    #[test]
    fn the_live_node_policy_drops_gas_ordinals_and_identity() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::live_node());
            let call = only_call(&projection);
            let trace = &projection["transaction_traces"][0];

            for field in ["gas_limit", "gas_consumed", "begin_ordinal", "end_ordinal"] {
                assert!(
                    call.get(field).is_none(),
                    "live_node must drop Call.{field}"
                );
            }
            for field in [
                "gas_limit",
                "gas_used",
                "gas_price",
                "hash",
                "nonce",
                "v",
                "r",
                "s",
            ] {
                assert!(
                    trace.get(field).is_none(),
                    "live_node must drop TransactionTrace.{field}"
                );
            }
            for field in ["hash", "number", "size"] {
                assert!(
                    projection.get(field).is_none(),
                    "live_node must drop Block.{field}"
                );
            }
            for field in ["timestamp", "state_root", "parent_hash", "logs_bloom"] {
                assert!(
                    projection["header"].get(field).is_none(),
                    "live_node must drop BlockHeader.{field}"
                );
            }

            assert_eq!(
                projection["ver"],
                Value::from(5),
                "the block version is not volatile"
            );
            assert_eq!(
                trace["status"],
                Value::from("SUCCEEDED"),
                "status is tracer-owned"
            );
        });
    }

    #[test]
    fn the_live_node_policy_deltaizes_balance_and_nonce_changes() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::live_node());
            let call = only_call(&projection);

            let transfer = &call["balance_changes"][0];
            assert_eq!(
                transfer["delta"],
                Value::from("-0x64"),
                "1000 -> 900 is a debit of 100"
            );
            assert!(
                transfer.get("old_value").is_none(),
                "the absolute balance is not reproducible"
            );
            assert!(transfer.get("new_value").is_none());
            assert_eq!(
                transfer["address"],
                Value::from("@alice"),
                "identity survives deltaization"
            );

            let nonce = &call["nonce_changes"][0];
            assert_eq!(nonce["delta"], Value::from("+1"));
            assert!(nonce.get("old_value").is_none());
        });
    }

    #[test]
    fn gas_derived_balance_amounts_are_dropped_rather_than_deltaized() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::live_node());
            let gas_buy = &only_call(&projection)["balance_changes"][1];

            assert_eq!(gas_buy["reason"], Value::from("REASON_GAS_BUY"));
            assert_eq!(gas_buy["address"], Value::from("@alice"));
            assert!(
                gas_buy.get("delta").is_none(),
                "the delta of a gas buy is the gas cost, which moves with the base fee"
            );
            assert!(gas_buy.get("old_value").is_none());
        });
    }

    #[test]
    fn storage_changes_keep_their_values_under_every_policy() {
        with_block(|block| {
            for policy in [VolatilePolicy::none(), VolatilePolicy::live_node()] {
                let projection = project(block, policy);
                let change = &only_call(&projection)["storage_changes"][0];

                assert_eq!(
                    change["old_value"],
                    Value::from(
                        "0x0000000000000000000000000000000000000000000000000000000000000064"
                    ),
                    "storage values are exactly what the tracer is under test for"
                );
                assert_eq!(
                    change["new_value"],
                    Value::from(
                        "0x00000000000000000000000000000000000000000000000000000000000000c8"
                    )
                );
            }
        });
    }

    #[test]
    fn a_bare_selector_matches_the_field_in_every_message() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none().drop_field("ordinal"));
            let call = only_call(&projection);

            assert!(call["logs"][0].get("ordinal").is_none());
            assert!(call["storage_changes"][0].get("ordinal").is_none());
            assert!(call["balance_changes"][0].get("ordinal").is_none());
            assert!(
                call.get("begin_ordinal").is_some(),
                "`ordinal` must not match the differently named `begin_ordinal`"
            );
        });
    }

    #[test]
    fn a_qualified_selector_matches_only_that_message() {
        with_block(|block| {
            let projection = project(block, VolatilePolicy::none().drop_field("Call.gas_limit"));

            assert!(only_call(&projection).get("gas_limit").is_none());
            assert!(
                projection["transaction_traces"][0]
                    .get("gas_limit")
                    .is_some(),
                "a qualified selector must not reach TransactionTrace.gas_limit"
            );
        });
    }

    #[test]
    fn an_explicit_keep_overrides_a_broader_drop() {
        with_block(|block| {
            let projection = project(
                block,
                VolatilePolicy::live_node().keep_field("Call.gas_limit"),
            );

            assert_eq!(only_call(&projection)["gas_limit"], Value::from(21000));
            assert!(
                projection["transaction_traces"][0]
                    .get("gas_limit")
                    .is_none(),
                "the broader drop still applies everywhere else"
            );
        });
    }

    #[test]
    fn a_transaction_can_be_projected_on_its_own() {
        with_block(|block| {
            let hash = block.transaction_traces[0].hash.clone();

            let projection = BlockProjection::new()
                .with_symbols(symbols())
                .transaction(block, &hash)
                .expect("projecting the transaction must succeed");

            assert_eq!(projection["from"], Value::from("@alice"));
            assert_eq!(projection["status"], Value::from("SUCCEEDED"));
            assert!(
                projection.get("transaction_traces").is_none(),
                "the block envelope is not included"
            );
        });
    }

    #[test]
    fn projecting_an_absent_transaction_reports_what_the_block_holds() {
        with_block(|block| {
            let error = BlockProjection::new()
                .transaction(block, &[0xde, 0xad])
                .expect_err("an unknown hash must fail");

            let message = error.to_string();
            assert!(
                message.contains("0xdead"),
                "the error names the hash asked for: {message}"
            );
            assert!(
                message.contains(&hex::encode(&block.transaction_traces[0].hash)),
                "the error lists the hashes the block does hold: {message}"
            );
        });
    }
}
