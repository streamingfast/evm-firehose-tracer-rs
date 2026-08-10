//! Minimal JSON-RPC client over the archive node a fixture is generated from.
//!
//! Only the handful of calls the generator needs are modelled, with response types narrow enough
//! that a field the generator does not use can never make a fetch fail.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, B256, B64, U256, U64};
use alloy_rpc_client::RpcClient;
use alloy_transport_http::{Client, Http};
use eyre::{eyre, Context};
use serde::{de::Error as _, Deserialize, Deserializer};

/// A mined transaction as `eth_getTransactionByHash` returns it.
///
/// Only the fields that place the transaction inside its block are modelled here: everything else
/// is the chain's own envelope, flattened in, so a chain contributes
/// [`PrestateChain::Transaction`](crate::PrestateChain::Transaction) and nothing more. This is the
/// same shape `alloy_rpc_types_eth::Transaction<T>` has, minus the parts the generator never reads.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction<E> {
    /// Hash of the block the transaction was mined in, absent while it is pending.
    #[serde(default)]
    pub block_hash: Option<B256>,
    /// Height of that block.
    #[serde(default)]
    pub block_number: Option<U64>,
    /// Index of the transaction within that block.
    #[serde(default)]
    pub transaction_index: Option<U64>,
    /// The chain's own EIP-2718 envelope.
    #[serde(flatten)]
    pub envelope: E,
}

/// The block header fields the generator reads off the archive node.
///
/// `eth_getBlockByHash` returns far more than this; everything not listed is ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockHeader {
    /// Hash of this block.
    pub hash: B256,
    /// Hash of the parent block.
    pub parent_hash: B256,
    /// Block height.
    pub number: U64,
    /// Unix timestamp in seconds.
    pub timestamp: U64,
    /// Block gas limit.
    pub gas_limit: U64,
    /// Gas consumed by the block.
    pub gas_used: U64,
    /// Block beneficiary.
    pub miner: Address,
    /// Post-Merge blocks report zero.
    pub difficulty: U256,
    /// `PREVRANDAO` post-Merge.
    #[serde(default)]
    pub mix_hash: Option<B256>,
    /// Always zero post-Merge.
    #[serde(default)]
    pub nonce: Option<B64>,
    /// Free-form header payload.
    #[serde(default)]
    pub extra_data: Option<Bytes>,
    /// EIP-1559 base fee, absent pre-London.
    #[serde(default)]
    pub base_fee_per_gas: Option<U256>,
    /// EIP-4844 excess blob gas, absent pre-Cancun.
    #[serde(default)]
    pub excess_blob_gas: Option<U64>,
    /// EIP-4844 blob gas used, absent pre-Cancun.
    #[serde(default)]
    pub blob_gas_used: Option<U64>,
}

/// One account as reported by `debug_traceTransaction` with the `prestateTracer`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrestateAccount {
    /// Balance at the start of the traced transaction.
    #[serde(default)]
    pub balance: Option<U256>,
    /// Nonce at the start of the traced transaction.
    ///
    /// Reported as a JSON number by current op-geth and as a hex string by older builds, so both
    /// are accepted.
    #[serde(default, deserialize_with = "PrestateAccount::deserialize_nonce")]
    pub nonce: Option<u64>,
    /// Deployed bytecode, absent for externally-owned accounts.
    #[serde(default)]
    pub code: Option<Bytes>,
    /// The storage slots the traced transaction touched.
    #[serde(default)]
    pub storage: Option<BTreeMap<B256, B256>>,
}

impl PrestateAccount {
    /// Accepts a nonce given as a JSON number, a `0x`-prefixed hex string or a decimal string.
    pub fn deserialize_nonce<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
            return Ok(None);
        };

        match value {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::Number(number) => number
                .as_u64()
                .map(Some)
                .ok_or_else(|| D::Error::custom("nonce is not a u64")),
            serde_json::Value::String(text) => {
                let parsed = text.strip_prefix("0x").map_or_else(
                    || {
                        text.parse::<u64>()
                            .map_err(|e| D::Error::custom(e.to_string()))
                    },
                    |hex| u64::from_str_radix(hex, 16).map_err(|e| D::Error::custom(e.to_string())),
                )?;

                Ok(Some(parsed))
            }
            other => Err(D::Error::custom(format!(
                "unsupported nonce encoding {other}"
            ))),
        }
    }
}

/// The reads [`PrestateGenerator`](crate::PrestateGenerator) performs against an archive node.
///
/// [`ArchiveClient`] is the real implementation; the trait exists so the generator can be driven
/// from recorded responses in a test, with no network.
#[allow(
    async_fn_in_trait,
    reason = "consumed generically, never as a trait object"
)]
pub trait ArchiveSource {
    /// Fetches a mined transaction, failing when it is unknown or still pending.
    ///
    /// The bounds on `E` are alloy's `RpcRecv`, spelled out so this crate does not have to depend
    /// on `alloy-json-rpc` for a bound alias. Every transaction envelope satisfies them.
    async fn transaction<E>(&self, hash: B256) -> eyre::Result<RpcTransaction<E>>
    where
        E: serde::de::DeserializeOwned + std::fmt::Debug + Send + Sync + Unpin + 'static;

    /// Fetches a block header by hash, with transaction hashes only.
    async fn block(&self, hash: B256) -> eyre::Result<RpcBlockHeader>;

    /// Runs `debug_traceTransaction` with the `prestateTracer`.
    async fn prestate(&self, hash: B256) -> eyre::Result<BTreeMap<Address, PrestateAccount>>;

    /// Reads one storage slot as of the end of `block`.
    async fn storage_at(&self, address: Address, slot: U256, block: u64) -> eyre::Result<B256>;

    /// Reads an account's code as of the end of `block`.
    async fn code_at(&self, address: Address, block: u64) -> eyre::Result<Bytes>;

    /// Reads an account's balance as of the end of `block`.
    async fn balance_at(&self, address: Address, block: u64) -> eyre::Result<U256>;

    /// Reads an account's nonce as of the end of `block`.
    async fn nonce_at(&self, address: Address, block: u64) -> eyre::Result<u64>;
}

/// A read-only JSON-RPC client against an archive node with the `debug_` namespace enabled.
#[derive(Debug)]
pub struct ArchiveClient {
    client: RpcClient,
}

impl ArchiveClient {
    /// Connects to `url`.
    pub fn new(url: &str) -> eyre::Result<Self> {
        let url = url
            .parse()
            .with_context(|| format!("parsing archive endpoint {url}"))?;

        Ok(Self {
            client: RpcClient::new(Http::<Client>::new(url), false),
        })
    }

    /// Formats a block height the way the JSON-RPC block parameter expects it.
    fn block_tag(block: u64) -> String {
        format!("0x{block:x}")
    }
}

impl ArchiveSource for ArchiveClient {
    async fn transaction<E>(&self, hash: B256) -> eyre::Result<RpcTransaction<E>>
    where
        E: serde::de::DeserializeOwned + std::fmt::Debug + Send + Sync + Unpin + 'static,
    {
        let transaction: Option<RpcTransaction<E>> = self
            .client
            .request("eth_getTransactionByHash", (hash,))
            .await
            .with_context(|| format!("eth_getTransactionByHash for {hash}"))?;

        let transaction = transaction.ok_or_else(|| eyre!("archive node does not know {hash}"))?;
        if transaction.block_hash.is_none() {
            return Err(eyre!(
                "{hash} is still pending; a prestate needs a mined transaction"
            ));
        }

        Ok(transaction)
    }

    async fn block(&self, hash: B256) -> eyre::Result<RpcBlockHeader> {
        let header: Option<RpcBlockHeader> = self
            .client
            .request("eth_getBlockByHash", (hash, false))
            .await
            .with_context(|| format!("eth_getBlockByHash for {hash}"))?;

        header.ok_or_else(|| eyre!("archive node does not know block {hash}"))
    }

    async fn prestate(&self, hash: B256) -> eyre::Result<BTreeMap<Address, PrestateAccount>> {
        let options = serde_json::json!({ "tracer": "prestateTracer" });

        self.client
            .request("debug_traceTransaction", (hash, options))
            .await
            .with_context(|| {
                format!(
                    "debug_traceTransaction with the prestateTracer for {hash}; the endpoint must \
                 expose the debug_ namespace over an archive state"
                )
            })
    }

    async fn storage_at(&self, address: Address, slot: U256, block: u64) -> eyre::Result<B256> {
        self.client
            .request("eth_getStorageAt", (address, slot, Self::block_tag(block)))
            .await
            .with_context(|| format!("eth_getStorageAt {address} slot {slot} at block {block}"))
    }

    async fn code_at(&self, address: Address, block: u64) -> eyre::Result<Bytes> {
        self.client
            .request("eth_getCode", (address, Self::block_tag(block)))
            .await
            .with_context(|| format!("eth_getCode {address} at block {block}"))
    }

    async fn balance_at(&self, address: Address, block: u64) -> eyre::Result<U256> {
        self.client
            .request("eth_getBalance", (address, Self::block_tag(block)))
            .await
            .with_context(|| format!("eth_getBalance {address} at block {block}"))
    }

    async fn nonce_at(&self, address: Address, block: u64) -> eyre::Result<u64> {
        let nonce: U64 = self
            .client
            .request("eth_getTransactionCount", (address, Self::block_tag(block)))
            .await
            .with_context(|| format!("eth_getTransactionCount {address} at block {block}"))?;

        Ok(nonce.to::<u64>())
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{Transaction as _, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::hex;

    use super::{PrestateAccount, RpcTransaction};

    /// A real `eth_getTransactionByHash` response, trimmed to the fields a node actually returns.
    ///
    /// Flattening the envelope into the RPC fields is the whole reason a chain only has to name its
    /// envelope type: if this stopped deserialising, every consumer would need a wrapper type.
    #[test]
    fn an_rpc_transaction_flattens_the_envelope() {
        let json = serde_json::json!({
            "blockHash": "0x1b4f1d1c1e2ab5b7dc4b6ea3e6bd9db65a0a4bd8b73e0eb4b2b0e5f7a1c3d9e0",
            "blockNumber": "0x10d4f",
            "transactionIndex": "0x9f",
            "hash": "0x32ecdb4e72df6ec331edb81256b58a768ba49d1e3e89a1a071b980a85d6b72c0",
            "type": "0x2",
            "chainId": "0x2105",
            "nonce": "0x6aa155",
            "gas": "0x1d4c0",
            "maxFeePerGas": "0x4c4b40",
            "maxPriorityFeePerGas": "0x0",
            "to": "0xec0e36a6060339694c618ffffcc9ec7da21cb0cc",
            "value": "0x0",
            "accessList": [],
            "input": "0xd67704ad000000000000000000000000000000000000000000000000000000036948f05a",
            "from": "0xabbac9becc5b171842ae47703dfa6640b23c9710",
            "r": "0x8b7e0d9b1a0d0f2d3e4c5b6a798877665544332211ffeeddccbbaa998877665",
            "s": "0x4c3b2a1908f7e6d5c4b3a29180716253443526170819a0b1c2d3e4f5a6b7c8d",
            "yParity": "0x1",
        });

        let transaction: RpcTransaction<TxEnvelope> =
            serde_json::from_value(json).expect("an RPC transaction must deserialise");

        assert_eq!(
            transaction.transaction_index.map(|index| index.to::<u64>()),
            Some(159)
        );
        assert_eq!(
            transaction.block_number.map(|number| number.to::<u64>()),
            Some(68943)
        );
        assert_eq!(transaction.envelope.chain_id(), Some(8453));
        assert_eq!(transaction.envelope.nonce(), 6_988_117);

        // The fixture's `input` is this, so a broken re-encoding is a broken fixture.
        let encoded = transaction.envelope.encoded_2718();
        assert_eq!(
            encoded.first(),
            Some(&2),
            "an EIP-1559 envelope re-encodes with its type byte"
        );
        assert!(hex::encode(&encoded).contains("d67704ad"));
    }

    /// A pending transaction has no `blockHash`, and the RPC fields are all optional.
    #[test]
    fn an_rpc_transaction_tolerates_missing_block_fields() {
        let json = serde_json::json!({
            "hash": "0x32ecdb4e72df6ec331edb81256b58a768ba49d1e3e89a1a071b980a85d6b72c0",
            "type": "0x0",
            "chainId": "0x1",
            "nonce": "0x1",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "to": "0x0000000000000000000000000000000000000001",
            "value": "0x1",
            "input": "0x",
            "r": "0x8b7e0d9b1a0d0f2d3e4c5b6a798877665544332211ffeeddccbbaa998877665",
            "s": "0x4c3b2a1908f7e6d5c4b3a29180716253443526170819a0b1c2d3e4f5a6b7c8d",
            "v": "0x26",
        });

        let transaction: RpcTransaction<TxEnvelope> =
            serde_json::from_value(json).expect("a pending RPC transaction must deserialise");

        assert!(transaction.block_hash.is_none());
        assert!(transaction.transaction_index.is_none());
        assert_eq!(transaction.envelope.chain_id(), Some(1));
    }

    /// op-geth reports the nonce as a number, older builds as a hex string; both are in the wild.
    #[test]
    fn a_prestate_nonce_accepts_every_encoding_seen_in_the_wild() {
        for (encoded, expected) in [
            (serde_json::json!({ "nonce": 42 }), Some(42)),
            (serde_json::json!({ "nonce": "0x2a" }), Some(42)),
            (serde_json::json!({ "nonce": "42" }), Some(42)),
            (
                serde_json::json!({ "nonce": serde_json::Value::Null }),
                None,
            ),
            (serde_json::json!({}), None),
        ] {
            let account: PrestateAccount = serde_json::from_value(encoded.clone())
                .unwrap_or_else(|error| panic!("{encoded} must deserialise: {error}"));

            assert_eq!(account.nonce, expected, "{encoded}");
        }
    }

    #[test]
    fn a_prestate_nonce_rejects_an_encoding_it_cannot_read() {
        let error = serde_json::from_value::<PrestateAccount>(serde_json::json!({ "nonce": [] }))
            .expect_err("an array nonce must be rejected");

        assert!(
            error.to_string().contains("unsupported nonce encoding"),
            "{error}"
        );
    }
}
