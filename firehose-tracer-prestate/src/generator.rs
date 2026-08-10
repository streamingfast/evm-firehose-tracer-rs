//! Builds a replayable `prestate.json` for a single mined transaction.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use alloy_consensus::Transaction as _;
use alloy_eips::eip2718::Encodable2718;
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256};
use eyre::{eyre, Context};
use serde_json::{json, Value};

use crate::{ArchiveClient, ArchiveSource, PrestateAccount, PrestateChain, RpcBlockHeader};

/// A generated fixture, ready to be written next to a test case.
#[derive(Debug, Clone)]
pub struct GeneratedPrestate {
    /// The fixture itself: `{ genesis, context, input }`.
    pub json: Value,
    /// Hash of the transaction the fixture replays.
    pub transaction_hash: B256,
    /// Height of the block the transaction was mined in.
    pub block_number: u64,
    /// Index of the transaction within that block.
    pub transaction_index: u64,
}

impl GeneratedPrestate {
    /// The file name a generated fixture is written under.
    pub const FILE_NAME: &'static str = "prestate.json";

    /// Writes [`Self::FILE_NAME`] into `case_folder`, creating the folder when needed.
    pub fn write_to(&self, case_folder: &Path) -> eyre::Result<PathBuf> {
        std::fs::create_dir_all(case_folder)
            .with_context(|| format!("creating {}", case_folder.display()))?;

        let path = case_folder.join(Self::FILE_NAME);
        let mut rendered = serde_json::to_string_pretty(&self.json)?;
        rendered.push('\n');
        std::fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;

        Ok(path)
    }
}

/// Turns a mined transaction hash into a self-contained prestate fixture.
///
/// This is the chain-agnostic Rust port of `streamingfast/go-ethereum`'s
/// `eth/tracers/internal/tracetest/firehose/generate-prestate`, with two differences the Go
/// generator does not need: the fork schedule comes from the chain itself
/// ([`PrestateChain::genesis_config`]) rather than a hand-copied table, and state a node reads
/// outside the EVM journal is seeded explicitly ([`PrestateChain::seeded_accounts`]).
#[derive(Debug)]
pub struct PrestateGenerator<C, A = ArchiveClient> {
    archive: A,
    chain: C,
}

impl<C: PrestateChain> PrestateGenerator<C, ArchiveClient> {
    /// Creates a generator reading from `archive` for `chain`.
    pub const fn new(archive: ArchiveClient, chain: C) -> Self {
        Self { archive, chain }
    }
}

impl<C: PrestateChain, A: ArchiveSource> PrestateGenerator<C, A> {
    /// Creates a generator over any [`ArchiveSource`], which is how a test drives it offline.
    pub const fn with_source(archive: A, chain: C) -> Self {
        Self { archive, chain }
    }

    /// Builds the fixture for `transaction_hash`.
    pub async fn generate(&self, transaction_hash: B256) -> eyre::Result<GeneratedPrestate> {
        let transaction = self
            .archive
            .transaction::<C::Transaction>(transaction_hash)
            .await?;
        let block_hash = transaction
            .block_hash
            .ok_or_else(|| eyre!("{transaction_hash} has no block hash"))?;
        let transaction_index = transaction
            .transaction_index
            .ok_or_else(|| eyre!("{transaction_hash} has no transaction index"))?
            .to::<u64>();

        let block = self.archive.block(block_hash).await?;
        let parent = self.archive.block(block.parent_hash).await?;
        let block_number = block.number.to::<u64>();

        let envelope = &transaction.envelope;
        let chain_id = envelope.chain_id();
        if chain_id.is_some_and(|id| id != self.chain.chain_id()) {
            return Err(eyre!(
                "{transaction_hash} carries chain id {:?} but the selected network is {}",
                chain_id,
                self.chain.chain_id()
            ));
        }

        let mut alloc = Self::into_alloc(self.archive.prestate(transaction_hash).await?);
        self.seed_accounts(&mut alloc, block_number).await?;

        let genesis = self.build_genesis(&parent, alloc)?;
        let json = json!({
            "genesis": serde_json::to_value(&genesis)?,
            "context": Self::build_context(&block),
            "input": format!("0x{}", alloy_primitives::hex::encode(envelope.encoded_2718())),
        });

        Ok(GeneratedPrestate {
            json,
            transaction_hash,
            block_number,
            transaction_index,
        })
    }

    /// The synthetic genesis: the parent header, the real fork schedule, and the traced alloc.
    fn build_genesis(
        &self,
        parent: &RpcBlockHeader,
        alloc: BTreeMap<Address, GenesisAccount>,
    ) -> eyre::Result<Genesis> {
        Ok(Genesis {
            config: self.chain.genesis_config()?,
            nonce: parent.nonce.map_or(0, |nonce| u64::from_be_bytes(nonce.0)),
            timestamp: parent.timestamp.to::<u64>(),
            extra_data: parent.extra_data.clone().unwrap_or_default(),
            gas_limit: parent.gas_limit.to::<u64>(),
            difficulty: parent.difficulty,
            mix_hash: parent.mix_hash.unwrap_or_default(),
            coinbase: parent.miner,
            alloc,
            base_fee_per_gas: parent.base_fee_per_gas.map(|fee| fee.to::<u128>()),
            excess_blob_gas: parent.excess_blob_gas.map(|gas| gas.to::<u64>()),
            blob_gas_used: parent.blob_gas_used.map(|gas| gas.to::<u64>()),
            number: Some(parent.number.to::<u64>()),
            // Deliberately omitted, as in the Go generator: the replay derives the parent hash
            // from the synthetic genesis itself, so carrying the real one would only be misleading.
            parent_hash: None,
        })
    }

    /// The block context the replay builds its synthetic header from.
    ///
    /// Emitted as decimal strings to match the Go generator and the existing fixtures; the
    /// deserialiser on the reading side accepts decimal and hex alike.
    fn build_context(block: &RpcBlockHeader) -> Value {
        let mut context = json!({
            "number": block.number.to_string(),
            "difficulty": block.difficulty.to_string(),
            "timestamp": block.timestamp.to_string(),
            "gasLimit": block.gas_limit.to_string(),
            "miner": block.miner.to_string(),
        });

        if let Some(base_fee) = block.base_fee_per_gas {
            context["baseFeePerGas"] = Value::String(base_fee.to_string());
        }

        context
    }

    /// Converts the tracer's account map into a genesis alloc.
    fn into_alloc(
        prestate: BTreeMap<Address, PrestateAccount>,
    ) -> BTreeMap<Address, GenesisAccount> {
        prestate
            .into_iter()
            .map(|(address, account)| {
                let genesis_account = GenesisAccount {
                    nonce: account.nonce,
                    balance: account.balance.unwrap_or_default(),
                    code: account.code,
                    storage: account.storage,
                    private_key: None,
                };

                (address, genesis_account)
            })
            .collect()
    }

    /// Adds the state the chain reads outside the EVM journal, which `prestateTracer` never reports.
    ///
    /// Read at `block_number` rather than at its parent on purpose: for the OP Stack's `L1Block`
    /// predeploy — the case this exists for — the slots are written by the L1-info deposit at index
    /// 0 of that very block, and those post-deposit values are what every other transaction in the
    /// block pays its L1 fee from. Anything the tracer already reported wins, so a slot the traced
    /// transaction genuinely touched keeps its traced value.
    async fn seed_accounts(
        &self,
        alloc: &mut BTreeMap<Address, GenesisAccount>,
        block_number: u64,
    ) -> eyre::Result<()> {
        for seeded in self.chain.seeded_accounts() {
            let address = seeded.address;
            let account = alloc.entry(address).or_default();

            if account.code.is_none() {
                let code = self.archive.code_at(address, block_number).await?;
                if !code.is_empty() {
                    account.code = Some(code);
                }
            }

            if account.nonce.is_none() {
                let nonce = self.archive.nonce_at(address, block_number).await?;
                account.nonce = (nonce != 0).then_some(nonce);
            }

            if account.balance.is_zero() {
                account.balance = self.archive.balance_at(address, block_number).await?;
            }

            let storage = account.storage.get_or_insert_with(BTreeMap::new);
            for slot in &seeded.slots {
                let key = B256::from(*slot);
                if storage.contains_key(&key) {
                    continue;
                }

                let value = self
                    .archive
                    .storage_at(address, *slot, block_number)
                    .await?;
                storage.insert(key, value);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use alloy_consensus::TxEnvelope;
    use alloy_genesis::ChainConfig;
    use alloy_primitives::{address, b256, bytes, Address, Bytes, B256, U256, U64};
    use serde_json::json;

    use super::{GeneratedPrestate, PrestateGenerator};
    use crate::{
        ArchiveSource, PrestateAccount, PrestateChain, RpcBlockHeader, RpcTransaction,
        SeededAccount,
    };

    const L1_BLOCK: Address = address!("0x4200000000000000000000000000000000000015");
    const TX: B256 = b256!("0x32ecdb4e72df6ec331edb81256b58a768ba49d1e3e89a1a071b980a85d6b72c0");
    const BLOCK: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const PARENT: B256 =
        b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
    const SENDER: Address = address!("0xabbac9becc5b171842ae47703dfa6640b23c9710");

    /// A chain that seeds one predeploy, standing in for the OP Stack's `L1Block`.
    struct TestChain {
        seeded: Vec<SeededAccount>,
    }

    impl TestChain {
        fn with_seeding() -> Self {
            Self {
                seeded: vec![SeededAccount::new(L1_BLOCK, [1, 3])],
            }
        }

        fn without_seeding() -> Self {
            Self { seeded: Vec::new() }
        }
    }

    impl PrestateChain for TestChain {
        type Transaction = TxEnvelope;

        fn chain_id(&self) -> u64 {
            1
        }

        fn genesis_config(&self) -> eyre::Result<ChainConfig> {
            Ok(ChainConfig {
                chain_id: 1,
                ..Default::default()
            })
        }

        fn seeded_accounts(&self) -> &[SeededAccount] {
            &self.seeded
        }
    }

    /// Replays recorded archive responses, so the whole `generate` path runs with no network.
    #[derive(Default)]
    struct RecordedArchive {
        prestate: BTreeMap<Address, PrestateAccount>,
        storage: BTreeMap<(Address, U256), B256>,
        code: BTreeMap<Address, Bytes>,
        balance: BTreeMap<Address, U256>,
        nonce: BTreeMap<Address, u64>,
        reads: RefCell<Vec<String>>,
    }

    impl RecordedArchive {
        fn header(hash: B256, parent_hash: B256, number: u64) -> RpcBlockHeader {
            RpcBlockHeader {
                hash,
                parent_hash,
                number: U64::from(number),
                timestamp: U64::from(1_700_000_000 + number),
                gas_limit: U64::from(60_000_000u64),
                gas_used: U64::from(21_000u64),
                miner: address!("0x4200000000000000000000000000000000000011"),
                difficulty: U256::ZERO,
                mix_hash: Some(B256::repeat_byte(0xaa)),
                nonce: None,
                extra_data: Some(bytes!("0xc0ffee")),
                base_fee_per_gas: Some(U256::from(5_000_000u64)),
                excess_blob_gas: None,
                blob_gas_used: None,
            }
        }
    }

    impl ArchiveSource for RecordedArchive {
        async fn transaction<E: serde::de::DeserializeOwned>(
            &self,
            _hash: B256,
        ) -> eyre::Result<RpcTransaction<E>> {
            let json = json!({
                "blockHash": BLOCK,
                "blockNumber": "0x2",
                "transactionIndex": "0x9f",
                "hash": TX,
                "type": "0x2",
                "chainId": "0x1",
                "nonce": "0x1",
                "gas": "0x5208",
                "maxFeePerGas": "0x4c4b40",
                "maxPriorityFeePerGas": "0x0",
                "to": "0x0000000000000000000000000000000000000001",
                "value": "0x1",
                "accessList": [],
                "input": "0x",
                "from": SENDER,
                "r": "0x8b7e0d9b1a0d0f2d3e4c5b6a798877665544332211ffeeddccbbaa998877665",
                "s": "0x4c3b2a1908f7e6d5c4b3a29180716253443526170819a0b1c2d3e4f5a6b7c8d",
                "yParity": "0x1",
            });

            Ok(serde_json::from_value(json)?)
        }

        async fn block(&self, hash: B256) -> eyre::Result<RpcBlockHeader> {
            match hash {
                BLOCK => Ok(Self::header(BLOCK, PARENT, 2)),
                PARENT => Ok(Self::header(PARENT, B256::ZERO, 1)),
                other => Err(eyre::eyre!("unexpected block {other}")),
            }
        }

        async fn prestate(&self, _hash: B256) -> eyre::Result<BTreeMap<Address, PrestateAccount>> {
            Ok(self.prestate.clone())
        }

        async fn storage_at(&self, address: Address, slot: U256, block: u64) -> eyre::Result<B256> {
            self.reads
                .borrow_mut()
                .push(format!("storage {address} {slot} @{block}"));

            Ok(self
                .storage
                .get(&(address, slot))
                .copied()
                .unwrap_or_default())
        }

        async fn code_at(&self, address: Address, block: u64) -> eyre::Result<Bytes> {
            self.reads
                .borrow_mut()
                .push(format!("code {address} @{block}"));

            Ok(self.code.get(&address).cloned().unwrap_or_default())
        }

        async fn balance_at(&self, address: Address, block: u64) -> eyre::Result<U256> {
            self.reads
                .borrow_mut()
                .push(format!("balance {address} @{block}"));

            Ok(self.balance.get(&address).copied().unwrap_or_default())
        }

        async fn nonce_at(&self, address: Address, block: u64) -> eyre::Result<u64> {
            self.reads
                .borrow_mut()
                .push(format!("nonce {address} @{block}"));

            Ok(self.nonce.get(&address).copied().unwrap_or_default())
        }
    }

    fn seeded_archive() -> RecordedArchive {
        RecordedArchive {
            prestate: BTreeMap::from([(
                SENDER,
                PrestateAccount {
                    balance: Some(U256::from(1_000u64)),
                    nonce: Some(1),
                    code: None,
                    storage: None,
                },
            )]),
            storage: BTreeMap::from([
                ((L1_BLOCK, U256::from(1)), B256::repeat_byte(0x11)),
                ((L1_BLOCK, U256::from(3)), B256::repeat_byte(0x33)),
            ]),
            code: BTreeMap::from([(L1_BLOCK, bytes!("0x6080"))]),
            balance: BTreeMap::from([(L1_BLOCK, U256::from(7u64))]),
            nonce: BTreeMap::from([(L1_BLOCK, 1)]),
            reads: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_fixture_carries_the_parent_header_the_traced_context_and_the_encoded_transaction() {
        let generator =
            PrestateGenerator::with_source(seeded_archive(), TestChain::without_seeding());
        let prestate = generator
            .generate(TX)
            .await
            .expect("generating must succeed");

        assert_eq!(prestate.block_number, 2);
        assert_eq!(prestate.transaction_index, 159);

        // The context is the *traced* block.
        assert_eq!(prestate.json["context"]["number"], json!("2"));
        assert_eq!(prestate.json["context"]["baseFeePerGas"], json!("5000000"));
        assert_eq!(prestate.json["context"]["gasLimit"], json!("60000000"));

        // The genesis is the *parent* block, and deliberately carries no parent hash.
        assert_eq!(prestate.json["genesis"]["number"], json!("0x1"));
        assert_eq!(prestate.json["genesis"]["timestamp"], json!("0x6553f101"));
        assert_eq!(prestate.json["genesis"]["extraData"], json!("0xc0ffee"));
        assert!(prestate.json["genesis"].get("parentHash").is_none());

        // The alloc is the traced prestate.
        let alloc = &prestate.json["genesis"]["alloc"];
        assert_eq!(
            alloc[SENDER.to_string().to_lowercase()]["balance"],
            json!("0x3e8")
        );

        // The input is EIP-2718 encoded, so it starts with the envelope's type byte.
        let input = prestate.json["input"]
            .as_str()
            .expect("input must be a string");
        assert!(input.starts_with("0x02"), "{input}");
    }

    /// The reason [`SeededAccount`] exists: the tracer never reports these, and a zero L1 fee is a
    /// silently wrong replay rather than an error.
    #[tokio::test]
    async fn seeded_accounts_are_read_at_the_traced_block_and_never_override_the_trace() {
        let mut archive = seeded_archive();
        // The traced transaction genuinely touched slot 1, so its value must survive.
        archive.prestate.insert(
            L1_BLOCK,
            PrestateAccount {
                balance: None,
                nonce: None,
                code: None,
                storage: Some(BTreeMap::from([(
                    B256::from(U256::from(1)),
                    B256::repeat_byte(0x99),
                )])),
            },
        );

        let generator = PrestateGenerator::with_source(archive, TestChain::with_seeding());
        let prestate = generator
            .generate(TX)
            .await
            .expect("generating must succeed");

        let storage =
            &prestate.json["genesis"]["alloc"][L1_BLOCK.to_string().to_lowercase()]["storage"];
        assert_eq!(
            storage[B256::from(U256::from(1)).to_string()],
            json!(B256::repeat_byte(0x99).to_string()),
            "a slot the trace reported wins over the seeded read"
        );
        assert_eq!(
            storage[B256::from(U256::from(3)).to_string()],
            json!(B256::repeat_byte(0x33).to_string()),
            "a slot the trace did not report is seeded"
        );

        let reads = generator.archive.reads.borrow().clone();
        assert!(
            reads.iter().all(|read| read.ends_with("@2")),
            "seeded state is read at the traced block, not its parent: {reads:?}"
        );
        assert!(
            !reads
                .iter()
                .any(|read| read.contains(&format!("storage {L1_BLOCK} 1 "))),
            "a slot the trace reported is never re-read: {reads:?}"
        );
    }

    #[tokio::test]
    async fn a_chain_that_seeds_nothing_reads_nothing_extra() {
        let generator =
            PrestateGenerator::with_source(seeded_archive(), TestChain::without_seeding());
        generator
            .generate(TX)
            .await
            .expect("generating must succeed");

        assert!(generator.archive.reads.borrow().is_empty());
    }

    /// A hash generated against the wrong network is caught before it becomes a misleading fixture.
    #[tokio::test]
    async fn a_transaction_from_another_chain_is_rejected() {
        struct OtherChain(TestChain);

        impl PrestateChain for OtherChain {
            type Transaction = TxEnvelope;

            fn chain_id(&self) -> u64 {
                8453
            }

            fn genesis_config(&self) -> eyre::Result<ChainConfig> {
                self.0.genesis_config()
            }
        }

        let generator = PrestateGenerator::with_source(
            seeded_archive(),
            OtherChain(TestChain::without_seeding()),
        );
        let error = generator
            .generate(TX)
            .await
            .expect_err("a foreign chain id must be rejected");

        assert!(error.to_string().contains("carries chain id"), "{error}");
    }

    #[tokio::test]
    async fn writing_a_fixture_creates_the_case_folder() {
        let generator =
            PrestateGenerator::with_source(seeded_archive(), TestChain::without_seeding());
        let prestate = generator
            .generate(TX)
            .await
            .expect("generating must succeed");

        let root = tempfile::tempdir().expect("a temp dir");
        let folder = root.path().join("cases").join("a_case");
        let path = prestate.write_to(&folder).expect("writing must succeed");

        assert_eq!(path, folder.join(GeneratedPrestate::FILE_NAME));

        let written = std::fs::read_to_string(&path).expect("reading back must succeed");
        assert!(written.ends_with('\n'), "the fixture ends with a newline");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&written).expect("valid json"),
            prestate.json
        );
    }
}
