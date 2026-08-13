//! The seam between the generic generator and a specific chain.

use alloy_consensus::Transaction as TransactionTrait;
use alloy_eips::eip2718::Encodable2718;
use alloy_genesis::ChainConfig;
use alloy_primitives::{Address, U256};
use serde::de::DeserializeOwned;

/// An account whose state has to be seeded into a fixture beyond what `prestateTracer` reports.
///
/// The tracer only reports what the EVM journal saw. State a node reads outside the journal — the
/// OP Stack's `L1Block` predeploy being the canonical case — is therefore absent from the trace,
/// and a replay built from the trace alone reads zero for it.
///
/// [`PrestateGenerator`](crate::PrestateGenerator) reads these at the *traced* block (not its
/// parent) and lets anything the tracer already reported win.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededAccount {
    /// The account to seed. Its balance, nonce and code are read whenever the trace left them
    /// unset, even when [`Self::slots`] is empty.
    pub address: Address,
    /// The storage slots to read for it.
    pub slots: Vec<U256>,
}

impl SeededAccount {
    /// A seeded account with the given slots.
    pub fn new(address: Address, slots: impl IntoIterator<Item = u64>) -> Self {
        Self {
            address,
            slots: slots.into_iter().map(U256::from).collect(),
        }
    }
}

/// Everything a prestate fixture needs that the generator cannot know on its own.
///
/// See the [crate docs](crate) for why [`Self::genesis_config`] and [`Self::seeded_accounts`] are
/// the two that fail silently when they are wrong.
pub trait PrestateChain {
    /// The EIP-2718 transaction envelope the archive node's `eth_getTransactionByHash` response
    /// decodes into, and which the fixture's `input` is re-encoded from.
    ///
    /// The chain-agnostic RPC fields around it are supplied by
    /// [`RpcTransaction`](crate::RpcTransaction), so this is the envelope alone —
    /// `alloy_consensus::TxEnvelope` for a plain EVM chain, `OpTxEnvelope` and its descendants for
    /// the OP Stack.
    /// The extra bounds beyond the two traits that carry meaning are alloy's `RpcRecv`, which the
    /// JSON-RPC client requires of anything it decodes; every envelope type satisfies them.
    type Transaction: DeserializeOwned
        + TransactionTrait
        + Encodable2718
        + std::fmt::Debug
        + Send
        + Sync
        + Unpin
        + 'static;

    /// The chain id transactions are expected to carry.
    ///
    /// A transaction whose envelope declares a different one is rejected, which catches a hash
    /// generated against the wrong network before it becomes a misleading fixture.
    fn chain_id(&self) -> u64;

    /// The genesis `config` a generated fixture embeds.
    ///
    /// This must describe **every** fork the node actually executes with, not just the ones the
    /// chain spec happens to keep in its own genesis config. See the [crate docs](crate).
    fn genesis_config(&self) -> eyre::Result<ChainConfig>;

    /// State to seed on top of what `prestateTracer` reported. Empty by default.
    fn seeded_accounts(&self) -> &[SeededAccount] {
        &[]
    }
}

impl<C: PrestateChain> PrestateChain for &C {
    type Transaction = C::Transaction;

    fn chain_id(&self) -> u64 {
        (*self).chain_id()
    }

    fn genesis_config(&self) -> eyre::Result<ChainConfig> {
        (*self).genesis_config()
    }

    fn seeded_accounts(&self) -> &[SeededAccount] {
        (*self).seeded_accounts()
    }
}
