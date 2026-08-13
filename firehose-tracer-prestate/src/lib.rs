//! Generate replayable Firehose prestate fixtures from real, mined transactions.
//!
//! This is the chain-agnostic Rust port of `streamingfast/go-ethereum`'s
//! [`generate-prestate`](https://github.com/streamingfast/go-ethereum/blob/release/geth-v1.17.x-fh3.0/eth/tracers/internal/tracetest/firehose/generate-prestate/main.go).
//! Point it at a transaction hash and an archive node and it writes a `prestate.json` that a
//! chain's own prestate runner replays through the Firehose tracer with no node, no Docker and no
//! network.
//!
//! # The two commands
//!
//! * `generate` turns a mined transaction hash into a self-contained fixture, read from an archive
//!   RPC. See [`PrestateGenerator`].
//! * `reference` seeds a case's *initial* golden with the same transaction as StreamingFast's
//!   production Firehose recorded it, so the first run of the case's test is a direct comparison
//!   against production. See [`ProductionReference`]. This is a one-time validation per case; after
//!   it passes the golden is an ordinary `GOLDEN_UPDATE=1` golden and no test needs credentials.
//!
//! # What a chain has to supply
//!
//! Everything except four things is chain-agnostic, and those four are the [`PrestateChain`] trait:
//!
//! 1. **The transaction envelope type**, for decoding the archive node's response and re-encoding
//!    it EIP-2718. The RPC envelope around it (`blockHash`, `transactionIndex`, …) is standard, so
//!    only [`PrestateChain::Transaction`] is yours: this crate wraps it in [`RpcTransaction`].
//! 2. **The genesis `config`** ([`PrestateChain::genesis_config`]).
//! 3. **Extra state to seed** beyond what `prestateTracer` reports
//!    ([`PrestateChain::seeded_accounts`]).
//! 4. **The chain id** ([`PrestateChain::chain_id`]), which rejects a hash generated against the
//!    wrong network before it becomes a misleading fixture.
//!
//! The production Firehose endpoint is deliberately *not* one of them: it is a property of a
//! network rather than of a chain, so `reference` takes it as `--firehose-endpoint` (or the
//! `FIREHOSE_ENDPOINT` environment variable).
//!
//! Points 2 and 3 are where the subtlety lives, and both fail *silently* when they are wrong. Read
//! the two sections below before implementing them.
//!
//! ## Why the genesis config is not just the chain spec's genesis config
//!
//! A chain spec's own `genesis.config` frequently carries only the *block-numbered* forks. On the
//! OP Stack every *timestamped* upgrade (canyon, ecotone, fjord, granite, holocene, isthmus,
//! jovian, plus a fork's own extras and its EIP-1559 parameters) reaches the spec through a
//! separate configuration table instead. Serialising the genesis config alone therefore drops them
//! all, and the fixture replays a post-Isthmus transaction under pre-Canyon rules — with no error,
//! just a quietly wrong result.
//!
//! Implementations must re-project whatever their spec keeps outside the genesis config back into
//! it (`alloy_genesis::ChainConfig::extra_fields` is the hatch for the non-standard ones), and
//! should carry a round-trip test asserting the emitted config rebuilds into *exactly* the chain
//! spec's hardforks:
//!
//! ```ignore
//! let mut genesis = expected.genesis.clone();
//! genesis.config = network.genesis_config()?;
//!
//! assert_eq!(
//!     MyChainSpec::from_genesis(genesis).hardforks.forks_iter().collect::<Vec<_>>(),
//!     expected.hardforks.forks_iter().collect::<Vec<_>>(),
//! );
//! ```
//!
//! Without it a dropped fork timestamp is invisible until a replay disagrees with production for
//! reasons that look like a tracer bug.
//!
//! ## Why extra state has to be seeded explicitly
//!
//! `debug_traceTransaction` with the `prestateTracer` reports the state the *EVM journal* saw. Any
//! state the node reads outside the journal is therefore missing from the fixture, and the replay
//! silently substitutes zero.
//!
//! The OP Stack is the worked example: the L1-cost function reads the `L1Block` predeploy
//! (`0x4200000000000000000000000000000000000015`) storage straight from the state database. A
//! fixture without those slots replays with a zero L1 fee, and every fee balance change in the
//! transaction comes out wrong. An OP-Stack [`PrestateChain`] therefore returns:
//!
//! ```ignore
//! fn seeded_accounts(&self) -> &[SeededAccount] {
//!     // Slots 1 (l1 base fee), 3 (Ecotone fee scalars), 5 (overhead), 6 (Bedrock scalar),
//!     // 7 (blob base fee) and 8 (Isthmus operator fee / Jovian DA footprint) — the union of
//!     // what `L1BlockInfo::try_fetch` reads across Bedrock, Ecotone, Isthmus and Jovian.
//!     &self.l1_block
//! }
//! ```
//!
//! Two details of how [`PrestateGenerator`] reads them matter:
//!
//! * They are read **at the traced block**, not at its parent. Those slots are written by the
//!   L1-info deposit at index 0 of that very block, and the post-deposit values are what every
//!   other transaction in the block pays its L1 fee from.
//! * **Anything the tracer already reported wins**, so a slot the traced transaction genuinely
//!   touched keeps its traced value.
//!
//! Chains with no such out-of-journal reads implement nothing here; the default is an empty list.
//!
//! # Wiring up a binary
//!
//! With the `cli` feature (on by default) a chain's tool is a thin wrapper around
//! [`PrestateCommand`]:
//!
//! ```ignore
//! #[derive(clap::Parser)]
//! struct Args {
//!     /// Which network the transaction belongs to; `global` so it can follow the subcommand.
//!     #[arg(long, value_enum, default_value = "my-chain", global = true)]
//!     network: MyNetwork,
//!
//!     #[command(subcommand)]
//!     command: PrestateCommand,
//! }
//!
//! #[tokio::main]
//! async fn main() -> eyre::Result<()> {
//!     let args = Args::parse();
//!     args.command.run(&args.network).await
//! }
//! ```

mod chain;
pub use chain::{PrestateChain, SeededAccount};

mod rpc;
pub use rpc::{ArchiveClient, ArchiveSource, PrestateAccount, RpcBlockHeader, RpcTransaction};

mod generator;
pub use generator::{GeneratedPrestate, PrestateGenerator};

mod firehose;
pub use firehose::{FirehoseAuth, FirehoseFetcher};

mod reference;
pub use reference::ProductionReference;

#[cfg(feature = "cli")]
mod cli;
#[cfg(feature = "cli")]
pub use cli::{GenerateArgs, PrestateCommand, ReferenceArgs};

/// Re-exported so a consumer's test crate can project a replay through the very same policy the
/// `reference` command projected production through.
pub use firehose_tracer_test::ProductionReplay;
