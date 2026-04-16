mod prelude;
use prelude::*;

use alloy_primitives::Bytes;
use base_execution_cli::{chainspec::OpChainSpecParser, Cli};
use base_node_core::args::RollupArgs;
use base_node_runner::{BaseNodeExtension, BaseNodeRunner, FromExtensionConfig, NodeHooks};
use clap::Parser;
use reth_firehose;
use reth_firehose::exex::mapper::u64_to_trimmed_bytes;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// CLI extension args: rollup args (required by BaseNodeRunner) plus the Firehose config path.
#[derive(Debug, Clone, Default, clap::Args)]
#[non_exhaustive]
pub struct ExtensionArgs {
    /// Rollup-specific arguments forwarded to the Base node.
    #[clap(flatten)]
    pub rollup_args: RollupArgs,

    /// Path to the JSON Firehose Tracer configuration file.
    #[clap(long, value_name = "PATH")]
    pub firehose_tracer_config: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// FirehoseExtension — installs the Firehose ExEx on the Base node
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FirehoseExtension {
    config: firehose::Config,
}

impl BaseNodeExtension for FirehoseExtension {
    fn apply(self: Box<Self>, hooks: NodeHooks) -> NodeHooks {
        let config = self.config;
        hooks.install_exex("firehose", async move |ctx| {
            let tracer = firehose::Tracer::new(config);
            Ok(reth_firehose::exex::run_loop(ctx, tracer, |tx| {
                // OpTxEnvelope::signature() returns None for deposit transactions.
                let Some(sig) = tx.signature() else {
                    return (B256::ZERO, B256::ZERO, Bytes::new());
                };

                let y_parity = sig.v() as u64;
                let v = if let Some(legacy) = tx.as_legacy() {
                    // Legacy without EIP-155: V = 27 or 28
                    // Legacy with EIP-155:   V = chain_id * 2 + 35 + y_parity
                    if let Some(chain_id) = legacy.tx().chain_id {
                        chain_id * 2 + 35 + y_parity
                    } else {
                        27 + y_parity
                    }
                } else {
                    // Typed transactions (EIP-2930, EIP-1559, EIP-7702): V = 0 or 1
                    y_parity
                };

                (
                    B256::new(sig.r().to_be_bytes::<32>()),
                    B256::new(sig.s().to_be_bytes::<32>()),
                    u64_to_trimmed_bytes(v),
                )
            }))
        })
    }
}

impl FromExtensionConfig for FirehoseExtension {
    type Config = firehose::Config;

    fn from_config(config: firehose::Config) -> Self {
        Self { config }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) =
        Cli::<OpChainSpecParser, ExtensionArgs>::parse().run(|builder, args| async move {
            info!(target: "firehose:tracer", args = ?args, "Launching Base node");

            let mut config =
                firehose::Config::load_or_default(args.firehose_tracer_config.as_ref())?;
            config.chain_client = firehose::ChainClient::Reth;

            let mut runner = BaseNodeRunner::new(args.rollup_args.clone());
            runner.install_ext::<FirehoseExtension>(config);
            runner.run(builder).await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
