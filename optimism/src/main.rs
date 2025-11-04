use shared::*;
use reth_optimism_cli::{chainspec::OpChainSpecParser, Cli};
use reth_optimism_node::{args::RollupArgs, OpNode};
use firehose;
use clap::Parser;

mod exex;
mod prelude;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// Combined arguments for OP-Reth with Firehose tracer
#[derive(Debug, Clone, Default, clap::Args)]
#[non_exhaustive]
pub struct OpFirehoseArgs {
    /// Rollup-specific arguments
    #[command(flatten)]
    pub rollup: RollupArgs,

    /// Path to the JSON Firehose Tracer configuration file
    #[clap(long, value_name = "PATH")]
    pub firehose_tracer_config: Option<PathBuf>,

    /// Flashblocks WebSocket URL for consuming real-time pre-confirmation blocks
    /// Example: wss://mainnet.flashblocks.base.org/ws
    #[clap(long, value_name = "URL")]
    pub flashblocks_ws_url: Option<String>,
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) = Cli::<OpChainSpecParser, OpFirehoseArgs>::parse().run(
        async move |builder, args| {
            info!(target: "firehose:tracer", args = ?args, "Launching OP-Reth node with Firehose tracer");

            let config = firehose::Config::load_or_default(args.firehose_tracer_config.as_ref())?;
            let flashblocks_url = args.flashblocks_ws_url.clone();

            let NodeHandle {
                node: _node,
                node_exit_future,
            } = builder
                .node(OpNode::new(args.rollup))
                .install_exex("firehose", async move |ctx| {
                    let tracer = firehose::Tracer::new(config);
                    Ok(exex::firehose_tracer(ctx, tracer, flashblocks_url))
                })
                .launch_with_debug_capabilities()
                .await?;

            node_exit_future.await
        },
    ) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
