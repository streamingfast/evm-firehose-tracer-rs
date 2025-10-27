use clap::Parser;
use reth::{builder::NodeHandle, chainspec::EthereumChainSpecParser, cli::Cli};
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::info;
use std::path::PathBuf;

mod exex;
mod prelude;

use firehose;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

#[derive(Debug, Clone, Default, clap::Args)]
#[non_exhaustive]
pub struct ExtensionArgs {
    /// Path to the JSON Firehose Tracer configuration file
    #[clap(long, value_name = "PATH")]
    pub firehose_tracer_config: Option<PathBuf>,
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) = Cli::<EthereumChainSpecParser, ExtensionArgs>::parse().run(
        async move |builder, extension_args| {
            info!(target: "firehose:tracer", args = ?extension_args, "Launching node");

            let config =
                firehose::Config::load_or_default(extension_args.firehose_tracer_config.as_ref())?;

            let NodeHandle {
                node: _node,
                node_exit_future,
            } = builder
                .node(EthereumNode::default())
                .install_exex("firehose", async move |ctx| {
                    let tracer = firehose::Tracer::new(config);
                    Ok(exex::firehose_tracer(ctx, tracer))
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
