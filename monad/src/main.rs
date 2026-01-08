//! Monad Firehose Tracer Binary
//!
//! This is the main binary for the Monad Firehose tracer that integrates
//! Monad execution events with the Firehose streaming protocol.

use clap::Parser;
use color_eyre::eyre::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use monad_plugin::{initialize_plugin, PluginConfig};
use monad_tracer::{FirehoseTracer, OutputFormat, TracerConfig};

/// Command line arguments for the Monad Firehose tracer
#[derive(Parser, Debug)]
#[command(name = "monad-firehose-tracer")]
#[command(about = "Ethereum Firehose tracer for Monad blockchain")]
#[command(version = "0.1.0")]
struct Args {
    /// Chain ID for the blockchain
    #[arg(long, default_value = "1")]
    chain_id: u64,

    /// Network name
    #[arg(long, default_value = "monad")]
    network_name: String,

    /// Path to Monad event ring buffer
    #[arg(
        long,
        env = "MONAD_EVENT_RING_PATH",
        default_value = "/tmp/monad_events"
    )]
    monad_event_ring_path: String,

    /// Buffer size for event processing
    #[arg(long, default_value = "1024")]
    buffer_size: usize,

    /// Timeout for event consumption in milliseconds
    #[arg(long, default_value = "1000")]
    timeout_ms: u64,

    /// Enable debug mode
    #[arg(long, env = "DEBUG")]
    debug: bool,

    /// Output format (firehose, json, binary)
    #[arg(long, default_value = "firehose")]
    output_format: String,

    /// Enable no-op mode
    #[arg(long)]
    no_op: bool,

    // TEMPORARY FLAGS FOR PERFORMANCE PROFILING - REMOVE AFTER OPTIMIZATION
    /// Skip event mapping (JSON parse, hex decode, data structures)
    #[arg(long)]
    skip_event_mapping: bool,

    /// Skip block finalization (bloom filter, gas calculations)
    #[arg(long)]
    skip_finalization: bool,

    /// Skip protobuf serialization
    #[arg(long)]
    skip_serialization: bool,

    /// Skip base64 encoding and stdout output
    #[arg(long)]
    skip_output: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install color-eyre for better error reporting
    color_eyre::install()?;

    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let level = if args.debug {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Monad Firehose tracer");
    info!("Chain ID: {}", args.chain_id);
    info!("Network: {}", args.network_name);
    info!("Event ring path: {}", args.monad_event_ring_path);
    info!("Debug mode: {}", args.debug);

    // Parse output format
    let output_format = match args.output_format.as_str() {
        "firehose" => OutputFormat::Firehose,
        "json" => OutputFormat::Json,
        "binary" => OutputFormat::Binary,
        _ => {
            eprintln!(
                "Invalid output format: {}. Valid options: firehose, json, binary",
                args.output_format
            );
            std::process::exit(1);
        }
    };

    // Create plugin configuration
    let plugin_config = PluginConfig {
        event_ring_path: args.monad_event_ring_path,
        buffer_size: args.buffer_size,
        timeout_ms: args.timeout_ms,
    };

    // Initialize the plugin
    let consumer = initialize_plugin(plugin_config).await?;

    // Create tracer configuration
    let tracer_config = TracerConfig::new(args.chain_id, args.network_name)
        .with_debug(args.debug)
        .with_buffer_size(args.buffer_size)
        .with_output_format(output_format)
        .with_no_op(args.no_op)
        .with_skip_event_mapping(args.skip_event_mapping)
        .with_skip_finalization(args.skip_finalization)
        .with_skip_serialization(args.skip_serialization)
        .with_skip_output(args.skip_output);

    // Create and start the tracer
    let mut tracer = FirehoseTracer::new(tracer_config).with_consumer(consumer);

    if args.no_op {
        info!("NO-OP MODE ENABLED: Only logging block numbers, no processing");
    }
    if args.skip_event_mapping {
        info!("PROFILING: Skipping event mapping");
    }
    if args.skip_finalization {
        info!("PROFILING: Skipping block finalization");
    }
    if args.skip_serialization {
        info!("PROFILING: Skipping protobuf serialization");
    }
    if args.skip_output {
        info!("PROFILING: Skipping base64 encoding and stdout");
    }

    info!("Starting Firehose tracer...");
    tracer.start().await?;

    Ok(())
}
