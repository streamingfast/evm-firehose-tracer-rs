//! The generic `generate` / `reference` subcommands.
//!
//! Everything a chain's binary has to add is the network selection, because only it knows what its
//! networks are. See the [crate docs](crate) for the wrapper.

use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use clap::{Args, Subcommand};

use crate::{
    ArchiveClient, FirehoseAuth, FirehoseFetcher, PrestateChain, PrestateGenerator,
    ProductionReference,
};

/// Write `prestate.json` for a mined transaction, read from an archive node.
#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// Hash of the transaction to replay.
    #[arg(long, value_name = "HASH")]
    pub tx: B256,

    /// Archive node exposing `debug_traceTransaction` with the `prestateTracer`.
    #[arg(long, env = "ARCHIVE_ENDPOINT", value_name = "URL")]
    pub rpc_url: String,

    /// Test case folder to write into.
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

impl GenerateArgs {
    /// Generates the fixture and writes it, returning the path written.
    pub async fn run<C: PrestateChain>(&self, chain: C) -> eyre::Result<PathBuf> {
        let generator = PrestateGenerator::new(ArchiveClient::new(&self.rpc_url)?, chain);
        let prestate = generator.generate(self.tx).await?;
        let path = prestate.write_to(&self.out)?;

        println!(
            "wrote {} for {} (block {}, index {})",
            path.display(),
            prestate.transaction_hash,
            prestate.block_number,
            prestate.transaction_index
        );

        Ok(path)
    }
}

/// Seed a case's golden with the transaction as production Firehose recorded it.
///
/// Run once per case: the first test run then compares the replay directly against production.
/// Afterwards the golden is regenerated with `GOLDEN_UPDATE=1` like every other.
#[derive(Args, Debug, Clone)]
pub struct ReferenceArgs {
    /// Hash of the transaction to project.
    #[arg(long, value_name = "HASH")]
    pub tx: B256,

    /// Block height, defaulting to the one recorded in the folder's `prestate.json`.
    #[arg(long, value_name = "NUMBER")]
    pub block: Option<u64>,

    /// Firehose endpoint to read the block back from, e.g. `https://<chain>.streamingfast.io:443`.
    ///
    /// Required because the endpoint is a property of the network, not of the chain: a fork's
    /// mainnet has a published one and its testnets typically do not. A chain whose binary wants a
    /// per-network default should supply it through this flag's `FIREHOSE_ENDPOINT` environment
    /// variable or set it in its own wrapper before calling [`Self::run`].
    #[arg(long, env = "FIREHOSE_ENDPOINT", value_name = "URL")]
    pub firehose_endpoint: String,

    /// Test case folder to write into.
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

impl ReferenceArgs {
    /// Fetches the block from production and writes the case's golden, returning the path written.
    pub async fn run(&self) -> eyre::Result<PathBuf> {
        let block = match self.block {
            Some(block) => block,
            None => ProductionReference::block_number_of(&self.out)?,
        };

        let fetcher = FirehoseFetcher::connect(
            &self.firehose_endpoint,
            FirehoseAuth::token_from_env().await?,
        )
        .await?;
        let reference = ProductionReference::fetch(&fetcher, block, self.tx).await?;
        let path = reference.write_to(&self.out)?;

        println!(
            "seeded golden {} from production for {} (block {}); run the case's test now to \
             validate the replay against it",
            path.display(),
            reference.transaction_hash,
            reference.block_number
        );

        Ok(path)
    }
}

/// The two subcommands, ready to be embedded in a chain's own `clap` parser.
#[derive(Subcommand, Debug, Clone)]
pub enum PrestateCommand {
    /// Write `prestate.json` for a mined transaction, read from an archive node.
    Generate(GenerateArgs),

    /// Seed a case's golden with the transaction as production Firehose recorded it.
    Reference(ReferenceArgs),
}

impl PrestateCommand {
    /// Runs the selected subcommand against `chain`, returning the path it wrote.
    ///
    /// `chain` is only consulted by `generate`; `reference` reads a finished block back and needs
    /// nothing chain-specific beyond the endpoint it is given.
    pub async fn run<C: PrestateChain>(&self, chain: C) -> eyre::Result<PathBuf> {
        match self {
            Self::Generate(args) => args.run(chain).await,
            Self::Reference(args) => args.run().await,
        }
    }

    /// The case folder the selected subcommand writes into.
    pub fn out(&self) -> &Path {
        match self {
            Self::Generate(args) => &args.out,
            Self::Reference(args) => &args.out,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser};

    use super::PrestateCommand;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        command: PrestateCommand,
    }

    #[test]
    fn the_subcommands_parse_the_shape_the_go_generator_used() {
        let cli = TestCli::try_parse_from([
            "prestate",
            "generate",
            "--tx",
            "0x32ecdb4e72df6ec331edb81256b58a768ba49d1e3e89a1a071b980a85d6b72c0",
            "--rpc-url",
            "https://archive.example",
            "--out",
            "tests/cases/a_case",
        ])
        .expect("generate must parse");

        let PrestateCommand::Generate(args) = cli.command else {
            panic!("expected the generate subcommand");
        };
        assert_eq!(args.rpc_url, "https://archive.example");
        assert_eq!(args.out.to_str(), Some("tests/cases/a_case"));
    }

    /// The endpoint is no longer a property of the chain, so `reference` must carry it itself.
    #[test]
    fn reference_takes_the_firehose_endpoint_on_the_command_line() {
        let cli = TestCli::try_parse_from([
            "prestate",
            "reference",
            "--tx",
            "0x32ecdb4e72df6ec331edb81256b58a768ba49d1e3e89a1a071b980a85d6b72c0",
            "--firehose-endpoint",
            "https://base-mainnet.streamingfast.io:443",
            "--out",
            "tests/cases/a_case",
        ])
        .expect("reference must parse");

        let PrestateCommand::Reference(args) = cli.command else {
            panic!("expected the reference subcommand");
        };
        assert_eq!(
            args.firehose_endpoint,
            "https://base-mainnet.streamingfast.io:443"
        );
        assert_eq!(args.block, None, "the height defaults to the fixture's");
    }

    #[test]
    fn clap_wiring_is_valid() {
        TestCli::command().debug_assert();
    }
}
