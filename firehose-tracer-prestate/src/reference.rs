//! Seeds a case's golden from production Firehose.
//!
//! This runs once per case, when the case is created: the golden it writes is the transaction as
//! production Firehose recorded it, so the very first run of the test proves the generator and the
//! tracer agree with production. From then on the golden is an ordinary
//! [`Golden`](firehose_tracer_test::Golden) regenerated with `GOLDEN_UPDATE=1` like any other, and
//! no test needs credentials or a production endpoint.

use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use eyre::{eyre, Context};
use firehose_tracer_test::ProductionReplay;
use serde_json::Value;

use crate::{FirehoseFetcher, GeneratedPrestate};

/// The projected transaction production Firehose emitted, ready to be written as a case's golden.
///
/// It goes through the very same [`ProductionReplay`] projection the test applies to its replayed
/// block, so a diff on the first run is a real difference in what the tracer recorded and never a
/// rendering artefact.
#[derive(Debug, Clone)]
pub struct ProductionReference {
    /// The projected transaction trace.
    pub json: Value,
    /// Height of the block the transaction was mined in.
    pub block_number: u64,
    /// Hash of the projected transaction.
    pub transaction_hash: B256,
}

impl ProductionReference {
    /// The golden file name for a case at `block_number`, matching the existing cases' convention.
    pub fn golden_name(block_number: u64) -> String {
        format!("block.{block_number}.json")
    }

    /// Fetches `block_number` from production and projects `transaction_hash` out of it.
    pub async fn fetch(
        fetcher: &FirehoseFetcher,
        block_number: u64,
        transaction_hash: B256,
    ) -> eyre::Result<Self> {
        let block = fetcher.block(block_number).await?;
        let json = ProductionReplay::projection()
            .transaction(&block, transaction_hash.as_slice())
            .map_err(|error| eyre!("projecting {transaction_hash} out of production: {error}"))?;

        Ok(Self {
            json,
            block_number,
            transaction_hash,
        })
    }

    /// Reads the block height out of a fixture written by the generator.
    pub fn block_number_of(case_folder: &Path) -> eyre::Result<u64> {
        let path = case_folder.join(GeneratedPrestate::FILE_NAME);
        let prestate: Value = serde_json::from_slice(
            &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;

        prestate["context"]["number"]
            .as_str()
            .ok_or_else(|| eyre!("{} has no context.number", path.display()))?
            .parse()
            .with_context(|| format!("parsing context.number in {}", path.display()))
    }

    /// Writes the golden into `case_folder`, creating the folder when needed.
    pub fn write_to(&self, case_folder: &Path) -> eyre::Result<PathBuf> {
        std::fs::create_dir_all(case_folder)
            .with_context(|| format!("creating {}", case_folder.display()))?;

        let path = case_folder.join(Self::golden_name(self.block_number));
        let mut rendered = serde_json::to_string_pretty(&self.json)?;
        rendered.push('\n');
        std::fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use serde_json::json;

    use super::ProductionReference;
    use crate::GeneratedPrestate;

    fn case_folder_with(context: serde_json::Value) -> tempfile::TempDir {
        let folder = tempfile::tempdir().expect("a temp dir");
        std::fs::write(
            folder.path().join(GeneratedPrestate::FILE_NAME),
            serde_json::to_string(&json!({ "context": context })).expect("valid json"),
        )
        .expect("writing the fixture");

        folder
    }

    /// `reference` defaults its block height to whatever `generate` recorded, so the two commands
    /// cannot drift apart for a case.
    #[test]
    fn the_block_number_comes_out_of_the_generated_fixture() {
        let folder = case_folder_with(json!({ "number": "49663794" }));

        assert_eq!(
            ProductionReference::block_number_of(folder.path()).expect("reading the height"),
            49_663_794
        );
    }

    #[test]
    fn a_fixture_without_a_context_number_is_an_error_rather_than_a_default() {
        let folder = case_folder_with(json!({}));
        let error = ProductionReference::block_number_of(folder.path())
            .expect_err("a missing height must be an error");

        assert!(
            error.to_string().contains("has no context.number"),
            "{error}"
        );
    }

    #[test]
    fn the_golden_name_matches_the_cases_convention() {
        assert_eq!(
            ProductionReference::golden_name(49_663_794),
            "block.49663794.json"
        );
    }

    #[test]
    fn writing_a_reference_creates_the_case_folder() {
        let root = tempfile::tempdir().expect("a temp dir");
        let folder = root.path().join("cases").join("a_case");

        let reference = ProductionReference {
            json: json!({ "hash": "0xdead" }),
            block_number: 42,
            transaction_hash: B256::repeat_byte(0xde),
        };
        let path = reference.write_to(&folder).expect("writing must succeed");

        assert_eq!(path, folder.join("block.42.json"));
        assert!(
            std::fs::read_to_string(&path)
                .expect("reading back")
                .ends_with('\n'),
            "the golden ends with a newline"
        );
    }
}
