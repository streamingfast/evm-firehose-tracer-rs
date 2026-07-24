//! Buffer-backed capture of a running tracer's output.
//!
//! [`FirehoseCapture`] reads back the `FIRE BLOCK` lines a tracer wrote to an [`InMemoryBuffer`]
//! instead of stdout, so a test that drives a real node can assert on the decoded protobuf blocks
//! that node produced.
//!
//! Installing the process-wide tracer is deliberately *not* this type's job. The `GLOBAL_TRACER`
//! singleton and the gate the execution path checks live in each chain's reth binding, which this
//! crate must not depend on. A chain installs its tracer however it already does and hands the
//! resulting buffer over:
//!
//! ```ignore
//! let capture = FirehoseCapture::new(reth_firehose::init_tracer_with_buffer(
//!     chain_id, shanghai_time, cancun_time, prague_time,
//! ));
//! ```
//!
//! That tracer is process-wide and installable only once, so a test binary using this type must
//! contain a single test — cargo and nextest both give each integration-test binary its own
//! process.

use std::time::{Duration, Instant};

use firehose_tracer::{pb::sf::ethereum::r#type::v2::Block, InMemoryBuffer};

use crate::tracer_tester::try_parse_firehose_block_entries;

/// Reader over the output a tracer wrote to an in-memory buffer.
pub struct FirehoseCapture {
    buffer: InMemoryBuffer,
}

impl std::fmt::Debug for FirehoseCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseCapture")
            .field("traced_blocks", &self.traced_block_numbers())
            .finish_non_exhaustive()
    }
}

impl FirehoseCapture {
    /// Interval between polls in [`Self::wait_for_block`].
    const POLL_INTERVAL: Duration = Duration::from_millis(250);

    /// Wraps the buffer a tracer is writing to.
    pub fn new(buffer: InMemoryBuffer) -> Self {
        Self { buffer }
    }

    /// Returns the raw bytes captured so far — every `FIRE` line the tracer has emitted.
    pub fn raw(&self) -> Vec<u8> {
        self.buffer.get_bytes()
    }

    /// Returns the captured output as lossy UTF-8, for inclusion in failure messages.
    pub fn raw_text(&self) -> String {
        String::from_utf8_lossy(&self.raw()).into_owned()
    }

    /// Returns the block numbers of every `FIRE BLOCK` line captured so far, in emission order.
    ///
    /// This only scans line prefixes, so it stays cheap enough to poll and tolerates the partially
    /// written trailing line a still-running node can leave behind.
    pub fn traced_block_numbers(&self) -> Vec<u64> {
        let raw = self.raw();
        let Ok(text) = std::str::from_utf8(&raw) else {
            return Vec::new();
        };

        text.lines()
            .filter_map(Self::block_number_of_line)
            .collect()
    }

    /// Decodes every captured block, in emission order.
    pub fn blocks(&self) -> eyre::Result<Vec<Block>> {
        Ok(try_parse_firehose_block_entries(&self.raw())?
            .into_iter()
            .map(|entry| entry.block)
            .collect())
    }

    /// Decodes the captured block with the given number.
    pub fn block(&self, number: u64) -> eyre::Result<Block> {
        let entries = try_parse_firehose_block_entries(&self.raw())?;
        let traced: Vec<u64> = entries.iter().map(|entry| entry.block_num).collect();

        entries
            .into_iter()
            .find(|entry| entry.block_num == number)
            .map(|entry| entry.block)
            .ok_or_else(|| {
                eyre::eyre!("no captured FIRE BLOCK for block #{number}; captured {traced:?}")
            })
    }

    /// Polls until block `number` has been traced, then decodes and returns it.
    ///
    /// A follower node validates blocks slightly behind the sequencer that produced them, so a test
    /// that sends a transaction through the sequencer's RPC must wait for the traced node to catch
    /// up before the block is available.
    pub async fn wait_for_block(&self, number: u64, timeout: Duration) -> eyre::Result<Block> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.traced_block_numbers().contains(&number) {
                return self.block(number);
            }

            if Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "timed out after {timeout:?} waiting for block #{number} to be traced; traced \
                     blocks so far: {:?}",
                    self.traced_block_numbers()
                ));
            }

            tokio::time::sleep(Self::POLL_INTERVAL).await;
        }
    }

    /// Extracts the block number from a `FIRE BLOCK <num> …` line, if the line is one.
    fn block_number_of_line(line: &str) -> Option<u64> {
        let mut parts = line.split(' ');
        if parts.next()? != "FIRE" || parts.next()? != "BLOCK" {
            return None;
        }

        parts.next()?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    //! A real consumer hands over the buffer its chain's `init_tracer_with_buffer` returned. These
    //! tests write the `FIRE` lines into the buffer directly instead, because what is under test is
    //! the read-back: which block numbers were seen, what decodes, and how a half-written line —
    //! routine when polling a node that is still running — is reported.

    use std::io::Write as _;
    use std::time::Duration;

    use base64_simd::STANDARD as BASE64;
    use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
    use firehose_tracer::InMemoryBuffer;
    use prost::Message as _;

    use super::*;

    /// Builds a block carrying enough to tell one from another.
    fn block(number: u64) -> pbeth::Block {
        pbeth::Block {
            number,
            ver: 5,
            hash: vec![number as u8; 32],
            transaction_traces: vec![pbeth::TransactionTrace {
                hash: vec![0xaa; 32],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Renders the `FIRE BLOCK` line a tracer emits for `block`.
    fn fire_line(block: &pbeth::Block) -> String {
        format!(
            "FIRE BLOCK {} 0 {} {} {} {} 1704067200000000000 {}\n",
            block.number,
            hex::encode(&block.hash),
            block.number.saturating_sub(1),
            hex::encode([0u8; 32]),
            block.number.saturating_sub(1),
            BASE64.encode_to_string(block.encode_to_vec()),
        )
    }

    /// A buffer holding an init line followed by one `FIRE BLOCK` line per number.
    fn buffer_with(numbers: impl IntoIterator<Item = u64>) -> InMemoryBuffer {
        let mut buffer = InMemoryBuffer::new();
        writeln!(buffer, "FIRE INIT 3.0 sf.ethereum.type.v2.Block 1 0").expect("write init");

        for number in numbers {
            write!(buffer, "{}", fire_line(&block(number))).expect("write block");
        }

        buffer
    }

    #[test]
    fn traced_block_numbers_are_listed_in_emission_order() {
        let capture = FirehoseCapture::new(buffer_with([100, 101, 102]));

        assert_eq!(capture.traced_block_numbers(), vec![100, 101, 102]);
    }

    #[test]
    fn a_traced_block_can_be_decoded_by_number() {
        let capture = FirehoseCapture::new(buffer_with([100, 101, 102]));

        let decoded = capture.block(101).expect("block #101 was traced");

        assert_eq!(decoded.number, 101);
        assert_eq!(decoded.transaction_traces.len(), 1);
    }

    #[test]
    fn every_traced_block_can_be_decoded_at_once() {
        let capture = FirehoseCapture::new(buffer_with([100, 101]));

        let blocks = capture.blocks().expect("decoding must succeed");

        assert_eq!(
            blocks.iter().map(|block| block.number).collect::<Vec<_>>(),
            vec![100, 101]
        );
    }

    #[test]
    fn asking_for_an_untraced_block_lists_the_ones_captured() {
        let capture = FirehoseCapture::new(buffer_with([100, 101]));

        let error = capture.block(999).expect_err("block #999 was never traced");
        let message = error.to_string();

        assert!(
            message.contains("no captured FIRE BLOCK for block #999"),
            "{message}"
        );
        assert!(
            message.contains("[100, 101]"),
            "the error lists what was captured: {message}"
        );
    }

    #[test]
    fn an_empty_buffer_yields_no_blocks() {
        let capture = FirehoseCapture::new(InMemoryBuffer::new());

        assert!(capture.traced_block_numbers().is_empty());
        assert!(capture
            .blocks()
            .expect("an empty buffer is not an error")
            .is_empty());
        assert!(capture.raw_text().is_empty());
    }

    #[test]
    fn non_block_lines_are_ignored() {
        let mut buffer = InMemoryBuffer::new();
        writeln!(buffer, "FIRE INIT 3.0 sf.ethereum.type.v2.Block 1 0").expect("write");
        writeln!(buffer, "some unrelated node log line").expect("write");
        write!(buffer, "{}", fire_line(&block(7))).expect("write");

        let capture = FirehoseCapture::new(buffer);

        assert_eq!(capture.traced_block_numbers(), vec![7]);
        assert_eq!(capture.blocks().expect("decode").len(), 1);
    }

    #[test]
    fn a_truncated_block_line_is_reported_rather_than_panicking() {
        let mut buffer = InMemoryBuffer::new();
        write!(buffer, "{}", fire_line(&block(100))).expect("write");
        writeln!(buffer, "FIRE BLOCK 101 0 abcd").expect("write");

        let capture = FirehoseCapture::new(buffer);

        // The cheap prefix scan still sees it, which is what makes polling safe...
        assert_eq!(capture.traced_block_numbers(), vec![100, 101]);

        // ...while decoding reports the problem instead of aborting the test binary.
        let error = capture
            .blocks()
            .expect_err("a truncated line must be an error");
        assert!(
            error.to_string().contains("should have 10 parts"),
            "{error}"
        );
    }

    #[test]
    fn a_header_disagreeing_with_its_payload_is_reported() {
        let mut buffer = InMemoryBuffer::new();
        let line = fire_line(&block(100)).replacen("FIRE BLOCK 100", "FIRE BLOCK 555", 1);
        write!(buffer, "{line}").expect("write");

        let capture = FirehoseCapture::new(buffer);

        let error = capture
            .blocks()
            .expect_err("a lying header must be an error");
        assert!(
            error
                .to_string()
                .contains("header says #555 but the protobuf says #100"),
            "{error}"
        );
    }

    #[test]
    fn raw_text_exposes_the_captured_output_for_failure_messages() {
        let capture = FirehoseCapture::new(buffer_with([100]));

        assert!(capture.raw_text().starts_with("FIRE INIT "));
        assert_eq!(capture.raw().len(), capture.raw_text().len());
    }

    #[tokio::test]
    async fn waiting_for_an_already_traced_block_returns_immediately() {
        let capture = FirehoseCapture::new(buffer_with([100]));

        let decoded = capture
            .wait_for_block(100, Duration::from_millis(10))
            .await
            .expect("block #100 is already there");

        assert_eq!(decoded.number, 100);
    }

    #[tokio::test]
    async fn a_block_arriving_late_is_waited_for() {
        let buffer = buffer_with([100]);
        let mut writer = buffer.clone();
        let capture = FirehoseCapture::new(buffer);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            write!(writer, "{}", fire_line(&block(101))).expect("write");
        });

        let decoded = capture
            .wait_for_block(101, Duration::from_secs(5))
            .await
            .expect("block #101 arrives while waiting");

        assert_eq!(decoded.number, 101);
    }

    #[tokio::test]
    async fn waiting_for_a_block_that_never_arrives_times_out() {
        let capture = FirehoseCapture::new(buffer_with([100]));

        let error = capture
            .wait_for_block(500, Duration::from_millis(50))
            .await
            .expect_err("block #500 is never traced");
        let message = error.to_string();

        assert!(message.contains("timed out"), "{message}");
        assert!(message.contains("traced blocks so far: [100]"), "{message}");
    }
}
