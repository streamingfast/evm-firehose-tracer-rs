use super::{Config, finality::FinalityStatus, mapper, ordinal::Ordinal, printer};
use crate::firehose::PROTOCOL_VERSION;
use crate::pb::sf::ethereum::r#type::v2::Block;
use crate::prelude::*;
use std::sync::Arc;

pub struct Tracer<Node: FullNodeComponents> {
    pub config: Config,
    chain_spec: Option<Arc<ChainSpec<Node>>>,
    current_block: Option<Block>,
    block_ordinal: Ordinal,
    finality_status: FinalityStatus,
    _phantom: std::marker::PhantomData<Node>,
}

impl<Node: FullNodeComponents> Tracer<Node> {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            chain_spec: None,
            current_block: None,
            block_ordinal: Ordinal::default(),
            finality_status: FinalityStatus::default(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// on_init initializes the tracer with chain configuration
    pub fn on_init(&mut self, spec: Arc<ChainSpec<Node>>) {
        self.chain_spec = Some(spec.clone());

        // Print Firehose init message to stdout
        printer::firehose_init_to_stdout(PROTOCOL_VERSION, "reth-firehose-tracer");

        info!(
            "Firehose tracer initialized: chain_id={}, protocol_version={}",
            spec.chain().id(),
            PROTOCOL_VERSION,
        );
    }

    /// on_block_start prepares for block processing a new block altogether
    pub fn on_block_start(&mut self, block: &RecoveredBlock<Node>) {
        let pb_block = mapper::recovered_block_to_protobuf::<Node>(block);

        self.current_block = Some(pb_block);
        self.block_ordinal.reset();
        self.finality_status.populate_from_chain(None);

        let block = self.current_block.as_ref().expect("current_block is set");

        debug!(
            "Processing block: number={}, hash={}",
            block.number,
            hex::encode(&block.hash),
        );
    }

    /// on_block_end finalizes block processing and outputs to stdout
    pub fn on_block_end(&mut self) {
        let current: Option<Block> = self.current_block.take();

        if let Some(block) = current {
            printer::firehose_block_to_stdout(block, self.finality_status);
        }

        // Reset state
        self.block_ordinal.reset();
        self.finality_status.reset();
    }
}
