//! Test support for the Firehose tracer.
//!
//! Two layers live here. The *inward* layer — [`TracerTester`], [`MockStateDB`] and the helpers
//! around them — drives the tracer directly and exists to unit-test its internals.
//!
//! The *outward* layer is a tracing-regression framework for the chains that embed the tracer
//! (Base, Optimism, Unichain, base-reth). It has three parts, meant to be used together:
//!
//! * [`FirehoseCapture`] reads the blocks a running node's tracer emitted into a buffer,
//! * [`BlockInvariants`] asserts content-independent properties on those blocks, so a violation is
//!   always a real tracing bug and never needs a golden regenerated,
//! * [`BlockProjection`] plus [`Golden`] diff a readable, descriptor-driven JSON projection against
//!   a checked-in file, with volatile fields removed by a [`VolatilePolicy`].
//!
//! Installing the process-wide tracer stays with each chain's reth binding; see
//! [`FirehoseCapture`] for how the two meet.

pub mod eip7702;
pub mod mock_state;
pub mod testing_helpers;
pub mod tracer_tester;

pub mod capture;
pub mod descriptor;
pub mod golden;
pub mod invariants;
pub mod projection;

// Re-export commonly used items for test convenience
pub use eip7702::{recover_set_code_auth_authority, sign_set_code_auth};
pub use mock_state::MockStateDB;
pub use testing_helpers::*;
pub use tracer_tester::{
    parse_firehose_block, parse_firehose_block_entries, test_access_list_trx, test_blob_trx,
    test_block, test_dynamic_fee_trx, test_legacy_trx, test_set_code_trx,
    try_parse_firehose_block_entries, FirehoseBlockEntry, InMemoryBuffer, TracerTester,
};

pub use capture::FirehoseCapture;
pub use descriptor::descriptor_pool;
pub use golden::{BlockDiff, Golden};
pub use invariants::{BlockInvariants, InvariantConfig, Violation};
pub use projection::{BlockProjection, SymbolTable, VolatilePolicy};
