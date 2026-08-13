//! The projection shared by a prestate replay and the production block its golden was seeded from.

use crate::{BlockProjection, VolatilePolicy};

/// Projection settings for a case whose golden was seeded from production Firehose.
///
/// A replay runs the transaction alone in a synthetic single-transaction block; production ran it
/// after every earlier transaction in the real block and after the block-level system calls. The
/// only fields that can legitimately differ are therefore *positional* — where the transaction sits
/// in the block and where each event sits in the block-wide ordinal sequence. Everything else, gas
/// accounting and absolute balances included, matches exactly: `prestateTracer` reports state as of
/// the start of the traced transaction, which is precisely the state the synthetic block starts
/// from.
///
/// That equality is what makes a production block usable as a case's initial golden, which
/// `firehose-tracer-prestate`'s `reference` command does once per case. Afterwards the golden is
/// regenerated from the replay with `GOLDEN_UPDATE=1` like any other; the same policy keeps
/// applying so the golden never picks up a positional field the replay could not reproduce.
#[derive(Debug)]
pub struct ProductionReplay;

impl ProductionReplay {
    /// Block-wide positional fields, and nothing else.
    pub fn policy() -> VolatilePolicy {
        let mut policy = VolatilePolicy::none();

        // Ordinals number every event across the whole block.
        for field in ["ordinal", "begin_ordinal", "end_ordinal"] {
            policy = policy.drop_field(field);
        }

        // Where the transaction sits in the block, and where its logs sit among the block's logs.
        policy = policy
            .drop_field("TransactionTrace.index")
            .drop_field("Log.block_index");

        // Gas consumed by the transactions that ran before this one.
        policy.drop_field("cumulative_gas_used")
    }

    /// A [`BlockProjection`] carrying [`Self::policy`].
    pub fn projection() -> BlockProjection {
        BlockProjection::new().with_policy(Self::policy())
    }
}
