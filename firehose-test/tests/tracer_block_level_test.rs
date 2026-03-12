use firehose_test::{
    alice_addr, beacon_roots_address, big_int, bob_addr, charlie_addr, hash32,
    history_storage_address, miner_addr, must_big_int, success_receipt, system_address,
    test_legacy_trx, u256_to_trimmed_bytes, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Block-Level Balance Changes Tests
// =============================================================================
// Tests balance changes that occur at block level (outside of transactions):
// miner rewards, uncle rewards, transaction fee distribution

#[test]
fn test_miner_block_reward() {
    // Miner receives block reward at end of block
    let block_reward = must_big_int("2000000000000000000"); // 2 ETH

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Block-level reward (outside transaction)
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            // Verify block has the miner reward
            assert_eq!(1, block.balance_changes.len());

            let reward = &block.balance_changes[0];
            assert_eq!(miner_addr().0.as_slice(), reward.address.as_slice());
            assert!(reward.old_value.is_none(), "Old value should be 0/None");
            assert_eq!(
                u256_to_trimmed_bytes(block_reward),
                reward.new_value.as_ref().unwrap().bytes
            );
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineBlock as i32,
                reward.reason
            );

            // Reward should have ordinal after transaction
            let trx = &block.transaction_traces[0];
            assert!(
                reward.ordinal > trx.end_ordinal,
                "Block reward should come after transaction (reward={}, trx_end={})",
                reward.ordinal,
                trx.end_ordinal
            );
        });
}

#[test]
fn test_uncle_reward() {
    // Uncle miner receives reward for uncle block
    let uncle_reward = must_big_int("1750000000000000000"); // 1.75 ETH (7/8 of block reward)

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // Uncle reward at block level
        .balance_change(
            charlie_addr(),
            big_int(0),
            uncle_reward,
            pbeth::balance_change::Reason::RewardMineUncle,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(1, block.balance_changes.len());

            let reward = &block.balance_changes[0];
            assert_eq!(charlie_addr().0.as_slice(), reward.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineUncle as i32,
                reward.reason
            );
            assert_eq!(
                u256_to_trimmed_bytes(uncle_reward),
                reward.new_value.as_ref().unwrap().bytes
            );
        });
}

#[test]
fn test_transaction_fee_reward() {
    // Miner receives transaction fees
    let gas_used = 21000_u64;
    let tx_fee = big_int(1_050_000_000_000_000); // 21000 * 50 gwei

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), gas_used, vec![])
        .end_call(vec![], gas_used)
        .end_trx(Some(success_receipt(gas_used)), None)
        // Transaction fee reward to miner
        .balance_change(
            miner_addr(),
            big_int(0),
            tx_fee,
            pbeth::balance_change::Reason::RewardTransactionFee,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(1, block.balance_changes.len());

            let reward = &block.balance_changes[0];
            assert_eq!(miner_addr().0.as_slice(), reward.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::RewardTransactionFee as i32,
                reward.reason
            );
            assert_eq!(
                u256_to_trimmed_bytes(tx_fee),
                reward.new_value.as_ref().unwrap().bytes
            );
        });
}

#[test]
fn test_multiple_rewards_combined() {
    // Block with: block reward + uncle reward + transaction fees
    let block_reward = big_int(2_000_000_000_000_000_000);
    let uncle_reward = big_int(1_750_000_000_000_000_000);
    let tx_fee = big_int(1_050_000_000_000_000);
    let miner_total = block_reward + tx_fee; // Combined block reward + tx fees

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // First transaction
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Second transaction
        .start_trx(test_legacy_trx())
        .start_call(bob_addr(), charlie_addr(), big_int(50), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Block-level rewards
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .balance_change(
            charlie_addr(),
            big_int(0),
            uncle_reward,
            pbeth::balance_change::Reason::RewardMineUncle,
        )
        .balance_change(
            miner_addr(),
            block_reward,
            miner_total,
            pbeth::balance_change::Reason::RewardTransactionFee,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(2, block.transaction_traces.len());
            assert_eq!(3, block.balance_changes.len());

            // Verify all rewards are present
            let rewards = &block.balance_changes;
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineBlock as i32,
                rewards[0].reason
            );
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineUncle as i32,
                rewards[1].reason
            );
            assert_eq!(
                pbeth::balance_change::Reason::RewardTransactionFee as i32,
                rewards[2].reason
            );

            // Verify ordinal ordering (rewards after all transactions)
            let last_trx = &block.transaction_traces[1];
            for reward in rewards {
                assert!(
                    reward.ordinal > last_trx.end_ordinal,
                    "All rewards should come after transactions (reward={}, trx_end={})",
                    reward.ordinal,
                    last_trx.end_ordinal
                );
            }
        });
}

#[test]
fn test_block_with_no_transactions_only_rewards() {
    // Empty block that still gets miner reward
    let block_reward = big_int(2_000_000_000_000_000_000);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(0, block.transaction_traces.len(), "No transactions");
            assert_eq!(1, block.balance_changes.len(), "Has block reward");

            let reward = &block.balance_changes[0];
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineBlock as i32,
                reward.reason
            );
        });
}

// =============================================================================
// Block-Level Code Changes Tests
// =============================================================================
// Tests code changes that occur at block level (outside transactions):
// consensus upgrades, hard forks, etc.

#[test]
fn test_block_level_code_deployment() {
    // Code deployed at block level (e.g., system contract upgrade)
    let contract_code = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Simple bytecode
    let empty_hash = alloy_primitives::B256::ZERO;
    let new_hash = hash32(12345);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Transaction happens first
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Block-level code change (outside transaction)
        .code_change(
            system_address(),
            empty_hash,
            new_hash,
            vec![],
            contract_code.clone(),
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(1, block.code_changes.len());

            let code_change = &block.code_changes[0];
            assert_eq!(
                system_address().0.as_slice(),
                code_change.address.as_slice()
            );
            assert_eq!(empty_hash.0.as_slice(), code_change.old_hash.as_slice());
            assert!(code_change.old_code.is_empty());
            assert_eq!(new_hash.0.as_slice(), code_change.new_hash.as_slice());
            assert_eq!(contract_code, code_change.new_code);

            // Code change should have ordinal after transaction
            let trx = &block.transaction_traces[0];
            assert!(
                code_change.ordinal > trx.end_ordinal,
                "Block-level code change should come after transaction"
            );
        });
}

#[test]
fn test_block_level_code_update() {
    // Code updated at block level (e.g., hard fork contract modification)
    let old_code = vec![0x60, 0x01];
    let new_code = vec![0x60, 0x02, 0x60, 0x03];
    let old_hash = hash32(100);
    let new_hash = hash32(200);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .code_change(
            beacon_roots_address(),
            old_hash,
            new_hash,
            old_code.clone(),
            new_code.clone(),
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(1, block.code_changes.len());

            let code_change = &block.code_changes[0];
            assert_eq!(
                beacon_roots_address().0.as_slice(),
                code_change.address.as_slice()
            );
            assert_eq!(old_code, code_change.old_code);
            assert_eq!(new_code, code_change.new_code);
        });
}

#[test]
fn test_multiple_block_level_code_changes() {
    // Multiple contracts updated at block level (e.g., multi-contract hard fork)
    let code1 = vec![0x60, 0x01];
    let code2 = vec![0x60, 0x02];
    let empty_hash = alloy_primitives::B256::ZERO;
    let hash1 = hash32(1);
    let hash2 = hash32(2);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .code_change(beacon_roots_address(), empty_hash, hash1, vec![], code1)
        .code_change(history_storage_address(), empty_hash, hash2, vec![], code2)
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(2, block.code_changes.len());

            // Verify both code changes
            assert_eq!(
                beacon_roots_address().0.as_slice(),
                block.code_changes[0].address.as_slice()
            );
            assert_eq!(
                history_storage_address().0.as_slice(),
                block.code_changes[1].address.as_slice()
            );

            // Verify ordinal ordering
            assert!(block.code_changes[0].ordinal < block.code_changes[1].ordinal);
        });
}

// =============================================================================
// Block-Level Withdrawals Tests
// =============================================================================
// Tests EIP-4895 beacon chain withdrawals

#[test]
fn test_single_withdrawal() {
    // Single validator withdrawal
    let withdrawal_amount = must_big_int("32000000000000000000"); // 32 ETH

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // Withdrawal happens (balance change with WITHDRAWAL reason)
        .balance_change(
            alice_addr(),
            big_int(0),
            withdrawal_amount,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .end_block(None)
        .validate_with_category("blocklevelwithdrawals", |block| {
            assert_eq!(1, block.balance_changes.len());

            let withdrawal = &block.balance_changes[0];
            assert_eq!(alice_addr().0.as_slice(), withdrawal.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::Withdrawal as i32,
                withdrawal.reason
            );
            assert_eq!(
                u256_to_trimmed_bytes(withdrawal_amount),
                withdrawal.new_value.as_ref().unwrap().bytes
            );
        });
}

#[test]
fn test_multiple_withdrawals() {
    // Multiple validator withdrawals in same block
    let amount1 = must_big_int("32000000000000000000");
    let amount2 = must_big_int("16000000000000000000");
    let amount3 = must_big_int("8000000000000000000");

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .balance_change(
            alice_addr(),
            big_int(0),
            amount1,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .balance_change(
            bob_addr(),
            big_int(0),
            amount2,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .balance_change(
            charlie_addr(),
            big_int(0),
            amount3,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(3, block.balance_changes.len());

            // Verify all are withdrawals
            for withdrawal in &block.balance_changes {
                assert_eq!(
                    pbeth::balance_change::Reason::Withdrawal as i32,
                    withdrawal.reason
                );
            }

            // Verify addresses
            assert_eq!(
                alice_addr().0.as_slice(),
                block.balance_changes[0].address.as_slice()
            );
            assert_eq!(
                bob_addr().0.as_slice(),
                block.balance_changes[1].address.as_slice()
            );
            assert_eq!(
                charlie_addr().0.as_slice(),
                block.balance_changes[2].address.as_slice()
            );
        });
}

#[test]
fn test_withdrawals_and_transactions() {
    // Block with both transactions and withdrawals
    let withdrawal_amount = must_big_int("32000000000000000000");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Transaction
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Withdrawal after transaction
        .balance_change(
            charlie_addr(),
            big_int(0),
            withdrawal_amount,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .end_block(None)
        .validate_with_category("blocklevelwithdrawals", |block| {
            assert_eq!(1, block.transaction_traces.len());
            assert_eq!(1, block.balance_changes.len());

            let withdrawal = &block.balance_changes[0];
            assert_eq!(
                pbeth::balance_change::Reason::Withdrawal as i32,
                withdrawal.reason
            );

            // Withdrawal should come after transaction
            let trx = &block.transaction_traces[0];
            assert!(withdrawal.ordinal > trx.end_ordinal);
        });
}

#[test]
fn test_withdrawals_and_rewards_combined() {
    // Block with withdrawals, miner rewards, and transactions
    let withdrawal_amount = must_big_int("32000000000000000000");
    let block_reward = big_int(2_000_000_000_000_000_000);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Transaction
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Block-level state changes
        .balance_change(
            charlie_addr(),
            big_int(0),
            withdrawal_amount,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(1, block.transaction_traces.len());
            assert_eq!(2, block.balance_changes.len());

            // Verify both balance changes
            assert_eq!(
                pbeth::balance_change::Reason::Withdrawal as i32,
                block.balance_changes[0].reason
            );
            assert_eq!(
                pbeth::balance_change::Reason::RewardMineBlock as i32,
                block.balance_changes[1].reason
            );

            // Both should come after transaction
            let trx = &block.transaction_traces[0];
            assert!(block.balance_changes[0].ordinal > trx.end_ordinal);
            assert!(block.balance_changes[1].ordinal > trx.end_ordinal);
        });
}

// =============================================================================
// Complex Block Scenarios Tests
// =============================================================================
// Tests complex combinations of block-level state changes

#[test]
fn test_full_block_with_all_state_types() {
    // Block with: system call, transactions, withdrawals, rewards, code changes
    let withdrawal_amount = must_big_int("32000000000000000000");
    let block_reward = big_int(2_000_000_000_000_000_000);
    let contract_code = vec![0x60, 0x80];
    let beacon_root = hash32(12345);
    let empty_hash = alloy_primitives::B256::ZERO;

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // System call
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        // Transaction
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Block-level state changes
        .balance_change(
            charlie_addr(),
            big_int(0),
            withdrawal_amount,
            pbeth::balance_change::Reason::Withdrawal,
        )
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .code_change(
            history_storage_address(),
            empty_hash,
            hash32(999),
            vec![],
            contract_code,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            // Verify all components present
            assert_eq!(1, block.system_calls.len(), "Has system call");
            assert_eq!(1, block.transaction_traces.len(), "Has transaction");
            assert_eq!(
                2,
                block.balance_changes.len(),
                "Has withdrawals and rewards"
            );
            assert_eq!(1, block.code_changes.len(), "Has code change");

            // Verify ordinal ordering
            let sys_call = &block.system_calls[0];
            let trx = &block.transaction_traces[0];
            let withdrawal = &block.balance_changes[0];
            let reward = &block.balance_changes[1];
            let code_change = &block.code_changes[0];

            // System call < Transaction < Block-level changes
            assert!(sys_call.end_ordinal < trx.begin_ordinal);
            assert!(trx.end_ordinal < withdrawal.ordinal);
            assert!(trx.end_ordinal < reward.ordinal);
            assert!(trx.end_ordinal < code_change.ordinal);
        });
}

#[test]
fn test_block_with_multiple_system_calls_and_rewards() {
    // System calls + transactions + rewards
    let beacon_root = hash32(11111);
    let parent_hash = hash32(22222);
    let block_reward = big_int(2_000_000_000_000_000_000);
    let uncle_reward = big_int(1_750_000_000_000_000_000);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // Multiple system calls
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        .system_call(
            system_address(),
            history_storage_address(),
            parent_hash.0.to_vec(),
            30_000_000,
            vec![],
            45_000,
        )
        // Transaction
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Rewards
        .balance_change(
            miner_addr(),
            big_int(0),
            block_reward,
            pbeth::balance_change::Reason::RewardMineBlock,
        )
        .balance_change(
            charlie_addr(),
            big_int(0),
            uncle_reward,
            pbeth::balance_change::Reason::RewardMineUncle,
        )
        .end_block(None)
        .validate_with_category("blocklevelbalancechanges", |block| {
            assert_eq!(2, block.system_calls.len());
            assert_eq!(1, block.transaction_traces.len());
            assert_eq!(2, block.balance_changes.len());

            // Verify ordering: sys calls < transaction < rewards
            assert!(block.system_calls[1].end_ordinal < block.transaction_traces[0].begin_ordinal);
            assert!(block.transaction_traces[0].end_ordinal < block.balance_changes[0].ordinal);
        });
}
