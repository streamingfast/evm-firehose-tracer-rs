use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Opcode Gas Change Tests
// =============================================================================
// Tests that gas changes are properly recorded for specific opcodes

#[test]
fn test_call_opcode_gas_change() {
    // CALL opcode (0xf1) should record a gas change with REASON_CALL
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        // Simulate CALL opcode execution with gas cost
        .opcode(0, 0xf1, 100000, 9000) // CALL costs ~9000 gas
        .start_call(bob_addr(), charlie_addr(), big_int(0), 90000, vec![])
        .end_call(vec![], 85000)
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Should have gas change recorded for CALL opcode
            assert!(!root_call.gas_changes.is_empty(), "Should have gas changes");

            // Find the CALL gas change
            let call_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::Call as i32);

            assert!(call_gas_change.is_some(), "Should have CALL gas change");
            let gc = call_gas_change.unwrap();
            assert_eq!(100000, gc.old_value, "Old gas value");
            assert_eq!(91000, gc.new_value, "New gas value after CALL");
        });
}

#[test]
fn test_create_opcode_gas_change() {
    // CREATE opcode (0xf0) should record a gas change with REASON_CONTRACT_CREATION
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 200000, vec![])
        // Simulate CREATE opcode execution
        .opcode(0, 0xf0, 200000, 32000) // CREATE costs ~32000 gas
        .start_create_call(
            bob_addr(),
            charlie_addr(),
            big_int(0),
            168000,
            vec![0x60, 0x80],
        )
        .end_call(vec![0x60, 0x80], 150000)
        .end_call(vec![], 180000)
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Should have gas change for CREATE
            let create_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::ContractCreation as i32);

            assert!(create_gas_change.is_some(), "Should have CREATE gas change");
            let gc = create_gas_change.unwrap();
            assert_eq!(200000, gc.old_value);
            assert_eq!(168000, gc.new_value);
        });
}

#[test]
fn test_create2_opcode_gas_change() {
    // CREATE2 opcode (0xf5) should record a gas change with REASON_CONTRACT_CREATION2
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 200000, vec![])
        // Simulate CREATE2 opcode execution
        .opcode(0, 0xf5, 200000, 32000) // CREATE2 costs similar to CREATE
        .start_create2_call(
            bob_addr(),
            charlie_addr(),
            big_int(0),
            168000,
            vec![0x60, 0x80],
        )
        .end_call(vec![0x60, 0x80], 150000)
        .end_call(vec![], 180000)
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            let create2_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::ContractCreation2 as i32);

            assert!(
                create2_gas_change.is_some(),
                "Should have CREATE2 gas change"
            );
            let gc = create2_gas_change.unwrap();
            assert_eq!(200000, gc.old_value);
            assert_eq!(168000, gc.new_value);
        });
}

#[test]
fn test_staticcall_opcode_gas_change() {
    // STATICCALL opcode (0xfa) should record a gas change with REASON_STATIC_CALL
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        .opcode(0, 0xfa, 100000, 700) // STATICCALL costs ~700 gas
        .start_static_call(bob_addr(), charlie_addr(), 99300, vec![])
        .end_call(vec![], 95000)
        .end_call(vec![], 99000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            let static_call_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::StaticCall as i32);

            assert!(
                static_call_gas_change.is_some(),
                "Should have STATICCALL gas change"
            );
            let gc = static_call_gas_change.unwrap();
            assert_eq!(100000, gc.old_value);
            assert_eq!(99300, gc.new_value);
        });
}

#[test]
fn test_delegatecall_opcode_gas_change() {
    // DELEGATECALL opcode (0xf4) should record a gas change with REASON_DELEGATE_CALL
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        .opcode(0, 0xf4, 100000, 700) // DELEGATECALL costs ~700 gas
        .start_delegate_call(bob_addr(), charlie_addr(), big_int(0), 99300, vec![])
        .end_call(vec![], 95000)
        .end_call(vec![], 99000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            let delegate_call_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::DelegateCall as i32);

            assert!(
                delegate_call_gas_change.is_some(),
                "Should have DELEGATECALL gas change"
            );
            let gc = delegate_call_gas_change.unwrap();
            assert_eq!(100000, gc.old_value);
            assert_eq!(99300, gc.new_value);
        });
}

#[test]
fn test_callcode_opcode_gas_change() {
    // CALLCODE opcode (0xf2) should record a gas change with REASON_CALL_CODE
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        .opcode(0, 0xf2, 100000, 700) // CALLCODE costs ~700 gas
        .start_call_code(bob_addr(), charlie_addr(), big_int(0), 99300, vec![])
        .end_call(vec![], 95000)
        .end_call(vec![], 99000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            let call_code_gas_change = root_call
                .gas_changes
                .iter()
                .find(|gc| gc.reason == pbeth::gas_change::Reason::CallCode as i32);

            assert!(
                call_code_gas_change.is_some(),
                "Should have CALLCODE gas change"
            );
            let gc = call_code_gas_change.unwrap();
            assert_eq!(100000, gc.old_value);
            assert_eq!(99300, gc.new_value);
        });
}

#[test]
fn test_no_gas_change_for_unmapped_opcodes() {
    // Opcodes not in the map (like PUSH, ADD, etc.) should not create gas changes
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        // PUSH1 (0x60) - not in map
        .opcode(0, 0x60, 100000, 3)
        // ADD (0x01) - not in map
        .opcode(0, 0x01, 99997, 3)
        // MUL (0x02) - not in map
        .opcode(0, 0x02, 99994, 5)
        .end_call(vec![], 99989)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("opcodegaschanges", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Should have no gas changes since none of these opcodes are in the map
            assert_eq!(
                0,
                root_call.gas_changes.len(),
                "Unmapped opcodes should not create gas changes"
            );
        });
}
