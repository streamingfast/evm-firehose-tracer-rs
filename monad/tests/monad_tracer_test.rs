use alloy_primitives::{Address, B256, U256};
use firehose_test::{alice_addr, bob_addr, miner_addr, parse_firehose_block, system_address, InMemoryBuffer};
use monad_exec_events::ffi::{
    monad_c_address, monad_c_bytes32, monad_c_eth_txn_header, monad_c_eth_txn_receipt,
    monad_c_uint256_ne, monad_exec_account_access, monad_exec_account_access_list_header,
    monad_exec_block_start, monad_exec_block_tag, monad_exec_txn_call_frame,
    monad_exec_txn_evm_output, monad_exec_txn_header_start, monad_exec_txn_log,
};
use monad_exec_events::ExecEvent;
use monad_tracer::{FirehosePlugin, FirehosePluginConfig};
use pb::sf::ethereum::r#type::v2 as pbeth;

// FFI helpers
fn zero_bytes32() -> monad_c_bytes32 { monad_c_bytes32 { bytes: [0u8; 32] } }
fn zero_u256() -> monad_c_uint256_ne { monad_c_uint256_ne { limbs: [0u64; 4] } }
fn zero_address() -> monad_c_address { monad_c_address { bytes: [0u8; 20] } }
fn addr_to_ffi(addr: Address) -> monad_c_address { monad_c_address { bytes: addr.into() } }
fn u256_to_ffi(v: U256) -> monad_c_uint256_ne { monad_c_uint256_ne { limbs: v.into_limbs() } }
fn bytes32_to_ffi(b: B256) -> monad_c_bytes32 { monad_c_bytes32 { bytes: b.into() } }

// MonadTracerTester
struct MonadTracerTester {
    plugin: FirehosePlugin,
    output_buffer: InMemoryBuffer,
}

impl MonadTracerTester {
    fn new() -> Self {
        let output_buffer = InMemoryBuffer::new();
        let config = FirehosePluginConfig::new(1, "test".to_string());
        let mut plugin = FirehosePlugin::new_with_writer(config, Box::new(output_buffer.clone()));
        plugin.on_blockchain_init("test", "1.0.0");
        Self { plugin, output_buffer }
    }

    fn send(&mut self, event: ExecEvent) -> &mut Self {
        self.plugin.add_event(event).expect("add_event failed");
        self
    }

    // Block lifecycle
    fn block_start(&mut self, number: u64, txn_count: u64) -> &mut Self {
        let mut bs: monad_exec_block_start = unsafe { std::mem::zeroed() };
        bs.block_tag = monad_exec_block_tag { id: zero_bytes32(), block_number: number };
        bs.eth_block_input.number = number;
        bs.eth_block_input.txn_count = txn_count;
        bs.eth_block_input.gas_limit = 30_000_000;
        bs.eth_block_input.timestamp = 1_700_000_000;
        bs.eth_block_input.base_fee_per_gas = u256_to_ffi(U256::from(1_000_000_000u64));
        self.send(ExecEvent::BlockStart(bs))
    }

    fn is_epilogue(&self) -> bool {
        self.plugin.is_epilogue()
    }

    fn block_start_with(&mut self, number: u64, gas_limit: u64, timestamp: u64, base_fee: U256) -> &mut Self {
        let mut bs: monad_exec_block_start = unsafe { std::mem::zeroed() };
        bs.block_tag = monad_exec_block_tag { id: zero_bytes32(), block_number: number };
        bs.eth_block_input.number = number;
        bs.eth_block_input.gas_limit = gas_limit;
        bs.eth_block_input.timestamp = timestamp;
        bs.eth_block_input.base_fee_per_gas = u256_to_ffi(base_fee);
        self.send(ExecEvent::BlockStart(bs))
    }

    fn block_end(&mut self) -> &mut Self {
        self.send(ExecEvent::BlockEnd(unsafe { std::mem::zeroed() }))
    }

    fn txn_end(&mut self) -> &mut Self {
        self.send(ExecEvent::TxnEnd)
    }

    // Transaction lifecycle
    fn txn_header_start(&mut self, txn_index: usize, from: Address, to: Option<Address>) -> &mut Self {
        self.send(ExecEvent::TxnHeaderStart {
            txn_index,
            txn_header_start: monad_exec_txn_header_start {
                txn_hash: zero_bytes32(),
                sender: addr_to_ffi(from),
                txn_header: monad_c_eth_txn_header {
                    txn_type: 0,
                    chain_id: zero_u256(),
                    nonce: 0,
                    gas_limit: 21_000,
                    max_fee_per_gas: u256_to_ffi(U256::from(1_000_000_000u64)),
                    max_priority_fee_per_gas: zero_u256(),
                    value: u256_to_ffi(U256::from(100u64)),
                    to: to.map(addr_to_ffi).unwrap_or(zero_address()),
                    is_contract_creation: to.is_none(),
                    r: zero_u256(), s: zero_u256(), y_parity: false,
                    max_fee_per_blob_gas: zero_u256(),
                    data_length: 0, blob_versioned_hash_length: 0,
                    access_list_count: 0, auth_list_count: 0,
                },
            },
            data_bytes: Box::new([]),
            blob_bytes: Box::new([]),
        })
    }

    fn txn_header_start_with_nonce(&mut self, txn_index: usize, from: Address, to: Option<Address>, nonce: u64) -> &mut Self {
        self.send(ExecEvent::TxnHeaderStart {
            txn_index,
            txn_header_start: monad_exec_txn_header_start {
                txn_hash: zero_bytes32(),
                sender: addr_to_ffi(from),
                txn_header: monad_c_eth_txn_header {
                    txn_type: 0,
                    chain_id: zero_u256(),
                    nonce,
                    gas_limit: 21_000,
                    max_fee_per_gas: u256_to_ffi(U256::from(1_000_000_000u64)),
                    max_priority_fee_per_gas: zero_u256(),
                    value: zero_u256(),
                    to: to.map(addr_to_ffi).unwrap_or(zero_address()),
                    is_contract_creation: to.is_none(),
                    r: zero_u256(), s: zero_u256(), y_parity: false,
                    max_fee_per_blob_gas: zero_u256(),
                    data_length: 0, blob_versioned_hash_length: 0,
                    access_list_count: 0, auth_list_count: 0,
                },
            },
            data_bytes: Box::new([]),
            blob_bytes: Box::new([]),
        })
    }

    fn txn_evm_output(&mut self, txn_index: usize, gas_used: u64, status: bool) -> &mut Self {
        self.txn_evm_output_with_frames(txn_index, gas_used, status, 0)
    }

    fn txn_evm_output_with_frames(&mut self, txn_index: usize, gas_used: u64, status: bool, call_frame_count: u32) -> &mut Self {
        self.send(ExecEvent::TxnEvmOutput {
            txn_index,
            output: monad_exec_txn_evm_output {
                receipt: monad_c_eth_txn_receipt { status, log_count: 0, gas_used },
                call_frame_count,
            },
        })
    }

    fn txn_call_frame(&mut self, txn_index: Option<usize>, from: Address, to: Address, opcode: u8, depth: u64, gas: u64, gas_used: u64) -> &mut Self {
        self.send(ExecEvent::TxnCallFrame {
            txn_index,
            txn_call_frame: monad_exec_txn_call_frame {
                index: 0,
                caller: addr_to_ffi(from),
                call_target: addr_to_ffi(to),
                opcode, value: zero_u256(), gas, gas_used,
                evmc_status: 0, depth, input_length: 0, return_length: 0,
            },
            input_bytes: Box::new([]),
            return_bytes: Box::new([]),
        })
    }

    fn account_access_header(&mut self, access_context: u8) -> &mut Self {
        self.send(ExecEvent::AccountAccessListHeader(monad_exec_account_access_list_header {
            entry_count: 0, access_context,
        }))
    }

    fn account_access_balance(&mut self, addr: Address, old: U256, new: U256) -> &mut Self {
        let mut a: monad_exec_account_access = unsafe { std::mem::zeroed() };
        a.address = addr_to_ffi(addr);
        a.is_balance_modified = true;
        a.prestate.balance = u256_to_ffi(old);
        a.modified_balance = u256_to_ffi(new);
        self.send(ExecEvent::AccountAccess(a))
    }

    fn account_access_nonce(&mut self, addr: Address, old: u64, new: u64) -> &mut Self {
        let mut a: monad_exec_account_access = unsafe { std::mem::zeroed() };
        a.address = addr_to_ffi(addr);
        a.is_nonce_modified = true;
        a.prestate.nonce = old;
        a.modified_nonce = new;
        self.send(ExecEvent::AccountAccess(a))
    }

    fn storage_access(&mut self, addr: Address, key: B256, old: B256, new: B256, modified: bool, transient: bool) -> &mut Self {
        let mut s: monad_exec_events::ffi::monad_exec_storage_access = unsafe { std::mem::zeroed() };
        s.address = addr_to_ffi(addr);
        s.key = bytes32_to_ffi(key);
        s.start_value = bytes32_to_ffi(old);
        s.end_value = bytes32_to_ffi(new);
        s.modified = modified;
        s.transient = transient;
        self.send(ExecEvent::StorageAccess(s))
    }

    fn txn_log(&mut self, txn_index: usize, addr: Address, data: &[u8]) -> &mut Self {
        self.send(ExecEvent::TxnLog {
            txn_index,
            txn_log: monad_exec_txn_log {
                address: addr_to_ffi(addr),
                index: 0,
                topic_count: 0,
                data_length: data.len() as u32,
            },
            topic_bytes: Box::new([]),
            data_bytes: data.to_vec().into_boxed_slice(),
        })
    }

    // Convenience combinators
    fn start_block_trx(&mut self, txn_index: usize, from: Address, to: Option<Address>) -> &mut Self {
        self.block_start(100, 1)
            .txn_header_start(txn_index, from, to)
    }

    fn end_block_trx(&mut self, txn_index: usize, gas_used: u64, status: bool) -> &mut Self {
        self.txn_evm_output_with_frames(txn_index, gas_used, status, 1)
            .txn_call_frame(Some(txn_index), alice_addr(), bob_addr(), 0xF1, 0, gas_used, gas_used)
            .txn_end()
            .block_end()
    }

    fn validate<F>(&self, f: F) where F: FnOnce(&pbeth::Block) {
        let block = parse_firehose_block(&self.output_buffer.get_bytes());
        f(&block);
    }
}

// BlockStart -> block header fields
#[test]
fn test_block_number_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start(42, 0).block_end();
    t.validate(|block| {
        assert_eq!(block.number, 42);
    });
}

#[test]
fn test_block_gas_limit_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start_with(1, 12_500_000, 0, U256::ZERO).block_end();
    t.validate(|block| {
        assert_eq!(block.header.as_ref().unwrap().gas_limit, 12_500_000);
    });
}

#[test]
fn test_block_timestamp_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start_with(1, 0, 1_234_567_890, U256::ZERO).block_end();
    t.validate(|block| {
        assert_eq!(block.header.as_ref().unwrap().timestamp.as_ref().unwrap().seconds, 1_234_567_890);
    });
}

#[test]
fn test_block_base_fee_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start_with(1, 0, 0, U256::from(7u64)).block_end();
    t.validate(|block| {
        let base_fee = block.header.as_ref().unwrap().base_fee_per_gas.as_ref().unwrap();
        assert_eq!(base_fee.bytes, vec![7]);
    });
}

// TxnHeaderStart -> TxEvent fields
#[test]
fn test_tx_from_mapped() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 21_000, true);
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].from, alice_addr().as_slice());
    });
}

#[test]
fn test_tx_to_mapped() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 21_000, true);
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert_eq!(call.address, bob_addr().as_slice());
    });
}

#[test]
fn test_tx_contract_creation_has_no_to() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), None)
        .end_block_trx(0, 21_000, true);
    t.validate(|block| {
        assert!(block.transaction_traces[0].to.is_empty(), "contract creation should have empty to");
    });
}

#[test]
fn test_tx_nonce_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start_with_nonce(0, alice_addr(), Some(bob_addr()), 42)
        .txn_evm_output(0, 21_000, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].nonce, 42);
    });
}

#[test]
fn test_tx_gas_limit_mapped() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 21_000, true);
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].gas_limit, 21_000);
    });
}

// TxnEvmOutput -> receipt
#[test]
fn test_tx_status_success() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 21_000, true);
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].status, 1);
    });
}

#[test]
fn test_tx_status_failure() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 21_000, false);
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].status, 2); // Failed = 2
    });
}

#[test]
fn test_tx_gas_used_mapped() {
    let mut t = MonadTracerTester::new();
    t.start_block_trx(0, alice_addr(), Some(bob_addr()))
        .end_block_trx(0, 55_000, true);
    t.validate(|block| {
        assert_eq!(block.transaction_traces[0].gas_used, 55_000);
    });
}

// TxnLog
#[test]
fn test_txn_log_mapped() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_log(0, bob_addr(), &data)  // arrives before call frame
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let receipt = block.transaction_traces[0].receipt.as_ref().unwrap();
        assert_eq!(receipt.logs.len(), 1, "log must be present even though it arrived before call frame");
        assert_eq!(receipt.logs[0].address, bob_addr().as_slice());
        assert_eq!(receipt.logs[0].data, data);
    });
}

// Parallel txns (Monad-specific: headers arrive before outputs)
#[test]
fn test_parallel_txns_all_present() {
    // Monad can emit all TxnHeaderStarts before any TxnEvmOutput due to parallel execution
    let mut t = MonadTracerTester::new();
    t
        .block_start(5, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output(0, 21_000, true)
        .txn_end()
        .txn_evm_output(1, 21_000, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces.len(), 2);
        assert_eq!(block.transaction_traces[0].from, alice_addr().as_slice());
        assert_eq!(block.transaction_traces[1].from, bob_addr().as_slice());
    });
}

// AccountAccess -> state changes
#[test]
fn test_balance_change_in_tx() {
    // The call is open when they arrive, so changes attach to the active call
    let mut t = MonadTracerTester::new();
    t
        .block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .account_access_balance(bob_addr(), U256::from(100u64), U256::from(200u64))
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(!calls[0].balance_changes.is_empty(), "balance change should be in call");
    });
}

#[test]
fn test_nonce_change_in_tx() {
    let mut t = MonadTracerTester::new();
    t
        .block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .account_access_nonce(alice_addr(), 5, 6)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(!calls[0].nonce_changes.is_empty(), "nonce change should be in call");
    });
}

#[test]
fn test_storage_change_in_tx() {
    let key = B256::repeat_byte(0x01);
    let mut t = MonadTracerTester::new();
    t
        .block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .storage_access(bob_addr(), key, B256::ZERO, B256::repeat_byte(0x02), true, false)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(!calls[0].storage_changes.is_empty(), "storage change should be in call");
    });
}

#[test]
fn test_transient_storage_not_mapped() {
    // transient=true -> should NOT produce a storage change
    let key = B256::repeat_byte(0x01);
    let mut t = MonadTracerTester::new();
    t
        .block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true)
        .account_access_header(1)
        .storage_access(bob_addr(), key, B256::ZERO, B256::repeat_byte(0x02), true, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.iter().any(|c| !c.storage_changes.is_empty()), "transient storage must not be mapped");
    });
}

#[test]
fn test_unmodified_storage_not_mapped() {
    // modified=false -> should NOT produce a storage change
    let key = B256::repeat_byte(0x01);
    let val = B256::repeat_byte(0xAA);
    let mut t = MonadTracerTester::new();
    t
        .block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true)
        .account_access_header(1)
        .storage_access(bob_addr(), key, val, val, false, false)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.iter().any(|c| !c.storage_changes.is_empty()), "unmodified storage must not be mapped");
    });
}

// Interleaved event ordering
#[test]
fn test_all_headers_before_any_output() {
    // all headers arrive before any output.
    let mut t = MonadTracerTester::new();
    t.block_start(1, 3)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_header_start(2, miner_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .txn_evm_output_with_frames(1, 22_000, true, 1)
        .txn_call_frame(Some(1), bob_addr(), alice_addr(), 0xF1, 0, 22_000, 22_000)
        .txn_end()
        .txn_evm_output_with_frames(2, 23_000, true, 1)
        .txn_call_frame(Some(2), miner_addr(), alice_addr(), 0xF1, 0, 23_000, 23_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces.len(), 3);
        assert_eq!(block.transaction_traces[0].from, alice_addr().as_slice());
        assert_eq!(block.transaction_traces[1].from, bob_addr().as_slice());
        assert_eq!(block.transaction_traces[2].from, miner_addr().as_slice());
        assert_eq!(block.transaction_traces[0].gas_used, 21_000);
        assert_eq!(block.transaction_traces[1].gas_used, 22_000);
        assert_eq!(block.transaction_traces[2].gas_used, 23_000);
    });
}

#[test]
fn test_header_arrives_after_own_output() {
    // TxnEvmOutput for tx 0 arrives before its own TxnHeaderStart.
    let result = std::panic::catch_unwind(|| {
        let mut t = MonadTracerTester::new();
        t.block_start(1, 1)
            .txn_evm_output(0, 21_000, true)
            .txn_header_start(0, alice_addr(), Some(bob_addr()))
            .txn_end()
            .block_end();
    });
    assert!(result.is_err(), "output arrived before its own header");
}

#[test]
fn test_outputs_out_of_index_order() {
    // Output for tx 1 arrives before output for tx 0, even though tx 0 has lower index.
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output(1, 30_000, true)
        .txn_end()
        .txn_evm_output(0, 21_000, false)
        .txn_end()
        .block_end();
    t.validate(|block| {
        // Two txns are produced, but ordering/attribution is not guaranteed to be correct yet.
        assert_eq!(block.transaction_traces.len(), 2);
    });
}

#[test]
fn test_header_for_tx1_arrives_after_output_for_tx0_but_before_txn_end() {
    // Tx1 header arrives after tx0's output but before tx0's TxnEnd.
    // Tests that the pending map correctly separates events by txn_index.
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true)
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_end()
        .txn_evm_output(1, 30_000, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces.len(), 2);
        assert_eq!(block.transaction_traces[0].from, alice_addr().as_slice());
        assert_eq!(block.transaction_traces[1].from, bob_addr().as_slice());
    });
}

#[test]
fn test_logs_arrive_for_tx_whose_header_not_yet_seen() {
    // TxnLog for tx 1 arrives before tx 1's TxnHeaderStart.
    let data = [0xAB, 0xCD];
    let result = std::panic::catch_unwind(|| {
        let mut t = MonadTracerTester::new();
        t.block_start(1, 1)
            .txn_header_start(0, alice_addr(), Some(bob_addr()))
            .txn_evm_output(0, 21_000, true)
            .txn_end()
            .txn_log(1, bob_addr(), &data)  // tx1 log before tx1 header or output
            .txn_header_start(1, bob_addr(), Some(alice_addr()))
            .txn_evm_output(1, 21_000, true)
            .txn_end()
            .block_end();
    });
    assert!(result.is_err(), "expected panic: log arrived before its transaction was started");
}

#[test]
fn test_tx_call_frames_arrive_after_output() {
    // So for the same tx: output -> logs -> call_frames -> account_accesses -> TxnEnd
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .txn_evm_output(1, 21_000, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces.len(), 2);
        assert_eq!(block.transaction_traces[0].calls.len(), 1);
        assert_eq!(block.transaction_traces[0].calls[0].caller, alice_addr().as_slice());
        // tx1 has call_frame_count=0, no TxnCallFrame arrives -> 0 calls
        assert_eq!(block.transaction_traces[1].calls.len(), 0);
    });
}

#[test]
fn test_account_accesses_arrive_after_output_before_txn_end() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(Some(0), alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1) // ctx=1 = TRANSACTION
        .account_access_balance(bob_addr(), U256::from(0u64), U256::from(100u64))
        .account_access_nonce(alice_addr(), 5, 6)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(calls.iter().any(|c| !c.balance_changes.is_empty()), "balance change expected");
        assert!(calls.iter().any(|c| !c.nonce_changes.is_empty()), "nonce change expected");
    });
}
