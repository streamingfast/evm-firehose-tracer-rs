use alloy_primitives::{Address, B256, U256};
use firehose_test::{
    alice_addr, bob_addr, miner_addr, parse_firehose_block, system_address, InMemoryBuffer,
};
use monad_exec_events::ffi::{
    monad_c_address, monad_c_bytes32, monad_c_eth_txn_header, monad_c_eth_txn_receipt,
    monad_c_uint256_ne, monad_exec_account_access, monad_exec_account_access_list_header,
    monad_exec_block_start, monad_exec_block_tag,
    monad_exec_block_tag as monad_exec_block_finalized, monad_exec_txn_call_frame,
    monad_exec_txn_evm_output, monad_exec_txn_header_start, monad_exec_txn_log,
};
use monad_exec_events::ExecEvent;
use monad_tracer::{FirehosePlugin, FirehosePluginConfig};
use pb::sf::ethereum::r#type::v2 as pbeth;

// FFI helpers
fn zero_bytes32() -> monad_c_bytes32 {
    monad_c_bytes32 { bytes: [0u8; 32] }
}
fn zero_u256() -> monad_c_uint256_ne {
    monad_c_uint256_ne { limbs: [0u64; 4] }
}
fn zero_address() -> monad_c_address {
    monad_c_address { bytes: [0u8; 20] }
}
fn addr_to_ffi(addr: Address) -> monad_c_address {
    monad_c_address { bytes: addr.into() }
}
fn u256_to_ffi(v: U256) -> monad_c_uint256_ne {
    monad_c_uint256_ne {
        limbs: v.into_limbs(),
    }
}
fn bytes32_to_ffi(b: B256) -> monad_c_bytes32 {
    monad_c_bytes32 { bytes: b.into() }
}

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
        Self {
            plugin,
            output_buffer,
        }
    }

    fn send(&mut self, event: ExecEvent) -> &mut Self {
        self.plugin.add_event(event).expect("add_event failed");
        self
    }

    // Block lifecycle
    fn block_start(&mut self, number: u64, txn_count: u64) -> &mut Self {
        let mut bs: monad_exec_block_start = unsafe { std::mem::zeroed() };
        bs.block_tag = monad_exec_block_tag {
            id: zero_bytes32(),
            block_number: number,
        };
        bs.eth_block_input.number = number;
        bs.eth_block_input.txn_count = txn_count;
        bs.eth_block_input.gas_limit = 30_000_000;
        bs.eth_block_input.timestamp = 1_700_000_000;
        bs.eth_block_input.base_fee_per_gas = u256_to_ffi(U256::from(1_000_000_000u64));
        self.send(ExecEvent::BlockStart(bs))
    }

    fn block_start_with(
        &mut self,
        number: u64,
        gas_limit: u64,
        timestamp: u64,
        base_fee: U256,
    ) -> &mut Self {
        let mut bs: monad_exec_block_start = unsafe { std::mem::zeroed() };
        bs.block_tag = monad_exec_block_tag {
            id: zero_bytes32(),
            block_number: number,
        };
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
    fn txn_header_start(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Option<Address>,
    ) -> &mut Self {
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
                    r: zero_u256(),
                    s: zero_u256(),
                    y_parity: false,
                    max_fee_per_blob_gas: zero_u256(),
                    data_length: 0,
                    blob_versioned_hash_length: 0,
                    access_list_count: 0,
                    auth_list_count: 0,
                },
            },
            data_bytes: Box::new([]),
            blob_bytes: Box::new([]),
        })
    }

    fn txn_header_start_type2(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Option<Address>,
        max_fee: u64,
        max_priority: u64,
    ) -> &mut Self {
        self.send(ExecEvent::TxnHeaderStart {
            txn_index,
            txn_header_start: monad_exec_txn_header_start {
                txn_hash: zero_bytes32(),
                sender: addr_to_ffi(from),
                txn_header: monad_c_eth_txn_header {
                    txn_type: 2,
                    chain_id: zero_u256(),
                    nonce: 0,
                    gas_limit: 21_000,
                    max_fee_per_gas: u256_to_ffi(U256::from(max_fee)),
                    max_priority_fee_per_gas: u256_to_ffi(U256::from(max_priority)),
                    value: zero_u256(),
                    to: to.map(addr_to_ffi).unwrap_or(zero_address()),
                    is_contract_creation: to.is_none(),
                    r: zero_u256(),
                    s: zero_u256(),
                    y_parity: false,
                    max_fee_per_blob_gas: zero_u256(),
                    data_length: 0,
                    blob_versioned_hash_length: 0,
                    access_list_count: 0,
                    auth_list_count: 0,
                },
            },
            data_bytes: Box::new([]),
            blob_bytes: Box::new([]),
        })
    }

    fn txn_header_start_with_nonce(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Option<Address>,
        nonce: u64,
    ) -> &mut Self {
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
                    r: zero_u256(),
                    s: zero_u256(),
                    y_parity: false,
                    max_fee_per_blob_gas: zero_u256(),
                    data_length: 0,
                    blob_versioned_hash_length: 0,
                    access_list_count: 0,
                    auth_list_count: 0,
                },
            },
            data_bytes: Box::new([]),
            blob_bytes: Box::new([]),
        })
    }

    fn txn_evm_output(&mut self, txn_index: usize, gas_used: u64, status: bool) -> &mut Self {
        self.txn_evm_output_with_frames(txn_index, gas_used, status, 0)
    }

    fn txn_evm_output_with_frames(
        &mut self,
        txn_index: usize,
        gas_used: u64,
        status: bool,
        call_frame_count: u32,
    ) -> &mut Self {
        self.send(ExecEvent::TxnEvmOutput {
            txn_index,
            output: monad_exec_txn_evm_output {
                receipt: monad_c_eth_txn_receipt {
                    status,
                    log_count: 0,
                    gas_used,
                },
                call_frame_count,
            },
        })
    }

    fn txn_call_frame(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Address,
        opcode: u8,
        depth: u64,
        gas: u64,
        gas_used: u64,
    ) -> &mut Self {
        self.send(ExecEvent::TxnCallFrame {
            txn_index,
            txn_call_frame: monad_exec_txn_call_frame {
                index: 0,
                caller: addr_to_ffi(from),
                call_target: addr_to_ffi(to),
                opcode,
                value: zero_u256(),
                gas,
                gas_used,
                evmc_status: 0,
                depth,
                input_length: 0,
                return_length: 0,
            },
            input_bytes: Box::new([]),
            return_bytes: Box::new([]),
        })
    }

    fn account_access_header(&mut self, access_context: u8) -> &mut Self {
        self.send(ExecEvent::AccountAccessListHeader(
            monad_exec_account_access_list_header {
                entry_count: 0,
                access_context,
            },
        ))
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

    fn storage_access(
        &mut self,
        addr: Address,
        key: B256,
        old: B256,
        new: B256,
        modified: bool,
        transient: bool,
    ) -> &mut Self {
        let mut s: monad_exec_events::ffi::monad_exec_storage_access =
            unsafe { std::mem::zeroed() };
        s.address = addr_to_ffi(addr);
        s.key = bytes32_to_ffi(key);
        s.start_value = bytes32_to_ffi(old);
        s.end_value = bytes32_to_ffi(new);
        s.modified = modified;
        s.transient = transient;
        self.send(ExecEvent::StorageAccess(s))
    }

    fn txn_log(&mut self, txn_index: usize, addr: Address, data: &[u8]) -> &mut Self {
        self.txn_log_indexed(txn_index, addr, &[], data, 0)
    }

    fn txn_log_indexed(
        &mut self,
        txn_index: usize,
        addr: Address,
        topics: &[B256],
        data: &[u8],
        index: u32,
    ) -> &mut Self {
        let mut topic_bytes: Vec<u8> = Vec::with_capacity(topics.len() * 32);
        for t in topics {
            topic_bytes.extend_from_slice(t.as_slice());
        }
        self.send(ExecEvent::TxnLog {
            txn_index,
            txn_log: monad_exec_txn_log {
                address: addr_to_ffi(addr),
                index,
                topic_count: topics.len() as u8,
                data_length: data.len() as u32,
            },
            topic_bytes: topic_bytes.into_boxed_slice(),
            data_bytes: data.to_vec().into_boxed_slice(),
        })
    }

    fn txn_call_frame_with_status(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Address,
        opcode: u8,
        depth: u64,
        gas: u64,
        gas_used: u64,
        evmc_status: i32,
    ) -> &mut Self {
        self.send(ExecEvent::TxnCallFrame {
            txn_index,
            txn_call_frame: monad_exec_txn_call_frame {
                index: 0,
                caller: addr_to_ffi(from),
                call_target: addr_to_ffi(to),
                opcode,
                value: zero_u256(),
                gas,
                gas_used,
                evmc_status,
                depth,
                input_length: 0,
                return_length: 0,
            },
            input_bytes: Box::new([]),
            return_bytes: Box::new([]),
        })
    }

    // Convenience combinators
    fn start_block_trx(
        &mut self,
        txn_index: usize,
        from: Address,
        to: Option<Address>,
    ) -> &mut Self {
        self.block_start(100, 1)
            .txn_header_start(txn_index, from, to)
    }

    fn end_block_trx(&mut self, txn_index: usize, gas_used: u64, status: bool) -> &mut Self {
        self.txn_evm_output_with_frames(txn_index, gas_used, status, 1)
            .txn_call_frame(
                txn_index,
                alice_addr(),
                bob_addr(),
                0xF1,
                0,
                gas_used,
                gas_used,
            )
            .txn_end()
            .block_end()
    }

    fn block_finalized(&mut self, block_number: u64) -> &mut Self {
        self.send(ExecEvent::BlockFinalized(monad_exec_block_finalized {
            id: zero_bytes32(),
            block_number,
        }))
    }

    /// Returns the lib_num field from the first FIRE BLOCK output line.
    fn parse_lib_num(&self) -> u64 {
        self.parse_all_fire_blocks()[0].1
    }

    /// Returns (block_num, lib_num) for every FIRE BLOCK line in output order.
    fn parse_all_fire_blocks(&self) -> Vec<(u64, u64)> {
        let bytes = self.output_buffer.get_bytes();
        let s = std::str::from_utf8(&bytes).expect("output is utf8");
        let mut results = Vec::new();
        for line in s.lines() {
            if line.starts_with("FIRE BLOCK ") {
                // FIRE BLOCK {num} {hash} {prev_num} {prev_hash} {lib_num} {timestamp} {base64}
                let parts: Vec<&str> = line.split_whitespace().collect();
                let block_num: u64 = parts[2].parse().expect("block_num is a number");
                let lib_num: u64 = parts[6].parse().expect("lib_num is a number");
                results.push((block_num, lib_num));
            }
        }
        assert!(!results.is_empty(), "No FIRE BLOCK found in output");
        results
    }

    fn validate<F>(&self, f: F)
    where
        F: FnOnce(&pbeth::Block),
    {
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
    t.block_start_with(1, 0, 1_234_567_890, U256::ZERO)
        .block_end();
    t.validate(|block| {
        assert_eq!(
            block
                .header
                .as_ref()
                .unwrap()
                .timestamp
                .as_ref()
                .unwrap()
                .seconds,
            1_234_567_890
        );
    });
}

#[test]
fn test_block_base_fee_mapped() {
    let mut t = MonadTracerTester::new();
    t.block_start_with(1, 0, 0, U256::from(7u64)).block_end();
    t.validate(|block| {
        let base_fee = block
            .header
            .as_ref()
            .unwrap()
            .base_fee_per_gas
            .as_ref()
            .unwrap();
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
        assert_eq!(
            block.transaction_traces[0].to,
            alloy_primitives::Address::ZERO.as_slice(),
            "contract creation uses zero address for to"
        );
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

// TODO: failing, TxnLog
#[test]
fn test_txn_log_mapped() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_log(0, bob_addr(), &data) // arrives before call frame
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let receipt = block.transaction_traces[0].receipt.as_ref().unwrap();
        assert_eq!(
            receipt.logs.len(),
            1,
            "log must be present even though it arrived before call frame"
        );
        assert_eq!(receipt.logs[0].address, bob_addr().as_slice());
        assert_eq!(receipt.logs[0].data, data);
    });
}

// Parallel txns (Monad-specific: headers arrive before outputs)
#[test]
fn test_parallel_txns_all_present() {
    // Monad can emit all TxnHeaderStarts before any TxnEvmOutput due to parallel execution
    let mut t = MonadTracerTester::new();
    t.block_start(5, 2)
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
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .account_access_balance(bob_addr(), U256::from(100u64), U256::from(200u64))
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(
            !calls[0].balance_changes.is_empty(),
            "balance change should be in call"
        );
    });
}

#[test]
fn test_nonce_change_in_tx() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .account_access_nonce(alice_addr(), 5, 6)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(
            !calls[0].nonce_changes.is_empty(),
            "nonce change should be in call"
        );
    });
}

#[test]
fn test_storage_change_in_tx() {
    let key = B256::repeat_byte(0x01);
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1)
        .storage_access(
            bob_addr(),
            key,
            B256::ZERO,
            B256::repeat_byte(0x02),
            true,
            false,
        )
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(!calls.is_empty(), "call must exist");
        assert!(
            !calls[0].storage_changes.is_empty(),
            "storage change should be in call"
        );
    });
}

#[test]
fn test_transient_storage_not_mapped() {
    // transient=true -> should NOT produce a storage change
    let key = B256::repeat_byte(0x01);
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true)
        .account_access_header(1)
        .storage_access(
            bob_addr(),
            key,
            B256::ZERO,
            B256::repeat_byte(0x02),
            true,
            true,
        )
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(
            !calls.iter().any(|c| !c.storage_changes.is_empty()),
            "transient storage must not be mapped"
        );
    });
}

#[test]
fn test_unmodified_storage_not_mapped() {
    // modified=false -> should NOT produce a storage change
    let key = B256::repeat_byte(0x01);
    let val = B256::repeat_byte(0xAA);
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true)
        .account_access_header(1)
        .storage_access(bob_addr(), key, val, val, false, false)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(
            !calls.iter().any(|c| !c.storage_changes.is_empty()),
            "unmodified storage must not be mapped"
        );
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
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .txn_evm_output_with_frames(1, 22_000, true, 1)
        .txn_call_frame(1, bob_addr(), alice_addr(), 0xF1, 0, 22_000, 22_000)
        .txn_end()
        .txn_evm_output_with_frames(2, 23_000, true, 1)
        .txn_call_frame(2, miner_addr(), alice_addr(), 0xF1, 0, 23_000, 23_000)
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
            .txn_log(1, bob_addr(), &data) // tx1 log before tx1 header or output
            .txn_header_start(1, bob_addr(), Some(alice_addr()))
            .txn_evm_output(1, 21_000, true)
            .txn_end()
            .block_end();
    });
    assert!(
        result.is_err(),
        "expected panic: log arrived before its transaction was started"
    );
}

#[test]
fn test_tx_call_frames_arrive_after_output() {
    // So for the same tx: output -> logs -> call_frames -> account_accesses -> TxnEnd
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .txn_evm_output(1, 21_000, true)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(block.transaction_traces.len(), 2);
        assert_eq!(block.transaction_traces[0].calls.len(), 1);
        assert_eq!(
            block.transaction_traces[0].calls[0].caller,
            alice_addr().as_slice()
        );
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
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .account_access_header(1) // ctx=1 = TRANSACTION
        .account_access_balance(bob_addr(), U256::from(0u64), U256::from(100u64))
        .account_access_nonce(alice_addr(), 5, 6)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert!(
            calls.iter().any(|c| !c.balance_changes.is_empty()),
            "balance change expected"
        );
        assert!(
            calls.iter().any(|c| !c.nonce_changes.is_empty()),
            "nonce change expected"
        );
    });
}

// Log ordering: in Monad, TxnLog arrives before TxnCallFrame for the same transaction.
// A log emitted by a call must end up attached to that call in the output
/// TxnLog events arrive before TxnCallFrame events
/// A log must be attached to the root call that caused it.
#[test]
fn test_log_before_call_frame_attached_to_call() {
    let data = [0xca, 0xfe, 0xba, 0xbe];
    let mut t = MonadTracerTester::new();
    // Monad event order for a transaction: TxnEvmOutput → TxnLog* → TxnCallFrame*
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_log(0, bob_addr(), &data)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert_eq!(calls.len(), 1, "root call must exist");
        assert_eq!(calls[0].logs.len(), 1, "log must be flushed into root call");
        assert_eq!(calls[0].logs[0].address, bob_addr().as_slice());
        assert_eq!(calls[0].logs[0].data, data);
    });
}

/// A log that arrives before its call frame must also appear in the transaction receipt.
#[test]
fn test_log_before_call_frame_appears_in_receipt() {
    let data = [0x01, 0x02, 0x03];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_log(0, bob_addr(), &data)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let receipt = block.transaction_traces[0].receipt.as_ref().unwrap();
        assert_eq!(receipt.logs.len(), 1, "receipt must have 1 log");
        assert_eq!(receipt.logs[0].address, bob_addr().as_slice());
        assert_eq!(receipt.logs[0].data, data);
    });
}

/// Multiple logs arriving before their call frame must all appear in the call, in order.
#[test]
fn test_multiple_logs_before_call_frame_preserve_order() {
    let topic1 = B256::repeat_byte(0xAA);
    let topic2 = B256::repeat_byte(0xBB);
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_log_indexed(0, alice_addr(), &[topic1], &[0x01], 0)
        .txn_log_indexed(0, bob_addr(), &[topic2], &[0x02], 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        assert_eq!(
            calls[0].logs.len(),
            2,
            "both logs must be present in the call"
        );
        // Order preserved
        assert_eq!(calls[0].logs[0].data, [0x01]);
        assert_eq!(calls[0].logs[1].data, [0x02]);
        // Topics preserved
        assert_eq!(calls[0].logs[0].topics[0], topic1.as_slice());
        assert_eq!(calls[0].logs[1].topics[0], topic2.as_slice());
        // Receipt also has both
        let receipt = block.transaction_traces[0].receipt.as_ref().unwrap();
        assert_eq!(receipt.logs.len(), 2);
    });
}

/// A log from tx0 must never appear in tx1's call, even if tx0 had no call frames
#[test]
fn test_log_from_one_tx_does_not_appear_in_next_tx() {
    // tx0 emits a log but has no call frames — the log belongs to tx0 and must be discarded.
    // tx1 has a call frame but no logs — its call must be empty.
    let data = [0xDE, 0xAD];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output(0, 21_000, true) // call_frame_count=0
        .txn_log(0, bob_addr(), &data) // log belongs to tx0, no call frame to attach it to
        .txn_end()
        // tx1: no logs, has a call frame
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(1, 21_000, true, 1)
        .txn_call_frame(1, bob_addr(), alice_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        // tx1's call must have NO logs (they belonged to tx0, were cleared)
        let tx1_calls = &block.transaction_traces[1].calls;
        assert_eq!(tx1_calls.len(), 1);
        assert_eq!(
            tx1_calls[0].logs.len(),
            0,
            "log from tx0 must not appear in tx1's call"
        );
    });
}

// Call failure: a call that did not succeed must be marked failed with a reason.
// A reverted call (REVERT opcode or insufficient balance) must also be marked reverted.
// A successful call must not be marked failed.
#[test]
fn test_successful_call_is_not_failed() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 0)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(
            !call.status_failed,
            "successful call must not be marked failed"
        );
        assert!(
            call.failure_reason.is_empty(),
            "successful call must have no failure reason"
        );
    });
}

#[test]
fn test_reverted_call_is_failed_and_reverted() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, false, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 2)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(call.status_failed, "reverted call must be marked failed");
        assert!(
            call.status_reverted,
            "reverted call must be marked reverted"
        );
        assert!(
            !call.failure_reason.is_empty(),
            "reverted call must have a failure reason"
        );
    });
}

#[test]
fn test_out_of_gas_call_is_failed_not_reverted() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, false, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 3)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(call.status_failed, "OOG call must be marked failed");
        assert!(!call.status_reverted, "OOG is not a revert");
        assert!(
            !call.failure_reason.is_empty(),
            "OOG call must have a failure reason"
        );
    });
}

#[test]
fn test_insufficient_balance_call_is_failed_and_reverted() {
    // Insufficient balance is treated as a revert (no gas consumed)
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, false, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 17)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(
            call.status_failed,
            "insufficient balance call must be marked failed"
        );
        assert!(
            call.status_reverted,
            "insufficient balance is treated as reverted"
        );
        assert!(
            !call.failure_reason.is_empty(),
            "must have a failure reason"
        );
    });
}

// Precompile calls (0x01-0x09): code is considered executed even with no gas consumed.

// Block header fields: zero hashes must be full 32-byte zeros, not empty
#[test]
fn test_block_header_requests_hash_is_zero_bytes() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 0).block_end();
    t.validate(|block| {
        let h = block.header.as_ref().unwrap();
        // requests_hash must be 32 zero bytes, not an empty vec (which would serialize as "0x")
        assert_eq!(
            h.requests_hash,
            vec![0u8; 32],
            "requests_hash must be present as 32 zero bytes"
        );
    });
}

#[test]
fn test_block_header_parent_beacon_root_is_zero_bytes() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 0).block_end();
    t.validate(|block| {
        let h = block.header.as_ref().unwrap();
        assert_eq!(
            h.parent_beacon_root,
            vec![0u8; 32],
            "parent_beacon_root must be 32 zero bytes"
        );
    });
}

#[test]
fn test_block_header_blob_gas_used_is_zero() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 0).block_end();
    t.validate(|block| {
        let h = block.header.as_ref().unwrap();
        assert_eq!(h.blob_gas_used, Some(0u64), "blob_gas_used must be 0");
    });
}

#[test]
fn test_block_header_excess_blob_gas_is_zero() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 0).block_end();
    t.validate(|block| {
        let h = block.header.as_ref().unwrap();
        assert_eq!(h.excess_blob_gas, Some(0u64), "excess_blob_gas must be 0");
    });
}

// EIP-1559 fields: type 0 has none, type 2 has them
#[test]
fn test_type0_tx_no_eip1559_fields() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr())) // type=0
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let tx = &block.transaction_traces[0];
        // type 0: max_fee_per_gas and max_priority_fee_per_gas should be absent/empty
        assert!(
            tx.max_fee_per_gas.is_none()
                || tx
                    .max_fee_per_gas
                    .as_ref()
                    .map(|b| b.bytes.is_empty())
                    .unwrap_or(true),
            "type 0 tx must not have max_fee_per_gas"
        );
        assert!(
            tx.max_priority_fee_per_gas.is_none()
                || tx
                    .max_priority_fee_per_gas
                    .as_ref()
                    .map(|b| b.bytes.is_empty())
                    .unwrap_or(true),
            "type 0 tx must not have max_priority_fee_per_gas"
        );
    });
}

#[test]
fn test_type2_tx_has_eip1559_fields() {
    let max_fee = 2_000_000_000u64;
    let max_priority = 1_000_000_000u64;
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start_type2(0, alice_addr(), Some(bob_addr()), max_fee, max_priority)
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let tx = &block.transaction_traces[0];
        let mfpg = tx
            .max_fee_per_gas
            .as_ref()
            .expect("type 2 must have max_fee_per_gas");
        let mpfpg = tx
            .max_priority_fee_per_gas
            .as_ref()
            .expect("type 2 must have max_priority_fee_per_gas");
        // Decode big-endian bytes back to u64
        let mfpg_val = U256::from_be_slice(&mfpg.bytes);
        let mpfpg_val = U256::from_be_slice(&mpfpg.bytes);
        assert_eq!(mfpg_val, U256::from(max_fee), "max_fee_per_gas mismatch");
        assert_eq!(
            mpfpg_val,
            U256::from(max_priority),
            "max_priority_fee_per_gas mismatch"
        );
    });
}

/// A call with no logs must have an empty logs list.
#[test]
fn test_call_with_no_logs_has_empty_logs() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(
            block.transaction_traces[0].calls[0].logs.len(),
            0,
            "call with no emitted logs must have empty logs list"
        );
    });
}

/// A log from tx0 must not appear in tx1, even when both transactions have call frames.
#[test]
fn test_log_isolated_to_its_transaction() {
    let data = [0xAA, 0xBB];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        // tx0: emits a log
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_log(0, bob_addr(), &data)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        // tx1: no logs
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(1, 21_000, true, 1)
        .txn_call_frame(1, bob_addr(), alice_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(
            block.transaction_traces[0].calls[0].logs.len(),
            1,
            "tx0 must have its log"
        );
        assert_eq!(
            block.transaction_traces[1].calls[0].logs.len(),
            0,
            "tx1 must not receive tx0's log"
        );
    });
}

/// tx1's log must not appear in tx0, even when tx1 is processed first.
#[test]
fn test_log_does_not_bleed_backward_into_previous_tx() {
    let data = [0xCC, 0xDD];
    let mut t = MonadTracerTester::new();
    t.block_start(1, 2)
        // tx0: no logs
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        // tx1: emits a log
        .txn_header_start(1, bob_addr(), Some(alice_addr()))
        .txn_evm_output_with_frames(1, 50_000, true, 1)
        .txn_log(1, alice_addr(), &data)
        .txn_call_frame(1, bob_addr(), alice_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        assert_eq!(
            block.transaction_traces[0].calls[0].logs.len(),
            0,
            "tx0 must not receive tx1's log"
        );
        assert_eq!(
            block.transaction_traces[1].calls[0].logs.len(),
            1,
            "tx1 must have its log"
        );
    });
}

/// The number of logs in the receipt must equal the number of logs across all calls.
#[test]
fn test_receipt_log_count_matches_call_log_count() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 50_000, true, 1)
        .txn_log_indexed(0, alice_addr(), &[], &[0x01], 0)
        .txn_log_indexed(0, bob_addr(), &[], &[0x02], 1)
        .txn_log_indexed(0, alice_addr(), &[], &[0x03], 2)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let trx = &block.transaction_traces[0];
        let call_log_count: usize = trx.calls.iter().map(|c| c.logs.len()).sum();
        let receipt_log_count = trx.receipt.as_ref().unwrap().logs.len();
        assert_eq!(
            call_log_count, receipt_log_count,
            "receipt log count must equal total call log count"
        );
        assert_eq!(receipt_log_count, 3);
    });
}

/// A transaction with no logs must have an empty receipt logs list.
#[test]
fn test_no_logs_means_empty_receipt_logs() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let receipt = block.transaction_traces[0].receipt.as_ref().unwrap();
        assert_eq!(receipt.logs.len(), 0, "no logs emitted means empty receipt");
    });
}

/// A successful call must not have status_reverted set.
#[test]
fn test_successful_call_is_not_reverted() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 0)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(
            !call.status_reverted,
            "successful call must not be marked reverted"
        );
    });
}

/// A failed-but-not-reverted call (OOG, invalid opcode) must not be marked as reverted.
#[test]
fn test_failed_non_revert_call_is_not_reverted() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, false, 1)
        // status=3 is OOG — failed but not reverted
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 3)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        assert!(call.status_failed, "OOG must be failed");
        assert!(!call.status_reverted, "OOG must not be reverted");
    });
}

/// A reverted call must be failed — reverted implies failed, never the other way.
#[test]
fn test_reverted_call_is_also_failed() {
    let mut t = MonadTracerTester::new();
    t.block_start(1, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, false, 1)
        .txn_call_frame_with_status(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000, 2)
        .txn_end()
        .block_end();
    t.validate(|block| {
        let call = &block.transaction_traces[0].calls[0];
        // If reverted, failed must also be true — they are not independent
        if call.status_reverted {
            assert!(call.status_failed, "reverted implies failed");
        }
    });
}

/// With no BlockFinalized event, lib_num in the FIRE BLOCK line is 0.
#[test]
fn test_no_block_finalized_means_lib_zero() {
    let mut t = MonadTracerTester::new();
    t.block_start(10, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    assert_eq!(
        t.parse_lib_num(),
        0,
        "no BlockFinalized → lib_num must be 0"
    );
}

/// A BlockFinalized event before block execution sets the lib_num for that block.
#[test]
fn test_block_finalized_before_block_sets_lib_num() {
    let mut t = MonadTracerTester::new();
    t.block_finalized(5)
        .block_start(10, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    assert_eq!(
        t.parse_lib_num(),
        5,
        "BlockFinalized(5) must produce lib_num=5"
    );
}

/// BlockFinalized arrives after block ends (the real Monad ordering):
/// finalization is emitted by the runloop AFTER execution completes,
/// so it is reflected in the NEXT block's lib_num, not the current one.
#[test]
fn test_block_finalized_after_block_end_reflected_in_next_block() {
    let mut t = MonadTracerTester::new();
    // Block 20 executes, then BlockFinalized(15) is emitted
    t.block_start(20, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end()
        .block_finalized(15);
    // Block 21 picks up the finality signal
    t.block_start(21, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    let blocks = t.parse_all_fire_blocks();
    assert_eq!(
        blocks[0],
        (20, 0),
        "block 20: finality not yet seen → lib=0"
    );
    assert_eq!(
        blocks[1],
        (21, 15),
        "block 21: BlockFinalized(15) seen after block 20 → lib=15"
    );
}

/// Multiple BlockFinalized events: only the highest block number is used.
#[test]
fn test_highest_block_finalized_wins() {
    let mut t = MonadTracerTester::new();
    t.block_finalized(3)
        .block_finalized(7)
        .block_finalized(5) // lower than 7, must not regress
        .block_start(10, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
    assert_eq!(
        t.parse_lib_num(),
        7,
        "lib_num must be the highest BlockFinalized seen, not regress"
    );
}

/// Helper: emit a minimal single-tx block with txn_count=1.
fn emit_block(t: &mut MonadTracerTester, number: u64) {
    t.block_start(number, 1)
        .txn_header_start(0, alice_addr(), Some(bob_addr()))
        .txn_evm_output_with_frames(0, 21_000, true, 1)
        .txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 21_000, 21_000)
        .txn_end()
        .block_end();
}

/// Multi-block scenario verifying lib_num evolves correctly at each block boundary.
/// In Monad, BlockFinalized is always emitted AFTER block execution completes,
/// so the signal is reflected in the NEXT block's lib_num.
///
/// - Block 1 executes                    → lib=0
/// - BlockFinalized(1) emitted
/// - Block 2 executes                    → lib=1
/// - BlockFinalized(3)
/// - Block 3 executes                    → lib=3
/// - Block 4 executes (no new signal)    → lib=3
/// - BlockFinalized(4) emitted
/// - Block 5 executes                    → lib=4
#[test]
fn test_lfb_progression_across_multiple_blocks() {
    let mut t = MonadTracerTester::new();

    emit_block(&mut t, 1);
    t.block_finalized(1);

    emit_block(&mut t, 2);
    t.block_finalized(3);

    emit_block(&mut t, 3);
    // no BlockFinalized here

    emit_block(&mut t, 4);
    t.block_finalized(4);

    emit_block(&mut t, 5);

    let blocks = t.parse_all_fire_blocks();
    assert_eq!(blocks.len(), 5, "expected 5 FIRE BLOCK lines");

    let (b1, lib1) = blocks[0];
    let (b2, lib2) = blocks[1];
    let (b3, lib3) = blocks[2];
    let (b4, lib4) = blocks[3];
    let (b5, lib5) = blocks[4];

    assert_eq!(b1, 1);
    assert_eq!(lib1, 0, "block 1: no signal yet");
    assert_eq!(b2, 2);
    assert_eq!(lib2, 1, "block 2: BlockFinalized(1) emitted after block 1");
    assert_eq!(b3, 3);
    assert_eq!(lib3, 3, "block 3: BlockFinalized(3) emitted after block 2");
    assert_eq!(b4, 4);
    assert_eq!(
        lib4, 3,
        "block 4: no new signal after block 3, lib persists"
    );
    assert_eq!(b5, 5);
    assert_eq!(lib5, 4, "block 5: BlockFinalized(4) emitted after block 4");
}

/// Events that arrive before the first BlockStart are silently dropped (mid-stream start)
/// Simulate mid-stream: a stray TxnHeaderStart arrives before any block.
#[test]
fn test_mid_stream_events_before_block_start_are_dropped() {
    let mut t = MonadTracerTester::new();

    t.txn_header_start(0, alice_addr(), Some(bob_addr()));

    t.block_finalized(7);

    emit_block(&mut t, 10);

    assert_eq!(
        t.parse_lib_num(),
        7,
        "stray TxnHeaderStart ignored; BlockFinalized(7) seeds lib"
    );
    let blocks = t.parse_all_fire_blocks();
    assert_eq!(
        blocks.len(),
        1,
        "only one block must be emitted — stray event must not create a block"
    );
}

/// State changes (storage, nonce) that arrive via AccountAccess after all call frames have been
/// flushed (via is_last) must be attributed to the root call via the deferred state path.
/// This matches the monad event log ordering where AccountAccess events arrive after all
/// TxnCallFrame events, with no way to attribute them to a specific sub-call.
#[test]
fn test_state_changes_after_is_last_flush_attributed_to_root_call() {
    let mut t = MonadTracerTester::new();

    // Block with 1 transaction, 2 call frames: root (depth 0) + sub-call (depth 1)
    t.block_start(1, 1);
    t.txn_header_start(0, alice_addr(), Some(bob_addr()));
    // 2 call frames
    t.txn_evm_output_with_frames(0, 50_000, true, 2);
    // frame 0: root call depth=0
    t.txn_call_frame(0, alice_addr(), bob_addr(), 0xF1, 0, 50_000, 50_000);
    // frame 1: sub-call depth=1, is_last=true → triggers flush(0) closing all calls
    t.txn_call_frame(0, bob_addr(), miner_addr(), 0xF1, 1, 30_000, 30_000);

    // AccountAccessListHeader arrives after all frames are already flushed
    t.account_access_header(1);

    // State changes arrive
    t.account_access_nonce(alice_addr(), 0, 1);
    t.storage_access(
        bob_addr(),
        B256::ZERO,
        B256::ZERO,
        B256::from([1u8; 32]),
        true,
        false,
    );

    t.txn_end().block_end();

    t.validate(|block| {
        let calls = &block.transaction_traces[0].calls;
        let root_call = &calls[0];
        assert_eq!(root_call.depth, 0, "root call must be at depth 0");

        // Nonce change must be on root call, not sub-call
        assert_eq!(
            root_call.nonce_changes.len(),
            1,
            "nonce change must be attributed to root call"
        );
        assert_eq!(root_call.nonce_changes[0].old_value, 0);
        assert_eq!(root_call.nonce_changes[0].new_value, 1);

        // Storage change must be on root call, not sub-call
        assert_eq!(
            root_call.storage_changes.len(),
            1,
            "storage change must be attributed to root call"
        );
        assert_eq!(root_call.storage_changes[0].new_value, vec![1u8; 32]);

        // Sub-call must have no state changes
        let sub_call = &calls[1];
        assert_eq!(sub_call.depth, 1);
        assert_eq!(
            sub_call.nonce_changes.len(),
            0,
            "sub-call must not have nonce changes"
        );
        assert_eq!(
            sub_call.storage_changes.len(),
            0,
            "sub-call must not have storage changes"
        );
    });
}
