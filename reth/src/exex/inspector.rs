use alloy_primitives::{Address, Log as AlloyLog, U256};
use firehose::{Opcode, StringError};
use reth::api::FullNodeComponents;
use reth::revm::revm::context_interface::{ContextTr, JournalTr};
use reth::revm::revm::inspector::{Inspector, JournalExt};
use reth::revm::revm::interpreter::{
    interpreter::EthInterpreter, interpreter_types::Jumps, CallInputs, CallOutcome, CreateInputs,
    CreateOutcome, Interpreter,
};

/// FirehoseInspector captures execution traces for the Firehose format
/// It hooks into EVM execution via the Inspector trait to build a complete call tree
pub struct Firehose<'a, Node: FullNodeComponents> {
    tracer: &'a mut firehose::Tracer,
    _phantom: std::marker::PhantomData<Node>,
}

impl<'a, Node: FullNodeComponents> Firehose<'a, Node> {
    pub fn new(tracer: &'a mut firehose::Tracer) -> Self {
        Self {
            tracer,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns a mutable reference to the tracer, allowing the runner to call tracer lifecycle
    /// methods (on_tx_start, on_tx_end, etc.) while the inspector owns the tracer borrow.
    pub fn tracer_mut(&mut self) -> &mut firehose::Tracer {
        self.tracer
    }

    /// Capture KECCAK256 preimage from the interpreter state.
    ///
    /// Called from `step` before the opcode executes. The stack still holds
    /// the inputs: stack[0] = offset, stack[1] = size.
    ///
    /// Since `step` fires before memory resize, the memory region may not yet
    /// be allocated. Like Geth's `scope.Memory.GetPtr`, we zero-pad any bytes
    /// beyond current memory length to produce a complete preimage.
    fn step_keccak256(tracer: &mut firehose::Tracer, interp: &mut Interpreter<EthInterpreter>) {
        let (Ok(offset), Ok(size)) = (interp.stack.peek(0), interp.stack.peek(1)) else {
            return;
        };

        let len = size.saturating_to::<usize>();
        if len == 0 {
            tracer.on_keccak_preimage(alloy_primitives::utils::KECCAK256_EMPTY, &[]);
            return;
        }

        let offset = offset.saturating_to::<usize>();
        let mem_len = interp.memory.len();

        if offset.checked_add(len).is_some_and(|end| end <= mem_len) {
            // Happy path: entire region is within current memory, no allocation
            let preimage = interp.memory.slice_len(offset, len);
            let hash = alloy_primitives::keccak256(&*preimage);
            tracer.on_keccak_preimage(hash, &preimage);
        } else {
            // Memory not yet resized (step fires before resize_memory!).
            // Zero-pad like Geth's Memory.GetPtr to produce a complete preimage.
            let mut buf = vec![0u8; len];
            if offset < mem_len {
                let copy_len = (mem_len - offset).min(len);
                buf[..copy_len].copy_from_slice(&interp.memory.slice_len(offset, copy_len));
            }
            let hash = alloy_primitives::keccak256(&buf);
            tracer.on_keccak_preimage(hash, &buf);
        }
    }

    /// Map EVM call scheme to Firehose call type opcode
    fn map_call_type_opcode(scheme: &reth::revm::revm::interpreter::CallScheme) -> u8 {
        use reth::revm::revm::interpreter::CallScheme;
        match scheme {
            CallScheme::Call => Opcode::Call as u8,
            CallScheme::CallCode => Opcode::CallCode as u8,
            CallScheme::DelegateCall => Opcode::DelegateCall as u8,
            CallScheme::StaticCall => Opcode::StaticCall as u8,
        }
    }

    /// Format EVM execution failure reason to match Geth's format
    fn failure_reason(result: reth::revm::revm::interpreter::InstructionResult) -> StringError {
        use reth::revm::revm::interpreter::InstructionResult;
        StringError(match result {
            InstructionResult::Revert => "execution reverted".to_string(),
            InstructionResult::InvalidFEOpcode => "invalid opcode: INVALID".to_string(),
            other => format!("{:?}", other),
        })
    }
}

impl<'a, Node: FullNodeComponents, CTX> Inspector<CTX, EthInterpreter> for Firehose<'a, Node>
where
    CTX: ContextTr,
    CTX::Journal: JournalExt,
{
    /// Called before each opcode executes (equivalent to Geth's OnOpcode hook)
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, context: &mut CTX) {
        let pc = interp.bytecode.pc() as u64;
        let op = interp.bytecode.opcode();
        let gas = interp.gas.remaining();
        let depth = context.journal().depth() as i32;

        self.tracer.on_opcode(pc, op, gas, 0, &[], depth, None);

        if op == Opcode::Keccak256 as u8 {
            Self::step_keccak256(&mut self.tracer, interp);
        }
    }

    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL is made
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let depth = context.journal().depth() as i32;
        let call_type = Self::map_call_type_opcode(&inputs.scheme);

        log_journal("call_enter", context);

        self.tracer.on_call_enter(
            depth,
            call_type,
            inputs.caller,
            inputs.target_address,
            inputs.input.bytes(context).as_ref(),
            inputs.gas_limit,
            inputs.value.get(),
        );

        None
    }

    /// CALL* operation completes
    fn call_end(&mut self, context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        log_journal("call_exit", context);

        let depth = context.journal().depth() as i32;
        let failed = !outcome.result.is_ok();
        let is_revert = outcome.result.result.is_revert();
        let err: Option<StringError> = if failed {
            Some(Self::failure_reason(outcome.result.result))
        } else {
            None
        };

        // EVM semantics: a halting error (not a revert) consumes all gas
        // allocated to the call. revm's gas.spent() only tracks opcodes that
        // actually executed, so we use gas.limit for non-revert failures.
        // Reverts only consume gas actually spent (remaining gas is returned).
        let gas_used = if failed && !is_revert {
            outcome.result.gas.limit()
        } else {
            outcome.result.gas.spent()
        };

        // The `reverted` parameter in on_call_exit means "did the call fail"
        // (any failure), not specifically "was it a REVERT opcode". The tracer
        // internally distinguishes reverts from other failures via the error string.
        self.tracer.on_call_exit(
            depth,
            outcome.result.output.as_ref(),
            gas_used,
            err.as_ref().map(|e| e as &dyn std::error::Error),
            failed,
        );
    }

    /// CREATE or CREATE2 is made
    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        use reth::revm::revm::context_interface::CreateScheme;

        let depth = context.journal().depth() as i32;
        let (call_type, created_address) = match inputs.scheme() {
            CreateScheme::Create2 { .. } => {
                // CREATE2 address is deterministic, no nonce needed
                (Opcode::Create2 as u8, inputs.created_address(0))
            }
            _ => {
                // CREATE address requires caller nonce
                let nonce = context
                    .journal_mut()
                    .load_account(inputs.caller())
                    .map(|acc| acc.info.nonce)
                    .unwrap_or(0);
                (Opcode::Create as u8, inputs.created_address(nonce))
            }
        };

        log_journal("create_enter", context);

        self.tracer.on_call_enter(
            depth,
            call_type,
            inputs.caller(),
            created_address,
            inputs.init_code(),
            inputs.gas_limit(),
            inputs.value(),
        );

        None
    }

    /// CREATE* operation completes
    fn create_end(
        &mut self,
        context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        log_journal("create_exit", context);

        let depth = context.journal().depth() as i32;
        let failed = !outcome.result.is_ok();
        let is_revert = outcome.result.result.is_revert();
        let err: Option<StringError> = if failed {
            Some(Self::failure_reason(outcome.result.result))
        } else {
            None
        };

        let gas_used = if failed && !is_revert {
            outcome.result.gas.limit()
        } else {
            outcome.result.gas.spent()
        };

        self.tracer.on_call_exit(
            depth,
            outcome.result.output.as_ref(),
            gas_used,
            err.as_ref().map(|e| e as &dyn std::error::Error),
            failed,
        );
    }

    /// LOG operation is executed
    fn log_full(
        &mut self,
        _interp: &mut Interpreter<EthInterpreter>,
        context: &mut CTX,
        log: AlloyLog,
    ) {
        // The journal tracks all non-reverted logs. log_full fires after the
        // log is appended, so logs().len() - 1 is this log's block-wide index.
        // On revert, the journal truncates logs back, so subsequent logs after
        // a revert get correct indices automatically.
        let block_index = (context.journal().logs().len() as u32).saturating_sub(1);
        self.tracer
            .on_log(log.address, log.topics(), &log.data.data, block_index);
    }

    /// SELFDESTRUCT is executed
    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        // In Geth's tracer, SELFDESTRUCT is modelled as a nested call at depth+1.
        // on_call_enter with OP_SELFDESTRUCT sets the `latest_call_enter_suicided` flag
        // and on_call_exit immediately clears it (no-op on call stack).
        // Depth doesn't affect SELFDESTRUCT handling so we use 1 (any non-zero value).
        self.tracer.on_call_enter(
            1,
            Opcode::SelfDestruct as u8,
            contract,
            target,
            &[],
            0,
            value,
        );
        self.tracer.on_call_exit(1, &[], 0, None, false);
    }
}

/// Logs the current journal entries (since the last checkpoint) using firehose trace-level logging.
///
/// The journal records state mutations made by the EVM: balance transfers, nonce bumps, storage
/// writes, account creation/warming, etc. This function is meant to be called at interesting
/// points during execution (e.g. before/after call/create) to aid debugging.
pub fn log_journal<CTX>(label: &str, context: &CTX)
where
    CTX: ContextTr,
    CTX::Journal: JournalExt,
{
    use reth::revm::revm::context::JournalEntry;

    if !firehose::logging::is_firehose_debug_enabled() {
        return;
    }

    let journal = context.journal().journal();
    if journal.is_empty() {
        firehose::firehose_debug!("{}: journal empty", label);
        return;
    }

    firehose::firehose_debug!("{}: journal ({} entries)", label, journal.len());
    for (i, entry) in journal.iter().enumerate() {
        match entry {
            JournalEntry::AccountTouched { address } => {
                firehose::firehose_debug!("  [{i}] AccountTouched addr={address}");
            }
            JournalEntry::AccountDestroyed {
                address,
                target,
                had_balance,
                ..
            } => {
                firehose::firehose_debug!(
                    "  [{i}] AccountDestroyed addr={address} target={target} balance={had_balance}"
                );
            }
            JournalEntry::BalanceChange {
                address,
                old_balance,
            } => {
                firehose::firehose_debug!("  [{i}] BalanceChange addr={address} old={old_balance}");
            }
            JournalEntry::BalanceTransfer { from, to, balance } => {
                firehose::firehose_debug!(
                    "  [{i}] BalanceTransfer from={from} to={to} amount={balance}"
                );
            }
            JournalEntry::NonceChange {
                address,
                previous_nonce,
            } => {
                firehose::firehose_debug!(
                    "  [{i}] NonceChange addr={address} prev_nonce={previous_nonce}"
                );
            }
            JournalEntry::NonceBump { address } => {
                firehose::firehose_debug!("  [{i}] NonceBump addr={address}");
            }
            JournalEntry::AccountCreated {
                address,
                is_created_globally,
            } => {
                firehose::firehose_debug!(
                    "  [{i}] AccountCreated addr={address} global={is_created_globally}"
                );
            }
            JournalEntry::StorageChanged {
                address,
                key,
                had_value,
            } => {
                firehose::firehose_debug!(
                    "  [{i}] StorageChanged addr={address} key={key} had={had_value}"
                );
            }
            JournalEntry::CodeChange { address } => {
                firehose::firehose_debug!("  [{i}] CodeChange addr={address}");
            }
            // Skip warm/cold tracking and transient storage — not relevant for Firehose
            _ => {}
        }
    }
}

/// Logs the EvmState (accounts and their info) using firehose trace-level logging.
///
/// This logs all accounts that have been touched/modified in the state, along with their
/// balance, nonce, code hash, and status flags. Useful for inspecting the full state picture
/// at a given point (e.g. via the OnStateHook after each transaction/system call).
pub fn log_evm_state(label: &str, state: &reth::revm::revm::state::EvmState) {
    if !firehose::logging::is_firehose_debug_enabled() {
        return;
    }

    if state.is_empty() {
        firehose::firehose_debug!("{}: evm_state empty", label);
        return;
    }

    firehose::firehose_debug!("{}: evm_state ({} accounts)", label, state.len());
    for (addr, account) in state {
        let info = &account.info;
        let storage_count = account.storage.len();
        firehose::firehose_debug!(
            "  {addr} balance={} nonce={} code_hash={} status={:?} storage_slots={storage_count}",
            info.balance,
            info.nonce,
            info.code_hash,
            account.status,
        );
    }
}
