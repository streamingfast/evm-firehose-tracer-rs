use alloy_primitives::{Address, Log as AlloyLog, U256};
use firehose::{Opcode, StringError};
use reth::api::FullNodeComponents;
use reth::revm::revm::context_interface::{ContextTr, JournalTr};
use reth::revm::revm::inspector::Inspector;
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
    CTX::Journal: reth::revm::revm::inspector::JournalExt,
{
    /// Called before each opcode executes (equivalent to Geth's OnOpcode hook)
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, context: &mut CTX) {
        let pc = interp.bytecode.pc() as u64;
        let op = interp.bytecode.opcode();
        let gas = interp.gas.remaining();
        let depth = context.journal().depth() as i32;

        self.tracer.on_opcode(pc, op, gas, 0, &[], depth, None);

        // FIXME: Implement on_keccak_preimage by checking for KECCAK256 opcode and
        // peeking into the stack for the preimage recomputing it. This was possible
        // in Geth as we had access to memory, hopefully Interpreter exposes memory...
    }

    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL is made
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let depth = context.journal().depth() as i32;
        let call_type = Self::map_call_type_opcode(&inputs.scheme);

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
        use reth::revm::revm::interpreter::InstructionResult;

        let depth = context.journal().depth() as i32;
        let success = outcome.result.is_ok();
        let (is_revert, err): (bool, Option<StringError>) = if success {
            (false, None)
        } else {
            let is_revert = matches!(outcome.result.result, InstructionResult::Revert);
            (is_revert, Some(Self::failure_reason(outcome.result.result)))
        };

        self.tracer.on_call_exit(
            depth,
            outcome.result.output.as_ref(),
            outcome.result.gas.spent(),
            err.as_ref().map(|e| e as &dyn std::error::Error),
            is_revert,
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
        use reth::revm::revm::interpreter::InstructionResult;

        let depth = context.journal().depth() as i32;
        let success = outcome.result.is_ok();
        let (is_revert, err): (bool, Option<StringError>) = if success {
            (false, None)
        } else {
            let is_revert = matches!(outcome.result.result, InstructionResult::Revert);
            (is_revert, Some(Self::failure_reason(outcome.result.result)))
        };

        self.tracer.on_call_exit(
            depth,
            outcome.result.output.as_ref(),
            outcome.result.gas.spent(),
            err.as_ref().map(|e| e as &dyn std::error::Error),
            is_revert,
        );
    }

    /// LOG operation is executed
    fn log_full(
        &mut self,
        _interp: &mut Interpreter<EthInterpreter>,
        _context: &mut CTX,
        log: AlloyLog,
    ) {
        self.tracer
            .on_log(log.address, log.topics(), &log.data.data, 0);
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
