use alloy_primitives::{Address, Log as AlloyLog, U256};
use pb::sf::ethereum::r#type::v2::CallType;
use reth::api::FullNodeComponents;
use reth::revm::revm::context_interface::ContextTr;
use reth::revm::revm::inspector::Inspector;
use reth::revm::revm::interpreter::{
    interpreter::EthInterpreter, CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter,
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

    /// Map EVM call scheme to Firehose CallType
    fn map_call_type(scheme: &reth::revm::revm::interpreter::CallScheme) -> CallType {
        use reth::revm::revm::interpreter::CallScheme;
        match scheme {
            CallScheme::Call => CallType::Call,
            CallScheme::CallCode => CallType::Callcode,
            CallScheme::DelegateCall => CallType::Delegate,
            CallScheme::StaticCall => CallType::Static,
        }
    }
}

impl<'a, Node: FullNodeComponents, CTX> Inspector<CTX, EthInterpreter> for Firehose<'a, Node>
where
    CTX: ContextTr,
    CTX::Journal: reth::revm::revm::inspector::JournalExt,
{
    /// Called after each step of EVM execution (AFTER opcode executes)
    fn step_end(&mut self, _interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        // FIXME: Re-implement correct mapping, also check if in Geth the on_opcode hook is called after opcode
        // execution (which would mean using step_end) or before (which would mean using step)
        // self.tracer.on_opcode(interp, context);
    }

    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL is made
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let call_type = Self::map_call_type(&inputs.scheme);

        self.tracer.on_call_enter(
            // FIXME: We might need to deal with depth here (depth++, depth--) on call/call_end (and probably mixed with create/create_end)
            0,
            // FIXME: Maps to OPCODE as it was shared tracer expect here
            call_type as u8,
            inputs.caller,
            inputs.target_address,
            inputs.input.bytes(context).as_ref(),
            inputs.gas_limit,
            inputs.value.get(),
        );

        None
    }

    /// CALL* operation completes
    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        use reth::revm::revm::interpreter::InstructionResult;

        let success = outcome.result.is_ok();
        let (is_revert, _failure_reason) = if success {
            (false, None)
        } else {
            // Only REVERT instruction is considered a revert
            let is_revert = matches!(outcome.result.result, InstructionResult::Revert);

            // Format failure reason to match Geth's format
            let reason = match outcome.result.result {
                InstructionResult::Revert => "execution reverted".to_string(),
                InstructionResult::InvalidFEOpcode => "invalid opcode: INVALID".to_string(),
                other => format!("{:?}", other),
            };
            (is_revert, Some(reason))
        };

        self.tracer.on_call_exit(
            // FIXME: We might need to deal with depth here (depth++, depth--) on call/call_end (and probably mixed with create/create_end)
            0,
            outcome.result.output.as_ref(),
            outcome.result.gas.spent(),
            // FIXME: We need to fix the error it should be the failure_reason wrapped so that it fits in a &dyn StdError
            None,
            is_revert,
        );
    }

    /// CREATE or CREATE2 is made
    fn create(&mut self, _context: &mut CTX, _inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        // FIXME: Re-implement correct mapping based on call(...) implementation
        // use reth::revm::revm::interpreter::CreateScheme;
        // let is_create2 = matches!(inputs.scheme, CreateScheme::Create2 { .. });
        // let call_type = Self::map_create_type(is_create2);

        // self.tracer.on_create_enter(
        //     inputs.caller,
        //     inputs.init_code.clone(),
        //     inputs.gas_limit,
        //     inputs.value,
        //     call_type as i32,
        // );

        None
    }

    /// CREATE* operation completes
    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        use reth::revm::revm::interpreter::InstructionResult;

        let created_address = outcome.address.unwrap_or_default();
        let success = outcome.result.is_ok();
        let (is_revert, failure_reason) = if success {
            (false, String::new())
        } else {
            // Only REVERT instruction is considered a revert
            let is_revert = matches!(outcome.result.result, InstructionResult::Revert);

            // Format failure reason to match Geth's format
            let reason = match outcome.result.result {
                InstructionResult::Revert => "execution reverted".to_string(),
                InstructionResult::InvalidFEOpcode => "invalid opcode: INVALID".to_string(),
                other => format!("{:?}", other),
            };
            (is_revert, reason)
        };

        // FIXME: Re-implement correct mapping based on call_end(...) implementation
        let _ = (created_address, success, is_revert, failure_reason);
        // self.tracer.on_create_exit(
        //     outcome.result.output.clone(),
        //     outcome.result.gas.spent(),
        //     success,
        //     created_address,
        //     is_revert,
        //     failure_reason,
        // );
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
    fn selfdestruct(&mut self, _contract: Address, _target: Address, _value: U256) {
        // FIXME: Re-implement correct mapping
        // self.tracer.on_selfdestruct(contract, target, value);
    }
}
