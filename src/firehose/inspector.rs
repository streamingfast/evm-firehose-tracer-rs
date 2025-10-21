use crate::firehose::Tracer;
use crate::pb::sf::ethereum::r#type::v2::CallType;
use crate::prelude::*;
use alloy_primitives::{Address, U256, Log as AlloyLog, Bytes};
use reth::revm::revm::context_interface::{ContextTr, LocalContextTr};
use reth::revm::revm::inspector::Inspector;
use reth::revm::revm::interpreter::{
    interpreter::EthInterpreter, CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter,
};

/// FirehoseInspector captures execution traces for the Firehose format
/// It hooks into EVM execution via the Inspector trait to build a complete call tree
pub struct FirehoseInspector<'a, Node: FullNodeComponents> {
    pub tracer: &'a mut Tracer<Node>,
}

impl<'a, Node: FullNodeComponents> FirehoseInspector<'a, Node> {
    pub fn new(tracer: &'a mut Tracer<Node>) -> Self {
        Self { tracer }
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

    /// Map create scheme to Firehose CallType
    fn map_create_type(_create2: bool) -> CallType {
        // Both CREATE and CREATE2 map to Create in the protobuf enum
        CallType::Create
    }
}

impl<'a, Node: FullNodeComponents, CTX> Inspector<CTX, EthInterpreter>
    for FirehoseInspector<'a, Node>
where
    CTX: ContextTr,
{
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL is made
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let call_type = Self::map_call_type(&inputs.scheme);

        // Extract the value from CallValue enum
        let value = match &inputs.value {
            reth::revm::revm::interpreter::CallValue::Transfer(v) |
            reth::revm::revm::interpreter::CallValue::Apparent(v) => *v,
        };

        // Extract input bytes from CallInput enum
        let input_bytes = match &inputs.input {
            reth::revm::revm::interpreter::CallInput::Bytes(bytes) => bytes.clone(),
            reth::revm::revm::interpreter::CallInput::SharedBuffer(range) => {
                let buffer = context.local().shared_memory_buffer();
                let borrowed = buffer.borrow();
                if range.end <= borrowed.len() {
                    Bytes::copy_from_slice(&borrowed[range.clone()])
                } else {
                    Bytes::new()
                }
            }
        };

        self.tracer.on_call_enter(
            inputs.caller,
            inputs.target_address,
            input_bytes,
            inputs.gas_limit,
            value,
            call_type as i32,
        );

        None
    }

    /// CALL* operation completes
    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        let success = outcome.result.is_ok();
        self.tracer.on_call_exit(
            outcome.result.output.clone(),
            outcome.result.gas.spent(),
            success,
        );
    }

    /// CREATE or CREATE2 is made
    fn create(&mut self, _context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        use reth::revm::revm::interpreter::CreateScheme;
        let is_create2 = matches!(inputs.scheme, CreateScheme::Create2 { .. });
        let call_type = Self::map_create_type(is_create2);

        self.tracer.on_create_enter(
            inputs.caller,
            inputs.init_code.clone(),
            inputs.gas_limit,
            inputs.value,
            call_type as i32,
        );

        None
    }

    /// CREATE* operation completes
    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        let created_address = outcome.address.unwrap_or_default();
        let success = outcome.result.is_ok();

        self.tracer.on_create_exit(
            outcome.result.output.clone(),
            outcome.result.gas.spent(),
            success,
            created_address,
        );
    }

    /// LOG operation is executed
    fn log(&mut self, _interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX, log: AlloyLog) {
        self.tracer.on_log(log);
    }

    /// SELFDESTRUCT is executed
    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.tracer.on_selfdestruct(contract, target, value);
    }
}
