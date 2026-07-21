use std::sync::OnceLock;

/// A wrapper that defers hex encoding until Display is called
/// This avoids the cost of hex encoding when logging is disabled
#[derive(Debug)]
pub struct HexView<T: AsRef<[u8]>>(pub T);

impl<T: AsRef<[u8]>> std::fmt::Display for HexView<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_ref()))
    }
}

/// A wrapper that defers opcode name lookup until Display is called.
/// Resolves the opcode byte to its human-readable EVM name (e.g. `CALL`, `SSTORE`);
/// unknown opcodes fall back to `0x??` hex.
#[derive(Debug, Clone, Copy)]
pub struct OpCodeView(pub u8);

impl std::fmt::Display for OpCodeView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = OPCODE_NAMES.get(&self.0) {
            write!(f, "{}", name)
        } else {
            write!(f, "0x{:02x}", self.0)
        }
    }
}

/// Maps EVM opcode bytes to their human-readable names.
/// Covers all opcodes defined in the Yellow Paper / EVM spec including Cancun additions.
static OPCODE_NAMES: std::sync::LazyLock<std::collections::HashMap<u8, &'static str>> =
    std::sync::LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        // Stop and Arithmetic
        m.insert(0x00, "STOP");
        m.insert(0x01, "ADD");
        m.insert(0x02, "MUL");
        m.insert(0x03, "SUB");
        m.insert(0x04, "DIV");
        m.insert(0x05, "SDIV");
        m.insert(0x06, "MOD");
        m.insert(0x07, "SMOD");
        m.insert(0x08, "ADDMOD");
        m.insert(0x09, "MULMOD");
        m.insert(0x0a, "EXP");
        m.insert(0x0b, "SIGNEXTEND");
        // Comparison & Bitwise Logic
        m.insert(0x10, "LT");
        m.insert(0x11, "GT");
        m.insert(0x12, "SLT");
        m.insert(0x13, "SGT");
        m.insert(0x14, "EQ");
        m.insert(0x15, "ISZERO");
        m.insert(0x16, "AND");
        m.insert(0x17, "OR");
        m.insert(0x18, "XOR");
        m.insert(0x19, "NOT");
        m.insert(0x1a, "BYTE");
        m.insert(0x1b, "SHL");
        m.insert(0x1c, "SHR");
        m.insert(0x1d, "SAR");
        // SHA3
        m.insert(0x20, "KECCAK256");
        // Environmental Information
        m.insert(0x30, "ADDRESS");
        m.insert(0x31, "BALANCE");
        m.insert(0x32, "ORIGIN");
        m.insert(0x33, "CALLER");
        m.insert(0x34, "CALLVALUE");
        m.insert(0x35, "CALLDATALOAD");
        m.insert(0x36, "CALLDATASIZE");
        m.insert(0x37, "CALLDATACOPY");
        m.insert(0x38, "CODESIZE");
        m.insert(0x39, "CODECOPY");
        m.insert(0x3a, "GASPRICE");
        m.insert(0x3b, "EXTCODESIZE");
        m.insert(0x3c, "EXTCODECOPY");
        m.insert(0x3d, "RETURNDATASIZE");
        m.insert(0x3e, "RETURNDATACOPY");
        m.insert(0x3f, "EXTCODEHASH");
        // Block Information
        m.insert(0x40, "BLOCKHASH");
        m.insert(0x41, "COINBASE");
        m.insert(0x42, "TIMESTAMP");
        m.insert(0x43, "NUMBER");
        m.insert(0x44, "PREVRANDAO");
        m.insert(0x45, "GASLIMIT");
        m.insert(0x46, "CHAINID");
        m.insert(0x47, "SELFBALANCE");
        m.insert(0x48, "BASEFEE");
        m.insert(0x49, "BLOBHASH");
        m.insert(0x4a, "BLOBBASEFEE");
        // Stack, Memory, Storage and Flow Operations
        m.insert(0x50, "POP");
        m.insert(0x51, "MLOAD");
        m.insert(0x52, "MSTORE");
        m.insert(0x53, "MSTORE8");
        m.insert(0x54, "SLOAD");
        m.insert(0x55, "SSTORE");
        m.insert(0x56, "JUMP");
        m.insert(0x57, "JUMPI");
        m.insert(0x58, "PC");
        m.insert(0x59, "MSIZE");
        m.insert(0x5a, "GAS");
        m.insert(0x5b, "JUMPDEST");
        m.insert(0x5c, "TLOAD");
        m.insert(0x5d, "TSTORE");
        m.insert(0x5e, "MCOPY");
        m.insert(0x5f, "PUSH0");
        // Push Operations
        m.insert(0x60, "PUSH1");
        m.insert(0x61, "PUSH2");
        m.insert(0x62, "PUSH3");
        m.insert(0x63, "PUSH4");
        m.insert(0x64, "PUSH5");
        m.insert(0x65, "PUSH6");
        m.insert(0x66, "PUSH7");
        m.insert(0x67, "PUSH8");
        m.insert(0x68, "PUSH9");
        m.insert(0x69, "PUSH10");
        m.insert(0x6a, "PUSH11");
        m.insert(0x6b, "PUSH12");
        m.insert(0x6c, "PUSH13");
        m.insert(0x6d, "PUSH14");
        m.insert(0x6e, "PUSH15");
        m.insert(0x6f, "PUSH16");
        m.insert(0x70, "PUSH17");
        m.insert(0x71, "PUSH18");
        m.insert(0x72, "PUSH19");
        m.insert(0x73, "PUSH20");
        m.insert(0x74, "PUSH21");
        m.insert(0x75, "PUSH22");
        m.insert(0x76, "PUSH23");
        m.insert(0x77, "PUSH24");
        m.insert(0x78, "PUSH25");
        m.insert(0x79, "PUSH26");
        m.insert(0x7a, "PUSH27");
        m.insert(0x7b, "PUSH28");
        m.insert(0x7c, "PUSH29");
        m.insert(0x7d, "PUSH30");
        m.insert(0x7e, "PUSH31");
        m.insert(0x7f, "PUSH32");
        // Duplication Operations
        m.insert(0x80, "DUP1");
        m.insert(0x81, "DUP2");
        m.insert(0x82, "DUP3");
        m.insert(0x83, "DUP4");
        m.insert(0x84, "DUP5");
        m.insert(0x85, "DUP6");
        m.insert(0x86, "DUP7");
        m.insert(0x87, "DUP8");
        m.insert(0x88, "DUP9");
        m.insert(0x89, "DUP10");
        m.insert(0x8a, "DUP11");
        m.insert(0x8b, "DUP12");
        m.insert(0x8c, "DUP13");
        m.insert(0x8d, "DUP14");
        m.insert(0x8e, "DUP15");
        m.insert(0x8f, "DUP16");
        // Exchange Operations
        m.insert(0x90, "SWAP1");
        m.insert(0x91, "SWAP2");
        m.insert(0x92, "SWAP3");
        m.insert(0x93, "SWAP4");
        m.insert(0x94, "SWAP5");
        m.insert(0x95, "SWAP6");
        m.insert(0x96, "SWAP7");
        m.insert(0x97, "SWAP8");
        m.insert(0x98, "SWAP9");
        m.insert(0x99, "SWAP10");
        m.insert(0x9a, "SWAP11");
        m.insert(0x9b, "SWAP12");
        m.insert(0x9c, "SWAP13");
        m.insert(0x9d, "SWAP14");
        m.insert(0x9e, "SWAP15");
        m.insert(0x9f, "SWAP16");
        // Logging Operations
        m.insert(0xa0, "LOG0");
        m.insert(0xa1, "LOG1");
        m.insert(0xa2, "LOG2");
        m.insert(0xa3, "LOG3");
        m.insert(0xa4, "LOG4");
        // System Operations
        m.insert(0xf0, "CREATE");
        m.insert(0xf1, "CALL");
        m.insert(0xf2, "CALLCODE");
        m.insert(0xf3, "RETURN");
        m.insert(0xf4, "DELEGATECALL");
        m.insert(0xf5, "CREATE2");
        m.insert(0xfa, "STATICCALL");
        m.insert(0xfd, "REVERT");
        m.insert(0xfe, "INVALID");
        m.insert(0xff, "SELFDESTRUCT");
        m
    });

/// Firehose Tracer log levels matching the Go implementation:
/// - Info: block start/end + trx start/end
/// - Debug: Info + call start/end + error
/// - Trace: Debug + state db changes, log, balance, nonce, code, storage, gas
/// - TraceFull: Trace + opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirehoseLogLevel {
    Disabled,
    Info,
    Debug,
    Trace,
    TraceFull,
}

impl FirehoseLogLevel {
    /// Parse log level from environment variable string
    fn from_env_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            "trace_full" => Self::TraceFull,
            _ => Self::Disabled,
        }
    }

    /// Check if info-level logging is enabled
    fn is_info_enabled(self) -> bool {
        matches!(
            self,
            Self::Info | Self::Debug | Self::Trace | Self::TraceFull
        )
    }

    /// Check if debug-level logging is enabled
    fn is_debug_enabled(self) -> bool {
        matches!(self, Self::Debug | Self::Trace | Self::TraceFull)
    }

    /// Check if trace-level logging is enabled
    fn is_trace_enabled(self) -> bool {
        matches!(self, Self::Trace | Self::TraceFull)
    }

    /// Check if trace-full-level logging is enabled
    fn is_trace_full_enabled(self) -> bool {
        matches!(self, Self::TraceFull)
    }
}

/// Global log level, evaluated lazily from environment variable
static FIREHOSE_LOG_LEVEL: OnceLock<FirehoseLogLevel> = OnceLock::new();

/// Get the current Firehose log level, evaluating from environment only once
fn get_firehose_log_level() -> FirehoseLogLevel {
    *FIREHOSE_LOG_LEVEL.get_or_init(|| {
        std::env::var("FIREHOSE_ETHEREUM_TRACER_LOG_LEVEL")
            .map(|level| FirehoseLogLevel::from_env_str(&level))
            .unwrap_or(FirehoseLogLevel::Disabled)
    })
}

/// Check if Firehose info-level logging is enabled
#[inline]
pub fn is_firehose_info_enabled() -> bool {
    get_firehose_log_level().is_info_enabled()
}

/// Check if Firehose debug-level logging is enabled
#[inline]
pub fn is_firehose_debug_enabled() -> bool {
    get_firehose_log_level().is_debug_enabled()
}

/// Check if Firehose trace-level logging is enabled
#[inline]
pub fn is_firehose_trace_enabled() -> bool {
    get_firehose_log_level().is_trace_enabled()
}

/// Check if Firehose trace-full-level logging is enabled
#[inline]
pub fn is_firehose_trace_full_enabled() -> bool {
    get_firehose_log_level().is_trace_full_enabled()
}

/// Firehose info-level logging macro
/// Only processes arguments if info logging is enabled
#[macro_export]
macro_rules! firehose_info {
    ($($arg:tt)*) => {
        if $crate::logging::is_firehose_info_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose debug-level logging macro
/// Only processes arguments if debug logging is enabled
#[macro_export]
macro_rules! firehose_debug {
    ($($arg:tt)*) => {
        if $crate::logging::is_firehose_debug_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose trace-level logging macro
/// Only processes arguments if trace logging is enabled
#[macro_export]
macro_rules! firehose_trace {
    ($($arg:tt)*) => {
        if $crate::logging::is_firehose_trace_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose trace-full-level logging macro
/// Only processes arguments if trace-full logging is enabled
#[macro_export]
macro_rules! firehose_trace_full {
    ($($arg:tt)*) => {
        if $crate::logging::is_firehose_trace_full_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(
            FirehoseLogLevel::from_env_str("info"),
            FirehoseLogLevel::Info
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str("INFO"),
            FirehoseLogLevel::Info
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str("debug"),
            FirehoseLogLevel::Debug
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str("trace"),
            FirehoseLogLevel::Trace
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str("trace_full"),
            FirehoseLogLevel::TraceFull
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str("invalid"),
            FirehoseLogLevel::Disabled
        );
        assert_eq!(
            FirehoseLogLevel::from_env_str(""),
            FirehoseLogLevel::Disabled
        );
    }

    #[test]
    fn test_log_level_enablement() {
        // Test Info level
        let info = FirehoseLogLevel::Info;
        assert!(info.is_info_enabled());
        assert!(!info.is_debug_enabled());
        assert!(!info.is_trace_enabled());
        assert!(!info.is_trace_full_enabled());

        // Test Debug level
        let debug = FirehoseLogLevel::Debug;
        assert!(debug.is_info_enabled());
        assert!(debug.is_debug_enabled());
        assert!(!debug.is_trace_enabled());
        assert!(!debug.is_trace_full_enabled());

        // Test Trace level
        let trace = FirehoseLogLevel::Trace;
        assert!(trace.is_info_enabled());
        assert!(trace.is_debug_enabled());
        assert!(trace.is_trace_enabled());
        assert!(!trace.is_trace_full_enabled());

        // Test TraceFull level
        let trace_full = FirehoseLogLevel::TraceFull;
        assert!(trace_full.is_info_enabled());
        assert!(trace_full.is_debug_enabled());
        assert!(trace_full.is_trace_enabled());
        assert!(trace_full.is_trace_full_enabled());

        // Test Disabled level
        let disabled = FirehoseLogLevel::Disabled;
        assert!(!disabled.is_info_enabled());
        assert!(!disabled.is_debug_enabled());
        assert!(!disabled.is_trace_enabled());
        assert!(!disabled.is_trace_full_enabled());
    }

    #[test]
    fn test_hex_view() {
        let data = vec![0x42, 0xff, 0x00, 0xab];
        let hex_view = super::HexView(&data);

        // HexView should format the same as hex::encode
        assert_eq!(format!("{}", hex_view), hex::encode(&data));
        assert_eq!(format!("{}", hex_view), "42ff00ab");

        // Test with slice
        let slice = &[0x12, 0x34];
        let hex_view_slice = super::HexView(slice);
        assert_eq!(format!("{}", hex_view_slice), "1234");
    }
}
