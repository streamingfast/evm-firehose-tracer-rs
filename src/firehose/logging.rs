use std::sync::OnceLock;

/// A wrapper that defers hex encoding until Display is called
/// This avoids the cost of hex encoding when logging is disabled
pub struct HexView<T: AsRef<[u8]>>(pub T);

impl<T: AsRef<[u8]>> std::fmt::Display for HexView<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_ref()))
    }
}

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
        if $crate::firehose::logging::is_firehose_info_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose debug-level logging macro
/// Only processes arguments if debug logging is enabled
#[macro_export]
macro_rules! firehose_debug {
    ($($arg:tt)*) => {
        if $crate::firehose::logging::is_firehose_debug_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose trace-level logging macro
/// Only processes arguments if trace logging is enabled
#[macro_export]
macro_rules! firehose_trace {
    ($($arg:tt)*) => {
        if $crate::firehose::logging::is_firehose_trace_enabled() {
            eprintln!("[Firehose] {}", format!($($arg)*));
        }
    };
}

/// Firehose trace-full-level logging macro
/// Only processes arguments if trace-full logging is enabled
#[macro_export]
macro_rules! firehose_trace_full {
    ($($arg:tt)*) => {
        if $crate::firehose::logging::is_firehose_trace_full_enabled() {
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
