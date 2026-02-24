use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

/// ChainConfig defines the chain configuration for the tracer
/// Simplified version - assumes all historical forks are active
/// Only tracks future timestamp-based forks that may affect tracing behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID for the blockchain
    pub chain_id: u64,

    // Timestamp-based forks (None = not activated, Some(0) = activated at genesis)
    // These are kept for potential future tracing behavior changes
    /// EIP-3651, EIP-3855, EIP-3860, EIP-4895 (withdrawals)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shanghai_time: Option<u64>,

    /// EIP-4844 (blobs), EIP-1153 (transient storage), EIP-5656, EIP-6780
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancun_time: Option<u64>,

    /// EIP-7702 (set code), EIP-2537 (BLS precompile)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prague_time: Option<u64>,

    /// Verkle tree transition (future)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verkle_time: Option<u64>,
}

impl ChainConfig {
    /// Create a new chain configuration
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            shanghai_time: None,
            cancun_time: None,
            prague_time: None,
            verkle_time: None,
        }
    }

    /// Returns whether the given timestamp is >= Shanghai fork
    pub fn is_shanghai(&self, _num: u64, timestamp: u64) -> bool {
        is_timestamp_forked(self.shanghai_time, timestamp)
    }

    /// Returns whether the given timestamp is >= Cancun fork
    pub fn is_cancun(&self, _num: u64, timestamp: u64) -> bool {
        is_timestamp_forked(self.cancun_time, timestamp)
    }

    /// Returns whether the given timestamp is >= Prague fork
    pub fn is_prague(&self, _num: u64, timestamp: u64) -> bool {
        is_timestamp_forked(self.prague_time, timestamp)
    }

    /// Returns whether the given timestamp is >= Verkle fork
    pub fn is_verkle(&self, _num: u64, timestamp: u64) -> bool {
        is_timestamp_forked(self.verkle_time, timestamp)
    }

    /// Computes the active fork rules for a specific block
    /// Note: All historical block-based forks (Homestead, Berlin, London, etc.) are assumed active
    pub fn rules(&self, num: u64, is_merge: bool, timestamp: u64) -> Rules {
        Rules {
            chain_id: self.chain_id,
            is_merge,
            is_shanghai: self.is_shanghai(num, timestamp),
            is_cancun: self.is_cancun(num, timestamp),
            is_prague: self.is_prague(num, timestamp),
            is_verkle: self.is_verkle(num, timestamp),
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::new(1) // Default to Ethereum mainnet
    }
}

/// Rules wraps ChainConfig and provides block-scoped fork flags
/// Computed ONCE per block, then passed to tracer hooks
/// Simplified - only tracks what's actually needed for tracing behavior
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    /// Chain ID for the blockchain
    pub chain_id: u64,

    // Timestamp-based forks
    /// Post-merge (PoS)
    pub is_merge: bool,

    /// EIP-4895 withdrawals
    pub is_shanghai: bool,

    /// EIP-4844 blobs, EIP-1153 transient storage
    pub is_cancun: bool,

    /// EIP-7702 set code
    pub is_prague: bool,

    /// Verkle tree transition
    pub is_verkle: bool,
}

impl Rules {
    /// Create rules from individual fork flags (useful for testing)
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            is_merge: false,
            is_shanghai: false,
            is_cancun: false,
            is_prague: false,
            is_verkle: false,
        }
    }

    /// Builder method to set merge flag
    pub fn with_merge(mut self, is_merge: bool) -> Self {
        self.is_merge = is_merge;
        self
    }

    /// Builder method to set Shanghai flag
    pub fn with_shanghai(mut self, is_shanghai: bool) -> Self {
        self.is_shanghai = is_shanghai;
        self
    }

    /// Builder method to set Cancun flag
    pub fn with_cancun(mut self, is_cancun: bool) -> Self {
        self.is_cancun = is_cancun;
        self
    }

    /// Builder method to set Prague flag
    pub fn with_prague(mut self, is_prague: bool) -> Self {
        self.is_prague = is_prague;
        self
    }

    /// Builder method to set Verkle flag
    pub fn with_verkle(mut self, is_verkle: bool) -> Self {
        self.is_verkle = is_verkle;
        self
    }
}

/// Config holds tracer runtime configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Chain configuration (fork activation rules)
    #[serde(default)]
    pub chain_config: ChainConfig,

    /// Feature flags
    /// Enable concurrent flushing of blocks
    #[serde(default)]
    pub enable_concurrent_flushing: bool,

    /// Buffer size for concurrent processing
    #[serde(default = "default_concurrent_buffer_size")]
    pub concurrent_buffer_size: usize,

    /// Output destination path (if None, defaults to stdout)
    /// Note: In Rust, we store the path rather than the writer itself
    /// The actual io::Writer will be created when needed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
}

impl Config {
    /// Create a new config with the given chain configuration
    pub fn new(chain_config: ChainConfig) -> Self {
        Self {
            chain_config,
            enable_concurrent_flushing: false,
            concurrent_buffer_size: default_concurrent_buffer_size(),
            output_path: None,
        }
    }

    /// Builder method to enable concurrent flushing
    pub fn with_concurrent_flushing(mut self, enable: bool) -> Self {
        self.enable_concurrent_flushing = enable;
        self
    }

    /// Builder method to set concurrent buffer size
    pub fn with_concurrent_buffer_size(mut self, size: usize) -> Self {
        self.concurrent_buffer_size = size;
        self
    }

    /// Builder method to set output path
    pub fn with_output_path(mut self, path: String) -> Self {
        self.output_path = Some(path);
        self
    }

    /// Create a writer based on the configuration
    /// Returns a boxed writer that writes to either stdout or a file
    pub fn create_writer(&self) -> eyre::Result<Box<dyn io::Write>> {
        match &self.output_path {
            Some(path) => {
                let file = fs::File::create(path)?;
                Ok(Box::new(file))
            }
            None => Ok(Box::new(io::stdout())),
        }
    }

    /// Load config from JSON file
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let json = fs::read_to_string(path)?;
        Self::from_json_str(&json)
    }

    /// Load config from JSON string
    pub fn from_json_str(json: &str) -> eyre::Result<Self> {
        let config: Config = serde_json::from_str(json)?;
        Ok(config)
    }

    /// Load config from file if provided, otherwise use default
    pub fn load_or_default<P: AsRef<Path>>(config_file: Option<P>) -> eyre::Result<Self> {
        match config_file {
            Some(path) if path.as_ref().exists() => Self::from_json_file(path),
            _ => Ok(Self::default()),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_config: ChainConfig::default(),
            enable_concurrent_flushing: false,
            concurrent_buffer_size: default_concurrent_buffer_size(),
            output_path: None,
        }
    }
}

/// Helper function to check if a timestamp-based fork is active
fn is_timestamp_forked(fork: Option<u64>, timestamp: u64) -> bool {
    match fork {
        None => false,
        Some(fork_time) => fork_time <= timestamp,
    }
}

/// Default concurrent buffer size
fn default_concurrent_buffer_size() -> usize {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config_fork_detection() {
        let config = ChainConfig {
            chain_id: 1,
            shanghai_time: Some(1681338455), // April 12, 2023
            cancun_time: Some(1710338135),   // March 13, 2024
            prague_time: None,
            verkle_time: None,
        };

        // Before Shanghai
        assert!(!config.is_shanghai(0, 1681338454));
        // At Shanghai
        assert!(config.is_shanghai(0, 1681338455));
        // After Shanghai
        assert!(config.is_shanghai(0, 1681338456));

        // Prague not activated
        assert!(!config.is_prague(0, u64::MAX));
    }

    #[test]
    fn test_rules_creation() {
        let config = ChainConfig {
            chain_id: 1,
            shanghai_time: Some(1000),
            cancun_time: Some(2000),
            prague_time: None,
            verkle_time: None,
        };

        // Before Shanghai
        let rules = config.rules(100, true, 500);
        assert_eq!(rules.chain_id, 1);
        assert!(rules.is_merge);
        assert!(!rules.is_shanghai);
        assert!(!rules.is_cancun);

        // After Shanghai, before Cancun
        let rules = config.rules(200, true, 1500);
        assert!(rules.is_shanghai);
        assert!(!rules.is_cancun);

        // After Cancun
        let rules = config.rules(300, true, 3000);
        assert!(rules.is_shanghai);
        assert!(rules.is_cancun);
    }

    #[test]
    fn test_is_timestamp_forked() {
        assert!(!is_timestamp_forked(None, 1000));
        assert!(is_timestamp_forked(Some(1000), 1000));
        assert!(is_timestamp_forked(Some(1000), 2000));
        assert!(!is_timestamp_forked(Some(2000), 1000));
    }

    #[test]
    fn test_config_builder() {
        let chain_config = ChainConfig::new(1);
        let config = Config::new(chain_config)
            .with_concurrent_flushing(true)
            .with_concurrent_buffer_size(200);

        assert!(config.enable_concurrent_flushing);
        assert_eq!(config.concurrent_buffer_size, 200);
    }

    #[test]
    fn test_rules_builder() {
        let rules = Rules::new(1)
            .with_merge(true)
            .with_shanghai(true)
            .with_cancun(false);

        assert_eq!(rules.chain_id, 1);
        assert!(rules.is_merge);
        assert!(rules.is_shanghai);
        assert!(!rules.is_cancun);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            chain_config: ChainConfig {
                chain_id: 1,
                shanghai_time: Some(1681338455),
                cancun_time: Some(1710338135),
                prague_time: None,
                verkle_time: None,
            },
            enable_concurrent_flushing: true,
            concurrent_buffer_size: 150,
            output_path: Some("/tmp/output.log".to_string()),
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(config.chain_config.chain_id, deserialized.chain_config.chain_id);
        assert_eq!(config.enable_concurrent_flushing, deserialized.enable_concurrent_flushing);
        assert_eq!(config.concurrent_buffer_size, deserialized.concurrent_buffer_size);
    }
}
