use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {}

impl Config {
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        let json = fs::read_to_string(path)?;
        Self::from_json_str(&json)
    }

    pub fn from_json_str(json: &str) -> eyre::Result<Self> {
        let config: Config = serde_json::from_str(json)?;
        Ok(config)
    }

    pub fn load_or_default<P: AsRef<Path>>(config_file: Option<P>) -> eyre::Result<Self> {
        match config_file {
            Some(path) if path.as_ref().exists() => Self::from_json_file(path),
            _ => Ok(Self::default()),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {}
    }
}
