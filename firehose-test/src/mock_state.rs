use alloy_primitives::{Address, Bytes};
use firehose::types::StateReader;
use std::collections::HashMap;

/// MockStateDB provides a simple in-memory state database for testing
/// This allows tests to provide state information to the tracer without
/// needing a full EVM implementation
#[derive(Debug, Default, Clone)]
pub struct MockStateDB {
    /// Account code storage
    code: HashMap<Address, Bytes>,
    /// Account nonce storage
    nonces: HashMap<Address, u64>,
    /// Account existence flags
    exists: HashMap<Address, bool>,
}

impl MockStateDB {
    /// Creates a new empty mock state database
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the code for an address
    pub fn set_code(&mut self, address: Address, code: Vec<u8>) {
        self.code.insert(address, Bytes::from(code));
    }

    /// Sets the nonce for an address
    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        self.nonces.insert(address, nonce);
    }

    /// Sets whether an address exists
    pub fn set_exist(&mut self, address: Address, exists: bool) {
        self.exists.insert(address, exists);
    }

    /// Checks if an address exists
    pub fn exist(&self, address: Address) -> bool {
        self.exists.get(&address).copied().unwrap_or(false)
    }
}

impl StateReader for MockStateDB {
    fn get_nonce(&self, address: Address) -> u64 {
        self.nonces.get(&address).copied().unwrap_or(0)
    }

    fn get_code(&self, address: Address) -> Bytes {
        self.code.get(&address).cloned().unwrap_or_default()
    }

    fn exists(&self, address: Address) -> bool {
        self.exist(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_state_db_default() {
        let db = MockStateDB::new();
        let addr = Address::from([0x1; 20]);

        assert_eq!(db.get_nonce(addr), 0);
        assert_eq!(db.get_code(addr), Bytes::default());
        assert!(!db.exist(addr));
    }

    #[test]
    fn test_mock_state_db_set_code() {
        let mut db = MockStateDB::new();
        let addr = Address::from([0x2; 20]);
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // Simple bytecode

        db.set_code(addr, code.clone());

        assert_eq!(db.get_code(addr), Bytes::from(code.clone()));
    }

    #[test]
    fn test_mock_state_db_set_nonce() {
        let mut db = MockStateDB::new();
        let addr = Address::from([0x3; 20]);

        db.set_nonce(addr, 42);

        assert_eq!(db.get_nonce(addr), 42);
    }

    #[test]
    fn test_mock_state_db_set_exist() {
        let mut db = MockStateDB::new();
        let addr = Address::from([0x4; 20]);

        db.set_exist(addr, true);

        assert!(db.exist(addr));
    }
}
