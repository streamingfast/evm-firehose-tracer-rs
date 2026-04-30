mod callstack;
pub mod config;
mod deferred_call_state;
mod eip7702;
pub mod emission;
pub mod finality;
pub mod logging;
pub mod mapper;
pub mod open_callstack;
mod ordinal;
pub mod pb;
pub mod printer;
mod tracer;
pub mod types;
pub mod utils;
pub mod version;

// Re-export Tracer and InMemoryBuffer so consumers can use them directly.
pub use tracer::{InMemoryBuffer, Tracer};
pub use emission::ShutdownHandle;
// Re-export EmissionMode for convenience.
pub use config::EmissionMode;
