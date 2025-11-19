mod extensions;
#[allow(dead_code)]
mod pb;

pub use pb::*;

// Re-export for backward compatibility with old imports
pub use sf::ethereum::r#type::v2::{block, Block, BlockHeader};
