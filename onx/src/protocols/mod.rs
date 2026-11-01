//! Protocol decoding: what packets contain
//!
//! A decoded packet is an ordered stack of typed headers, outermost first.

pub mod numbers;

// Re-export commonly used types
pub use numbers::EtherType;
pub use numbers::IpProtocol;
