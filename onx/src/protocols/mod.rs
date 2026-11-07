//! Protocol decoding: what packets contain
//!
//! A decoded packet is an ordered stack of typed headers, outermost first.

pub mod numbers;
pub mod span;
pub mod stop;

// Re-export commonly used types
pub use numbers::EtherType;
pub use numbers::IpProtocol;
pub use span::Span;
pub use stop::{HeaderKind, Stop};
