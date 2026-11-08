//! Protocol decoding: what packets contain
//!
//! A decoded packet is an ordered stack of typed headers, outermost first.
//! Decode a captured packet with [`RawPacket::decode`](crate::core::packet::RawPacket::decode).

mod dissect;
pub mod ethernet;
pub mod header;
mod next;
pub mod numbers;
pub mod packet;
pub mod span;
pub mod stats;
pub mod stop;

// Re-export commonly used types
pub use ethernet::{Ethernet, MacAddr};
pub use header::{Header, HeaderKind};
pub use numbers::EtherType;
pub use numbers::IpProtocol;
pub use packet::{Packet, MAX_DEPTH};
pub use span::Span;
pub use stats::ProtocolStats;
pub use stop::Stop;
