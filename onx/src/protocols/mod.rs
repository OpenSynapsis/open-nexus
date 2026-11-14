//! Protocol decoding: what packets contain
//!
//! A decoded packet is an ordered stack of typed headers, outermost first.
//! Decode a captured packet with [`RawPacket::decode`](crate::core::packet::RawPacket::decode).

mod dissect;
pub mod ethernet;
pub mod fragment;
pub mod header;
pub mod ipv4;
pub mod ipv6;
mod next;
pub mod numbers;
pub mod packet;
pub mod span;
pub mod stats;
pub mod stop;

// Re-export commonly used types
pub use ethernet::{Ethernet, MacAddr};
pub use fragment::Fragment;
pub use header::{Header, HeaderKind};
pub use ipv4::Ipv4;
pub use ipv6::{Ipv6, Ipv6Fragment};
pub use numbers::EtherType;
pub use numbers::IpProtocol;
pub use packet::{Packet, MAX_DEPTH};
pub use span::Span;
pub use stats::ProtocolStats;
pub use stop::Stop;
