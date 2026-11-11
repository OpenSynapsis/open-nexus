//! Internet Protocol version 6

use std::net::Ipv6Addr;

use crate::protocols::{IpProtocol, Span};

/// IPv6 fixed header (40 bytes)
///
/// Extension headers (Hop-by-Hop, Routing, Fragment, Destination Options)
/// are separate headers in the packet's stack, each with its own span.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6 {
    /// Source address
    pub source: Ipv6Addr,
    /// Destination address
    pub destination: Ipv6Addr,
    /// Header that follows: an extension header or the upper-layer protocol
    pub next_header: IpProtocol,
    /// Length of everything after the fixed header (extensions included),
    /// announced by the header
    pub payload_len: u16,
    /// Flow label (20 bits)
    pub flow_label: u32,
    /// Position of the header in the raw packet
    pub span: Span,
}
