//! Internet Protocol version 4

use std::net::Ipv4Addr;

use crate::protocols::{fragment::Fragment, IpProtocol, Span};

/// IPv4 header
///
/// Options are not extracted; the header length (options included) is the
/// length of `span`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4 {
    /// Source address
    pub source: Ipv4Addr,
    /// Destination address
    pub destination: Ipv4Addr,
    /// Protocol carried by the packet
    pub protocol: IpProtocol,
    /// Identification of the datagram, shared by its fragments
    pub identification: u16,
    /// Length of the packet (header and payload) announced by the header
    pub total_len: u16,
    /// Position of the packet in a fragmented datagram
    pub fragment: Fragment,
    /// Position of the header in the raw packet
    pub span: Span,
}
