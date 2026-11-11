//! What to decode after a header

use crate::core::packet::LinkType;
use crate::protocols::{EtherType, IpProtocol};

/// Hint given by a decoded header about the header that follows it.
///
/// Internal to the dissection loop: users see `Header` and `Stop` only.
/// Each protocol adds the variant it produces (e.g. `IpProtocol` with IPv4,
/// `End` with UDP and TCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// The first header, given by the link type of the capture
    Link(LinkType),
    /// The next header is identified by an EtherType
    EtherType(EtherType),
    /// The next header is identified by an IP protocol number
    IpProtocol(IpProtocol),
    /// The next header is an IPv6 extension header. Its number is an IP
    /// protocol number, but it only means "extension" after IPv6.
    Ipv6Extension(IpProtocol),
    /// Nothing more to decode: the packet ends normally (e.g. the payload
    /// of a non-first IP fragment has no header)
    End,
}
