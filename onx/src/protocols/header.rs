//! Decoded headers: one variant per protocol decoded by onx

use std::fmt;

use crate::protocols::{ethernet::Ethernet, ipv4::Ipv4, Span};

/// A decoded header.
///
/// A packet is an ordered stack of headers, outermost first. Each variant
/// wraps the struct of its protocol, defined in the protocol's own file.
///
/// `#[non_exhaustive]`: adding a protocol is not a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Header {
    Ethernet(Ethernet),
    Ipv4(Ipv4),
}

impl Header {
    /// Returns the kind of this header, without its fields
    pub fn kind(&self) -> HeaderKind {
        match self {
            Header::Ethernet(_) => HeaderKind::Ethernet,
            Header::Ipv4(_) => HeaderKind::Ipv4,
        }
    }

    /// Returns the position of this header in the raw packet
    pub fn span(&self) -> Span {
        match self {
            Header::Ethernet(ethernet) => ethernet.span,
            Header::Ipv4(ipv4) => ipv4.span,
        }
    }
}

/// Kind of a header decoded by onx, without its fields.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeaderKind {
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

impl fmt::Display for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HeaderKind::Ethernet => "Ethernet",
            HeaderKind::Ipv4 => "IPv4",
            HeaderKind::Ipv6 => "IPv6",
            HeaderKind::Tcp => "TCP",
            HeaderKind::Udp => "UDP",
            HeaderKind::Icmpv4 => "ICMPv4",
            HeaderKind::Icmpv6 => "ICMPv6",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocols::{ethernet::MacAddr, EtherType, Fragment, IpProtocol};

    #[test]
    fn kind_and_span_of_ethernet() {
        let header = Header::Ethernet(Ethernet {
            destination: MacAddr::new([0xff; 6]),
            source: MacAddr::new([0x02, 0, 0, 0, 0, 0x01]),
            ether_type: EtherType::IPV4,
            span: Span::new(0, 14),
        });

        assert_eq!(header.kind(), HeaderKind::Ethernet);
        assert_eq!(header.span(), Span::new(0, 14));
    }

    #[test]
    fn kind_and_span_of_ipv4() {
        let header = Header::Ipv4(Ipv4 {
            destination: Ipv4Addr::new(10, 0, 48, 1),
            source: Ipv4Addr::new(10, 0, 48, 2),
            protocol: IpProtocol::TCP,
            identification: 48300,
            total_len: 100,
            fragment: Fragment::new(0, false),
            span: Span::new(14, 20),
        });

        assert_eq!(header.kind(), HeaderKind::Ipv4);
        assert_eq!(header.span(), Span::new(14, 20));
    }
}
